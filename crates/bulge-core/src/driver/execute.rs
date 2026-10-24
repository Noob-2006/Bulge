//! Running one step's tool calls: permission rules, the reviewer gate, and
//! dispatch with their results logged.

use bulge_llm::assemble::Assembler;
use bulge_llm::{GenerateRequest, Message, Purpose, Role, TokenUsage};
use bulge_store::{JobEvent, JobHandle, JobStatus, PlanItem, StoreError};
use futures::StreamExt;
use futures::future::LocalBoxFuture;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use crate::budget::BudgetTracker;
use crate::complete;
use crate::dispatch::{DELEGATE_TOOL, ORG_STATUS_TOOL, PLAN_TOOL, PROPOSE_ROLE_TOOL, RECALL_TOOL, SKILL_TOOL, ToolCall};
use crate::schedule::{CallOutcome, PlannedCall, run_tool_calls};
use super::{DelegateRequest, Driver, ExtractedCall, LoopOutcome, PermissionBlock, assistant_text, call_resource, harness_note, outcome_value, parse_lenient, parse_plan, render_outcome, split_image};

impl Driver {
    /// Claim calls, consult the guard, run the allowed ones, and log results.
    /// Returns `Some(outcome)` when a critical loop requires stopping the job.
    pub(super) async fn dispatch_calls(
        &self,
        job: &mut JobHandle,
        calls: Vec<ExtractedCall>,
        cancel: &CancellationToken,
        detector: &mut Option<bulge_guard::LoopDetector>,
        warned: &mut std::collections::HashSet<String>,
        budget: &mut BudgetTracker,
    ) -> Result<Option<LoopOutcome>, StoreError> {
        // Write-ahead: claim every call before any of them runs — host-side tools
        // (delegate, role proposals) included — so a crash at any later point
        // leaves claims that recovery closes with an "interrupted" result. From
        // here on every path must log one result per call, right after the
        // assistant message, before any other message.
        let claims = calls
            .iter()
            .map(|c| JobEvent::ToolClaimed { call_id: c.id.clone(), name: c.name.clone(), arguments: parse_lenient(&c.arguments) })
            .collect();
        job.append(claims)?;

        // Loop detection (before anything runs): critical → stop; warning →
        // remind once, after this turn's results.
        let mut reminders: Vec<String> = Vec::new();
        if let Some(detector) = detector.as_ref() {
            let known = self.tool_names();
            for call in &calls {
                let args = parse_lenient(&call.arguments);
                if let Some(verdict) = detector.check(&call.name, &args, !known.contains(&call.name)) {
                    match verdict.level {
                        bulge_guard::Level::Critical => {
                            let note = "not run: the job was stopped because it is repeating itself";
                            let mut events = Vec::with_capacity(calls.len() * 2 + 1);
                            for call in &calls {
                                let (ok, value, text) = render_outcome(CallOutcome::Err { code: "NOT_RUN".into(), message: note.into() });
                                events.push(JobEvent::ToolCompleted { call_id: call.id.clone(), ok, result: value });
                                events.push(JobEvent::Message { message: Message::tool_result(call.id.clone(), text, true) });
                            }
                            events.push(JobEvent::Message { message: harness_note(&verdict.message) });
                            job.append(events)?;
                            return Ok(Some(self.finish(job, LoopOutcome::Stuck, JobStatus::Incomplete, Some(verdict.message)).await?));
                        }
                        bulge_guard::Level::Warning => {
                            let key = format!("{:?}:{}", verdict.detector, call.name);
                            if warned.insert(key) {
                                reminders.push(verdict.message);
                            }
                        }
                    }
                }
            }
        }

        // Host-side tools are handled here, never sent to the VM. All `delegate`
        // calls of this turn run concurrently on this thread (their futures are
        // `!Send`, so concurrency is cooperative, not multi-threaded): one future
        // per call, then join them all before the remaining calls are dispatched.
        let mut host: std::collections::HashMap<String, CallOutcome> = std::collections::HashMap::new();
        if let Some(handler) = self.delegate.clone() {
            let mut pending: Vec<(String, LocalBoxFuture<'_, CallOutcome>)> = Vec::new();
            for call in &calls {
                if call.name != DELEGATE_TOOL {
                    continue;
                }
                let args = parse_lenient(&call.arguments);
                let goal = args.get("goal").and_then(Value::as_str).unwrap_or("").trim().to_string();
                if goal.is_empty() {
                    pending.push((
                        call.id.clone(),
                        Box::pin(async {
                            CallOutcome::Err { code: "BAD_DELEGATE".into(), message: "delegate needs a non-empty `goal`".into() }
                        }),
                    ));
                    continue;
                }
                let context = args.get("context").and_then(Value::as_str).map(str::to_string);
                let role = args.get("role").and_then(Value::as_str).map(str::to_string);
                let model = args
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|model| !model.is_empty())
                    .map(str::to_string);
                let acceptance = match args.get("acceptance") {
                    Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_string).collect(),
                    Some(Value::String(one)) => vec![one.clone()],
                    _ => Vec::new(),
                };
                // Cancelling the parent cancels every child.
                let child_cancel = cancel.child_token();
                let handler = handler.clone();
                pending.push((
                    call.id.clone(),
                    Box::pin(async move {
                        match handler.run(DelegateRequest { goal, context, role, model, acceptance }, child_cancel).await {
                            Ok(report) => CallOutcome::Ok(serde_json::to_value(&report).unwrap_or_default()),
                            Err(message) => CallOutcome::Err { code: "DELEGATE_FAILED".into(), message },
                        }
                    }),
                ));
            }
            let ids: Vec<String> = pending.iter().map(|(id, _)| id.clone()).collect();
            let outcomes = futures::future::join_all(pending.into_iter().map(|(_, future)| future)).await;
            for (id, outcome) in ids.into_iter().zip(outcomes) {
                host.insert(id, outcome);
            }
        }
        for tool in &self.host_tools {
            for call in calls.iter().filter(|c| c.name == tool.name()) {
                let outcome = match tool.call(&parse_lenient(&call.arguments)) {
                    Ok(value) => CallOutcome::Ok(value),
                    Err(message) => CallOutcome::Err { code: "TOOL_FAILED".into(), message },
                };
                host.insert(call.id.clone(), outcome);
            }
        }
        if let Some(handler) = self.recall.clone() {
            for call in &calls {
                if call.name != RECALL_TOOL {
                    continue;
                }
                let args = parse_lenient(&call.arguments);
                let query = args.get("query").and_then(Value::as_str).unwrap_or("").trim().to_string();
                let outcome = if query.is_empty() {
                    CallOutcome::Err { code: "BAD_RECALL".into(), message: "recall needs a non-empty `query`".into() }
                } else {
                    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(5).clamp(1, 20) as usize;
                    CallOutcome::Ok(serde_json::json!({ "results": handler.recall(&query, limit) }))
                };
                host.insert(call.id.clone(), outcome);
            }
        }
        if let Some(handler) = self.skills.clone() {
            for call in &calls {
                if call.name != SKILL_TOOL {
                    continue;
                }
                let args = parse_lenient(&call.arguments);
                let name = args.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
                let outcome = match handler.load(&name) {
                    Ok(steps) => CallOutcome::Ok(Value::String(steps)),
                    Err(message) => CallOutcome::Err { code: "BAD_SKILL".into(), message },
                };
                host.insert(call.id.clone(), outcome);
            }
        }
        if let Some(handler) = self.org_status.clone() {
            for call in &calls {
                if call.name != ORG_STATUS_TOOL {
                    continue;
                }
                let outcome = CallOutcome::Ok(serde_json::json!({ "report": handler.status() }));
                host.insert(call.id.clone(), outcome);
            }
        }
        if let Some(handler) = self.propose_role.clone() {
            for call in &calls {
                if call.name != PROPOSE_ROLE_TOOL {
                    continue;
                }
                let args = parse_lenient(&call.arguments);
                let charter = args
                    .get("charter")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let reason = args
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let outcome = if charter.is_empty() {
                    CallOutcome::Err {
                        code: "BAD_PROPOSE_ROLE".into(),
                        message: "propose_role needs a non-empty `charter`".into(),
                    }
                } else if reason.is_empty() {
                    CallOutcome::Err {
                        code: "BAD_PROPOSE_ROLE".into(),
                        message: "propose_role needs a non-empty `reason`".into(),
                    }
                } else {
                    let child_cancel = cancel.child_token();
                    match handler.propose(charter, reason, child_cancel).await {
                        Ok(value) => CallOutcome::Ok(value),
                        Err(message) => CallOutcome::Err {
                            code: "PROPOSE_ROLE_FAILED".into(),
                            message,
                        },
                    }
                };
                host.insert(call.id.clone(), outcome);
            }
        }
        let mut plan_update: Option<Vec<PlanItem>> = None;
        for call in &calls {
            if call.name == PLAN_TOOL {
                match parse_plan(&call.arguments) {
                    Ok(items) => {
                        let outcome = CallOutcome::Ok(serde_json::json!({ "ok": true, "items": items.len() }));
                        plan_update = Some(items);
                        host.insert(call.id.clone(), outcome);
                    }
                    Err(message) => {
                        host.insert(call.id.clone(), CallOutcome::Err { code: "BAD_PLAN".into(), message });
                    }
                }
            }
        }

        // Permission: a blocked call is never run; the model is told so it adapts.
        // `Ask` fails closed too — there is no tool approval channel here.
        let mut blocked: std::collections::HashMap<String, PermissionBlock> = calls
            .iter()
            .filter(|c| !host.contains_key(&c.id))
            .filter_map(|c| self.permission_block(c).map(|block| (c.id.clone(), block)))
            .collect();

        // LLM review gate: a second opinion on every mutating (barrier) call that
        // policy did not already block. Runs sequentially before anything executes.
        if self.review {
            for call in &calls {
                if host.contains_key(&call.id) || blocked.contains_key(&call.id) || self.dispatcher.concurrency_safe(&call.name) {
                    continue;
                }
                let (denial, usage) = self.review_denial(job, call, cancel).await;
                job.append(vec![JobEvent::Usage { model: job.state().spec.model.model.clone(), usage }])?;
                budget.record_tokens(usage.total());
                if let Some(reason) = denial {
                    blocked.insert(call.id.clone(), PermissionBlock::Deny(reason));
                }
            }
        }
        // Every asked call is recorded as awaiting a human before it is failed
        // closed, so the log preserves what the guard wanted to ask.
        let approvals: Vec<JobEvent> = calls
            .iter()
            .filter_map(|call| match blocked.get(&call.id) {
                Some(PermissionBlock::Ask { resource }) => Some(JobEvent::ApprovalAsked {
                    id: call.id.clone(),
                    kind: "tool".into(),
                    detail: serde_json::json!({
                        "tool": call.name,
                        "resource": resource,
                        "reason": "this action requires a human",
                    }),
                }),
                _ => None,
            })
            .collect();
        if !approvals.is_empty() {
            job.append(approvals)?;
        }
        // Record the plan update (if any) between claim and completion.
        if let Some(items) = plan_update {
            job.append(vec![JobEvent::Plan { items }])?;
        }

        let planned: Vec<PlannedCall> = calls
            .iter()
            .filter(|c| !blocked.contains_key(&c.id) && !host.contains_key(&c.id))
            .map(|c| PlannedCall {
                call_id: c.id.clone(),
                name: c.name.clone(),
                raw_arguments: c.arguments.clone(),
                concurrency_safe: self.dispatcher.concurrency_safe(&c.name),
            })
            .collect();

        let dispatcher = self.dispatcher.clone();
        let mut results = run_tool_calls(
            planned,
            self.max_parallel,
            cancel,
            |_, _| {},
            |call, args, token| {
                let dispatcher = dispatcher.clone();
                async move { dispatcher.dispatch(ToolCall { name: call.name, arguments: args }, token).await }
            },
        )
        .await;

        // Fold in blocked calls as errors, preserving model order.
        let by_id: std::collections::HashMap<String, CallOutcome> = results.drain(..).map(|r| (r.call_id, r.outcome)).collect();
        let mut images: Vec<Message> = Vec::new();
        let mut events = Vec::with_capacity(calls.len() * 2);
        for call in &calls {
            let outcome = if let Some(outcome) = host.get(&call.id) {
                outcome.clone()
            } else if let Some(block) = blocked.get(&call.id) {
                match block {
                    PermissionBlock::Deny(reason) => CallOutcome::Err { code: "PERMISSION_DENIED".into(), message: reason.clone() },
                    PermissionBlock::Ask { resource } => CallOutcome::Err {
                        code: "REQUIRES_HUMAN".into(),
                        message: format!(
                            "{} on {resource} needs a human; it was not run. Do not retry it or work around it — finish what you can and say in your answer exactly what the human must do.",
                            call.name
                        ),
                    },
                }
            } else {
                by_id.get(&call.id).cloned().unwrap_or(CallOutcome::Skipped)
            };
            if let Some(detector) = detector.as_mut() {
                let ok = matches!(outcome, CallOutcome::Ok(_));
                let result = outcome_value(&outcome);
                detector.observe(bulge_guard::Observation { tool: call.name.clone(), arguments: parse_lenient(&call.arguments), ok, result });
            }
            let (outcome, image) = if call.name == crate::dispatch::VIEW_IMAGE_TOOL { split_image(outcome) } else { (outcome, None) };
            let (ok, value, text) = render_outcome(outcome);
            events.push(JobEvent::ToolCompleted { call_id: call.id.clone(), ok, result: value });
            events.push(JobEvent::Message { message: Message::tool_result(call.id.clone(), text, !ok) });
            images.extend(image);
        }
        // Images and loop reminders go after the results: a message between
        // an assistant tool call and its results is rejected by providers
        // (and tool results cannot carry images).
        events.extend(images.into_iter().map(|message| JobEvent::Message { message }));
        events.extend(reminders.into_iter().map(|note| JobEvent::Message { message: harness_note(note) }));
        job.append(events)?;
        Ok(None)
    }

    /// If the guard's rules block this call, why. `Ask` is a block: without a
    /// human approval channel the only safe reading of "ask" is "do not run".
    pub(super) fn permission_block(&self, call: &ExtractedCall) -> Option<PermissionBlock> {
        let guard = self.guard.as_ref()?;
        let resource = call_resource(call);
        match bulge_guard::evaluate(&call.name, &resource, &[&guard.rules]) {
            bulge_guard::Effect::Deny => Some(PermissionBlock::Deny(format!("blocked by policy: {} on {resource}", call.name))),
            bulge_guard::Effect::Ask => Some(PermissionBlock::Ask { resource }),
            bulge_guard::Effect::Allow => None,
        }
    }

    /// A bounded LLM review of one mutating call. Returns `Some(reason)` to block.
    /// The reviewer sees ONLY the proposed call (never prior tool output), so a
    /// prompt-injection in earlier results cannot talk it into approving. Any
    /// error, timeout, or malformed reply fails OPEN (returns `None`) — the review
    /// is a second opinion, not the primary boundary (the sandbox is). The call's
    /// token usage is returned either way so it is logged and charged.
    pub(super) async fn review_denial(&self, job: &JobHandle, call: &ExtractedCall, cancel: &CancellationToken) -> (Option<String>, TokenUsage) {
        let model = job.state().spec.model.model.clone();
        let proposal = format!("Tool: {}\nArguments: {}", call.name, call.arguments);
        let request = GenerateRequest {
            model: model.clone(),
            messages: vec![
                Message::text(Role::System, complete::REVIEW_POLICY),
                Message::text(Role::User, proposal),
            ],
            tools: Vec::new(),
            max_tokens: Some(200),
            temperature: Some(0.0),
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: Purpose::Memory,
        };
        let mut stream = self.backend.stream(request, cancel.clone());
        let mut assembler = Assembler::new();
        while let Some(chunk) = stream.next().await {
            assembler.push(&chunk);
        }
        let assembled = assembler.finish(&model);
        let denial = assistant_text(&assembled.message).and_then(|text| complete::parse_review_denial(&text));
        (denial, assembled.usage)
    }
}
