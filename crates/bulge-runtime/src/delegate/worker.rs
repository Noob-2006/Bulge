//! Workers in their VM slots: leasing a slot, the child job, driving it,
//! collecting and merging its changes, the independent review, and the
//! summary that goes back to the delegating agent.

use bulge_util::now_ms;
use std::sync::Arc;
use std::time::{Duration, Instant};
use bulge_core::driver::{DelegateReport, LoopOutcome, Sampling};
use bulge_core::VmDispatcher;
use bulge_llm::{Message, Role, ToolSchema};
use bulge_org::{BoardEvent, Review, parse_review, review_task};
use bulge_store::{Budget, JobEvent, JobHandle, JobSpec, JobStatus, JobStore, ModelRef};
use bulge_vm::slots::{self, MergeConflict, MergeReport};
use tokio_util::sync::CancellationToken;
use super::{CHILD_MAX_STEPS, CHILD_MAX_TOKENS, CHILD_MAX_WALL_SECS, ChildFactory, MAX_CONCURRENT_SUBAGENTS, ReviewOutcome, ReviewerPlan, RunSummary, SlotLease, TicketPlan, Worker, report_summary, send_bus_report};

/// Characters of a child's final answer returned to the parent; longer answers
/// are shortened in the middle (the full text stays in the child's job log).
pub(crate) const SUMMARY_CAP_CHARS: usize = 6_000;

/// How long a ticket waits for a free VM slot for its reviewer before failing.
pub(crate) const REVIEW_SLOT_WAIT: Duration = Duration::from_secs(10 * 60);

impl ChildFactory {
    /// Lease a VM slot and open it. The reviewer path waits up to ten minutes in
    /// one-second steps (honouring cancellation); the worker path fails at once.
    pub(crate) async fn lease_slot(&self, wait: bool, cancel: &CancellationToken) -> Result<SlotLease, String> {
        let deadline = Instant::now() + REVIEW_SLOT_WAIT;
        loop {
            if cancel.is_cancelled() {
                return Err("CANCELLED: the delegation was cancelled".into());
            }
            if let Some(lease) = self.vm_slots.lease() {
                let slot = lease.index();
                match slots::open(&self.vm, slot).await {
                    Ok(()) => return Ok(lease),
                    Err(error) => {
                        drop(lease);
                        return Err(format!("SLOT_OPEN: could not open VM workspace slot {slot}: {error}"));
                    }
                }
            }
            if !wait {
                return Err(format!(
                    "SLOTS_FULL: all {MAX_CONCURRENT_SUBAGENTS} VM workspace slots are in use; wait for one to finish"
                ));
            }
            if Instant::now() >= deadline {
                return Err("SLOTS_FULL: no VM workspace slot became free for the reviewer within 10 minutes".into());
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
                () = cancel.cancelled() => return Err("CANCELLED: the delegation was cancelled".into()),
            }
        }
    }

    pub(crate) fn create_child_job(&self, task: &str, model: &str, ledger: &Arc<bulge_core::ledger::Ledger>) -> Result<(JobHandle, String), String> {
        let store = JobStore::new(&self.store_root);
        let job_id = bulge_store::new_job_id().map_err(|error| format!("child job id: {error}"))?;
        let title: String = task.lines().next().unwrap_or("sub-task").chars().take(80).collect();
        let mut job = store
            .create(JobSpec {
                id: job_id.clone(),
                title,
                goal: task.to_string(),
                workspace: self.workspace.clone(),
                autonomy: self.recipe.autonomy,
                budget: Budget {
                    max_steps: CHILD_MAX_STEPS,
                    max_tokens: ledger.token_limit(),
                    max_wall_secs: ledger.remaining_secs().unwrap_or(CHILD_MAX_WALL_SECS),
                },
                model: ModelRef {
                    backend: self.backend_id.clone(),
                    model: model.to_string(),
                },
            })
            .map_err(|error| format!("create child job: {error}"))?;
        job.append(vec![JobEvent::Message {
            message: Message::text(Role::User, task),
        }])
        .map_err(|error| format!("append child task: {error}"))?;
        Ok((job, job_id))
    }

    /// Lease and open the worker's slot, create its job, and claim/start the ticket.
    pub(crate) async fn start_worker(
        &self,
        plan: &TicketPlan,
        task: &str,
        model: &str,
        cancel: &CancellationToken,
    ) -> Result<Worker, String> {
        let lease = self.lease_slot(false, cancel).await?;
        let slot = lease.index();
        let ledger = plan.ledger.child(CHILD_MAX_TOKENS, Some(CHILD_MAX_WALL_SECS));
        if ledger.exhausted() {
            let _ = slots::close(&self.vm, slot).await;
            return Err("BUDGET_EXHAUSTED: the ticket has nothing left for a worker".into());
        }
        let (job, job_id) = match self.create_child_job(task, model, &ledger) {
            Ok(job) => job,
            Err(error) => {
                let _ = slots::close(&self.vm, slot).await;
                return Err(error);
            }
        };
        self.record_board(BoardEvent::Claimed {
            id: plan.ticket_id.clone(),
            owner: job_id.clone(),
            at_ms: now_ms(),
        });
        self.record_board(BoardEvent::Started {
            id: plan.ticket_id.clone(),
            at_ms: now_ms(),
        });
        Ok(Worker {
            lease,
            slot,
            job,
            ledger,
            job_id,
        })
    }

    pub(crate) async fn run_worker(&self, worker: &mut Worker, plan: &TicketPlan, cancel: &CancellationToken) -> Result<RunSummary, String> {
        self.drive_child(
            &mut worker.job,
            &worker.ledger,
            worker.slot,
            plan.system_prompt.clone(),
            plan.tools.clone(),
            plan.sampling.clone(),
            cancel,
        )
        .await
    }

    /// Run one child driver against a slot and summarize its final state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn drive_child(
        &self,
        job: &mut JobHandle,
        ledger: &Arc<bulge_core::ledger::Ledger>,
        slot: u8,
        system_prompt: String,
        tools: Vec<ToolSchema>,
        sampling: Sampling,
        cancel: &CancellationToken,
    ) -> Result<RunSummary, String> {
        let dispatcher = crate::recipe::with_hooks(Arc::new(VmDispatcher::new(self.vm.clone(), self.tool_timeout).with_slot(slot)), &self.hooks);
        let driver = self.recipe.driver(dispatcher, tools, system_prompt, sampling, ledger.clone());

        let outcome = driver
            .run(job, cancel.clone())
            .await
            .map_err(|error| format!("child run: {error}"))?;
        Ok(run_summary(job, outcome))
    }

    pub(crate) async fn collect_changes(&self, slot: u8) -> (Vec<String>, Vec<MergeConflict>) {
        match slots::collect(&self.vm, slot).await {
            Ok(changes) => (changes.iter().map(|change| change.path().to_string()).collect(), Vec::new()),
            Err(error) => {
                eprintln!("delegate: collect changes from VM slot {slot}: {error}");
                (
                    Vec::new(),
                    vec![MergeConflict {
                        path: "*".into(),
                        reason: format!("could not collect the sub-agent's changes: {error}"),
                    }],
                )
            }
        }
    }

    pub(crate) async fn merge_slot(&self, slot: u8, changed: &[String], lost: Vec<MergeConflict>) -> MergeReport {
        let mut merge = match slots::merge(&self.vm, slot, changed).await {
            Ok(report) => report,
            Err(error) => {
                eprintln!("delegate: merge from VM slot {slot}: {error}");
                MergeReport {
                    merged: Vec::new(),
                    conflicts: changed
                        .iter()
                        .map(|path| MergeConflict {
                            path: path.clone(),
                            reason: format!("merge failed: {error}"),
                        })
                        .collect(),
                }
            }
        };
        merge.conflicts.extend(lost);
        merge
    }

    pub(crate) async fn finish_worker(&self, worker: Worker) {
        let Worker { lease, slot, .. } = worker;
        if let Err(error) = slots::close(&self.vm, slot).await {
            eprintln!("delegate: close VM slot {slot}: {error}");
        }
        drop(lease);
    }

    /// Open a staging slot containing the worker's changed files, run the reviewer
    /// (once more if the first answer has no verdict), and always discard the
    /// staging slot afterwards. The worker's slot is not touched here.
    pub(crate) async fn review(
        &self,
        plan: &TicketPlan,
        reviewer: &ReviewerPlan,
        worker_summary: &str,
        changed: &[String],
        from_slot: u8,
        cancel: &CancellationToken,
    ) -> Result<ReviewOutcome, String> {
        let lease = self.lease_slot(true, cancel).await?;
        let slot = lease.index();
        let result: Result<ReviewOutcome, String> = async {
            slots::stage(&self.vm, slot, from_slot, changed)
                .await
                .map_err(|error| format!("SLOT_STAGE: copy the worker's changes into review slot {slot}: {error}"))?;
            let task = review_task(&plan.goal, &plan.acceptance, worker_summary, changed);
            let mut last_job = String::new();
            for attempt in 0..2 {
                let ledger = plan.ledger.child(CHILD_MAX_TOKENS, Some(CHILD_MAX_WALL_SECS));
                if ledger.exhausted() {
                    return Err("BUDGET_EXHAUSTED: the ticket has nothing left for a reviewer".into());
                }
                let (mut job, job_id) = self.create_child_job(&task, &reviewer.model, &ledger)?;
                last_job = job_id.clone();
                let run = match self
                    .drive_child(
                        &mut job,
                        &ledger,
                        slot,
                        reviewer.system_prompt.clone(),
                        reviewer.tools.clone(),
                        reviewer.sampling.clone(),
                        cancel,
                    )
                    .await
                {
                    Ok(run) => run,
                    Err(error) if cancel.is_cancelled() => {
                        return Err(format!("CANCELLED: the review was cancelled: {error}"));
                    }
                    Err(error) => {
                        if attempt == 0 {
                            eprintln!(
                                "delegate: reviewer {} for ticket {} failed: {error}; asking once more",
                                reviewer.name, plan.ticket_id
                            );
                        } else {
                            eprintln!(
                                "delegate: reviewer {} for ticket {} failed: {error}",
                                reviewer.name, plan.ticket_id
                            );
                        }
                        continue;
                    }
                };
                if cancel.is_cancelled() {
                    return Err("CANCELLED: the review was cancelled".into());
                }
                if let Some(Review { accept, feedback }) = parse_review(&run.summary) {
                    return Ok(ReviewOutcome {
                        reviewed: true,
                        accepted: Some(accept),
                        feedback,
                        job_id,
                    });
                }
                if attempt == 0 {
                    eprintln!(
                        "delegate: reviewer {} for ticket {} produced no verdict; asking once more",
                        reviewer.name, plan.ticket_id
                    );
                }
            }
            Ok(ReviewOutcome {
                reviewed: true,
                accepted: None,
                feedback: String::new(),
                job_id: last_job,
            })
        }
        .await;
        if let Err(error) = slots::close(&self.vm, slot).await {
            eprintln!("delegate: close review slot {slot}: {error}");
        }
        drop(lease);
        result
    }

    /// Build and send the final report, appending the verdict line when there is one.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize(
        &self,
        plan: &TicketPlan,
        run: &RunSummary,
        job_id: &str,
        reviewed: bool,
        accepted: Option<bool>,
        feedback: &str,
        attempts: u32,
        models: Vec<String>,
        changed: Vec<String>,
        merged: Vec<String>,
        conflicts: Vec<String>,
        note: Option<&str>,
    ) -> DelegateReport {
        let summary = report_summary(&run.summary, accepted, feedback, note, &conflicts);
        let (summary, quarantined) = {
            let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            send_bus_report(&mut org, &plan.ticket_id, job_id, &self.head, &summary)
        };
        DelegateReport {
            status: run.status.clone(),
            outcome: run.outcome.clone(),
            role: plan.role_name.clone(),
            ticket: plan.ticket_id.clone(),
            summary,
            truncated: run.truncated || quarantined,
            tokens: plan.ledger.spent(),
            steps: run.steps,
            job_id: job_id.to_string(),
            changed,
            merged,
            conflicts,
            reviewed,
            accepted,
            feedback: feedback.to_string(),
            attempts,
            models,
        }
    }
}

/// Summarize a finished child (worker, reviewer, or lead) job: prefer its
/// recorded summary, else fall back to the last assistant message.
pub(crate) fn run_summary(job: &JobHandle, outcome: LoopOutcome) -> RunSummary {
    let state = job.state();
    let text = if let Some(summary) = state.summary.clone().filter(|summary| !summary.trim().is_empty()) {
        summary
    } else {
        let last = state.history.iter().rev().find_map(|message| {
            if message.role != Role::Assistant {
                return None;
            }
            let text = message.joined_text();
            (!text.trim().is_empty()).then_some(text)
        });
        last.unwrap_or_else(|| "(sub-agent produced no summary)".to_string())
    };
    let (summary, truncated) = truncate_summary(&text, SUMMARY_CAP_CHARS);
    let status = serde_json::to_value(state.status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    RunSummary {
        succeeded: state.status == JobStatus::Succeeded,
        status,
        outcome: outcome_name(outcome).to_string(),
        summary,
        truncated,
        steps: state.steps,
    }
}

/// Format merge conflicts for the report.
pub(crate) fn format_conflicts(conflicts: &[MergeConflict]) -> Vec<String> {
    conflicts
        .iter()
        .map(|conflict| format!("{}: {}", conflict.path, conflict.reason))
        .collect()
}

/// The `LoopOutcome`'s snake_case name, for the report's `outcome` field.
pub(crate) fn outcome_name(outcome: LoopOutcome) -> &'static str {
    match outcome {
        LoopOutcome::Stopped => "stopped",
        LoopOutcome::BudgetExhausted => "budget_exhausted",
        LoopOutcome::Cancelled => "cancelled",
        LoopOutcome::Failed => "failed",
        LoopOutcome::Stuck => "stuck",
        LoopOutcome::Incomplete => "incomplete",
    }
}

/// Shorten `text` to at most `cap` characters for the parent's context: short
/// text is returned unchanged; long text keeps the first two-thirds and the last
/// third, joined by a note pointing at the child's full job log. Always slices on
/// char boundaries (never bytes), so it is UTF-8 safe.
pub fn truncate_summary(text: &str, cap: usize) -> (String, bool) {
    let total = text.chars().count();
    if total <= cap {
        return (text.to_string(), false);
    }
    let head_len = cap * 2 / 3;
    let tail_len = cap / 3;
    let omitted = total.saturating_sub(head_len + tail_len);
    let head: String = text.chars().take(head_len).collect();
    let tail: String = text.chars().skip(total - tail_len).collect();
    (
        format!("{head}\n[… {omitted} chars omitted; full text in the sub-agent's job log …]\n{tail}"),
        true,
    )
}
