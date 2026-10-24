//! The child factory: runs a delegated sub-agent (worker, reviewer, lead) in
//! its own VM slot and reports back.

use bulge_util::now_ms;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use bulge_core::driver::{DelegateHandler, DelegateRequest, DelegateReport, Sampling};
use bulge_core::hooks::HookRunner;
use bulge_core::VmDispatcher;
use bulge_llm::ToolSchema;
use bulge_org::{BoardEvent, PerformanceBook, RoleCharter, RoleKind, RoleLibrary};
use bulge_store::JobHandle;
use bulge_vm::vm::Vm;
use futures::future::LocalBoxFuture;
use tokio_util::sync::CancellationToken;
use super::{CHILD_MAX_TOKENS, CHILD_MAX_WALL_SECS, Governance, OrgState, OrgStatus, SlotLease, VmSlots, child_task_message, post_ticket, report_summary, resolve_role, reviewer_role, role_sampling, run_summary, send_bus_report};

/// A reviewer's frozen role settings for one ticket.
pub(crate) struct ReviewerPlan {
    pub(super) name: String,
    pub(super) system_prompt: String,
    pub(super) tools: Vec<ToolSchema>,
    pub(super) sampling: Sampling,
    pub(super) model: String,
}

/// Everything one ticket needs, frozen before the loop starts.
pub(crate) struct TicketPlan {
    pub(super) ticket_id: String,
    pub(super) role_name: String,
    pub(super) system_prompt: String,
    pub(super) tools: Vec<ToolSchema>,
    pub(super) sampling: Sampling,
    pub(super) candidates: Vec<String>,
    pub(super) base_task: String,
    pub(super) goal: String,
    pub(super) acceptance: Vec<String>,
    pub(super) requested_model: Option<String>,
    pub(super) reviewer: Option<ReviewerPlan>,
    pub(super) ledger: Arc<bulge_core::ledger::Ledger>,
}

/// A worker job and its private VM slot, kept across reworks.
pub(crate) struct Worker {
    pub(super) lease: SlotLease,
    pub(super) slot: u8,
    pub(super) job: JobHandle,
    pub(super) ledger: Arc<bulge_core::ledger::Ledger>,
    pub(super) job_id: String,
}

/// What one driver run produced.
#[derive(Debug, Clone)]
pub(crate) struct RunSummary {
    pub(super) status: String,
    pub(super) outcome: String,
    pub(super) summary: String,
    pub(super) truncated: bool,
    pub(super) succeeded: bool,
    pub(super) steps: u64,
}

/// What one independent review produced.
pub(crate) struct ReviewOutcome {
    /// At least one reviewer ran (even if it produced no verdict).
    pub(super) reviewed: bool,
    pub(super) accepted: Option<bool>,
    pub(super) feedback: String,
    pub(super) job_id: String,
}

/// Everything a delegation needs to spawn and run a child agent. All fields are
/// cheap clones / `Arc`s so the dispatcher can capture them per call.
#[derive(Clone)]
pub struct ChildFactory {
    /// The backend, guard, autonomy, context and review every agent shares.
    pub recipe: crate::recipe::DriverRecipe,
    /// The session's VM. Every child builds its own slot dispatcher against it.
    pub vm: Arc<Vm>,
    /// VM workspace slots shared by every child of this session.
    pub vm_slots: Arc<VmSlots>,
    /// User lifecycle hooks, applied to each child's tool calls.
    pub hooks: Arc<HookRunner>,
    /// Per-tool-call timeout, matching the parent's `VmDispatcher`.
    pub tool_timeout: Duration,
    /// Tools the child sees (parent tools minus `delegate`/`org_status` and any
    /// `mcp__*` tools); the role's allowlist filters this per child.
    pub child_tools: Vec<ToolSchema>,
    /// Tools a sub-lead sees: the child tools plus `delegate` and `org_status`.
    pub lead_tools: Vec<ToolSchema>,
    pub store_root: PathBuf,
    pub workspace: PathBuf,
    pub model: String,
    pub backend_id: String,
    pub sampling: Sampling,
    /// The parent's node of this turn's budget tree. Children are made as its
    /// child nodes, so their spend is charged to the parent's budget.
    pub ledger: Arc<bulge_core::ledger::Ledger>,
    /// The organization's role library, shared so an installed role becomes
    /// usable in the same session.
    pub roles: Arc<RwLock<RoleLibrary>>,
    /// Where governed role charters are installed.
    pub roles_dir: PathBuf,
    /// The append-only governance decision log.
    pub governance_path: PathBuf,
    /// The session's persistent performance book.
    pub perf: Arc<Mutex<PerformanceBook>>,
    /// Where the performance book is saved after every recorded verdict.
    pub perf_path: PathBuf,
    /// The head's board and bus for this session.
    pub org: Arc<Mutex<OrgState>>,
    /// The parent job id, used as the head's name on the board and bus.
    pub head: String,
    /// Depth of the agent that owns this factory (the head is 0).
    pub depth: u32,
    /// The ticket the owning agent is working on; `None` for the head.
    pub parent_ticket: Option<String>,
    /// Merged paths from this team's children, accumulated for a lead's report.
    pub merged_accumulator: Option<Arc<Mutex<Vec<String>>>>,
}

/// The per-team fields [`ChildFactory::for_sub_team`] replaces. Kept separate
/// from the factory's VM-backed state so the transition is independently
/// testable without launching a VM.
pub(crate) struct SubTeamIdentity {
    pub(super) depth: u32,
    pub(super) ticket: String,
    pub(super) head: String,
    pub(super) ledger: Arc<bulge_core::ledger::Ledger>,
}

pub(crate) fn sub_team_identity(
    depth: u32,
    ticket: String,
    head: String,
    ledger: Arc<bulge_core::ledger::Ledger>,
) -> SubTeamIdentity {
    SubTeamIdentity {
        depth,
        ticket,
        head,
        ledger,
    }
}

impl ChildFactory {
    /// A clone of this factory for a sub-lead's team: the new team sits one
    /// level deeper, posts tickets under `ticket`, reports to `head`, and spends
    /// from `ledger`. Everything else (VM, slots, hooks, roles, org, perf) is
    /// shared.
    pub fn for_sub_team(
        &self,
        depth: u32,
        ticket: String,
        head: String,
        ledger: Arc<bulge_core::ledger::Ledger>,
    ) -> ChildFactory {
        let identity = sub_team_identity(depth, ticket, head, ledger);
        let mut factory = self.clone();
        factory.depth = identity.depth;
        factory.parent_ticket = Some(identity.ticket);
        factory.head = identity.head;
        factory.ledger = identity.ledger;
        // A new team starts its own merge accumulator; run_lead installs it.
        factory.merged_accumulator = None;
        factory
    }

    /// Build the governance handler this agent uses for `propose_role`. It
    /// shares the role library, organization, ledger, and VM with the factory.
    pub fn governance(&self) -> Governance {
        Governance {
            roles: self.roles.clone(),
            recipe: self.recipe.clone(),
            vm: self.vm.clone(),
            tool_timeout: self.tool_timeout,
            store_root: self.store_root.clone(),
            workspace: self.workspace.clone(),
            model: self.model.clone(),
            backend_id: self.backend_id.clone(),
            sampling: self.sampling.clone(),
            ledger: self.ledger.clone(),
            org: self.org.clone(),
            head: self.head.clone(),
            depth: self.depth,
            roles_dir: self.roles_dir.clone(),
            governance_path: self.governance_path.clone(),
        }
    }

    /// Run one sub-task to completion and return a structured report. Takes one
    /// tree-wide sub-agent slot for the whole ticket (released on return), draws
    /// the ticket's budget from the parent's ledger node, and gives workers and
    /// reviewers their own VM workspace slots. A resolved lead runs its own team
    /// instead: no VM slot and no review, but a scoped board and its own factory.
    pub(crate) async fn run_child(&self, request: DelegateRequest, cancel: CancellationToken) -> Result<DelegateReport, String> {
        // Take one short read lock to resolve the role, its tools, and the
        // reviewer; never hold it across an await. A newly installed trial role
        // is visible here immediately.
        let (role_name, is_lead, system_prompt, tools, sampling, budget_share, candidates, reviewer) = {
            let roles = self.roles.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            let role = resolve_role(&roles, request.role.as_deref(), self.depth)?;
            let role_name = role.name.clone();
            let is_lead = role.kind == RoleKind::Lead;
            let system_prompt = role.system_prompt();
            let tools = self.tools_for(role);
            let sampling = role_sampling(&self.sampling, role)?;
            let candidates = role.candidate_models(&self.model);
            let accepted_so_far = {
                let mut models = BTreeSet::new();
                models.insert(self.model.clone());
                for name in roles.names() {
                    if let Some(existing) = roles.get(&name) {
                        if let Some(model) = &existing.model {
                            models.insert(model.clone());
                        }
                        for alternate in &existing.alternates {
                            models.insert(alternate.clone());
                        }
                    }
                }
                let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                models
                    .iter()
                    .map(|model| book.get(&role_name, model).accepted)
                    .sum()
            };
            let budget_share = role.effective_budget_share(accepted_so_far);
            let reviewer = if is_lead {
                None
            } else {
                match reviewer_role(&roles) {
                    Some(charter) => Some(ReviewerPlan {
                        name: charter.name.clone(),
                        system_prompt: charter.system_prompt(),
                        tools: self.role_tools(charter),
                        sampling: role_sampling(&self.sampling, charter)?,
                        model: charter.model.clone().unwrap_or_else(|| self.model.clone()),
                    }),
                    None => None,
                }
            };
            (
                role_name,
                is_lead,
                system_prompt,
                tools,
                sampling,
                budget_share,
                candidates,
                reviewer,
            )
        };

        let _slot = match self.ledger.try_acquire_slot() {
            Some(slot) => slot,
            None => {
                let (spawned, total_max) = self.ledger.spawned();
                if spawned >= total_max {
                    return Err(format!(
                        "TOTAL_AGENTS_REACHED: {spawned} of {total_max} agents have been spawned for this goal"
                    ));
                }
                let (used, max) = self.ledger.slots();
                return Err(format!(
                    "SLOTS_FULL: {used} of {max} sub-agents are already running; wait for one to finish or do the work yourself"
                ));
            }
        };

        if !is_lead && !bulge_vm::slots::supports_slots(&self.vm) {
            return Err(
                "SLOTS_UNSUPPORTED: this VM's rootfs has no workspace slot commands; rebuild the rootfs with scripts/build-rootfs.sh".into(),
            );
        }

        // The ticket's budget node: worker and reviewer attempts are its children,
        // so retries and reviews stay inside the role's share of the parent budget.
        let shared_limit = (self.ledger.remaining() as f64 * budget_share) as u64;
        let ticket_limit = CHILD_MAX_TOKENS.min(shared_limit);
        let ticket_ledger = self.ledger.child(ticket_limit, Some(CHILD_MAX_WALL_SECS));
        if ticket_ledger.exhausted() {
            return Err("BUDGET_EXHAUSTED: the parent budget has nothing left for a sub-agent".into());
        }

        // Post the ticket before any work runs. A posting failure fails the
        // delegation (there is no ticket to attach later failures to).
        let ticket_id = {
            let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            post_ticket(
                &mut org,
                self.parent_ticket.clone(),
                &role_name,
                &request.goal,
                &request.acceptance,
                ticket_ledger.token_limit(),
            )?
        };

        let base_task = child_task_message(&request.goal, request.context.as_deref(), &request.acceptance);
        let plan = TicketPlan {
            ticket_id: ticket_id.clone(),
            role_name,
            system_prompt,
            tools,
            sampling,
            candidates,
            base_task,
            goal: request.goal,
            acceptance: request.acceptance,
            requested_model: request.model,
            reviewer,
            ledger: ticket_ledger,
        };

        let outcome = if is_lead {
            self.run_lead(&plan, &cancel).await
        } else {
            let mut worker: Option<Worker> = None;
            let outcome = self.ticket_loop(&plan, &cancel, &mut worker).await;
            if let Some(worker) = worker.take() {
                self.finish_worker(worker).await;
            }
            outcome
        };
        match &outcome {
            Ok(report) => self.accumulate_merged(&report.merged),
            Err(reason) => self.fail_if_open(&ticket_id, reason, cancel.is_cancelled()),
        }
        outcome
    }

    /// A sub-lead runs its own team: the same board and bus, a factory whose
    /// children are its tickets, and a situation report scoped to its team. It
    /// edits no files, so it takes no VM slot and its own ticket is never
    /// reviewed or merged; the parent judges its report.
    pub(crate) async fn run_lead(&self, plan: &TicketPlan, cancel: &CancellationToken) -> Result<DelegateReport, String> {
        let model = self.choose_first(plan.requested_model.as_deref(), &plan.role_name, &plan.candidates);
        let (mut job, job_id) = self.create_child_job(&plan.base_task, &model, &plan.ledger)?;
        self.record_board(BoardEvent::Claimed {
            id: plan.ticket_id.clone(),
            owner: job_id.clone(),
            at_ms: now_ms(),
        });
        self.record_board(BoardEvent::Started {
            id: plan.ticket_id.clone(),
            at_ms: now_ms(),
        });

        let merged = Arc::new(Mutex::new(Vec::new()));
        let mut sub_factory = self.for_sub_team(
            self.depth.saturating_add(1),
            plan.ticket_id.clone(),
            job_id.clone(),
            plan.ledger.clone(),
        );
        sub_factory.merged_accumulator = Some(merged.clone());
        let run = self.drive_lead(&mut job, plan, &sub_factory, cancel).await?;

        let merged_paths = merged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let failure = (!run.succeeded).then(|| {
            format!("lead run did not succeed: {}/{}", run.status, run.outcome)
        });
        if run.succeeded {
            self.record_board(BoardEvent::Submitted {
                id: plan.ticket_id.clone(),
                summary: run.summary.clone(),
                at_ms: now_ms(),
            });
        } else {
            let reason = failure.clone().unwrap_or_else(|| "lead run did not succeed".into());
            self.record_board(BoardEvent::Failed {
                id: plan.ticket_id.clone(),
                reason,
                at_ms: now_ms(),
            });
        }

        let summary = report_summary(&run.summary, None, "", failure.as_deref(), &[]);
        let (summary, quarantined) = {
            let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            send_bus_report(&mut org, &plan.ticket_id, &job_id, &self.head, &summary)
        };
        Ok(DelegateReport {
            status: run.status.clone(),
            outcome: run.outcome.clone(),
            role: plan.role_name.clone(),
            ticket: plan.ticket_id.clone(),
            summary,
            truncated: run.truncated || quarantined,
            tokens: plan.ledger.spent(),
            steps: run.steps,
            job_id,
            changed: merged_paths.clone(),
            merged: merged_paths,
            conflicts: Vec::new(),
            reviewed: false,
            accepted: None,
            feedback: String::new(),
            attempts: 1,
            models: vec![model],
        })
    }

    /// Drive one lead against the main workspace (no slot) with its own
    /// delegation factory and a team-scoped situation report.
    pub(crate) async fn drive_lead(
        &self,
        job: &mut JobHandle,
        plan: &TicketPlan,
        sub_factory: &ChildFactory,
        cancel: &CancellationToken,
    ) -> Result<RunSummary, String> {
        let dispatcher = crate::recipe::with_hooks(Arc::new(VmDispatcher::new(self.vm.clone(), self.tool_timeout)), &self.hooks);
        let ledger = plan.ledger.clone();
        let driver = self
            .recipe
            .driver(dispatcher, plan.tools.clone(), plan.system_prompt.clone(), plan.sampling.clone(), ledger.clone())
            .with_delegate(Arc::new(sub_factory.clone()))
            .with_propose_role(Arc::new(sub_factory.governance()))
            .with_org_status(Arc::new(OrgStatus { org: self.org.clone(), ledger, scope: Some(plan.ticket_id.clone()) }));

        let outcome = driver
            .run(job, cancel.clone())
            .await
            .map_err(|error| format!("lead run: {error}"))?;
        Ok(run_summary(job, outcome))
    }

    /// The tools one role may use, with host-side MCP tools always removed.
    pub(crate) fn tools_for(&self, role: &RoleCharter) -> Vec<ToolSchema> {
        let all = if role.kind == RoleKind::Lead { &self.lead_tools } else { &self.child_tools };
        role.filter_tools(all)
            .into_iter()
            .filter(|tool| !tool.name.starts_with("mcp__"))
            .collect()
    }

    /// Append a completed child's merged paths to this team's accumulator, if it
    /// has one. Used to build a lead's `changed`/`merged` report lists.
    pub(crate) fn accumulate_merged(&self, merged: &[String]) {
        let Some(accumulator) = &self.merged_accumulator else { return };
        let mut paths = accumulator.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for path in merged {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }
    }

    /// The tools one role may use, with host-side MCP tools always removed.
    pub(crate) fn role_tools(&self, role: &RoleCharter) -> Vec<ToolSchema> {
        role.filter_tools(&self.child_tools)
            .into_iter()
            .filter(|tool| !tool.name.starts_with("mcp__"))
            .collect()
    }
}

impl DelegateHandler for ChildFactory {
    fn run<'a>(&'a self, request: DelegateRequest, cancel: CancellationToken) -> LocalBoxFuture<'a, Result<DelegateReport, String>> {
        Box::pin(self.run_child(request, cancel))
    }
}
