//! A live VM plus the job it serves: launch, turns, restart, shutdown.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use bulge_core::driver::RequestPrefix;
use crate::delegate;
use bulge_core::hooks::{HookConfig, HookRunner, HookedDispatcher};
use bulge_core::mcp::{self, CompositeDispatcher, McpBundle};
use bulge_core::dispatch::DELEGATE_TOOL;
use bulge_core::{ORG_STATUS_TOOL, ToolDispatcher, VmDispatcher, builtin_tools, plan_tool, propose_role_tool};
use bulge_guard::{Effect, Rule};
use bulge_harness::SurfaceSpec;
use bulge_llm::{LlmBackend, Message, Role};
use bulge_org::RoleLibrary;
use bulge_store::{Autonomy, JobEvent, JobSpec, JobStatus, JobStore, ModelRef};
use bulge_vm::changes;
use bulge_vm::vm::{Vm, VmConfig};
use tokio_util::sync::CancellationToken;
use crate::backend::{self, BackendSpec};
use super::{DEFAULT_SYSTEM_PROMPT, ExtraTool, LineSink, RunConfig, RunOutcome, Sampling, build_turn_context, improve, learning_skip_reason, read_tree, tail_jsonl};

/// A modest baseline ruleset. The VM sandbox is the real boundary; these denies
/// are a second line against obviously destructive guest commands.
pub(crate) fn default_ruleset() -> Vec<Rule> {
    vec![
        Rule::new("*", "*", Effect::Allow),
        Rule::new("exec", "rm -rf /*", Effect::Deny),
        Rule::new("exec", "rm -fr /*", Effect::Deny),
    ]
}

/// Tools for workers and reviewers: the built-ins and the plan tool, never
/// `delegate`/`org_status` (they do not recruit) and never `mcp__*` (MCP servers
/// run on the host, outside every VM workspace slot).
pub(crate) fn child_tool_list(mcp: &[bulge_llm::ToolSchema]) -> Vec<bulge_llm::ToolSchema> {
    let mut tools = builtin_tools();
    tools.push(plan_tool());
    tools.extend(mcp.iter().cloned());
    tools.retain(|tool| tool.name != DELEGATE_TOOL && tool.name != ORG_STATUS_TOOL && !tool.name.starts_with("mcp__"));
    tools
}

/// Tools for the head: everything a child has, plus the user's MCP tools (the
/// head runs on the main workspace and its calls are routed to the servers),
/// plus delegation, recall, the situation report and role proposals.
pub(crate) fn head_tool_list(child: &[bulge_llm::ToolSchema], mcp: &[bulge_llm::ToolSchema], delegate: bulge_llm::ToolSchema) -> Vec<bulge_llm::ToolSchema> {
    let mut tools = child.to_vec();
    tools.extend(mcp.iter().cloned());
    tools.push(delegate);
    tools.push(crate::recall::recall_tool());
    tools.push(crate::skills::skill_tool());
    tools.push(bulge_core::browser_tool());
    tools.push(bulge_core::org_status_tool());
    tools.push(propose_role_tool());
    tools
}

/// Build the system prompt: the explicit persona, else the user-authored
/// always-on harness files, else the default prompt. Only content that is
/// identical across jobs and turns belongs here — the provider's prefix cache
/// covers system + tools, so anything the agent itself rewrites (skills catalog,
/// profile) or that varies per job (lessons, past tasks) goes in
/// [`build_turn_context`].
pub(crate) fn build_system_prompt(harness_dir: &Path, persona: Option<&str>) -> String {
    match persona {
        Some(text) if !text.trim().is_empty() => text.to_string(),
        _ => {
            let surfaced = bulge_harness::always_on(&read_tree(harness_dir), &SurfaceSpec::default());
            if surfaced.trim().is_empty() { DEFAULT_SYSTEM_PROMPT.to_string() } else { surfaced }
        }
    }
}

/// Decide the egress shape. Outbound never uses the raw NIC — it goes through the
/// two-key gateway, which always blocks private/LAN/cloud-metadata addresses
/// (DNS-rebind safe). The roadmap's stance: allow public internet, block the
/// host/LAN. On top of that:
///   - network off → no egress at all;
///   - collaborative + an approval channel → auto-allow package/dev sources, and
///     ASK before the agent reaches any other host (the "only prompt when data
///     leaves to a non-model API" rule — the model API is a host-side call and
///     never comes through here);
///   - otherwise → allow any public host without prompting.
pub(crate) fn egress_setup(network: bool, autonomy: Autonomy, approvals: Option<bulge_vm::net::EgressApprovalTx>) -> (Vec<String>, Option<bulge_vm::net::EgressApprovalTx>) {
    if !network {
        return (Vec::new(), None);
    }
    match (autonomy, approvals) {
        (Autonomy::Collaborative, Some(tx)) => (bulge_guard::netgate::allowlist_suffixes(), Some(tx)),
        _ => (vec!["*".to_string()], None),
    }
}

/// Build the `VmConfig` for this run from the environment plus the mutable shape
/// (cpus / ram / network) a session may later restart with.
pub(crate) fn vm_config_for(
    workspace: &Path,
    cpus: u8,
    ram_mib: u32,
    network: bool,
    autonomy: Autonomy,
    approvals: Option<bulge_vm::net::EgressApprovalTx>,
    real_world: Arc<bulge_guard::RealWorldPolicy>,
) -> Result<VmConfig, String> {
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (egress_allow, egress_approvals) = egress_setup(network, autonomy, approvals);
    Ok(VmConfig {
        vmm_binary: repo.join("target/debug/bulge-vmm"),
        libkrun_dir: home.join(".local/lib"),
        rootfs: home.join(".bulge/rootfs/current"),
        workspace: workspace.to_path_buf(),
        // Without XDG_RUNTIME_DIR, a directory under ~/.bulge (not /tmp,
        // where another local user could create it first).
        runtime_root: match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(dir) => PathBuf::from(dir).join("bulge"),
            None => bulge_util::home_dir().map(|h| h.join(".bulge/run")).unwrap_or_else(|_| PathBuf::from("/nonexistent")),
        },
        cpus,
        ram_mib,
        network: false,
        egress_allow,
        egress_approvals,
        real_world,
    })
}

/// A live conversation: one VM plus the store job it serves. Outlives a single
/// turn so that follow-up turns reuse the same VM (in-VM files persist) and so
/// the VM can be restarted on its own.
pub struct Session {
    /// The model accepts image input: the head gets `view_image`.
    images: bool,
    extra_tools: Vec<ExtraTool>,
    backend: Arc<dyn LlmBackend>,
    vm: Arc<Vm>,
    /// VM workspace slots shared by every child of this session.
    vm_slots: Arc<delegate::VmSlots>,
    pub(super) job: bulge_store::JobHandle,
    harness_dir: PathBuf,
    workspace: PathBuf,
    backend_spec: BackendSpec,
    autonomy: Autonomy,
    sampling: Sampling,
    system_prompt: Option<String>,
    /// Egress approval channel (used when restarting with network on, collaborative).
    egress_approvals: Option<bulge_vm::net::EgressApprovalTx>,
    /// Connected MCP servers (kept alive for the session) plus their tool routing.
    mcp: McpBundle,
    /// User-declared lifecycle hooks (`~/.bulge/hooks.json`), shared across turns.
    hooks: Arc<HookRunner>,
    /// Skip the offline learning loop on shutdown (autonomous scheduled runs).
    skip_review: bool,
    /// Enable the LLM review gate on mutating tool calls.
    auto_review: bool,
    /// The VM shape last launched with; restart tweaks these.
    vm_config: VmConfig,
    /// The user's review rules (`~/.bulge/review_ignore`): which changes are
    /// by-products, listed but not selected for write-back.
    review_rules: bulge_vm::review::ReviewRules,
    /// The role library loaded once for this session, shared so a role
    /// installed through governance is usable in the same session.
    roles: Arc<RwLock<RoleLibrary>>,
    /// The persistent performance book shared by every child of this session.
    perf: Arc<Mutex<bulge_org::PerformanceBook>>,
    /// Where the performance book is saved after every verdict.
    perf_path: PathBuf,
    /// The head's ticket board and message bus, persisted under the job directory.
    org: Arc<Mutex<delegate::OrgState>>,
    /// The last turn's request prefix; post-job learning calls replay it so they
    /// hit the provider's prefix cache instead of resending the job uncached.
    prefix: Option<RequestPrefix>,
    /// User turns run in this session; a follow-up turn usually carries a
    /// correction, so a multi-turn conversation always goes through learning.
    turns: usize,
}

impl Session {
    /// Open (or create) the conversation's store job and launch its VM. No turn
    /// is run yet — call [`Session::run_turn`].
    pub async fn launch(config: RunConfig) -> Result<Self, String> {
        let images = backend::probe_images(&config.backend).await;
        let backend = backend::build(&config.backend, images, config.sampling.reasoning_effort)?;
        let store = JobStore::new(&config.store_root);
        let job = match &config.job_id {
            // Reopen an existing conversation; the driver replays its full history.
            Some(id) => {
                let (job, _recovery) = store.open(id).map_err(|e| format!("open job: {e}"))?;
                job
            }
            None => {
                let job_id = bulge_store::new_job_id().map_err(|e| format!("job id: {e}"))?;
                store
                    .create(JobSpec {
                        id: job_id,
                        title: config.title.clone(),
                        goal: config.goal.clone(),
                        workspace: config.workspace.clone(),
                        autonomy: config.autonomy,
                        budget: config.budget.clone(),
                        model: ModelRef { backend: config.backend.id.clone(), model: config.backend.model.clone() },
                    })
                    .map_err(|e| format!("create job: {e}"))?
            }
        };

        // Load the role library once per session. A broken charter is reported
        // and skipped; its built-ins remain available.
        let (roles, problems) = RoleLibrary::load(&config.harness_dir.join("org").join("roles"));
        for problem in problems {
            eprintln!("org: role {}: {}", problem.path, problem.message);
        }

        // Load the performance book once per session. A malformed book is a
        // session start error: silently replacing it would forget who is reliable.
        let perf_path = config.harness_dir.join("org").join("performance.json");
        let perf = bulge_org::PerformanceBook::load(&perf_path)
            .map_err(|error| format!("load performance book {}: {error}", perf_path.display()))?;

        // The head's board and bus live with the job so they survive follow-up
        // turns. There is no in-memory fallback: without persistence the
        // organization cannot be resumed correctly.
        let org = match delegate::OrgState::open(&job.dir().join("org")) {
            Ok(org) => org,
            Err(error) => {
                eprintln!("org: {error}");
                return Err(format!("open org state: {error}"));
            }
        };

        let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?);
        let real_world_path = home.join(".bulge/real_world.json");
        let real_world = Arc::new(
            bulge_guard::RealWorldPolicy::load(&real_world_path)
                .map_err(|error| format!("load real-world policy {}: {error}", real_world_path.display()))?,
        );
        let review_rules = bulge_vm::review::ReviewRules::load(&home.join(".bulge/review_ignore"))
            .map_err(|error| format!("load review rules: {error}"))?;
        // Age unused skills (active → stale → archived) before any skills index
        // is built for this session.
        match crate::skills::curate(&config.harness_dir, bulge_util::now_secs()) {
            Ok(changed) => {
                for (name, state) in changed {
                    eprintln!("skill `{name}` is now {state:?} (unused)");
                }
            }
            Err(error) => eprintln!("skill lifecycle not updated: {error}"),
        }

        let vm_config = vm_config_for(
            &config.workspace,
            config.cpus,
            config.ram_mib,
            config.network,
            config.autonomy,
            config.egress_approvals.clone(),
            real_world,
        )?;
        let vm = Arc::new(Vm::launch(vm_config.clone()).await.map_err(|e| format!("launch VM: {e}"))?);
        let vm_slots = delegate::VmSlots::new(delegate::MAX_CONCURRENT_SUBAGENTS);

        // Connect any user-declared MCP servers (~/.bulge/mcp.json). Best-effort: a
        // broken server only loses its tools, it never blocks the run.
        let mcp = match mcp::McpConfig::load(&home.join(".bulge/mcp.json")) {
            Ok(_) if !config.host_integrations => McpBundle::default(),
            Ok(cfg) => {
                let bundle = mcp::connect_all(&cfg).await;
                for err in &bundle.errors {
                    eprintln!("mcp: {err}");
                }
                if !bundle.tools.is_empty() {
                    eprintln!("mcp: {} tool(s) from {} server(s)", bundle.tools.len(), bundle.clients.len());
                }
                bundle
            }
            Err(e) => {
                eprintln!("mcp: {e}");
                McpBundle::default()
            }
        };

        // Load user-declared lifecycle hooks (~/.bulge/hooks.json). Best-effort:
        // a malformed file loses its hooks but never blocks the run.
        let hooks = match HookConfig::load(&home.join(".bulge/hooks.json")) {
            Ok(_) if !config.host_integrations => Arc::new(HookRunner::default()),
            Ok(cfg) => {
                if !cfg.is_empty() {
                    let count: usize = cfg.hooks.values().map(Vec::len).sum();
                    eprintln!("hooks: {count} matcher group(s) loaded");
                }
                Arc::new(HookRunner::new(cfg))
            }
            Err(e) => {
                eprintln!("hooks: {e}");
                Arc::new(HookRunner::default())
            }
        };

        Ok(Self {
            backend,
            images,
            extra_tools: config.extra_tools,
            vm,
            vm_slots,
            job,
            harness_dir: config.harness_dir,
            workspace: config.workspace,
            backend_spec: config.backend,
            autonomy: config.autonomy,
            sampling: config.sampling,
            system_prompt: config.system_prompt,
            egress_approvals: config.egress_approvals,
            mcp,
            hooks,
            skip_review: config.skip_review,
            auto_review: config.auto_review,
            vm_config,
            review_rules,
            roles: Arc::new(RwLock::new(roles)),
            perf: Arc::new(Mutex::new(perf)),
            perf_path,
            org: Arc::new(Mutex::new(org)),
            prefix: None,
            turns: 0,
        })
    }

    /// The real store job id (stable across turns).
    pub fn job_id(&self) -> &str {
        self.job
            .dir()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    }

    /// Run one turn: append the user message, drive the loop to a stop against the
    /// *persistent* VM, and collect the (cumulative) workspace diff for review.
    /// The VM is left running for the next turn.
    pub async fn run_turn(&mut self, goal: String, cancel: CancellationToken, sink: LineSink) -> Result<RunOutcome, String> {
        self.turns += 1;
        let jobs_dir = self.job.dir().parent().map(std::path::Path::to_path_buf);
        let system_prompt = build_system_prompt(&self.harness_dir, self.system_prompt.as_deref());
        // The workspace snapshot is only true before the first turn touches it.
        let first_turn = self.job.state().history.is_empty();
        let turn_context = build_turn_context(
            &self.harness_dir,
            &goal,
            jobs_dir.as_deref(),
            self.job_id(),
            first_turn.then_some(self.workspace.as_path()),
        );
        let user_turn = if turn_context.is_empty() { goal.clone() } else { format!("{turn_context}\n\n{goal}") };

        // Append the user turn; flip a finished job back to Running (best effort).
        self.job
            .append(vec![JobEvent::Message { message: Message::text(Role::User, user_turn) }])
            .map_err(|e| format!("append turn: {e}"))?;
        let _ = self.job.append(vec![JobEvent::StatusChanged { status: JobStatus::Running, summary: None }]);

        let log_path = self.job.dir().join("job.jsonl");
        // Stream only the newly-appended events (start at the current EOF) so the
        // UI doesn't duplicate the transcript it already shows.
        let tail_start = std::fs::metadata(&log_path).map(|m| m.len() as usize).unwrap_or(0);

        // Rebuild the per-turn dispatcher/driver against the current VM (so a
        // restarted VM is picked up) — cheap; the VM is the expensive part. MCP
        // tools (if any) route to their server; everything else goes to the VM.
        let tool_timeout = Duration::from_secs(120);
        let vm_dispatcher = Arc::new(VmDispatcher::new(self.vm.clone(), tool_timeout));
        let base: Arc<dyn ToolDispatcher> = if self.mcp.routes.is_empty() {
            vm_dispatcher
        } else {
            Arc::new(CompositeDispatcher::new(vm_dispatcher, self.mcp.routes.clone()))
        };
        // Wrap in the lifecycle-hook layer (a no-op pass-through when no hooks are
        // declared). PreToolUse may block/rewrite a call; PostToolUse may inject.
        let hooked: Arc<dyn ToolDispatcher> = if self.hooks.is_empty() {
            base
        } else {
            Arc::new(HookedDispatcher::new(base, self.hooks.clone()))
        };

        // Child tools are everything the parent has EXCEPT `delegate` and
        // `org_status` (workers and reviewers do not recruit), and EXCEPT
        // `mcp__*` tools: MCP servers run on the host, outside any VM workspace
        // slot. Sub-leads get the same list plus delegation and status.
        let child_tools = child_tool_list(&self.mcp.tools);

        // One budget tree per turn: the parent and every sub-agent draw from it, so
        // delegating can never spend past the job's own limit.
        let budget = self.job.state().spec.budget.clone();
        let spent = self.job.state().tokens_spent();
        let ledger = bulge_core::ledger::Ledger::root_with_total(
            budget.max_tokens.saturating_sub(spent),
            Some(budget.max_wall_secs),
            delegate::MAX_CONCURRENT_SUBAGENTS,
            bulge_core::ledger::DEFAULT_TOTAL_AGENTS,
        );

        let roles = self.roles.clone();
        let org = self.org.clone();
        let head = self.job_id().to_string();
        // Build the role-aware delegate schema from a short read lock; no lock is
        // held while the agent runs.
        let delegate_schema = {
            let roles = roles.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            delegate::delegate_tool(&roles)
        };
        let mut lead_tools = child_tools.clone();
        lead_tools.push(delegate_schema.clone());
        lead_tools.push(bulge_core::org_status_tool());
        lead_tools.push(propose_role_tool());

        // Wrap in the delegation layer: `delegate` spawns a child agent in its
        // own VM workspace slot (still under the hook/review stack), playing a
        // role and reporting back its structured report through the org bus.
        // Real-world rules go LAST so they override the allow-all baseline for the
        // head, every child, reviewer, and auditor.
        let mut guard_rules = default_ruleset();
        guard_rules.extend(self.vm_config.real_world.rules());
        let recipe = crate::recipe::DriverRecipe {
            backend: self.backend.clone(),
            guard_rules,
            autonomy: self.autonomy,
            context_window: self.backend_spec.context_window,
            auto_review: self.auto_review,
        };
        let factory = delegate::ChildFactory {
            recipe: recipe.clone(),
            vm: self.vm.clone(),
            vm_slots: self.vm_slots.clone(),
            hooks: self.hooks.clone(),
            tool_timeout,
            child_tools: child_tools.clone(),
            lead_tools,
            store_root: self.job.dir().parent().map(std::path::Path::to_path_buf).unwrap_or_default(),
            workspace: self.workspace.clone(),
            model: self.backend_spec.model.clone(),
            backend_id: self.backend_spec.id.clone(),
            sampling: self.sampling.clone(),
            ledger: ledger.clone(),
            roles: roles.clone(),
            perf: self.perf.clone(),
            perf_path: self.perf_path.clone(),
            org: org.clone(),
            head,
            depth: 0,
            parent_ticket: None,
            merged_accumulator: None,
            roles_dir: self.harness_dir.join("org").join("roles"),
            governance_path: self.harness_dir.join("org").join("governance.jsonl"),
        };
        let governance = Arc::new(factory.governance());
        let dispatcher: Arc<dyn ToolDispatcher> = hooked;

        let mut tools = head_tool_list(&child_tools, &self.mcp.tools, delegate_schema);
        if self.images {
            tools.push(bulge_core::view_image_tool());
        }
        tools.extend(self.extra_tools.iter().map(|t| t.schema.clone()));
        let recall_handler = Arc::new(crate::recall::StoreRecall { jobs_dir: jobs_dir.clone().unwrap_or_default() });
        let driver = recipe
            .driver(dispatcher.clone(), tools, system_prompt, self.sampling.clone(), ledger.clone())
            .with_delegate(Arc::new(factory))
            .with_propose_role(governance)
            .with_recall(recall_handler)
            .with_skills(Arc::new(crate::skills::HarnessSkills::new(&self.harness_dir)))
            .with_org_status(Arc::new(delegate::OrgStatus { org, ledger: ledger.clone(), scope: None }));
        let driver = self.extra_tools.iter().fold(driver, |driver, tool| driver.with_host_tool(tool.handler.clone()));

        let stop = CancellationToken::new();
        let tail = tokio::spawn(tail_jsonl(log_path.clone(), stop.clone(), sink, tail_start));
        // Every way out of this turn, errors included, stops the log tail
        // (a leaked one would replay later turns' lines a second time).
        let _stop_tail = stop.clone().drop_guard();

        let own_before = self.job.state().usage.total();
        let outcome = driver.run(&mut self.job, cancel).await.map_err(|e| format!("run: {e}"))?;
        // The turn's ledger root was charged by this job's own calls (also logged
        // as Usage) and by every sub-agent (logged only in their own jobs).
        // Record the sub-agents' share here so the next turn's budget sees it.
        let own = self.job.state().usage.total().saturating_sub(own_before);
        let delegated = ledger.spent().saturating_sub(own);
        if delegated > 0 {
            self.job
                .append(vec![bulge_store::JobEvent::DelegatedUsage { tokens: delegated }])
                .map_err(|e| format!("record sub-agent usage: {e}"))?;
        }

        stop.cancel();
        let _ = tail.await;

        // Collect workspace changes and write the diff out (the host is not touched).
        let mut diff: Option<String> = None;
        let mut collected: Vec<changes::Change> = Vec::new();
        let mut changes_error: Option<String> = None;
        let mut ignored: Vec<(String, String)> = Vec::new();
        match changes::collect(&self.vm).await {
            Ok(pending) if pending.is_empty() => {}
            Ok(pending) => {
                ignored = bulge_vm::review::classify(&self.workspace, &self.review_rules, &pending);
                let rendered = changes::render_diff(&self.workspace, &pending, &ignored);
                let diff_path = self.job.dir().join("changes.diff");
                if let Err(error) = std::fs::write(&diff_path, &rendered) {
                    changes_error = Some(format!("could not save {}: {error}", diff_path.display()));
                }
                diff = Some(rendered);
                collected = pending;
            }
            Err(error) => changes_error = Some(format!("collecting workspace changes failed: {error}")),
        }

        // Full-auto writes back by itself, under a snapshot (ORG.md §11).
        let mut auto_writeback = None;
        if self.autonomy == Autonomy::FullAuto && !collected.is_empty() {
            let selection = crate::writeback::auto_selection(&collected, &ignored);
            if !selection.is_empty() {
                match bulge_vm::writeback::apply(&self.workspace, &collected, &selection, self.job.dir(), true) {
                    Ok(manifest) => auto_writeback = Some(manifest),
                    Err(error) => {
                        let message = format!("full-auto write-back not done (snapshot failed, workspace untouched): {error}");
                        changes_error = Some(changes_error.map_or(message.clone(), |earlier| format!("{earlier}; {message}")));
                    }
                }
            }
        }

        // The driver/dispatcher drop here, releasing their VM clones; `self.vm`
        // keeps the VM alive for the next turn.
        self.prefix = Some(driver.prefix());
        drop(driver);
        drop(dispatcher);

        Ok(RunOutcome {
            outcome,
            status: self.job.state().status,
            job_dir: self.job.dir().to_path_buf(),
            job_id: self.job_id().to_string(),
            workspace: self.workspace.clone(),
            diff,
            changes: collected,
            ignored,
            auto_writeback,
            changes_error,
        })
    }

    /// Restart the VM on its own with a new shape (cpus / ram / network). The
    /// conversation (store job, history) is untouched; only the machine is
    /// replaced, so this resets in-VM files but never the agent's memory. Used
    /// when the user changes execution settings mid-conversation.
    pub async fn restart_vm(&mut self, cpus: u8, ram_mib: u32, network: bool) -> Result<(), String> {
        let (egress_allow, egress_approvals) = egress_setup(network, self.autonomy, self.egress_approvals.clone());
        let mut cfg = self.vm_config.clone();
        cfg.cpus = cpus;
        cfg.ram_mib = ram_mib;
        cfg.egress_allow = egress_allow;
        cfg.egress_approvals = egress_approvals;

        // Launch the replacement before tearing down the old one, so a failed
        // relaunch leaves the running VM intact.
        let new_vm = Vm::launch(cfg.clone()).await.map_err(|e| format!("restart VM: {e}"))?;
        let old = std::mem::replace(&mut self.vm, Arc::new(new_vm));
        if let Ok(vm) = Arc::try_unwrap(old) {
            vm.shutdown().await;
        }
        self.vm_config = cfg;
        // The replacement VM has no open slots, so its lease pool starts empty.
        self.vm_slots = delegate::VmSlots::new(delegate::MAX_CONCURRENT_SUBAGENTS);
        Ok(())
    }

    /// Finish the conversation: propose durable lessons offline, then shut the VM
    /// down (and clean up its runtime directory).
    pub async fn shutdown(mut self) {
        if !self.skip_review
            && let Some(prefix) = self.prefix.take()
        {
            match learning_skip_reason(self.job.state(), self.turns) {
                Some(reason) => eprintln!("learning skipped: {reason}"),
                None => improve(self.backend.as_ref(), &mut self.job, &self.harness_dir, &self.backend_spec.model, &prefix).await,
            }
        }
        let Session { vm, .. } = self;
        if let Ok(vm) = Arc::try_unwrap(vm) {
            vm.shutdown().await;
        }
    }

    /// Shut the VM down without the offline-improvement pass (e.g. on eviction).
    pub async fn shutdown_quietly(self) {
        let Session { vm, .. } = self;
        if let Ok(vm) = Arc::try_unwrap(vm) {
            vm.shutdown().await;
        }
    }
}
