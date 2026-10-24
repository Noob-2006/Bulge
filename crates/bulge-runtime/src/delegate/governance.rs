//! Governance tools: role proposals and the organization's status report.

use bulge_util::now_ms;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use bulge_core::driver::{OrgStatusHandler, ProposeRoleHandler, Sampling};
use bulge_core::{ToolDispatcher, VmDispatcher, builtin_tools};
use bulge_llm::{Message, Role, ToolSchema};
use bulge_org::{LedgerView, MessageKind, OrgMessage, Review, RoleCharter, RoleLibrary, TRIAL_BUDGET_SHARE, append_decision, as_trial, audit_task, check_proposal, parse_charter, parse_review, vetoed_names};
use bulge_store::{Budget, JobEvent, JobSpec, JobStore, ModelRef};
use bulge_vm::vm::Vm;
use futures::future::LocalBoxFuture;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use super::{CHILD_MAX_STEPS, CHILD_MAX_TOKENS, CHILD_MAX_WALL_SECS, MAX_DEPTH, OrgState, reviewer_role, role_sampling, run_summary};

/// Governance of role proposals: validates a proposed charter, runs one
/// independent auditor (the `reviewer` role, no VM slot, read-only tools), and
/// installs the role on trial when both pass. The shared role library is updated
/// in place so the role is usable for the rest of the session.
pub struct Governance {
    pub roles: Arc<RwLock<RoleLibrary>>,
    /// The backend, guard, autonomy, context and review every agent shares.
    pub recipe: crate::recipe::DriverRecipe,
    pub vm: Arc<Vm>,
    pub tool_timeout: Duration,
    pub store_root: PathBuf,
    pub workspace: PathBuf,
    pub model: String,
    pub backend_id: String,
    pub sampling: Sampling,
    pub ledger: Arc<bulge_core::ledger::Ledger>,
    pub org: Arc<Mutex<OrgState>>,
    pub head: String,
    pub depth: u32,
    pub roles_dir: PathBuf,
    pub governance_path: PathBuf,
}

impl Governance {
    /// Announce a governance event on the org bus to the human observer.
    pub(crate) fn announce(&self, summary: &str) {
        let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = org.bus.send(OrgMessage {
            from: self.head.clone(),
            to: "observer".to_string(),
            ticket: None,
            kind: MessageKind::Ruling,
            summary: summary.to_string(),
            attachments: Vec::new(),
            at_ms: now_ms(),
        });
    }

    pub(crate) fn decision(&self, event: &str, role: &str, detail: &str) -> Result<(), String> {
        append_decision(
            &self.governance_path,
            event,
            role,
            &self.head,
            detail,
            now_ms(),
        )
    }

    /// Run exactly one auditor child as the reviewer role. It runs in the main
    /// workspace with no VM slot and only read-only tools because it judges the
    /// charter text, not a set of changes.
    pub(crate) async fn audit(
        &self,
        task: &str,
        reviewer: &RoleCharter,
        cancel: &CancellationToken,
    ) -> Result<Option<Review>, String> {
        let ledger = self
            .ledger
            .child(CHILD_MAX_TOKENS, Some(CHILD_MAX_WALL_SECS));
        if ledger.exhausted() {
            return Err("BUDGET_EXHAUSTED: no budget is left to audit the proposal".into());
        }
        let model = reviewer.model.clone().unwrap_or_else(|| self.model.clone());
        let store = JobStore::new(&self.store_root);
        let job_id = bulge_store::new_job_id().map_err(|error| format!("auditor job id: {error}"))?;
        let title: String = task.lines().next().unwrap_or("role audit").chars().take(80).collect();
        let mut job = store
            .create(JobSpec {
                id: job_id,
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
                    model: model.clone(),
                },
            })
            .map_err(|error| format!("create auditor job: {error}"))?;
        job.append(vec![JobEvent::Message {
            message: Message::text(Role::User, task.to_string()),
        }])
        .map_err(|error| format!("append auditor task: {error}"))?;

        let tools: Vec<ToolSchema> = reviewer
            .filter_tools(&builtin_tools())
            .into_iter()
            .filter(|tool| matches!(tool.name.as_str(), "read" | "grep" | "glob"))
            .collect();
        let dispatcher: Arc<dyn ToolDispatcher> =
            Arc::new(VmDispatcher::new(self.vm.clone(), self.tool_timeout));
        let sampling = role_sampling(&self.sampling, reviewer)?;
        let driver = self.recipe.driver(dispatcher, tools, reviewer.system_prompt(), sampling, ledger);

        let outcome = driver
            .run(&mut job, cancel.clone())
            .await
            .map_err(|error| format!("auditor run: {error}"))?;
        let run = run_summary(&job, outcome);
        Ok(parse_review(&run.summary))
    }

    pub(crate) async fn propose_inner(
        &self,
        charter: String,
        reason: String,
        cancel: CancellationToken,
    ) -> Result<serde_json::Value, String> {
        let vetoed = vetoed_names(&self.governance_path)?;
        let (checked, library) = {
            let roles = self.roles.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut known = BTreeSet::new();
            known.insert(self.model.clone());
            for name in roles.names() {
                if let Some(role) = roles.get(&name) {
                    if let Some(model) = &role.model {
                        known.insert(model.clone());
                    }
                    for alternate in &role.alternates {
                        known.insert(alternate.clone());
                    }
                }
            }
            let known: Vec<String> = known.into_iter().collect();
            let allow_lead = self.depth.saturating_add(1) < MAX_DEPTH;
            match check_proposal(&charter, &roles, &vetoed, allow_lead, &known) {
                Ok(checked) => (checked, roles.clone()),
                Err(violations) => {
                    let violations: Vec<String> =
                        violations.into_iter().map(|violation| violation.0).collect();
                    return Ok(json!({ "installed": false, "violations": violations }));
                }
            }
        };
        let name = checked.name.clone();

        // Announce the proposal before the audit so the observer sees both the
        // proposal and its outcome even if the auditor fails.
        self.decision("proposed", &name, &reason)?;
        self.announce(&format!(
            "{} proposed role {}: {}",
            self.head, name, reason
        ));

        let Some(reviewer) = reviewer_role(&library).cloned() else {
            return Err("no reviewer role is defined; cannot audit the proposal".into());
        };
        let task = audit_task(&self.head, &reason, &charter, &library);
        let verdict = match self.audit(&task, &reviewer, &cancel).await {
            Ok(Some(review)) => review,
            Ok(None) => Review {
                accept: false,
                feedback: "auditor gave no verdict".to_string(),
            },
            Err(error) => Review {
                accept: false,
                feedback: format!("auditor failed: {error}"),
            },
        };
        if cancel.is_cancelled() {
            return Err("CANCELLED: the proposal was cancelled".into());
        }
        if !verdict.accept {
            let feedback = if verdict.feedback.trim().is_empty() {
                "auditor rejected the proposal".to_string()
            } else {
                verdict.feedback.clone()
            };
            self.decision("rejected", &name, &feedback)?;
            self.announce(&format!("rejected role {}: {}", name, feedback));
            return Ok(json!({ "installed": false, "auditor": feedback }));
        }

        let source = as_trial(&charter)?;
        let installed = parse_charter(&source)?;
        let path = self.roles_dir.join(format!("{name}.md"));
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(format!(
                    "refusing to overwrite existing role file {}",
                    path.display()
                ));
            }
            Err(error) => {
                return Err(format!("create {}: {error}", path.display()));
            }
        };
        if let Err(error) = file.write_all(source.as_bytes()) {
            let _ = std::fs::remove_file(&path);
            return Err(format!("write {}: {error}", path.display()));
        }
        drop(file);

        {
            let mut roles = self.roles.write().unwrap_or_else(std::sync::PoisonError::into_inner);
            if roles.get(&name).is_some() {
                let _ = std::fs::remove_file(&path);
                return Err(format!("role `{name}` appeared while the proposal was audited"));
            }
            roles.insert(installed);
        }

        self.decision("installed", &name, "installed on trial")?;
        self.announce(&format!(
            "installed trial role {}; veto with `bulge org veto {}`",
            name, name
        ));
        Ok(json!({
            "installed": true,
            "role": name,
            "trial": true,
            "budget_share": TRIAL_BUDGET_SHARE,
        }))
    }
}

impl ProposeRoleHandler for Governance {
    fn propose<'a>(
        &'a self,
        charter: String,
        reason: String,
        cancel: CancellationToken,
    ) -> LocalBoxFuture<'a, Result<serde_json::Value, String>> {
        Box::pin(self.propose_inner(charter, reason, cancel))
    }
}

/// The head's live organization status, rendered without a model call.
pub struct OrgStatus {
    pub org: Arc<Mutex<OrgState>>,
    pub ledger: Arc<bulge_core::ledger::Ledger>,
    /// Restrict the report to one lead's descendants (the head uses `None`).
    pub scope: Option<String>,
}

impl OrgStatusHandler for OrgStatus {
    fn status(&self) -> String {
        let org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (slots_used, slots_max) = self.ledger.slots();
        let ledger = LedgerView {
            spent: self.ledger.spent(),
            limit: self.ledger.token_limit(),
            slots_used,
            slots_max,
        };
        bulge_org::bus::situation_report_scoped(&org.board, &ledger, 20, self.scope.as_deref())
    }
}
