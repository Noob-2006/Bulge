//! `bulge eval`: run a set of tasks through the agent and score each with a blind
//! judge model (Harness²'s eval, adapted). Reports the completion rate — the L4
//! acceptance signal — and a boundary-violation count (confinement itself is
//! verified separately by the escape-test suite, so this count is informational).

use std::path::PathBuf;

use bulge_harness::{EvalSummary, EvalTask, judge_prompt, parse_judgment};
use bulge_llm::{GenerateRequest, LlmBackend, Message, Purpose, Role};
use bulge_store::{Autonomy, Budget, JobStatus};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::backend::{self, BackendSpec};
use crate::run::{RunConfig, run};

pub struct EvalConfig {
    pub tasks_file: PathBuf,
    pub workspace_root: PathBuf,
    pub store_root: PathBuf,
    pub harness_dir: PathBuf,
    pub autonomy: Autonomy,
    pub budget: Budget,
    pub backend: BackendSpec,
    pub network: bool,
    pub cpus: u8,
    pub ram_mib: u32,
}

/// Clone a BackendSpec (small, no secrets held).
fn clone_backend(spec: &BackendSpec) -> BackendSpec {
    BackendSpec {
        id: spec.id.clone(),
        base_url: spec.base_url.clone(),
        protocol: spec.protocol,
        model: spec.model.clone(),
        context_window: spec.context_window,
        max_tokens: spec.max_tokens,
        reasoning: spec.reasoning,
    }
}

pub async fn run_eval(config: EvalConfig) -> Result<EvalSummary, String> {
    let raw = std::fs::read_to_string(&config.tasks_file).map_err(|e| format!("read tasks {}: {e}", config.tasks_file.display()))?;
    let tasks: Vec<EvalTask> = serde_json::from_str(&raw).map_err(|e| format!("parse tasks: {e}"))?;
    if tasks.is_empty() {
        return Err("the tasks file has no tasks".into());
    }

    // The judge backend is built once and reused.
    let judge = backend::build(&config.backend)?;
    let mut summary = EvalSummary::default();

    for task in &tasks {
        eprintln!("== task {} ==", task.id);
        let workspace = config.workspace_root.join(format!("bulge-eval-{}-{}", std::process::id(), sanitize(&task.id)));
        if let Err(error) = seed_workspace(&workspace, task) {
            eprintln!("  setup failed: {error}");
            summary.record(false, false);
            continue;
        }

        let run_config = RunConfig {
            job_id: None,
            goal: task.goal.clone(),
            title: format!("eval:{}", task.id),
            workspace: workspace.clone(),
            store_root: config.store_root.clone(),
            harness_dir: config.harness_dir.clone(),
            autonomy: config.autonomy,
            budget: config.budget.clone(),
            backend: clone_backend(&config.backend),
            network: config.network,
            cpus: config.cpus,
            ram_mib: config.ram_mib,
        };

        let result = match run(run_config).await {
            Ok(result) => result,
            Err(error) => {
                eprintln!("  run failed: {error}");
                summary.record(false, false);
                continue;
            }
        };

        let artifacts = result.diff.clone().unwrap_or_else(|| "(no workspace changes were made)".into());
        let judgment = judge_task(judge.as_ref(), &config.backend.model, task, &artifacts).await;
        match judgment {
            Some(j) => {
                eprintln!("  verdict: {}  — {}", if j.passed { "PASS" } else { "FAIL" }, j.reason);
                summary.record(j.passed, false);
            }
            None => {
                eprintln!("  verdict: (no verdict from judge) — counted as FAIL");
                summary.record(false, false);
            }
        }
        // A completion with a terminal non-succeeded status is still judged, but
        // worth flagging in the log, alongside where the full job log lives.
        if result.status != JobStatus::Succeeded {
            eprintln!("  (loop {:?}, status {:?}; log at {})", result.outcome, result.status, result.job_dir.display());
        }

        let _ = std::fs::remove_dir_all(&workspace);
    }

    eprintln!(
        "\n== eval summary ==\ntasks: {}  passed: {}  completion rate: {:.1}%  boundary violations: {}",
        summary.total,
        summary.passed,
        summary.pass_rate() * 100.0,
        summary.boundary_violations,
    );
    Ok(summary)
}

/// Make a fresh workspace and write the task's setup files.
fn seed_workspace(workspace: &PathBuf, task: &EvalTask) -> std::io::Result<()> {
    let _ = std::fs::remove_dir_all(workspace);
    std::fs::create_dir_all(workspace)?;
    for (rel, content) in &task.setup {
        let path = workspace.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
    }
    Ok(())
}

/// Ask the judge model to score one task's artifacts.
async fn judge_task(backend: &dyn LlmBackend, model: &str, task: &EvalTask, artifacts: &str) -> Option<bulge_harness::Judgment> {
    let request = GenerateRequest {
        model: model.to_string(),
        messages: vec![
            Message::text(Role::System, bulge_harness::eval::JUDGE_SYSTEM),
            Message::text(Role::User, judge_prompt(task, artifacts)),
        ],
        tools: Vec::new(),
        max_tokens: None,
        temperature: None,
        stop: Vec::new(),
        reasoning_effort: None,
        purpose: Purpose::Classify,
    };
    let mut stream = backend.stream(request, CancellationToken::new());
    let mut assembler = bulge_llm::assemble::Assembler::new();
    while let Some(chunk) = stream.next().await {
        assembler.push(&chunk);
    }
    let assembled = assembler.finish(model);
    let text = assembled.message.content.iter().find_map(|b| match b {
        bulge_llm::ContentBlock::Text { text } => Some(text.clone()),
        _ => None,
    })?;
    parse_judgment(&text)
}

/// A filesystem-safe fragment from a task id.
fn sanitize(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}
