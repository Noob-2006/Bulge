//! The side panels: MCP servers, memory, skills, hooks, schedules, profile,
//! usage, past jobs and the organization chart.

use std::path::PathBuf;
use bulge_store::JobStore;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct McpServerDto {
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) disabled: bool,
}

/// The MCP servers declared in `~/.bulge/mcp.json` (read-only view for settings).
/// bulge connects to the enabled ones at the start of each conversation.
#[tauri::command]
pub(crate) fn mcp_servers() -> Vec<McpServerDto> {
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let path = PathBuf::from(home).join(".bulge/mcp.json");
    match bulge_core::mcp::McpConfig::load(&path) {
        Ok(cfg) => cfg
            .servers
            .into_iter()
            .map(|(name, s)| McpServerDto { name, command: s.command, disabled: s.disabled })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Serialize)]
pub(crate) struct MemoryDto {
    pub(crate) id: String,
    pub(crate) uses: u32,
    pub(crate) cue: String,
    pub(crate) lesson: String,
    pub(crate) evidence: String,
    pub(crate) confidence: f32,
}

/// The durable lessons the agent has learned (read-only view for settings).
#[tauri::command]
pub(crate) fn list_memory() -> Vec<MemoryDto> {
    let Ok(harness) = bulge_util::fs::harness_dir() else { return Vec::new() };
    let root = harness.join("memory");
    match bulge_harness::MemoryStore::open(&root).and_then(|memory| memory.lessons()) {
        Ok(lessons) => lessons
            .into_iter()
            .map(|l| MemoryDto { id: l.id, cue: l.cue, lesson: l.lesson, evidence: l.evidence, confidence: l.confidence, uses: l.uses })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Forget one lesson.
#[tauri::command]
pub(crate) fn remove_lesson(id: String) -> Result<(), String> {
    memory_store()?.remove_lesson(&id).map(|_| ())
}

pub(crate) fn memory_store() -> Result<bulge_harness::MemoryStore, String> {
    bulge_harness::MemoryStore::open(&bulge_util::fs::harness_dir()?.join("memory"))
}

#[derive(Serialize)]
pub(crate) struct SkillDto {
    pub(crate) name: String,
    pub(crate) description: String,
}

/// The reusable skills the agent has proposed (read-only view for settings). Reads
/// `~/.bulge/harness/skills/<name>/SKILL.md` frontmatter.
#[tauri::command]
pub(crate) fn list_skills() -> Vec<SkillDto> {
    let Ok(harness) = bulge_util::fs::harness_dir() else { return Vec::new() };
    let dir = harness.join("skills");
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut skills = Vec::new();
    for entry in entries.flatten() {
        let md = entry.path().join("SKILL.md");
        let Ok(text) = std::fs::read_to_string(&md) else { continue };
        let name = frontmatter_field(&text, "name").unwrap_or_else(|| entry.file_name().to_string_lossy().into_owned());
        let description = frontmatter_field(&text, "description").unwrap_or_default();
        skills.push(SkillDto { name, description });
    }
    skills.sort_by(|a, b| a.name.cmp(&b.name));
    skills
}

/// Pull one `key: value` line from a leading `---` frontmatter block.
pub(crate) fn frontmatter_field(text: &str, key: &str) -> Option<String> {
    let body = text.strip_prefix("---")?;
    let end = body.find("\n---")?;
    for line in body[..end].lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}:")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[derive(Serialize)]
pub(crate) struct HookDto {
    pub(crate) event: String,
    pub(crate) matcher: String,
    pub(crate) actions: String,
}

/// The lifecycle hooks declared in `~/.bulge/hooks.json` (read-only settings view).
#[tauri::command]
pub(crate) fn list_hooks() -> Vec<HookDto> {
    use bulge_core::hooks::{HookAction, HookEvent};
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let cfg = bulge_core::hooks::HookConfig::load(&PathBuf::from(home).join(".bulge/hooks.json")).unwrap_or_default();
    let mut out = Vec::new();
    for (event, groups) in &cfg.hooks {
        let event = match event {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
        };
        for group in groups {
            let actions: Vec<&str> = group
                .hooks
                .iter()
                .map(|a| match a {
                    HookAction::Deny { .. } => "deny",
                    HookAction::Allow { .. } => "allow",
                    HookAction::Command { .. } => "command",
                })
                .collect();
            let matcher = if group.matcher.trim().is_empty() { "*".to_string() } else { group.matcher.clone() };
            out.push(HookDto { event: event.to_string(), matcher, actions: actions.join(", ") });
        }
    }
    out
}

/// The saved scheduled tasks (read-only settings view).
#[tauri::command]
pub(crate) fn list_schedules() -> Vec<bulge_runtime::cron::TaskSummary> {
    bulge_runtime::cron::summaries()
}

/// Create a scheduled task from the settings form.
#[expect(clippy::too_many_arguments, reason = "the form posts one field per argument")]
#[tauri::command]
pub(crate) fn add_schedule(
    goal: String,
    workspace: String,
    autonomy: String,
    model: String,
    base_url: String,
    protocol: String,
    kind: String,
    value: String,
    offset_minutes: i32,
) -> Result<String, String> {
    bulge_runtime::cron::add_task(&goal, &workspace, &autonomy, &model, &base_url, &protocol, &kind, &value, offset_minutes)
}

/// Remove a scheduled task by id.
#[tauri::command]
pub(crate) fn remove_schedule(id: String) -> Result<bool, String> {
    bulge_runtime::cron::remove_task(&id)
}

/// Enable or disable a scheduled task by id.
#[tauri::command]
pub(crate) fn set_schedule_enabled(id: String, enabled: bool) -> Result<bool, String> {
    bulge_runtime::cron::set_enabled(&id, enabled)
}

#[derive(Serialize)]
pub(crate) struct ProfileEntryDto {
    pub(crate) file: String,
    pub(crate) key: String,
    pub(crate) body: String,
}

/// The durable profile surfaces USER.md / MEMORY.md (read-only settings view).
#[tauri::command]
pub(crate) fn list_profile() -> Vec<ProfileEntryDto> {
    let Ok(memory) = memory_store() else { return Vec::new() };
    let mut out = Vec::new();
    for (file, target) in [("USER", bulge_harness::ProfileTarget::User), ("MEMORY", bulge_harness::ProfileTarget::Env)] {
        let profile = memory.profile(target).unwrap_or_default();
        for section in profile.sections {
            out.push(ProfileEntryDto { file: file.to_string(), key: section.key, body: section.body });
        }
    }
    out
}

/// Resolve a profile surface name (`USER` / `MEMORY`, as the UI names them).
pub(crate) fn profile_target(file: &str) -> Result<bulge_harness::ProfileTarget, String> {
    match file {
        "USER" => Ok(bulge_harness::ProfileTarget::User),
        "MEMORY" => Ok(bulge_harness::ProfileTarget::Env),
        other => Err(format!("未知的 profile {other:?}(應為 USER 或 MEMORY)")),
    }
}

/// Add or replace one section of USER.md / MEMORY.md after threat scanning and
/// secret redaction.
#[tauri::command]
pub(crate) fn save_profile_entry(file: String, key: String, body: String) -> Result<(), String> {
    let target = profile_target(&file)?;
    if key.trim().is_empty() {
        return Err("章節名稱是空的".into());
    }
    if bulge_guard::is_threat(&body, bulge_guard::Scope::Strict) {
        return Err("內容含提示注入或外洩模式,已拒絕寫入".into());
    }
    let body = bulge_guard::redact_secrets(&body);
    let memory = memory_store()?;
    let mut profile = memory.profile(target)?;
    profile.upsert(&key, &body);
    memory.save_profile(target, &profile)
}

/// Remove one section from USER.md / MEMORY.md.
#[tauri::command]
pub(crate) fn remove_profile_entry(file: String, key: String) -> Result<(), String> {
    let target = profile_target(&file)?;
    memory_store()?.remove_profile_section(target, &key).map(|_| ())
}

#[derive(Serialize)]
pub(crate) struct UsageDto {
    pub(crate) name: String,
    pub(crate) created_by: String,
    pub(crate) uses: u32,
    pub(crate) patches: u32,
    pub(crate) state: String,
    pub(crate) pinned: bool,
}

/// The skill usage ledger (`.usage.json`): authorship and lifecycle per skill.
#[tauri::command]
pub(crate) fn list_usage() -> Vec<UsageDto> {
    use bulge_harness::{Author, Lifecycle};
    let Ok(path) = skill_usage_path() else { return Vec::new() };
    let ledger = bulge_harness::UsageLedger::load(&path).unwrap_or_default();
    ledger
        .entries
        .into_iter()
        .map(|(name, u)| UsageDto {
            name,
            created_by: match u.created_by { Author::Agent => "agent", Author::User => "user" }.to_string(),
            uses: u.uses,
            patches: u.patches,
            state: match u.state { Lifecycle::Active => "active", Lifecycle::Stale => "stale", Lifecycle::Archived => "archived" }.to_string(),
            pinned: u.pinned,
        })
        .collect()
}

/// The skill usage ledger path (`~/.bulge/harness/skills/.usage.json`).
pub(crate) fn skill_usage_path() -> Result<PathBuf, String> {
    Ok(bulge_util::fs::harness_dir()?.join("skills").join(bulge_harness::usage::USAGE_FILE))
}

/// Pin or unpin a skill so curators leave it alone.
#[tauri::command]
pub(crate) fn set_skill_pinned(name: String, pinned: bool) -> Result<(), String> {
    let path = skill_usage_path()?;
    let mut ledger = bulge_harness::UsageLedger::load(&path)?;
    ledger.set_pinned(&name, pinned);
    ledger.save(&path)
}

/// Move a skill through its lifecycle (active / stale / archived).
#[tauri::command]
pub(crate) fn set_skill_state(name: String, state: String) -> Result<(), String> {
    use bulge_harness::Lifecycle;
    let state = match state.as_str() {
        "active" => Lifecycle::Active,
        "stale" => Lifecycle::Stale,
        "archived" => Lifecycle::Archived,
        other => return Err(format!("未知的技能狀態 {other:?}(應為 active|stale|archived)")),
    };
    let path = skill_usage_path()?;
    let mut ledger = bulge_harness::UsageLedger::load(&path)?;
    ledger.set_state(&name, state);
    ledger.save(&path)
}

/// Drop a skill from the usage ledger entirely.
#[tauri::command]
pub(crate) fn forget_skill(name: String) -> Result<(), String> {
    let path = skill_usage_path()?;
    let mut ledger = bulge_harness::UsageLedger::load(&path)?;
    ledger.forget(&name);
    ledger.save(&path)
}

/// Keyword search over past job transcripts (for the sidebar history search).
#[tauri::command]
pub(crate) fn search_jobs(query: String) -> Vec<bulge_runtime::recall::RecallHit> {
    bulge_runtime::recall::search_default(&query, 20)
}

#[derive(Serialize)]
pub(crate) struct JobSummaryDto {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) status: String,
    pub(crate) created_ms: u64,
}

/// Recent jobs for the sidebar history, newest first.
#[tauri::command]
pub(crate) fn list_jobs() -> Vec<JobSummaryDto> {
    let Ok(jobs) = bulge_util::fs::jobs_dir() else { return Vec::new() };
    let store = JobStore::new(jobs);
    store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|s| JobSummaryDto { id: s.id, title: s.title, status: format!("{:?}", s.status), created_ms: s.created_ms })
        .collect()
}

#[derive(Serialize)]
pub(crate) struct LoadedJobDto {
    pub(crate) jsonl: String,
    pub(crate) diff: Option<String>,
}

/// Read a past job's event log (and diff, if any) for read-only viewing. Changes
/// from an earlier run cannot be re-applied — the VM overlay is gone — so the
/// viewer shows the transcript and diff only. A follow-up turn resumes the
/// conversation in a fresh VM.
#[tauri::command]
pub(crate) fn load_job(id: String) -> Result<LoadedJobDto, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("無效的任務 id".into());
    }
    let dir = bulge_util::fs::jobs_dir()?.join(&id);
    let jsonl = std::fs::read_to_string(dir.join("job.jsonl")).map_err(|e| format!("讀取任務失敗:{e}"))?;
    let diff = std::fs::read_to_string(dir.join("changes.diff")).ok();
    Ok(LoadedJobDto { jsonl, diff })
}

/// One ticket in the read-only organization view.
#[derive(Serialize)]
pub(crate) struct OrgTicketDto {
    pub(crate) id: String,
    pub(crate) parent: Option<String>,
    pub(crate) role: String,
    pub(crate) status: String,
    pub(crate) owner: Option<String>,
    pub(crate) goal: String,
    pub(crate) budget_tokens: u64,
    pub(crate) rejections: u32,
    pub(crate) updated_ms: u64,
    /// The sub-agent job that served this ticket (== owner) if its log exists on
    /// disk, so the UI can offer "open transcript".
    pub(crate) job_available: bool,
}

#[derive(Serialize)]
pub(crate) struct OrgChartDto {
    pub(crate) tickets: Vec<OrgTicketDto>,
    pub(crate) report: String,
    pub(crate) exists: bool,
}

/// Read one job's organization without changing how it runs: replay the ticket
/// board and render the same model-free situation report the agents see. A job
/// that never delegated has no `org/board.jsonl`, so `exists` is false.
#[tauri::command]
pub(crate) fn org_chart(job_id: String) -> Result<OrgChartDto, String> {
    if job_id.is_empty() || !job_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("無效的任務 id".into());
    }
    let jobs = bulge_util::fs::jobs_dir()?;
    let board_path = jobs.join(&job_id).join("org").join("board.jsonl");
    if !board_path.exists() {
        return Ok(OrgChartDto { tickets: Vec::new(), report: String::new(), exists: false });
    }
    // `BoardLog::open` is the crate's replay path; opening an existing board also
    // lets it repair a torn final newline, so we never duplicate the state machine.
    let (_log, board) = bulge_org::BoardLog::open(&board_path)
        .map_err(|error| format!("讀取組織失敗:{error}"))?;
    let tickets = board
        .tickets()
        .into_iter()
        .map(|ticket| {
            let job_available = ticket.owner.as_deref().is_some_and(|owner| {
                !owner.is_empty()
                    && owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    && jobs.join(owner).join("job.jsonl").is_file()
            });
            OrgTicketDto {
                id: ticket.id.clone(),
                parent: ticket.parent.clone(),
                role: ticket.role.clone(),
                status: ticket.status.to_string(),
                owner: ticket.owner.clone(),
                goal: ticket.goal.clone(),
                budget_tokens: ticket.budget_tokens,
                rejections: ticket.rejections,
                updated_ms: ticket.updated_ms,
                job_available,
            }
        })
        .collect();
    // Ledger counts are live-only and not persisted with the board; the report's
    // ticket section is what an observer needs from a past run.
    let ledger = bulge_org::LedgerView { spent: 0, limit: 0, slots_used: 0, slots_max: 0 };
    let report = bulge_org::situation_report(&board, &ledger, 50);
    Ok(OrgChartDto { tickets, report, exists: true })
}
