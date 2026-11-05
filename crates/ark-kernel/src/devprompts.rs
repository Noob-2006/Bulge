//! Built-in prompt commands that become a normal turn (no tool or system-prompt footprint,
//! so the prompt cache is untouched): `/init` (Hermes `hermes_cli/init_command.py`) asks the
//! agent to generate or update the project's AGENTS.md; `/plan` (Hermes `agent/plan_prompt.py`)
//! asks for a saved markdown implementation plan under `.ark/plans/` without executing.

use std::path::{Path, PathBuf};

const QUALITY_BAR: &str = "\
Quality bar for the file you write (this is what separates a useful AGENTS.md
from noise):
- CONCISE: target under 100 lines. Agents load this file every session — every
  line costs context. No essays, no marketing prose, no filler.
- Commands must be EXACT invocations you verified from the repo (package.json
  scripts, Makefile targets, pyproject/tox/CI config, existing docs). Write
  `npm run test:unit` or `scripts/run_tests.sh tests/foo`, never \"run the
  tests\". NEVER invent a command you didn't see evidence for.
- No generic advice. \"Write tests for new code\" and \"follow best practices\"
  are banned — if a line would be true of any repo, cut it.
- Conventions must be OBSERVED, not assumed: naming patterns, module layout,
  error-handling style, commit-message format — only what the code actually
  shows.
- Include pitfalls that would genuinely trip up a newcomer or an agent
  (required env vars, generated files not to hand-edit, slow test suites,
  ports already in use), if you found any. Skip the section if you found none.
- Markdown structure: a short title + one-paragraph overview, then focused
  sections (e.g. \"Dev environment\", \"Build & test\", \"Conventions\",
  \"Pitfalls\"). Flat and scannable — no deep nesting.";

/// The `/init` prompt; `existing` (current AGENTS.md) switches to merge discipline,
/// `extra` is the user's free text after `/init`.
pub fn build_init_prompt(cwd: &str, existing: Option<&str>, extra: &str) -> String {
    let extra = extra.trim();
    let update = existing.is_some();
    let mut parts: Vec<String> = vec![
        format!("[/init] The user wants you to {} AGENTS.md project-instructions file for the project at: {cwd}\n", if update { "UPDATE the existing" } else { "generate an" }),
        "AGENTS.md is the instruction file coding agents (ark included) load as project context every session. It should teach an agent how to work in THIS repo: what the project is, how to set up, the exact build/test/lint commands, the conventions the code actually follows, and the pitfalls that waste time.\n".into(),
        format!(
            "Do this:\n\
1. Inspect the project with your read-only tools (`read`, `glob`, `grep`) — start with manifests and toolchain files \
(package.json, pyproject.toml, Cargo.toml, go.mod, Makefile, CI workflow configs, lockfiles), then the directory layout, existing \
README/docs, and test/lint configuration. Learn the real commands, don't guess them.\n\
2. Write the file to {}/AGENTS.md with `write`{}\n\
3. Confirm to the user the exact path you wrote and summarize in one or two lines what the file covers.\n",
            cwd.trim_end_matches('/'),
            if update { " — but this is an UPDATE, so follow the merge discipline below." } else { "." }
        ),
    ];
    if let Some(e) = existing {
        parts.push(format!(
            "MERGE DISCIPLINE — an AGENTS.md already exists (its current content is below). Do NOT overwrite or regenerate it from \
scratch. Preserve the user's existing content — their wording, their sections, their rules — and merge in only what is missing \
or verifiably stale (e.g. a command that no longer exists in the repo). When existing content conflicts with what you observed, \
prefer minimal surgical edits over rewrites, and keep the user's intent. The result must still meet the quality bar.\n\n\
CURRENT AGENTS.md CONTENT:\n<<<EXISTING_AGENTS_MD\n{e}\nEXISTING_AGENTS_MD\n"
        ));
    }
    parts.push(QUALITY_BAR.into());
    if !extra.is_empty() {
        parts.push(format!("\nUSER NOTES — honor these while authoring (they override the defaults above where they conflict):\n{extra}"));
    }
    parts.join("\n")
}

/// `/init` for a workspace: reads an existing AGENTS.md so the prompt merges instead of overwriting.
pub fn init_prompt_for(ws: &Path, extra: &str) -> String {
    let existing = std::fs::read_to_string(ws.join("AGENTS.md")).ok().map(|s| s.trim_start_matches('\u{feff}').to_string());
    build_init_prompt(&ws.to_string_lossy(), existing.as_deref(), extra)
}

const PLAN_MODE_RULES: &str = "\
For this turn, you are in PLAN MODE — planning only.

- Do not implement code.
- Do not edit project files except the plan markdown file itself.
- Do not run mutating terminal commands, commit, push, or perform external
  actions.
- You may inspect the repo or other context with read-only commands/tools
  when needed.
- Your deliverable is a markdown plan saved inside the active workspace under
  `.ark/plans/YYYY-MM-DD_HHMMSS-<slug>.md` (create the directory if
  needed). If the runtime provides a specific target path, use that exact
  path instead.
";

const PLAN_CRAFT: &str = "\
Write the plan for an implementer with zero context for the codebase and
questionable taste. A good plan makes implementation obvious — if someone has
to guess, the plan is incomplete.

Structure (include the sections that are relevant):
- Goal — one sentence.
- Current context / assumptions.
- Architecture / proposed approach — 2-3 sentences.
- Step-by-step tasks. Each task is bite-sized (2-5 minutes of focused work),
  names exact file paths (`src/models/user.py`, not \"the model file\"),
  includes complete copy-pasteable code where code is needed, and exact
  commands with expected output for verification.
- Tests / validation — for code tasks, follow the TDD cycle per task: write
  the failing test, run it to verify failure, implement minimally, run to
  verify pass, commit.
- Risks, tradeoffs, and open questions.

Principles: DRY, YAGNI, TDD, frequent commits. Avoid vague tasks (\"add
authentication\"), incomplete code (\"add validation here\"), and unverifiable
steps (\"test it works\" — instead: the exact command and its expected output).

Interaction style:
- If the request is clear enough, write the plan directly.
- If it is genuinely underspecified, ask a brief clarifying question instead
  of guessing.
- After saving the plan, reply briefly with what you planned and the saved
  path, and offer to execute it (e.g. via sub-agents) — but do not start
  executing in this turn.
";

/// The plan-mode prompt; an empty `task` asks the agent to infer it from the conversation.
/// `target` is the exact path the runtime chose for the plan file.
pub fn build_plan_prompt(task: &str, target: Option<&Path>) -> String {
    let task = task.trim();
    let task_block = if task.is_empty() {
        "No explicit task was given with /plan — infer the task from the current conversation context (the thing we have been discussing or working toward). If the conversation does not imply a task, ask a brief clarifying question.\n".to_string()
    } else {
        format!("Task to plan:\n{task}\n")
    };
    let target = target.map(|p| format!("\nTarget path for the plan file: {}\n", p.display())).unwrap_or_default();
    format!("[/plan — plan mode]\n\n{PLAN_MODE_RULES}{target}\n{task_block}\n{PLAN_CRAFT}")
}

/// `<ws>/.ark/plans/YYYY-MM-DD_HHMMSS-<slug>.md` at `unix` seconds (local `utc_offset` minutes).
pub fn plan_path(ws: &Path, task: &str, unix: i64, utc_offset: i32) -> PathBuf {
    let t = unix + utc_offset as i64 * 60;
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    let (y, m, d) = civil(days);
    let mut slug: String = task.chars().map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug: String = slug.trim_matches('-').chars().take(48).collect();
    let slug = slug.trim_end_matches('-');
    let slug = if slug.is_empty() { "plan" } else { slug };
    ws.join(".ark/plans").join(format!("{y:04}-{m:02}-{d:02}_{:02}{:02}{:02}-{slug}.md", secs / 3600, secs % 3600 / 60, secs % 60))
}

fn civil(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's days_from_civil inverse.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `/init …` and `/plan …` as built-in commands for any surface (chat, channels).
pub fn expand_builtin(name: &str, args: &str, ws: &Path, utc_offset: i32) -> Option<String> {
    match name {
        "init" => Some(init_prompt_for(ws, args)),
        "plan" => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
            let target = plan_path(ws, args, now, utc_offset);
            Some(build_plan_prompt(args, Some(&target)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_prompt_generate_vs_update() {
        let p = build_init_prompt("/w/", None, "");
        assert!(p.starts_with("[/init] The user wants you to generate an AGENTS.md"));
        assert!(p.contains("/w/AGENTS.md with `write`.") && p.contains("CONCISE") && !p.contains("MERGE DISCIPLINE") && !p.contains("USER NOTES"));
        let p = build_init_prompt("/w", Some("# Old rules"), "  mention the pnpm workspace ");
        assert!(p.contains("UPDATE the existing") && p.contains("MERGE DISCIPLINE") && p.contains("<<<EXISTING_AGENTS_MD\n# Old rules\nEXISTING_AGENTS_MD"));
        assert!(p.ends_with("mention the pnpm workspace"));
        let ws = ark_core::tmp::scratch_path(format!("ark-init-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&ws).unwrap();
        assert!(!init_prompt_for(&ws, "").contains("MERGE"));
        std::fs::write(ws.join("AGENTS.md"), "\u{feff}keep me").unwrap();
        assert!(init_prompt_for(&ws, "").contains("<<<EXISTING_AGENTS_MD\nkeep me\n"));
        assert!(expand_builtin("init", "x", &ws, 0).unwrap().contains("USER NOTES"));
        assert!(expand_builtin("other", "", &ws, 0).is_none());
    }

    #[test]
    fn plan_prompt_and_path() {
        let p = build_plan_prompt("Add OAuth login", Some(Path::new("/w/.ark/plans/x.md")));
        assert!(p.starts_with("[/plan — plan mode]") && p.contains("Do not implement code.") && p.contains("Task to plan:\nAdd OAuth login") && p.contains("Target path for the plan file: /w/.ark/plans/x.md"));
        assert!(build_plan_prompt("", None).contains("infer the task from the current conversation"));
        // 2026-11-03 04:05:06 UTC, shown at UTC+8.
        let path = plan_path(Path::new("/w"), "Add OAuth: login!!", 1_793_678_706, 480);
        assert_eq!(path, Path::new("/w/.ark/plans/2026-11-03_120506-add-oauth-login.md"));
        assert!(plan_path(Path::new("/w"), "  ", 0, 0).ends_with("1970-01-01_000000-plan.md"));
        assert!(plan_path(Path::new("/w"), "部署 正式", 0, 0).to_string_lossy().ends_with("-部署-正式.md"));
        let ws = ark_core::tmp::scratch("ark-ws");
        assert!(expand_builtin("plan", "x", &ws, 480).unwrap().contains(".ark/plans/"));
    }
}
