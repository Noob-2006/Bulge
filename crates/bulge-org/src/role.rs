//! Role charters: Markdown role definitions with a small, dependency-free
//! frontmatter block.
//!
//! A charter declares a role's purpose, domain, accountabilities, decision
//! rights, tool allowlist, model preference, and budget share. The rendered
//! [`RoleCharter::system_prompt`] is identical for every instance of a role so
//! instances share a cached prompt prefix.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use bulge_llm::ToolSchema;
use serde::{Deserialize, Serialize};

/// The kind of position a role occupies in an organization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleKind {
    /// A worker that produces deliverables and never recruits.
    #[default]
    Worker,
    /// A lead that breaks goals into tickets, delegates, and integrates.
    Lead,
    /// An independent reviewer that accepts or rejects deliverables.
    Reviewer,
}

impl fmt::Display for RoleKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Worker => "worker",
            Self::Lead => "lead",
            Self::Reviewer => "reviewer",
        };
        formatter.write_str(name)
    }
}

impl RoleKind {
    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "worker" => Ok(Self::Worker),
            "lead" => Ok(Self::Lead),
            "reviewer" => Ok(Self::Reviewer),
            other => Err(format!(
                "kind must be worker, lead, or reviewer, got `{other}`"
            )),
        }
    }
}

/// A parsed role charter.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleCharter {
    /// Kebab-case role name; must equal the file stem when loaded from a file.
    pub name: String,
    /// The position kind.
    pub kind: RoleKind,
    /// What the role exists to accomplish.
    pub purpose: String,
    /// Path globs this role owns.
    pub domain: Vec<String>,
    /// What the role is accountable for delivering.
    pub accountabilities: Vec<String>,
    /// Decisions and actions the role may take on its own.
    pub act: Vec<String>,
    /// Subjects on which the role must be consulted.
    pub recommend: Vec<String>,
    /// Subjects the role decides.
    pub decide: Vec<String>,
    /// Tool allowlist; required and non-empty.
    pub tools: Vec<String>,
    /// Preferred model, if any.
    pub model: Option<String>,
    /// Other models this role may run with, in preference order.
    pub alternates: Vec<String>,
    /// Reasoning effort, one of `off`, `low`, `high`, `max`.
    pub reasoning_effort: Option<String>,
    /// Share of the enclosing circle's budget this role may consume.
    pub budget_share: f64,
    /// Whether this is a trial role: usable at once, but with a capped budget
    /// share until it has a track record.
    pub trial: bool,
    /// Performance indicators for this role.
    pub kpis: Vec<String>,
    /// Markdown guidance following the frontmatter, trimmed.
    pub body: String,
}

/// The budget share a trial role is capped at until it graduates.
pub const TRIAL_BUDGET_SHARE: f64 = 0.10;

/// Accepted tickets a trial role needs before its normal budget share applies.
pub const TRIAL_GRADUATION: u64 = 3;

impl RoleCharter {
    /// The budget share this role may use given how many tickets it has had
    /// accepted: a trial role is capped at [`TRIAL_BUDGET_SHARE`] until it has
    /// [`TRIAL_GRADUATION`] accepted tickets.
    pub fn effective_budget_share(&self, accepted_so_far: u64) -> f64 {
        if self.trial && accepted_so_far < TRIAL_GRADUATION {
            self.budget_share.min(TRIAL_BUDGET_SHARE)
        } else {
            self.budget_share
        }
    }

    /// Render the deterministic system prompt shared by every instance of this
    /// role.
    pub fn system_prompt(&self) -> String {
        let mut prompt = String::new();
        prompt.push_str(&format!(
            "You are the `{}` role ({}) in a bulge organization of AI agents.\n",
            self.name, self.kind
        ));
        prompt.push_str(&format!("Purpose: {}\n", self.purpose));
        if !self.accountabilities.is_empty() {
            prompt.push_str("Accountabilities:\n");
            for accountability in &self.accountabilities {
                prompt.push_str("- ");
                prompt.push_str(accountability);
                prompt.push('\n');
            }
        }
        prompt.push_str(&format!(
            "Decision rights: act on {}; recommend on {}; decide on {}.\n",
            join_or(&self.act, "nothing"),
            join_or(&self.recommend, "nothing"),
            join_or(&self.decide, "nothing"),
        ));
        prompt.push_str(&format!(
            "Domain you own: {}.\n",
            join_or(&self.domain, "none (do not modify files)")
        ));
        prompt.push_str(
            "Rules: stay within your purpose and domain; another role reviews your work, so report what you did and how\n",
        );
        prompt.push_str(
            "you verified it; never take real-world actions (payments, real personal data or credentials, irreversible\n",
        );
        prompt.push_str("external messages) — those always need the human.");
        if !self.body.is_empty() {
            prompt.push_str("\n\n");
            prompt.push_str(&self.body);
        }
        prompt.push('\n');
        prompt
    }

    /// Keep only the tools whose names are in this role's allowlist, preserving
    /// the order of `all`.
    pub fn filter_tools(&self, all: &[ToolSchema]) -> Vec<ToolSchema> {
        all.iter()
            .filter(|tool| self.allows_tool(&tool.name))
            .cloned()
            .collect()
    }

    /// Whether `name` appears in this role's tool allowlist.
    pub fn allows_tool(&self, name: &str) -> bool {
        self.tools.iter().any(|tool| tool == name)
    }

    /// The models this role may run with, in preference order: `model` (if set) then `alternates`.
    /// `default_model` (the session's model) is used when the charter names none, and is appended last when absent.
    pub fn candidate_models(&self, default_model: &str) -> Vec<String> {
        let mut models = Vec::new();
        if let Some(model) = &self.model {
            models.push(model.clone());
        }
        for alternate in &self.alternates {
            if !models.contains(alternate) {
                models.push(alternate.clone());
            }
        }
        if !models.iter().any(|model| model == default_model) {
            models.push(default_model.to_string());
        }
        models
    }
}

fn join_or(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        empty.to_string()
    } else {
        items.join(", ")
    }
}

fn parse_scalar(value: &str) -> String {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

fn list_item(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let item = trimmed
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(trimmed);
    if item.is_empty() && trimmed != "\"\"" {
        return Err("list values must not contain an empty item".to_string());
    }
    Ok(item.to_string())
}

fn parse_list(value: &str) -> Result<Vec<String>, String> {
    let value = value.trim();
    let inner = value
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .ok_or_else(|| format!("expected a list `[...]` for value `{value}`"))?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in inner.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ',' if !quoted => {
                items.push(list_item(&current)?);
                current.clear();
            }
            _ => current.push(character),
        }
    }
    if quoted {
        return Err("unterminated double quote in list value".to_string());
    }
    items.push(list_item(&current)?);
    Ok(items)
}

fn is_kebab_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// Parse a role charter from a Markdown source with a `---`-delimited
/// frontmatter block.
pub fn parse_charter(source: &str) -> Result<RoleCharter, String> {
    let lines: Vec<&str> = source
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    let first = lines
        .first()
        .ok_or_else(|| "charter is empty".to_string())?;
    if *first != "---" {
        return Err("missing frontmatter: the first line must be exactly `---`".to_string());
    }
    let close = lines
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| (*line == "---").then_some(index))
        .ok_or_else(|| "unterminated frontmatter: missing a closing `---` line".to_string())?;
    let body = lines[close + 1..].join("\n").trim().to_string();

    let mut name = None;
    let mut kind = RoleKind::Worker;
    let mut purpose = None;
    let mut domain = Vec::new();
    let mut accountabilities = Vec::new();
    let mut act = Vec::new();
    let mut recommend = Vec::new();
    let mut decide = Vec::new();
    let mut tools = Vec::new();
    let mut model = None;
    let mut alternates = Vec::new();
    let mut reasoning_effort = None;
    let mut budget_share = None;
    let mut trial = false;
    let mut kpis = Vec::new();
    let mut seen = BTreeSet::new();

    for (offset, raw) in lines[1..close].iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("frontmatter line {}: expected `key: value`", offset + 2))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("frontmatter line {}: empty key", offset + 2));
        }
        if !seen.insert(key.to_string()) {
            return Err(format!("duplicate frontmatter key `{key}`"));
        }
        let value = value.trim();
        match key {
            "name" => name = Some(parse_scalar(value)),
            "kind" => kind = RoleKind::parse(&parse_scalar(value))?,
            "purpose" => purpose = Some(parse_scalar(value)),
            "domain" => domain = parse_list(value)?,
            "accountabilities" => accountabilities = parse_list(value)?,
            "act" => act = parse_list(value)?,
            "recommend" => recommend = parse_list(value)?,
            "decide" => decide = parse_list(value)?,
            "tools" => tools = parse_list(value)?,
            "model" => {
                let model_value = parse_scalar(value);
                model = (!model_value.is_empty()).then_some(model_value);
            }
            "alternates" => alternates = parse_list(value)?,
            "reasoning_effort" => {
                reasoning_effort = Some(parse_scalar(value));
            }
            "budget_share" => {
                let parsed = parse_scalar(value)
                    .parse::<f64>()
                    .map_err(|_| format!("budget_share is not a number: `{value}`"))?;
                budget_share = Some(parsed);
            }
            "trial" => {
                let parsed = parse_scalar(value).to_ascii_lowercase();
                trial = match parsed.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(format!(
                            "trial must be true or false, got `{other}`"
                        ));
                    }
                };
            }
            "kpis" => kpis = parse_list(value)?,
            other => return Err(format!("unknown frontmatter key `{other}`")),
        }
    }

    let name = name.ok_or_else(|| "missing required frontmatter key `name`".to_string())?;
    if !is_kebab_name(&name) {
        return Err(format!(
            "name `{name}` must be kebab-case using only [a-z0-9-]"
        ));
    }
    let purpose =
        purpose.ok_or_else(|| "missing required frontmatter key `purpose`".to_string())?;
    if purpose.trim().is_empty() {
        return Err("purpose must not be empty".to_string());
    }
    if tools.is_empty() {
        return Err("tools must list at least one tool".to_string());
    }
    let budget_share = budget_share.unwrap_or(0.25);
    if !budget_share.is_finite() || budget_share <= 0.0 || budget_share > 1.0 {
        return Err(format!(
            "budget_share must be greater than 0 and at most 1, got {budget_share}"
        ));
    }
    if let Some(effort) = &reasoning_effort
        && !matches!(effort.as_str(), "off" | "low" | "high" | "max")
    {
        return Err(format!(
            "reasoning_effort must be one of off, low, high, max, got `{effort}`"
        ));
    }
    let mut seen_alternates = BTreeSet::new();
    for alternate in &alternates {
        if alternate.trim().is_empty() {
            return Err("alternates must not contain an empty item".to_string());
        }
        if !seen_alternates.insert(alternate) {
            return Err(format!("duplicate alternate model `{alternate}`"));
        }
        if model.as_deref() == Some(alternate.as_str()) {
            return Err(format!(
                "alternate model `{alternate}` duplicates the role's model"
            ));
        }
    }

    Ok(RoleCharter {
        name,
        kind,
        purpose,
        domain,
        accountabilities,
        act,
        recommend,
        decide,
        tools,
        model,
        alternates,
        reasoning_effort,
        budget_share,
        trial,
        kpis,
        body,
    })
}

const CHIEF: &str = r#"---
name: chief
kind: lead
purpose: own the whole goal end to end — turn it into department-sized missions, staff them, integrate the results, and accept or reject the final outcome
tools: [delegate, update_plan, read, grep, glob, recall, org_status, propose_role]
domain: []
accountabilities: ["hold exactly one owner (a lead) for each mission, with a written deliverable and acceptance criteria agreed before work starts", "integrate only work that a reviewer has accepted; never ship unreviewed output", "keep the whole org inside the goal's budget and stop or replace a department that keeps failing"]
decide: [mission breakdown, which departments/leads exist, final acceptance of the delivered result]
recommend: [overall architecture and interfaces between missions]
kpis: [goal_delivered, rework_rate, cost_vs_budget, zero_real_world_actions_without_human]
---
You are the chief. You run the company; you do not do the line work. Think in missions, not tasks:
split the goal into a few independent, department-sized missions with clean interfaces between them,
and hand each to a lead with `delegate` (role: lead). Write the deliverable and acceptance criteria for
each mission before anyone starts, so success is checkable, not a matter of opinion.

Delegate independent missions in the SAME message so departments run in parallel. Do not open files,
write code, or run commands yourself — if you feel the urge to, you have mis-scoped a mission; make it a
ticket instead. Use `org_status` to watch progress, budget, and anything stuck; chase a blocked or
repeatedly-rejected mission rather than taking it over.

Every mission costs a lead, its workers, and their reviewers, so make missions few and substantial;
fold small or dependent pieces into one. Judge results, don't just collect them: integrate only what came
back accepted, check the pieces fit at the seams, and reconcile conflicts between departments. An accepted
result is verified — do not commission another audit of it without a concrete reason to doubt it. A real-world action (payment, real credentials,
an irreversible external message) always stops at you and the human — never route one into a mission to
get it done quietly. Finish with a short report: what was delivered, how it was verified, what remains.
"#;

const LEAD: &str = r#"---
name: lead
kind: lead
purpose: deliver one mission by breaking it into small reviewed tickets, staffing them well, and integrating only accepted work
tools: [delegate, update_plan, read, grep, glob, recall, org_status, propose_role]
domain: []
accountabilities: ["break the mission into small tickets, each with ONE owner, one concrete deliverable, and acceptance criteria written before the work", "pick the role and model for each ticket from track record, and never let the same agent do a task and review it", "get every deliverable independently reviewed; give concrete feedback on rejection and replace work that keeps failing"]
decide: [ticket breakdown within the mission, role and model per ticket, accept a ticket's integration]
recommend: [the mission's internal design, propose a new role when none fits]
kpis: [mission_delivered, acceptance_rate, rework_rate, cost_per_ticket]
---
You are a department head. Your job is coordination, not line work: turn your mission into as few
tickets as keep each one independently checkable, each with acceptance criteria you write up front. Every
ticket costs a new agent plus a reviewer, so do not split work one agent can finish in one session, and
keep dependent work (code and the tests written against it) in the same ticket. Give each ticket a
single owner. Acceptance criteria state what the mission needs, not extra rituals (mutation testing,
repeated reruns) nobody asked for.

Staff by fit: pick the role, and let the performance record pick the model; put a different agent on
review than on the work. `delegate` independent tickets in the same message so they run in parallel;
`org_status` shows you progress, budget, and stalls. Never edit files, run builds, or write code
yourself — delegate it, even if it looks trivial.

Every deliverable that changes files is checked by a `reviewer` before you integrate it. On a rejection,
pass the reviewer's concrete feedback back to the same worker; if a ticket keeps failing, reassign it to
another model or role rather than lowering the bar. When the mission is done, report a concise result to
the chief: what was built, how it was verified, and anything left open.
"#;

const IMPLEMENTER: &str = r#"---
name: implementer
kind: worker
purpose: make exactly the change a ticket asks for and prove it meets the acceptance criteria
tools: [read, write, edit, exec, grep, glob, update_plan]
domain: ["**"]
accountabilities: ["satisfy every acceptance criterion with the smallest change that does so", "run the checks yourself and report the observed results, not the intended ones", "stay within the ticket; surface anything it needs that is outside your reach instead of guessing"]
act: [edit files in the workspace, run build and test commands]
recommend: [a cleaner approach, a change to the ticket's scope]
decide: []
kpis: [acceptance_rate, rework_rate, tokens_per_ticket]
---
Do exactly what the ticket asks and no more — resist gold-plating and scope creep. Read the inputs first;
make the smallest change that satisfies every acceptance criterion.

Then prove it: run the build, the tests, or the program itself, and report what you actually observed
(paste the real output), never what you expected. If a criterion is ambiguous or the inputs contradict
it, state the assumption you made. A successful write means the file landed — do not re-read it to admire
it. Finish with a few lines: what you changed, the exact checks you ran, and their results.
"#;

const REVIEWER: &str = r#"---
name: reviewer
kind: reviewer
purpose: independently decide whether a deliverable meets its acceptance criteria, without trusting the worker's account of it
tools: [read, grep, glob, exec]
domain: []
accountabilities: ["check each acceptance criterion yourself by reading the files and running the proving checks", "accept only when every criterion holds; on a reject, say exactly what fails and what would fix it"]
decide: [accept or reject a submitted deliverable]
recommend: [follow-up work the ticket revealed]
kpis: [escaped_defects, review_turnaround]
---
You are an independent reviewer. The workspace already contains the worker's changes; your own edits are
discarded, so do not fix anything — judge it. Do NOT trust the worker's summary: verify each acceptance
criterion yourself by reading the changed files and running whatever proves it (the tests, the program,
a recomputation from the source). Actively try to break it on the edges the criteria imply. The criteria
set the bar: prove each one once, batch your checks into as few `exec` calls as you can, and add no checks
they do not call for.

Be brief. End with exactly one line, `VERDICT: ACCEPT` or `VERDICT: REJECT`. On a reject, give concrete,
located, actionable feedback: what is wrong, where (file and line), and what would make it acceptable —
enough that the worker can fix it without guessing.
"#;

const EXPLORER: &str = r#"---
name: explorer
kind: worker
purpose: investigate and report facts about the workspace or a question without changing anything
tools: [read, grep, glob, exec]
domain: []
accountabilities: ["answer the question asked with evidence (file paths, line numbers, command output)", "separate what you verified from what you inferred, and say plainly when something is unknown"]
act: [read files, run read-only commands]
recommend: [where the real work should focus next]
decide: []
kpis: [findings_used, claims_backed_by_evidence]
---
You investigate; you do not change anything. Answer exactly the question asked, and back every claim with
evidence the reader can check — a path, a line number, a command and its output. Run only read-only
commands.

Keep verified facts separate from inference, and when the workspace does not answer the question, say so
rather than inventing an answer. Report concisely: the finding first, then the evidence for it.
"#;

const BUILTIN_SOURCES: [&str; 5] = [CHIEF, EXPLORER, IMPLEMENTER, REVIEWER, LEAD];

/// The five built-in role charters, parsed with the same parser as user files.
pub fn builtin_roles() -> Vec<RoleCharter> {
    BUILTIN_SOURCES
        .iter()
        .filter_map(|source| parse_charter(source).ok())
        .collect()
}

/// A role library: built-ins plus user charters, keyed by role name.
#[derive(Debug, Clone, Default)]
pub struct RoleLibrary {
    roles: BTreeMap<String, RoleCharter>,
}

/// A user charter file that could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleProblem {
    /// Path reported to the operator.
    pub path: String,
    /// Why the file was skipped.
    pub message: String,
}

impl RoleLibrary {
    /// Load built-ins, then every `<dir>/*.md` file sorted by name, overriding
    /// or adding by role name. A broken file is reported and skipped; a missing
    /// directory is not an error.
    pub fn load(dir: &Path) -> (RoleLibrary, Vec<RoleProblem>) {
        let mut library = Self::builtin();
        let mut problems = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (library, problems);
            }
            Err(error) => {
                problems.push(RoleProblem {
                    path: dir.display().to_string(),
                    message: format!("could not read role directory: {error}"),
                });
                return (library, problems);
            }
        };
        let mut files = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("md")
                    {
                        files.push(path);
                    }
                }
                Err(error) => problems.push(RoleProblem {
                    path: dir.display().to_string(),
                    message: format!("could not read directory entry: {error}"),
                }),
            }
        }
        files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
        for path in files {
            let source = match std::fs::read_to_string(&path) {
                Ok(source) => source,
                Err(error) => {
                    problems.push(RoleProblem {
                        path: path.display().to_string(),
                        message: format!("could not read charter: {error}"),
                    });
                    continue;
                }
            };
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                problems.push(RoleProblem {
                    path: path.display().to_string(),
                    message: "file name is not valid UTF-8".to_string(),
                });
                continue;
            };
            match parse_charter(&source) {
                Ok(charter) if charter.name == stem => {
                    library.roles.insert(charter.name.clone(), charter);
                }
                Ok(charter) => problems.push(RoleProblem {
                    path: path.display().to_string(),
                    message: format!(
                        "charter name `{}` does not match file stem `{stem}`",
                        charter.name
                    ),
                }),
                Err(message) => problems.push(RoleProblem {
                    path: path.display().to_string(),
                    message,
                }),
            }
        }
        (library, problems)
    }

    /// A library containing only the built-in roles.
    pub fn builtin() -> RoleLibrary {
        let mut library = Self::default();
        for charter in builtin_roles() {
            library.roles.insert(charter.name.clone(), charter);
        }
        library
    }

    /// Look a role up by name.
    pub fn get(&self, name: &str) -> Option<&RoleCharter> {
        self.roles.get(name)
    }

    /// Add or replace a role in the library.
    pub fn insert(&mut self, charter: RoleCharter) {
        self.roles.insert(charter.name.clone(), charter);
    }

    /// All role names, sorted.
    pub fn names(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }

    /// Roles of a given kind, sorted by name.
    pub fn by_kind(&self, kind: RoleKind) -> Vec<&RoleCharter> {
        self.roles
            .values()
            .filter(|charter| charter.kind == kind)
            .collect()
    }
}

#[cfg(test)]
#[path = "role_tests.rs"]
mod tests;
