//! The `skill` tool — one surface for the whole skills system, replacing seagent-tools' builtin.
//!
//! * `action=view` (read/show/get) loads one skill through the same path as `/<name>`:
//!   preprocessing (template vars, inline shell), declared environment, `[skills.config.<skill>]`,
//!   the setup note and the supporting-file list, plugin-provided `plugin:name` skills included
//!   (Hermes `tools/skills_tool.py` `skill_view`).
//! * `action=list` (`category`, `query`, `verbose`) is `skills_list`: the offered catalog with
//!   each skill's category, description and SKILL.md path, and — verbose — which installed skills
//!   have unmet requirements on this host.
//! * `action=search` (`query`, `limit`) is `skills_search`: ranked BM25 over name/description/body
//!   (`super::search`, OpenClaw `skills_search`).
//! * `action=patch` (`old_string` → `new_string`, `replace_all`, `file_path`) and
//!   `operations=[…]` (an atomic batch of create/update/patch) go through `super::manage`:
//!   security guard, lint gate, ledger entry, approval gate.
//! * `action=workshop` (`operation=draft|validate|refine`) returns a SKILL.md proposal the model
//!   then saves (`super::workshop`).
//! * everything else — `create` / `update` / `archive` — falls through to seagent-tools' writer, so
//!   there is one implementation of those rules. One exception: `update`/`patch` carrying a full
//!   SKILL.md in `content` is a whole-file rewrite, which the builtin would store as the body; that
//!   shape goes to `super::manage` instead.
//!
//! Registered by name through `core::tools`, which replaces the builtin `skill` tool.

use super::search;
use super::settings::{Settings, Store};
use super::usage;
use super::{invoke, manage, workshop};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput};
use seagent_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::sync::Arc;

/// Names the builtin `skill` tool accepts for "load it" (its synonyms included).
const VIEW_ACTIONS: &[&str] = &["view", "read", "show", "get"];
const LIST_ACTIONS: &[&str] = &["list", "ls", "catalog", "skills"];
const SEARCH_ACTIONS: &[&str] = &["search", "find", "query"];
const PATCH_ACTIONS: &[&str] = &["patch", "replace"];
const FILE_ACTIONS: &[&str] = &["write_file", "remove_file"];
const WORKSHOP_ACTIONS: &[&str] = &["workshop", "draft", "validate", "refine", "compose"];

/// What a call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    View,
    List,
    Search,
    Manage,
    Workshop,
    /// seagent-tools' writer: create / update / archive.
    Builtin,
}

/// Whether this call loads a skill rather than writing one. Mirrors the builtin's inference: no
/// `action` but a `name` (and no body/description) is a view.
pub fn view_call(input: &Value) -> bool {
    match input.get("action").and_then(Value::as_str) {
        Some(a) => VIEW_ACTIONS.contains(&a.trim().to_ascii_lowercase().as_str()),
        None => {
            let has = |k: &str| input.get(k).is_some();
            has("name") && !["body", "content", "steps", "instructions", "text", "description"].iter().any(|k| has(k))
        }
    }
}

fn action_of(input: &Value) -> Option<String> {
    input.get("action").and_then(Value::as_str).map(|a| a.trim().to_ascii_lowercase()).filter(|a| !a.is_empty())
}

fn has_full_content(input: &Value) -> bool {
    input.get("content").and_then(Value::as_str).is_some_and(|c| c.trim_start().starts_with("---"))
}

/// Which implementation answers this call.
pub fn route(input: &Value) -> Route {
    if input.get("operations").is_some() {
        return Route::Manage;
    }
    if input.get("goal").is_some() && action_of(input).is_none() {
        return Route::Workshop;
    }
    match action_of(input).as_deref() {
        Some(a) if VIEW_ACTIONS.contains(&a) => Route::View,
        Some(a) if LIST_ACTIONS.contains(&a) => Route::List,
        Some(a) if SEARCH_ACTIONS.contains(&a) => Route::Search,
        Some(a) if PATCH_ACTIONS.contains(&a) || FILE_ACTIONS.contains(&a) => Route::Manage,
        Some(a) if WORKSHOP_ACTIONS.contains(&a) => Route::Workshop,
        // A full SKILL.md in `content` is a rewrite, which only the guarded writer can store safely.
        Some("update" | "edit") if has_full_content(input) => Route::Manage,
        None if input.get("query").is_some() => Route::Search,
        None if view_call(input) => Route::View,
        _ => Route::Builtin,
    }
}

pub struct SkillTool {
    cfg: Config,
    paths: Paths,
}

impl SkillTool {
    pub fn new(cfg: &Config, paths: &Paths) -> SkillTool {
        SkillTool { cfg: cfg.clone(), paths: paths.clone() }
    }

    fn spec_schema() -> Value {
        json!({"type":"object","properties":{
            "action":{"type":"string","enum":["view","list","search","patch","write_file","remove_file","workshop","create","update","archive"],"description":"view loads one skill; list is the catalog; search finds one by task; patch edits one line-range of an existing skill; workshop drafts/validates/refines a SKILL.md; create/update/archive write your own skills."},
            "name":{"type":"string","description":"Skill name (lowercase-dashes). `plugin:name` loads a plugin-provided skill."},
            "description":{"type":"string","description":"create/update: one line describing when to use it (≤300 chars)."},
            "body":{"type":"string","description":"create/update: the Markdown procedure."},
            "content":{"type":"string","description":"A full SKILL.md (frontmatter + body): a rewrite for patch/update, or the draft to validate."},
            "category":{"type":"string","description":"list: only skills in this category folder."},
            "query":{"type":"string","description":"list: substring filter; search: the task or words to rank by."},
            "verbose":{"type":"boolean","description":"list: also name the installed skills whose requirements are unmet here, and why."},
            "limit":{"type":"integer","description":"search: at most this many results (default 5, max 20)."},
            "old_string":{"type":"string","description":"patch: the EXACT text to replace (must match once unless replace_all)."},
            "new_string":{"type":"string","description":"patch: the replacement (empty deletes the match)."},
            "replace_all":{"type":"boolean","description":"patch: replace every occurrence."},
            "file_path":{"type":"string","description":"patch/write_file/remove_file: SKILL.md (default) or a file under references/, templates/, scripts/, assets/."},
            "operations":{"type":"array","description":"An atomic batch: [{action: create|update|patch|write_file|remove_file, name, description, body, content, old_string, new_string, file_path}]. Applied or rejected as a whole."},
            "operation":{"type":"string","enum":["draft","validate","refine"],"description":"workshop: draft from a goal, validate a SKILL.md, or refine an existing skill into a proposal."},
            "goal":{"type":"string","description":"workshop draft: the class of task this skill is for."},
            "steps":{"type":"array","items":{"type":"string"},"description":"workshop draft/refine: the ordered steps that worked."},
            "focus":{"type":"string","description":"workshop refine: what the new section is about."}},
            "required":["action"]})
    }
}

impl Tool for SkillTool {
    fn spec(&self) -> seagent_core::ToolSpec {
        let mut spec = seagent_tools::Skill.spec();
        spec.description = "Skills are reusable procedures (SKILL.md). action=view loads one by name (do this before using a skill from the index; `plugin:name` for a plugin-provided skill) with its rendered content, declared environment and files. action=list shows the catalog by category (verbose names the skills this host cannot run and why). action=search ranks installed skills by a task description. action=patch fixes a line range of an existing skill (unique old_string → new_string) instead of rewriting it; write_file/remove_file add or drop a supporting file under references/, templates/, scripts/ or assets/; operations=[…] applies several create/update/patch/write_file calls atomically. action=workshop drafts a SKILL.md from a goal, validates a draft, or refines an existing skill into a proposal. action=create/update writes your own skills (name: lowercase-dashes, description, body) so future sessions can reuse a procedure that worked; action=archive retires one you wrote.".into();
        spec.input_schema = Self::spec_schema();
        spec
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match route(input) {
            Route::View | Route::List | Route::Search | Route::Workshop => vec![],
            Route::Manage => {
                // The batch may touch several skills; report every skill directory it names.
                let mut ops = manage::parse(input).unwrap_or_default();
                if ops.is_empty() {
                    ops.push(manage::Op { action: "patch".into(), name: input.get("name").and_then(Value::as_str).unwrap_or("").to_string(), description: None, body: None, content: None, old_string: None, new_string: None, replace_all: false, file_path: None });
                }
                ops.iter().map(|o| Effect::Write { path: self.paths.data.join("skills").join(&o.name) }).collect()
            }
            Route::Builtin => seagent_tools::Skill.effects(ctx, input),
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let s = Settings::load(&self.cfg);
        // A user lock refuses every mutating route, including the builtin writer's create/update
        // and an atomic batch that names the skill somewhere other than the top level.
        if !matches!(route(&input), Route::View | Route::List | Route::Search | Route::Workshop) {
            let st = Store::new(&self.paths);
            let mut names: Vec<String> = vec![input.get("name").and_then(Value::as_str).unwrap_or("").to_string()];
            names.extend(input.get("operations").and_then(Value::as_array).into_iter().flatten().filter_map(|o| o.get("name").and_then(Value::as_str)).map(String::from));
            if let Some(n) = names.into_iter().find(|n| !n.is_empty() && usage::is_locked(&st, n)) {
                return ToolOutput::err(usage::lock_refusal(&n));
            }
        }
        match route(&input) {
            Route::List => ToolOutput::ok(self.list(&ctx.workspace, &s, &input)),
            Route::Search => match self.search(&ctx.workspace, &s, &input) {
                Ok(t) => ToolOutput::ok(t),
                Err(e) => ToolOutput::err(e),
            },
            Route::Workshop => match self.workshop(&ctx.workspace, &input) {
                Ok(t) => ToolOutput::ok(t),
                Err(e) => ToolOutput::err(e),
            },
            Route::Manage => {
                let ops = match manage::parse(&input) {
                    Ok(o) => o,
                    Err(e) => return ToolOutput::err(e),
                };
                let c = manage::Ctx { cfg: &self.cfg, paths: &self.paths, ws: &ctx.workspace, settings: &s, session: Some(&ctx.session_id) };
                match manage::run(&c, &ops) {
                    Ok(t) => ToolOutput::ok(t),
                    Err(e) => ToolOutput::err(e),
                }
            }
            Route::View => self.view(ctx, &s, &input),
            Route::Builtin => {
                // The writer's note promises the index updates "from the next session on"; the live
                // delta announces a skill on the next turn of this same session (`core::index`).
                let mut out = seagent_tools::Skill.call(ctx, input);
                if !out.is_error {
                    out.content = out.content.replace("listed from the next session on", "the skills index lists it from the next turn on");
                }
                out
            }
        }
    }
}

impl SkillTool {
    fn view(&self, ctx: &ToolCtx, s: &Settings, input: &Value) -> ToolOutput {
        let name = input.get("name").and_then(Value::as_str).unwrap_or("").trim();
        if name.is_empty() {
            return ToolOutput::err("`name` is required");
        }
        if s.is_disabled(name) {
            return ToolOutput::err(format!("skill `{name}` is disabled ([skills] disabled); enable it with `seagent skills config enable {name}` or inspect the files directly on disk"));
        }
        let l = invoke::Loader::new(&self.cfg, &self.paths, &ctx.workspace, s);
        match view_skill(&l, name, Some(&ctx.session_id)) {
            Some(Ok(text)) => ToolOutput::ok(text),
            Some(Err(e)) => ToolOutput::err(e),
            // Not in the catalog (unreadable frontmatter, a name outside the roots): the builtin's
            // lookup decides, and reports what it always reported.
            None => seagent_tools::Skill.call(ctx, json!({"action": "view", "name": name})),
        }
    }

    fn list(&self, ws: &std::path::Path, s: &Settings, input: &Value) -> String {
        let (mut visible, hidden) = invoke::catalog_split(&self.cfg, &self.paths, ws, s);
        let category = input.get("category").and_then(Value::as_str).map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
        let query = input.get("query").and_then(Value::as_str).map(|q| q.trim().to_lowercase()).filter(|q| !q.is_empty());
        let filtered = category.is_some() || query.is_some();
        if let Some(c) = &category {
            visible.retain(|k| k.category.as_deref() == Some(c.as_str()) || invoke::group_of(k) == *c);
        }
        if let Some(q) = &query {
            visible.retain(|k| k.name.to_lowercase().contains(q) || k.description.to_lowercase().contains(q) || k.category.as_deref().is_some_and(|c| c.to_lowercase().contains(q)));
        }
        let verbose = input.get("verbose").and_then(Value::as_bool).unwrap_or(false);
        // A filtered view is about the filter, not the host: the gated-out names stay out of it.
        let hidden = if filtered { Vec::new() } else { hidden };
        invoke::list_text(&visible, &hidden, filtered, verbose)
    }

    fn search(&self, ws: &std::path::Path, s: &Settings, input: &Value) -> Result<String, String> {
        let cat = invoke::catalog(&self.cfg, &self.paths, ws, s);
        let query = input.get("query").and_then(Value::as_str).unwrap_or("");
        let limit = input.get("limit").and_then(Value::as_u64).map(|l| l as usize);
        let (hits, more) = search::search(&cat, query, limit)?;
        Ok(search::render(query.trim(), &hits, more))
    }

    fn workshop(&self, ws: &std::path::Path, input: &Value) -> Result<String, String> {
        let op = input
            .get("operation")
            .and_then(Value::as_str)
            .map(|o| o.trim().to_ascii_lowercase())
            .or_else(|| action_of(input).filter(|a| WORKSHOP_ACTIONS.contains(&a.as_str())))
            .unwrap_or_default();
        let op = match op.as_str() {
            "draft" | "compose" | "" => "draft",
            "validate" | "lint" | "check" => "validate",
            "refine" | "improve" => "refine",
            other => return Err(format!("unknown workshop operation `{other}` (draft, validate, refine)")),
        };
        let steps: Vec<String> = input.get("steps").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default();
        let name = input.get("name").and_then(Value::as_str).map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
        match op {
            "draft" => {
                let goal = input.get("goal").and_then(Value::as_str).or_else(|| input.get("description").and_then(Value::as_str)).unwrap_or("");
                let d = workshop::draft(goal, name.as_deref(), input.get("description").and_then(Value::as_str), &steps)?;
                let v = workshop::validate(&d.content, Some(&d.name), None);
                let mut out = format!("Draft SKILL.md for `{}` (not saved):\n\n{}\n\n{}", d.name, d.content, v.render(&d.name));
                if v.ok() {
                    out.push_str(&format!(
                        "\nSave it with `skill action=create name={} description=<one line> body=<the procedure>` (or `action=operations` to add references/ in the same call).",
                        d.name
                    ));
                }
                Ok(out)
            }
            "validate" => {
                let content = input.get("content").and_then(Value::as_str).map(String::from).or_else(|| {
                    let body = input.get("body").and_then(Value::as_str)?;
                    let n = name.clone()?;
                    Some(workshop::draft(body, Some(&n), input.get("description").and_then(Value::as_str), &[]).ok()?.content)
                });
                let content = content.ok_or("`validate` needs `content` (a full SKILL.md) or `name` + `body`")?;
                let v = workshop::validate(&content, name.as_deref(), None);
                Ok(v.render(name.as_deref().unwrap_or("draft")))
            }
            _ => {
                let n = name.ok_or("`refine` needs `name` (the skill to refine)")?;
                let settings = Settings::load(&self.cfg);
                let cat = invoke::catalog_loadable(&self.cfg, &self.paths, ws, &settings);
                let sk = invoke::resolve(&cat, &n).ok_or_else(|| format!("no skill `{n}` to refine"))?;
                let current = std::fs::read_to_string(&sk.file).map_err(|e| format!("{}: {e}", sk.file.display()))?;
                let focus = input.get("focus").and_then(Value::as_str).unwrap_or("");
                let r = workshop::refine(&current, &sk.name, focus, &steps)?;
                let v = workshop::validate(&r.content, Some(&r.name), None);
                let mut out = format!("Proposal for `{}` (not saved) — new section:\n\n{}\n\n{}{}", r.name, r.section, v.render(&r.name), if r.advisories.is_empty() { String::new() } else { format!("\n{}", r.advisories.join("\n")) });
                out.push_str(&format!("\nApply it with `skill action=update name={} content=<the proposal>` (a full rewrite) or `action=patch` for one line.", r.name));
                Ok(out)
            }
        }
    }
}

/// `view` for one skill: the preprocessed body under its SKILL.md path, then the directory,
/// `[skills.config.<skill>]`, the setup note and the supporting files (`skill_block`).
pub fn view_skill(l: &invoke::Loader, name: &str, session: Option<&str>) -> Option<Result<String, String>> {
    let cat = l.catalog();
    let sk = invoke::resolve(&cat, name)?;
    let st = Store::new(l.paths);
    usage::bump_view(&st, &sk.name);
    usage::bump_use(&st, &sk.name);
    super::review::note_loaded(&st, session, &sk.name);
    Some(invoke::skill_block(sk, &sk.file.display().to_string(), "", session, l.cfg, l.settings, &l.vault))
}

/// The tool the kernel registers instead of the builtin (`core::tools`).
pub fn tool(cfg: &Config, paths: &Paths) -> Arc<dyn Tool> {
    Arc::new(SkillTool::new(cfg, paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_kernel::vault::Vault;

    fn fixture(tag: &str) -> (std::path::PathBuf, Paths, std::path::PathBuf) {
        let d = seagent_core::tmp::scratch_path(format!("seagent-skilltool-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        let ws = d.join("ws");
        std::fs::create_dir_all(ws.join(".seagent/skills/deploy/scripts")).unwrap();
        std::fs::write(
            ws.join(".seagent/skills/deploy/SKILL.md"),
            "---\nname: deploy\ndescription: Ship it\nrequired_environment_variables: [SEAGENT_T_DEPLOY_TOKEN]\nmetadata:\n  seagent:\n    config:\n      - key: region\n      - key: account\n        default: acme\n      - key: roster\n---\nRun ${SEAGENT_SKILL_DIR}/scripts/go.sh today !`echo inline-ok`\n",
        )
        .unwrap();
        std::fs::write(ws.join(".seagent/skills/deploy/scripts/go.sh"), "echo").unwrap();
        std::fs::create_dir_all(paths.data.join("plugins/portable/skills/fmt")).unwrap();
        std::fs::write(paths.data.join("plugins/portable/skills/fmt/SKILL.md"), "---\nname: fmt\ndescription: Format\n---\nfmt body").unwrap();
        (d, paths, ws)
    }

    fn ctx(ws: &std::path::Path, paths: &Paths) -> ToolCtx {
        struct NoHost;
        impl seagent_core::ToolHost for NoHost {
            fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &seagent_core::Cancel) -> Result<String, String> {
                Err("no sub-agents in this test".into())
            }
            fn ask_user(&self, _: &str) -> Result<String, String> {
                Err("headless".into())
            }
        }
        ToolCtx {
            workspace: ws.to_path_buf(),
            session_id: "ses-1".into(),
            artifacts: ws.join(".seagent/artifacts"),
            // The kernel hands tools `paths.data` as `home`: the builtin writer's own skills dir.
            home: paths.data.clone(),
            cancel: Default::default(),
            host: std::sync::Arc::new(NoHost),
            secrets: std::sync::Arc::new(|s: &str| s.to_string()),
        }
    }

    #[test]
    fn view_goes_through_preprocessing_setup_and_plugins() {
        let (d, paths, ws) = fixture("a");
        let mut cfg = Config::default();
        cfg.skills.insert("template_vars".into(), toml::Value::Boolean(true));
        cfg.skills.insert("inline_shell".into(), toml::Value::Boolean(true));
        let mut table = toml::Table::new();
        table.insert("deploy".into(), toml::from_str("region = \"eu-west-1\"").unwrap());
        cfg.skills.insert("config".into(), toml::Value::Table(table));
        let tool = tool(&cfg, &paths);
        let c = ctx(&ws, &paths);
        let out = tool.call(&c, json!({"action": "view", "name": "deploy"}));
        assert!(!out.is_error, "{}", out.content);
        // Joined per component (native separators); the shell-facing directory is `path_str`.
        let dir = ws.join(".seagent").join("skills").join("deploy");
        assert!(out.content.starts_with(&format!("{}", dir.join("SKILL.md").display())), "path first: {}", out.content);
        assert!(out.content.contains(&format!("Run {}/scripts/go.sh today inline-ok", seagent_core::platform::shell::path_str(&dir))), "templates + inline shell: {}", out.content);
        assert!(out.content.contains("[Skill directory:") && out.content.contains("- scripts/go.sh"));
        assert!(out.content.contains("[Skill config ([skills.config.deploy]):\n  region = eu-west-1\n  account = acme\n  roster = (not set)\n]"), "{}", out.content);
        assert!(out.content.contains("[Skill setup note: Setup needed before using this skill: missing env $SEAGENT_T_DEPLOY_TOKEN."), "{}", out.content);
        // A collected secret makes it ready and lands in the skill's environment.
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let vault = Vault::load(&paths.secrets()).unwrap();
        vault.set("SEAGENT_T_DEPLOY_TOKEN", "tok-9").unwrap();
        let out = tool.call(&c, json!({"action": "view", "name": "deploy"}));
        assert!(!out.content.contains("Skill setup note"), "{}", out.content);
        assert_eq!(std::env::var("SEAGENT_T_DEPLOY_TOKEN").as_deref(), Ok("tok-9"));
        // Plugin-provided skills load by their qualified name (the builtin cannot find those).
        let out = tool.call(&c, json!({"name": "portable:fmt"}));
        assert!(!out.is_error && out.content.contains("fmt body"), "{}", out.content);
        // Unknown names keep the builtin's wording.
        let out = tool.call(&c, json!({"action": "view", "name": "nope"}));
        assert!(out.is_error && out.content.contains("no skill `nope`"), "{}", out.content);
        // Writes still go through the builtin writer, with its rules and messages.
        assert!(tool.call(&c, json!({"action": "create", "name": "mine", "description": "", "body": "x"})).is_error);
        let out = tool.call(&c, json!({"action": "create", "name": "mine", "description": "d", "body": "step 1"}));
        assert!(!out.is_error && out.content.contains("created skill `mine`"), "{}", out.content);
        assert!(out.content.contains("the skills index lists it from the next turn on"), "not \"next session\": {}", out.content);
        assert!(tool.call(&c, json!({"action": "create", "name": "mine", "description": "d", "body": "x"})).content.contains("exists; use action=update"));
        assert!(view_call(&json!({"name": "mine"})) && !view_call(&json!({"name": "mine", "body": "b"})));
        assert!(tool.effects(&c, &json!({"action": "view", "name": "deploy"})).is_empty());
        assert!(matches!(tool.effects(&c, &json!({"action": "create", "name": "x"})).first(), Some(Effect::Write { .. })));
        // A disabled skill is refused with the reason and the way back (upstream `skill_view`).
        cfg.skills.insert("disabled".into(), toml::Value::Array(vec![toml::Value::String("deploy".into())]));
        let out = super::tool(&cfg, &paths).call(&c, json!({"action": "view", "name": "deploy"}));
        assert!(out.is_error && out.content.contains("is disabled") && out.content.contains("seagent skills config enable deploy"), "{}", out.content);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The three new read actions and the write actions, through the registered tool.
    #[test]
    fn list_search_patch_workshop_and_operations() {
        let (d, paths, ws) = fixture("b");
        let cfg = Config::default();
        // A skill whose requirement cannot be met here stays out of list/search but can be viewed.
        std::fs::create_dir_all(ws.join(".seagent/skills/needs-cli")).unwrap();
        std::fs::write(ws.join(".seagent/skills/needs-cli/SKILL.md"), "---\nname: needs-cli\ndescription: Drive a missing CLI\nmetadata:\n  openclaw:\n    requires:\n      bins: [seagent-absent-binary]\n---\nneeds body").unwrap();
        let tool = tool(&cfg, &paths);
        let c = ctx(&ws, &paths);
        // list: every offered skill with its category and path; gated one only when verbose.
        let list = tool.call(&c, json!({"action": "list"}));
        assert!(!list.is_error && list.content.contains("- deploy: Ship it (") && list.content.contains("needs-cli"), "{}", list.content);
        assert!(list.content.contains("cannot run on this host") && list.content.contains("pass verbose=true"), "{}", list.content);
        let verbose = tool.call(&c, json!({"action": "list", "verbose": true}));
        assert!(verbose.content.contains("- needs-cli: Drive a missing CLI (") && verbose.content.contains("bins: seagent-absent-binary"), "{}", verbose.content);
        // The category filter and the query filter.
        std::fs::create_dir_all(ws.join(".seagent/skills/devops/ship")).unwrap();
        std::fs::write(ws.join(".seagent/skills/devops/ship/SKILL.md"), "---\nname: ship\ndescription: Release train\n---\nship body").unwrap();
        let cat = tool.call(&c, json!({"action": "list", "category": "devops"}));
        assert!(cat.content.contains("- ship: Release train") && !cat.content.contains("- deploy:"), "{}", cat.content);
        let q = tool.call(&c, json!({"action": "list", "query": "format"}));
        assert!(q.content.contains("portable:fmt") && !q.content.contains("- deploy:"), "plugin skills are listed too: {}", q.content);
        // search: ranked, bounded, gated skills excluded.
        let s = tool.call(&c, json!({"action": "search", "query": "ship the release"}));
        assert!(!s.is_error && s.content.contains("- deploy: Ship it ("), "{}", s.content);
        assert!(!s.content.contains("needs-cli"), "an ineligible skill is not a search result: {}", s.content);
        assert!(!tool.call(&c, json!({"action": "search", "query": "drive"})).content.contains("needs-cli"));
        assert!(tool.call(&c, json!({"action": "search", "query": "nonsense-zzz"})).content.contains("no skill matches"));
        assert!(tool.call(&c, json!({"action": "search", "query": "x", "limit": 99})).is_error);
        // patch: a targeted edit of an own skill, guarded and ledgered.
        assert!(!tool.call(&c, json!({"action": "create", "name": "notes", "description": "Note taking", "body": "## When to Use\nAlways.\n\n- write it down"})).is_error);
        let p = tool.call(&c, json!({"action": "patch", "name": "notes", "old_string": "- write it down", "new_string": "- write it down twice"}));
        assert!(!p.is_error && p.content.contains("patched SKILL.md in skill `notes`"), "{}", p.content);
        assert!(p.content.contains("undo with `seagent skills rollback"), "{}", p.content);
        let md = std::fs::read_to_string(paths.data.join("skills/notes/SKILL.md")).unwrap();
        assert!(md.contains("write it down twice"), "{md}");
        assert!(tool.call(&c, json!({"action": "patch", "name": "notes", "old_string": "absent", "new_string": "x"})).is_error);
        // A patch is a write effect on the skill's directory.
        assert!(matches!(tool.effects(&c, &json!({"action": "patch", "name": "notes", "old_string": "a", "new_string": "b"})).first(), Some(Effect::Write { path }) if path.ends_with("skills/notes")));
        assert!(tool.effects(&c, &json!({"action": "search", "query": "x"})).is_empty());
        // operations: an atomic batch (create + patch of the same new skill).
        let batch = tool.call(
            &c,
            json!({"operations":[
                {"action":"create","name":"triage","description":"Triage bugs","body":"## When to Use\nBugs arrive.\n\n1. reproduce"},
                {"action":"patch","name":"triage","old_string":"1. reproduce","new_string":"1. reproduce, then bisect"}
            ]}),
        );
        assert!(!batch.is_error && batch.content.contains("created skill `triage`") && batch.content.contains("patched SKILL.md in skill `triage`"), "{}", batch.content);
        assert!(std::fs::read_to_string(paths.data.join("skills/triage/SKILL.md")).unwrap().contains("1. reproduce, then bisect"));
        // write_file / remove_file: supporting files under the same guard and ledger.
        let wf = tool.call(&c, json!({"action": "write_file", "name": "triage", "file_path": "references/triage.md", "content": "# Triage\n1. reproduce\n"}));
        assert!(!wf.is_error && wf.content.contains("wrote `references/triage.md` in skill `triage`"), "{}", wf.content);
        assert_eq!(std::fs::read_to_string(paths.data.join("skills/triage/references/triage.md")).unwrap(), "# Triage\n1. reproduce\n");
        let bad = tool.call(&c, json!({"action": "write_file", "name": "triage", "file_path": "SKILL.md.bak", "content": "x"}));
        assert!(bad.is_error && bad.content.contains("must name SKILL.md or a file under"), "{}", bad.content);
        let rf = tool.call(&c, json!({"action": "remove_file", "name": "triage", "file_path": "references/triage.md"}));
        assert!(!rf.is_error && rf.content.contains("removed `references/triage.md`"), "{}", rf.content);
        assert!(!paths.data.join("skills/triage/references/triage.md").exists());
        assert!(tool.call(&c, json!({"action": "remove_file", "name": "triage", "file_path": "references/gone.md"})).is_error);
        assert_eq!(route(&json!({"action": "write_file", "name": "x", "file_path": "references/a.md", "content": "y"})), Route::Manage);
        // workshop: draft → validate → refine are proposals, never writes.
        let draft = tool.call(&c, json!({"action": "workshop", "operation": "draft", "goal": "Rebuild the search index safely", "name": "reindex", "steps": ["Stop writers", "Swap the alias"]}));
        assert!(!draft.is_error && draft.content.contains("Draft SKILL.md for `reindex`") && draft.content.contains("## Procedure\n1. Stop writers\n2. Swap the alias"), "{}", draft.content);
        assert!(draft.content.contains("draft is valid") && draft.content.contains("Save it with `skill action=create"), "{}", draft.content);
        assert!(!paths.data.join("skills/reindex").exists(), "a draft is never written");
        let v = tool.call(&c, json!({"action": "workshop", "operation": "validate", "content": "---\nname: x\ndescription: d\n---\n\n# X\n"}));
        assert!(!v.is_error && v.content.contains("draft is valid"), "{}", v.content);
        let v = tool.call(&c, json!({"action": "workshop", "operation": "validate", "content": "nope"}));
        assert!(v.content.contains("blocking problem"), "{}", v.content);
        let r = tool.call(&c, json!({"action": "workshop", "operation": "refine", "name": "notes", "focus": "Filing", "steps": ["File it under the right project"]}));
        assert!(!r.is_error && r.content.contains("Proposal for `notes`") && r.content.contains("## Filing\n1. File it under the right project"), "{}", r.content);
        assert!(r.content.contains("Apply it with `skill action=update"), "{}", r.content);
        assert!(!std::fs::read_to_string(paths.data.join("skills/notes/SKILL.md")).unwrap().contains("## Filing"), "the proposal is not applied");
        // Applying the proposal: `update` with a full SKILL.md goes to the guarded writer.
        let apply = tool.call(&c, json!({"action": "update", "name": "notes", "content": "---\nname: notes\ndescription: Note taking\n---\n\n## Filing\n1. File it\n"}));
        assert!(!apply.is_error, "{}", apply.content);
        assert!(apply.content.contains("rewrote SKILL.md of `notes`"), "{}", apply.content);
        assert!(std::fs::read_to_string(paths.data.join("skills/notes/SKILL.md")).unwrap().contains("## Filing"));
        // Routing is stable for the builtin's own actions.
        assert_eq!(route(&json!({"action": "create", "name": "x", "body": "y"})), Route::Builtin);
        assert_eq!(route(&json!({"action": "archive", "name": "x"})), Route::Builtin);
        assert_eq!(route(&json!({"action": "update", "name": "x", "body": "y"})), Route::Builtin);
        assert_eq!(route(&json!({"action": "update", "name": "x", "content": "---\nname: x\n---\nb"})), Route::Manage);
        assert_eq!(route(&json!({"query": "pdf"})), Route::Search);
        assert_eq!(route(&json!({"goal": "do a thing"})), Route::Workshop);
        assert_eq!(route(&json!({"action": "list"})), Route::List);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Upstream `skill_view` details: a name in two roots resolves to the first root, a plugin
    /// skill keeps its qualified name, and the setup note lists every missing variable.
    #[test]
    fn view_dedupes_first_root_and_reports_every_missing_env() {
        let (d, paths, ws) = fixture("c");
        std::fs::create_dir_all(paths.data.join("skills/deploy")).unwrap();
        std::fs::write(paths.data.join("skills/deploy/SKILL.md"), "---\nname: deploy\ndescription: user copy\n---\nuser body").unwrap();
        std::fs::write(ws.join(".seagent/skills/deploy/SKILL.md"), "---\nname: deploy\ndescription: project copy\nrequired_environment_variables: [SEAGENT_T_ONE, SEAGENT_T_TWO]\n---\nproject body").unwrap();
        let cfg = Config::default();
        let tool = tool(&cfg, &paths);
        let c = ctx(&ws, &paths);
        let out = tool.call(&c, json!({"action": "view", "name": "deploy"}));
        assert!(out.content.contains("project body") && !out.content.contains("user body"), "the project root wins: {}", out.content);
        assert!(out.content.contains("missing env $SEAGENT_T_ONE, env $SEAGENT_T_TWO"), "{}", out.content);
        let settings = Settings::load(&cfg);
        let l = invoke::Loader::new(&cfg, &paths, &ws, &settings);
        let cat = l.catalog();
        assert_eq!(cat.iter().filter(|k| k.name == "deploy").count(), 1, "one entry per name");
        assert!(cat.iter().any(|k| k.name == "portable:fmt"), "plugin skills keep their namespace");
        let _ = std::fs::remove_dir_all(&d);
    }
}
