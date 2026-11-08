//! `deploy` — controlled deploys and rollbacks (pro-071) over kubectl, helm, docker/podman
//! compose and systemctl.
//!
//! The flow is fixed and every step is recorded in the unified audit stream
//! (`seagent_security::audit`, kinds `deploy.plan` / `deploy.apply` / `deploy.rollback`):
//!
//! 1. `action=plan` runs only dry-runs and reads (`kubectl diff` + `apply --dry-run=server`,
//!    `helm diff`/`upgrade --dry-run`, `compose config`, `systemctl status`), snapshots the
//!    current state (live objects, the deployed helm revision, the running image ids, the unit
//!    state) and **prepares the rollback command** before anything changes. The plan is stored
//!    under `<seagent home>/deploy/<plan_id>/` with a hash of its inputs.
//! 2. `action=apply plan_id=…` runs exactly the planned command. It refuses when the plan
//!    failed, expired, was already applied, or when the manifest / values / compose file changed
//!    since the plan (re-plan). The call declares the command (`Exec`) and the change to a
//!    remote system (`Net` to `deploy://<target>` carrying the change summary), so the
//!    kernel's existing risk tiers decide: tier 2 (asks under every preset; an envelope may
//!    cover it), tier 3 for destructive shapes (`kubectl delete`, prod + backup). This tool
//!    never asks, approves or bypasses anything itself.
//! 3. `action=rollback plan_id=…` runs the prepared rollback through the same gates.
//!
//! Binaries, timeouts and guard rails come from `[integrations.deploy]`:
//! `kubectl`, `helm`, `docker` (or `compose_engine = "podman"`), `systemctl` paths;
//! `timeout_seconds` (300), `plan_ttl_minutes` (60), `require_context` (true: kubectl/helm need
//! an explicit `context`, never the ambient current-context), `allow_contexts` (globs).

use super::run::{join, run, RunOut};
use super::{arg, arg_list, now_unix, rfc3339, Integrations};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub struct Deploy {
    pub cfg: Arc<Integrations>,
}

const SEC: &str = "deploy";

fn plans_dir(ctx: &ToolCtx) -> PathBuf {
    ctx.home.join("deploy")
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn load(ctx: &ToolCtx, id: &str) -> Result<Value, String> {
    if !valid_id(id) {
        return Err(format!("`{id}` is not a plan id (use the plan_id returned by action=plan)"));
    }
    let p = plans_dir(ctx).join(id).join("plan.json");
    let t = std::fs::read_to_string(&p).map_err(|_| format!("plan {id} not found (run action=plan first)"))?;
    serde_json::from_str(&t).map_err(|e| format!("plan {id} is unreadable: {e}"))
}

fn save(ctx: &ToolCtx, plan: &Value) -> Result<(), String> {
    let id = plan["id"].as_str().unwrap_or_default();
    let d = plans_dir(ctx).join(id);
    std::fs::create_dir_all(&d).map_err(|e| format!("cannot write plan: {e}"))?;
    crate::util::atomic_write(&d.join("plan.json"), serde_json::to_string_pretty(plan).unwrap_or_default().as_bytes()).map_err(|e| format!("cannot write plan: {e}"))
}

fn argv(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn audit(ctx: &ToolCtx, kind: &str, plan: &Value, outcome: &str, extra: Value) {
    let mut detail = json!({"plan_id": plan["id"], "kind": plan["kind"], "summary": plan["summary"], "apply": join(&argv(&plan["apply"])), "rollback": join(&argv(&plan["rollback"]))});
    if let (Some(d), Some(e)) = (detail.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    let ev = seagent_security::audit::Event::new(kind, seagent_security::audit::Actor::new("agent", &ctx.session_id), plan["target"].as_str().unwrap_or(""), outcome).session(&ctx.session_id).detail(detail);
    seagent_security::audit::record(&ctx.home, ev);
}

/// sha256 over the files a plan depends on (a directory: every regular file, sorted).
fn inputs_hash(paths: &[PathBuf]) -> String {
    let mut files: Vec<PathBuf> = vec![];
    for p in paths {
        if p.is_dir() {
            let mut stack = vec![p.clone()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let ep = e.path();
                    if ep.is_dir() {
                        stack.push(ep);
                    } else {
                        files.push(ep);
                    }
                }
            }
        } else {
            files.push(p.clone());
        }
    }
    files.sort();
    let mut buf = Vec::new();
    for f in files {
        buf.extend_from_slice(f.to_string_lossy().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&std::fs::read(&f).unwrap_or_default());
        buf.push(0);
    }
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(&buf))
}

/// Drop the server-managed fields that make a re-apply of a snapshot conflict.
pub fn strip_server_fields(yaml: &str) -> String {
    yaml.lines()
        .filter(|l| {
            let t = l.trim_start();
            !["resourceVersion:", "uid:", "creationTimestamp:", "generation:", "selfLink:"].iter().any(|k| t.starts_with(k))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct Planner<'a> {
    cfg: &'a Integrations,
    ctx: &'a ToolCtx,
    timeout: Duration,
}

impl Planner<'_> {
    fn bin(&self, key: &str, default: &str) -> String {
        self.cfg.str(SEC, key).unwrap_or_else(|| default.to_string())
    }
    fn exec(&self, a: &[String]) -> Result<RunOut, String> {
        run(a, Some(&self.ctx.workspace), self.timeout, &self.ctx.cancel)
    }
    fn context(&self, input: &Value) -> Result<Option<String>, String> {
        let c = arg(input, "context").map(String::from);
        if c.is_none() && self.cfg.bool(SEC, "require_context") != Some(false) {
            return Err("`context` (the kube context) is required: deploys never target the ambient current-context ([integrations.deploy] require_context = false to allow it)".into());
        }
        if let Some(c) = &c {
            if c.starts_with('-') || c.contains(char::is_whitespace) {
                return Err(format!("bad context `{c}`"));
            }
            let allow = self.cfg.list(SEC, "allow_contexts");
            if !allow.is_empty() && !allow.iter().any(|g| seagent_security::glob::fnmatch(g, c)) {
                return Err(format!("context `{c}` is not in [integrations.deploy] allow_contexts"));
            }
        }
        Ok(c)
    }
    fn file(&self, input: &Value, key: &str) -> Result<PathBuf, String> {
        let raw = arg(input, key).ok_or_else(|| format!("`{key}` is required"))?;
        let p = self.ctx.resolve(raw);
        if !p.exists() {
            return Err(format!("{key} `{}` does not exist", p.display()));
        }
        Ok(p)
    }
}

fn name_ok(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.len() <= 253 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@:/".contains(c))
}

/// The dry-run / read commands of a plan and whether all of them passed.
struct Checks {
    list: Vec<Value>,
    ok: bool,
}

impl Default for Checks {
    fn default() -> Checks {
        Checks { list: vec![], ok: true }
    }
}

impl Checks {
    fn record(&mut self, a: &[String], o: &RunOut, passed: bool) {
        self.ok &= passed;
        self.list.push(json!({"command": join(a), "exit": o.code, "ok": passed, "output": crate::util::truncate_str(&o.text(), 12_000)}));
    }
    fn run(&mut self, p: &Planner, a: Vec<String>, good: &dyn Fn(&RunOut) -> bool) -> Result<RunOut, String> {
        let o = p.exec(&a)?;
        self.record(&a, &o, good(&o));
        Ok(o)
    }
}

/// Build (and dry-run) a plan. Returns the plan record.
fn make_plan(p: &Planner, input: &Value) -> Result<Value, String> {
    let kind = arg(input, "kind").ok_or("`kind` is required: kubectl, helm, compose or systemd")?;
    let id = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(8));
    let dir = plans_dir(p.ctx).join(&id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create plan dir: {e}"))?;
    let mut ck = Checks::default();
    let (target, summary, apply, rollback, rollback_note, inputs): (String, String, Vec<String>, Vec<String>, String, Vec<PathBuf>);
    match kind {
        "kubectl" => {
            let bin = p.bin("kubectl", "kubectl");
            let ctxn = p.context(input)?;
            let m = p.file(input, "manifest")?;
            let mut base = vec![bin];
            if let Some(c) = &ctxn {
                base.extend(["--context".into(), c.clone()]);
            }
            let ns = arg(input, "namespace");
            if let Some(n) = ns {
                if !name_ok(n) {
                    return Err(format!("bad namespace `{n}`"));
                }
                base.extend(["-n".into(), n.into()]);
            }
            let ms = m.to_string_lossy().to_string();
            let with = |extra: &[&str]| -> Vec<String> { base.iter().cloned().chain(extra.iter().map(|s| s.to_string())).collect() };
            // kubectl diff: 0 = no change, 1 = changes, >1 = error.
            ck.run(p, with(&["diff", "-f", &ms]), &|o| matches!(o.code, Some(0) | Some(1)))?;
            ck.run(p, with(&["apply", "--dry-run=server", "-f", &ms]), &|o| o.ok())?;
            let snap = p.exec(&with(&["get", "-f", &ms, "-o", "yaml", "--ignore-not-found"]))?;
            let before = dir.join("before.yaml");
            let had = snap.ok() && snap.stdout.contains("kind:");
            if had {
                std::fs::write(&before, strip_server_fields(&snap.stdout)).map_err(|e| format!("cannot save snapshot: {e}"))?;
            }
            target = format!("kube:{}/{}", ctxn.as_deref().unwrap_or("current-context"), ns.unwrap_or("default"));
            summary = format!("kubectl apply -f {} on {target}", m.display());
            apply = with(&["apply", "-f", &ms]);
            rollback = if had { with(&["apply", "-f", &before.to_string_lossy()]) } else { vec![] };
            rollback_note = if had {
                format!("re-applies the live objects captured before the change ({}); objects this change creates are not deleted by the rollback", before.display())
            } else {
                "none of the objects exist yet, so there is nothing to restore; undoing means deleting them (`kubectl delete -f`, tier 3, ask the owner)".into()
            };
            inputs = vec![m];
        }
        "helm" => {
            let bin = p.bin("helm", "helm");
            let ctxn = p.context(input)?;
            let release = arg(input, "release").filter(|r| name_ok(r)).ok_or("`release` is required (helm release name)")?.to_string();
            let chart = arg(input, "chart").filter(|c| name_ok(c)).ok_or("`chart` is required (repo/chart, OCI ref or a local path)")?.to_string();
            let mut base = vec![bin];
            if let Some(c) = &ctxn {
                base.extend(["--kube-context".into(), c.clone()]);
            }
            let ns = arg(input, "namespace");
            if let Some(n) = ns {
                if !name_ok(n) {
                    return Err(format!("bad namespace `{n}`"));
                }
                base.extend(["-n".into(), n.into()]);
            }
            let mut opts: Vec<String> = vec![];
            if let Some(v) = arg(input, "version") {
                opts.extend(["--version".into(), v.into()]);
            }
            let mut files = vec![];
            for f in arg_list(input, "values") {
                let fp = p.ctx.resolve(&f);
                if !fp.is_file() {
                    return Err(format!("values file `{}` does not exist", fp.display()));
                }
                opts.extend(["-f".into(), fp.to_string_lossy().into()]);
                files.push(fp);
            }
            for s in arg_list(input, "set") {
                if s.starts_with('-') || !s.contains('=') {
                    return Err(format!("bad --set `{s}` (key=value)"));
                }
                opts.extend(["--set".into(), s]);
            }
            let cmd = |head: &[&str], tail: &[&str]| -> Vec<String> {
                base.iter().cloned().chain(head.iter().map(|s| s.to_string())).chain([release.clone(), chart.clone()]).chain(opts.iter().cloned()).chain(tail.iter().map(|s| s.to_string())).collect()
            };
            let hist = p.exec(&base.iter().cloned().chain(["history".into(), release.clone(), "-o".into(), "json".into(), "--max".into(), "1".into()]).collect::<Vec<_>>())?;
            let current: Option<u64> = if hist.ok() { serde_json::from_str::<Value>(&hist.stdout).ok().and_then(|v| v.as_array()?.last()?.get("revision")?.as_u64()) } else { None };
            // `helm diff` is a plugin; without it the server-side dry-run still renders and validates.
            let diff = p.exec(&cmd(&["diff", "upgrade", "--install"], &[]))?;
            if diff.ok() {
                ck.record(&cmd(&["diff", "upgrade", "--install"], &[]), &diff, true);
            }
            ck.run(p, cmd(&["upgrade", "--install"], &["--dry-run=server"]), &|o| o.ok())?;
            target = format!("helm:{}/{}/{release}", ctxn.as_deref().unwrap_or("current-context"), ns.unwrap_or("default"));
            summary = format!("helm upgrade --install {release} {chart} on {target}");
            apply = cmd(&["upgrade", "--install"], &["--atomic", "--wait", "--timeout", "10m0s"]);
            match current {
                Some(rev) => {
                    rollback = base.iter().cloned().chain(["rollback".into(), release.clone(), rev.to_string(), "--wait".into()]).collect();
                    rollback_note = format!("returns {release} to revision {rev}, the one deployed when this plan was made");
                }
                None => {
                    rollback = vec![];
                    rollback_note = format!("{release} is not installed yet; undoing the first install is `helm uninstall {release}` (ask the owner)");
                }
            }
            inputs = files;
        }
        "compose" => {
            let engine = if p.cfg.str(SEC, "compose_engine").as_deref() == Some("podman") { p.bin("podman", "podman") } else { p.bin("docker", "docker") };
            let f = p.file(input, "file")?;
            let mut base = vec![engine.clone(), "compose".into(), "-f".into(), f.to_string_lossy().into()];
            let project = arg(input, "project");
            let mut proj = vec![];
            if let Some(pr) = project {
                if !name_ok(pr) {
                    return Err(format!("bad project `{pr}`"));
                }
                proj = vec!["-p".to_string(), pr.to_string()];
            }
            let services = arg_list(input, "services");
            if let Some(s) = services.iter().find(|s| !name_ok(s)) {
                return Err(format!("bad service `{s}`"));
            }
            let with = |b: &[String], extra: &[&str], svc: bool| -> Vec<String> {
                b.iter().cloned().chain(proj.iter().cloned()).chain(extra.iter().map(|s| s.to_string())).chain(if svc { services.clone() } else { vec![] }).collect()
            };
            ck.run(p, with(&base, &["config", "--quiet"], false), &|o| o.ok())?;
            ck.run(p, with(&base, &["config", "--images"], false), &|o| o.ok())?;
            // Running containers → their exact image ids, pinned in a rollback override.
            let ps = p.exec(&with(&base, &["ps", "--format", "json"], false))?;
            let rows: Vec<Value> = ps.stdout.lines().filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok()).flat_map(|v| if let Value::Array(a) = v { a } else { vec![v] }).collect();
            let mut pins: Vec<(String, String)> = vec![];
            for r in &rows {
                let (Some(svc), Some(cid)) = (r["Service"].as_str(), r["ID"].as_str()) else { continue };
                let insp = p.exec(&[engine.clone(), "inspect".into(), "--format".into(), "{{.Image}}".into(), cid.into()])?;
                let img = insp.stdout.trim();
                if insp.ok() && !img.is_empty() && !pins.iter().any(|(s, _)| s == svc) {
                    pins.push((svc.to_string(), img.to_string()));
                }
            }
            target = format!("compose:{}", project.map(String::from).unwrap_or_else(|| f.display().to_string()));
            summary = format!("{} up -d {}", join(&with(&base, &[], false)), services.join(" "));
            apply = with(&base, &["up", "-d"], true);
            if pins.is_empty() {
                rollback = vec![];
                rollback_note = "no running containers were found, so there is no previous state to return to".into();
            } else {
                let over = dir.join("rollback.override.yml");
                let mut y = String::from("# seagent deploy rollback: images running before the change\nservices:\n");
                for (s, i) in &pins {
                    y.push_str(&format!("  {s}:\n    image: {i}\n"));
                }
                std::fs::write(&over, y).map_err(|e| format!("cannot save rollback override: {e}"))?;
                base.extend(["-f".into(), over.to_string_lossy().into()]);
                rollback = with(&base, &["up", "-d"], true);
                rollback_note = format!("recreates {} with the image ids that were running before ({})", pins.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>().join(", "), over.display());
            }
            inputs = vec![f];
        }
        "systemd" => {
            let bin = p.bin("systemctl", "systemctl");
            let unit = arg(input, "unit").filter(|u| name_ok(u)).ok_or("`unit` is required")?.to_string();
            let op = arg(input, "operation").unwrap_or("restart");
            if !["restart", "reload", "start", "stop", "try-restart", "reload-or-restart"].contains(&op) {
                return Err(format!("operation `{op}`: use restart, reload, reload-or-restart, try-restart, start or stop"));
            }
            let mut base = vec![bin];
            if input.get("user").and_then(Value::as_bool) == Some(true) {
                base.push("--user".into());
            }
            let with = |extra: &[&str]| -> Vec<String> { base.iter().cloned().chain(extra.iter().map(|s| s.to_string())).collect() };
            let show = ck.run(p, with(&["show", &unit, "-p", "LoadState,ActiveState,SubState,MainPID,FragmentPath,NeedDaemonReload,ExecMainStartTimestamp"]), &|o| o.ok() && !o.stdout.contains("LoadState=not-found"))?;
            ck.run(p, with(&["status", &unit, "--no-pager", "--lines", "20"]), &|o| matches!(o.code, Some(0) | Some(3)))?;
            let active = show.stdout.lines().find_map(|l| l.strip_prefix("ActiveState=")).unwrap_or("").trim().to_string();
            target = format!("systemd:{}{unit}", if base.len() > 1 { "user/" } else { "" });
            summary = format!("systemctl {op} {unit} (now {active})");
            apply = with(&[op, &unit]);
            (rollback, rollback_note) = match (op, active.as_str()) {
                ("stop", "active") => (with(&["start", &unit]), format!("starts {unit} again")),
                ("start", "inactive") | ("start", "failed") => (with(&["stop", &unit]), format!("stops {unit} again")),
                _ => (vec![], format!("a {op} has no prior state to restore; if the unit misbehaves afterwards, roll back what changed it (package, config) and restart")),
            };
            inputs = vec![];
        }
        other => return Err(format!("unknown kind `{other}`: use kubectl, helm, compose or systemd")),
    }
    let now = now_unix();
    let ttl = p.cfg.u64(SEC, "plan_ttl_minutes").unwrap_or(60).clamp(1, 7 * 24 * 60) as i64 * 60;
    Ok(json!({
        "id": id, "kind": kind, "target": target, "summary": summary, "ok": ck.ok, "status": if ck.ok { "planned" } else { "plan_failed" },
        "created": now, "expires": now + ttl, "reason": arg(input, "reason"),
        "inputs": inputs.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(), "inputs_hash": inputs_hash(&inputs),
        "apply": apply, "rollback": rollback, "rollback_note": rollback_note, "checks": ck.list, "session": p.ctx.session_id,
    }))
}

fn render_plan(plan: &Value) -> String {
    let mut s = format!(
        "plan_id: {}\ntarget: {}\nchange: {}\nstatus: {}\nexpires: {}\n\napply (runs only with action=apply plan_id={}; the approval gate decides):\n  {}\n\nprepared rollback:\n  {}\n  ({})\n",
        plan["id"].as_str().unwrap_or(""),
        plan["target"].as_str().unwrap_or(""),
        plan["summary"].as_str().unwrap_or(""),
        plan["status"].as_str().unwrap_or(""),
        rfc3339(plan["expires"].as_i64().unwrap_or(0)),
        plan["id"].as_str().unwrap_or(""),
        join(&argv(&plan["apply"])),
        if argv(&plan["rollback"]).is_empty() { "(none)".to_string() } else { join(&argv(&plan["rollback"])) },
        plan["rollback_note"].as_str().unwrap_or("")
    );
    for c in plan["checks"].as_array().into_iter().flatten() {
        s.push_str(&format!("\n$ {}  [exit {}{}]\n{}\n", c["command"].as_str().unwrap_or(""), c["exit"], if c["ok"] == true { "" } else { ", FAILED" }, c["output"].as_str().unwrap_or("")));
    }
    s
}

impl Deploy {
    fn planner<'a>(&'a self, ctx: &'a ToolCtx, apply: bool) -> Planner<'a> {
        let t = self.cfg.u64(SEC, "timeout_seconds").unwrap_or(if apply { 600 } else { 180 }).clamp(5, 3600);
        Planner { cfg: &self.cfg, ctx, timeout: Duration::from_secs(t) }
    }

    /// The plan an apply / rollback would run, after every refusal check.
    fn runnable(&self, ctx: &ToolCtx, input: &Value, rollback: bool) -> Result<(Value, Vec<String>), String> {
        let id = arg(input, "plan_id").ok_or("`plan_id` is required (from action=plan)")?;
        let plan = load(ctx, id)?;
        let status = plan["status"].as_str().unwrap_or("");
        if rollback {
            let a = argv(&plan["rollback"]);
            if a.is_empty() {
                return Err(format!("plan {id} has no prepared rollback: {}", plan["rollback_note"].as_str().unwrap_or("")));
            }
            if !matches!(status, "applied" | "apply_failed") {
                return Err(format!("plan {id} is `{status}`: only an applied (or failed) change is rolled back"));
            }
            return Ok((plan, a));
        }
        match status {
            "planned" => {}
            "plan_failed" => return Err(format!("plan {id} failed its dry-run; fix the errors it showed and plan again")),
            s => return Err(format!("plan {id} is already `{s}`; plan again for a new change")),
        }
        if plan["expires"].as_i64().unwrap_or(0) < now_unix() {
            return Err(format!("plan {id} expired; plan again so the diff reflects the current state"));
        }
        let inputs: Vec<PathBuf> = plan["inputs"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(PathBuf::from)).collect();
        if inputs_hash(&inputs) != plan["inputs_hash"].as_str().unwrap_or("") {
            return Err(format!("the files of plan {id} changed after the dry-run; plan again"));
        }
        Ok((plan.clone(), argv(&plan["apply"])))
    }

    fn execute(&self, ctx: &ToolCtx, input: &Value, rollback: bool) -> ToolOutput {
        let (mut plan, cmd) = match self.runnable(ctx, input, rollback) {
            Ok(x) => x,
            Err(e) => return ToolOutput::err(e),
        };
        let kind = if rollback { "deploy.rollback" } else { "deploy.apply" };
        let p = self.planner(ctx, true);
        let out = match p.exec(&cmd) {
            Ok(o) => o,
            Err(e) => {
                audit(ctx, kind, &plan, "error", json!({"error": e}));
                return ToolOutput::err(e);
            }
        };
        let ok = out.ok();
        plan["status"] = json!(match (rollback, ok) {
            (false, true) => "applied",
            (false, false) => "apply_failed",
            (true, true) => "rolled_back",
            (true, false) => "rollback_failed",
        });
        plan[if rollback { "rolled_back_at" } else { "applied_at" }] = json!(now_unix());
        plan[if rollback { "rollback_exit" } else { "apply_exit" }] = json!(out.code);
        let _ = save(ctx, &plan);
        audit(ctx, kind, &plan, if ok { "ok" } else { "error" }, json!({"exit": out.code, "command": join(&cmd), "timed_out": out.timed_out}));
        let id = plan["id"].as_str().unwrap_or("");
        let next = match (rollback, ok, argv(&plan["rollback"]).is_empty()) {
            (false, true, false) => format!("Verify the change (alerts, error rate, rollout status). If it misbehaves: action=rollback plan_id={id}."),
            (false, false, false) => format!("The apply failed. Inspect the output; action=rollback plan_id={id} restores the previous state."),
            (false, _, true) => format!("No automatic rollback exists for this change: {}", plan["rollback_note"].as_str().unwrap_or("")),
            (true, true, _) => "Rolled back. Confirm recovery with the monitoring tools and record the incident timeline.".into(),
            (true, false, _) => "The rollback failed: escalate to a human now with this output.".into(),
        };
        let text = format!("{} {} ({}) exit {:?}\n$ {}\n{}\n\n{next}", if rollback { "rollback" } else { "apply" }, if ok { "succeeded" } else { "FAILED" }, plan["target"].as_str().unwrap_or(""), out.code, join(&cmd), crate::util::truncate_str(&out.text(), 16_000));
        if ok { ToolOutput::ok(text) } else { ToolOutput::err(text) }
    }
}

impl Tool for Deploy {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "deploy".into(),
            description: "Controlled deploy / rollback for kubectl, helm, docker compose and systemd units. action=plan first: dry-run + diff only, snapshots the current state and prepares the rollback; returns plan_id. action=apply plan_id=… runs exactly that plan (goes through the normal approval tiers; refuses stale or changed plans). action=rollback plan_id=… runs the prepared rollback. action=history lists recent plans; action=show plan_id=… shows one. Every step is written to the audit log.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["plan","apply","rollback","history","show"]},
                "kind":{"type":"string","enum":["kubectl","helm","compose","systemd"]},
                "plan_id":{"type":"string"},
                "context":{"type":"string","description":"kube context (kubectl/helm); required unless the operator disabled require_context"},
                "namespace":{"type":"string"},
                "manifest":{"type":"string","description":"kubectl: file or directory for -f"},
                "release":{"type":"string"},"chart":{"type":"string"},"version":{"type":"string"},
                "values":{"type":"array","items":{"type":"string"},"description":"helm values files"},
                "set":{"type":"array","items":{"type":"string"},"description":"helm --set key=value"},
                "file":{"type":"string","description":"compose file"},"project":{"type":"string"},"services":{"type":"array","items":{"type":"string"}},
                "unit":{"type":"string"},"operation":{"type":"string","enum":["restart","reload","reload-or-restart","try-restart","start","stop"]},"user":{"type":"boolean","description":"systemctl --user"},
                "reason":{"type":"string","description":"why (ticket / incident id), kept in the audit record"}},
                "required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let action = arg(input, "action").unwrap_or("");
        match action {
            // Dry-runs and reads: the commands are declared as they will run.
            "plan" => {
                let k = arg(input, "kind").unwrap_or("");
                let c = arg(input, "context").map(|c| format!(" --context {c}")).unwrap_or_default();
                let cmd = match k {
                    "kubectl" => format!("kubectl{c} diff -f {} ; kubectl{c} apply --dry-run=server -f {}", arg(input, "manifest").unwrap_or(""), arg(input, "manifest").unwrap_or("")),
                    "helm" => format!("helm upgrade --install {} {} --dry-run=server", arg(input, "release").unwrap_or(""), arg(input, "chart").unwrap_or("")),
                    "compose" => format!("docker compose -f {} config --quiet ; docker compose ps", arg(input, "file").unwrap_or("")),
                    "systemd" => format!("systemctl show {} ; systemctl status {} --no-pager", arg(input, "unit").unwrap_or(""), arg(input, "unit").unwrap_or("")),
                    _ => return vec![],
                };
                vec![Effect::Exec { command: cmd }]
            }
            "apply" | "rollback" => match self.runnable(ctx, input, action == "rollback") {
                Ok((plan, cmd)) => vec![
                    Effect::Exec { command: join(&cmd) },
                    Effect::Net { dest: format!("deploy://{}", plan["target"].as_str().unwrap_or("")), payload: format!("{} {}: {}", action, plan["summary"].as_str().unwrap_or(""), arg(input, "reason").or(plan["reason"].as_str()).unwrap_or("")) },
                ],
                Err(_) => vec![],
            },
            _ => vec![],
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match arg(&input, "action").unwrap_or("") {
            "plan" => {
                let p = self.planner(ctx, false);
                match make_plan(&p, &input) {
                    Ok(plan) => {
                        if let Err(e) = save(ctx, &plan) {
                            return ToolOutput::err(e);
                        }
                        audit(ctx, "deploy.plan", &plan, if plan["ok"] == true { "ok" } else { "error" }, json!({"reason": plan["reason"]}));
                        let text = render_plan(&plan);
                        if plan["ok"] == true { ToolOutput::ok(text) } else { ToolOutput::err(format!("dry-run failed; nothing can be applied from this plan.\n\n{text}")) }
                    }
                    Err(e) => ToolOutput::err(e),
                }
            }
            "apply" => self.execute(ctx, &input, false),
            "rollback" => self.execute(ctx, &input, true),
            "show" => match arg(&input, "plan_id").ok_or_else(|| "`plan_id` is required".to_string()).and_then(|id| load(ctx, id)) {
                Ok(p) => ToolOutput::ok(render_plan(&p)),
                Err(e) => ToolOutput::err(e),
            },
            "history" => {
                let mut rows: Vec<Value> = std::fs::read_dir(plans_dir(ctx)).into_iter().flatten().flatten().filter_map(|e| std::fs::read_to_string(e.path().join("plan.json")).ok()).filter_map(|t| serde_json::from_str(&t).ok()).collect();
                rows.sort_by_key(|p: &Value| std::cmp::Reverse(p["created"].as_i64().unwrap_or(0)));
                let lines: Vec<String> = rows.iter().take(20).map(|p| format!("{}  {}  {:<15} {}  {}", p["id"].as_str().unwrap_or(""), rfc3339(p["created"].as_i64().unwrap_or(0)), p["status"].as_str().unwrap_or(""), p["target"].as_str().unwrap_or(""), p["summary"].as_str().unwrap_or(""))).collect();
                ToolOutput::ok(if lines.is_empty() { "no deploy plans yet".into() } else { lines.join("\n") })
            }
            other => ToolOutput::err(format!("unknown action `{other}`: use plan, apply, rollback, history or show")),
        }
    }
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[cfg(unix)]
    /// A fake CLI: logs its argv to `<dir>/calls.log` and answers from a script.
    fn fake(dir: &Path, name: &str, body: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\necho \"{name} $*\" >> {}/calls.log\n{body}\n", dir.display())).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_string_lossy().into()
    }

    fn calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
    }

    #[cfg(unix)]
    #[test]
    fn kubectl_plan_apply_rollback_round_trip_with_audit() {
        let ctx = crate::testutil::ctx("deploy-kube");
        let bin = ctx.workspace.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let kubectl = fake(&bin, "kubectl", r#"case "$*" in
  *" diff "*) echo "-replicas: 2"; echo "+replicas: 3"; exit 1;;
  *" get "*) printf 'apiVersion: v1\nkind: List\nitems:\n- kind: Deployment\n  metadata:\n    name: api\n    resourceVersion: "42"\n    uid: abc\n';;
  *) echo ok;;
esac"#);
        let m = ctx.workspace.join("deploy.yaml");
        std::fs::write(&m, "kind: Deployment\n").unwrap();
        let t = Deploy { cfg: Arc::new(Integrations::new(json!({"deploy": {"kubectl": kubectl, "allow_contexts": ["staging-*"]}}))) };
        // No context → refused (never the ambient current-context); context outside the allowlist → refused.
        assert!(t.call(&ctx, json!({"action": "plan", "kind": "kubectl", "manifest": "deploy.yaml"})).content.contains("context"));
        assert!(t.call(&ctx, json!({"action": "plan", "kind": "kubectl", "manifest": "deploy.yaml", "context": "prod-eu"})).content.contains("allow_contexts"));
        let o = t.call(&ctx, json!({"action": "plan", "kind": "kubectl", "manifest": "deploy.yaml", "context": "staging-1", "namespace": "web", "reason": "INC-7"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("+replicas: 3") && o.content.contains("prepared rollback"), "{}", o.content);
        let id = o.content.lines().next().unwrap().trim_start_matches("plan_id: ").to_string();
        let before = std::fs::read_to_string(ctx.home.join("deploy").join(&id).join("before.yaml")).unwrap();
        assert!(before.contains("name: api") && !before.contains("resourceVersion") && !before.contains("uid:"));
        // Planning ran only dry-runs and reads.
        let log = calls(&bin);
        assert!(log.contains("diff -f") && log.contains("--dry-run=server") && !log.lines().any(|l| l.contains(" apply -f")), "{log}");
        // Apply declares the exact command and a remote change (→ tier 2 in the kernel).
        let fx = t.effects(&ctx, &json!({"action": "apply", "plan_id": id}));
        assert!(matches!(&fx[0], Effect::Exec { command } if command.ends_with(&format!("--context staging-1 -n web apply -f {}", m.display()))), "{fx:?}");
        assert!(matches!(&fx[1], Effect::Net { dest, payload } if dest == "deploy://kube:staging-1/web" && payload.contains("INC-7")), "{fx:?}");
        let c = seagent_security::risk::Candidate { exec: vec![match &fx[0] { Effect::Exec { command } => command.clone(), _ => unreachable!() }], hosts: vec!["kube:staging-1".into()], payload: Some("x".into()), ..Default::default() };
        assert!(seagent_security::risk::assess(&c).tier >= seagent_security::risk::Tier::Impactful);
        // A rollback before the apply is refused; then apply; a second apply is refused.
        assert!(t.call(&ctx, json!({"action": "rollback", "plan_id": id})).is_error);
        let a = t.call(&ctx, json!({"action": "apply", "plan_id": id}));
        assert!(!a.is_error && a.content.contains("action=rollback"), "{}", a.content);
        assert!(t.call(&ctx, json!({"action": "apply", "plan_id": id})).content.contains("already `applied`"));
        let r = t.call(&ctx, json!({"action": "rollback", "plan_id": id}));
        assert!(!r.is_error, "{}", r.content);
        assert!(calls(&bin).contains(&format!("apply -f {}", ctx.home.join("deploy").join(&id).join("before.yaml").display())));
        let h = t.call(&ctx, json!({"action": "history"}));
        assert!(h.content.contains("rolled_back"), "{}", h.content);
        let kinds: Vec<String> = seagent_security::audit::all(&ctx.home).iter().map(|e| e["kind"].as_str().unwrap_or("").to_string()).collect();
        assert_eq!(kinds, ["deploy.plan", "deploy.apply", "deploy.rollback"], "{kinds:?}");
    }

    #[cfg(unix)]
    #[test]
    fn changed_files_failed_dry_runs_and_expired_plans_are_refused() {
        let ctx = crate::testutil::ctx("deploy-guard");
        let bin = ctx.workspace.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let ok = fake(&bin, "kubectl", "case \"$*\" in *\" get \"*) exit 0;; *) echo ok;; esac");
        std::fs::write(ctx.workspace.join("m.yaml"), "a").unwrap();
        let t = Deploy { cfg: Arc::new(Integrations::new(json!({"deploy": {"kubectl": ok}}))) };
        let o = t.call(&ctx, json!({"action": "plan", "kind": "kubectl", "manifest": "m.yaml", "context": "c1"}));
        assert!(o.content.contains("nothing to restore"), "{}", o.content);
        let id = o.content.lines().next().unwrap().trim_start_matches("plan_id: ").to_string();
        std::fs::write(ctx.workspace.join("m.yaml"), "b").unwrap();
        assert!(t.call(&ctx, json!({"action": "apply", "plan_id": id})).content.contains("changed after the dry-run"));
        assert!(t.effects(&ctx, &json!({"action": "apply", "plan_id": id})).is_empty());
        let mut plan = load(&ctx, &id).unwrap();
        plan["inputs_hash"] = json!(inputs_hash(&[ctx.workspace.join("m.yaml")]));
        plan["expires"] = json!(1);
        save(&ctx, &plan).unwrap();
        assert!(t.call(&ctx, json!({"action": "apply", "plan_id": id})).content.contains("expired"));
        assert!(t.call(&ctx, json!({"action": "apply", "plan_id": "../../etc"})).is_error);
        let bad = fake(&bin, "kubectl2", "echo 'error: invalid' >&2; exit 2");
        let t2 = Deploy { cfg: Arc::new(Integrations::new(json!({"deploy": {"kubectl": bad}}))) };
        let o = t2.call(&ctx, json!({"action": "plan", "kind": "kubectl", "manifest": "m.yaml", "context": "c1"}));
        assert!(o.is_error && o.content.contains("dry-run failed"), "{}", o.content);
        let id2 = o.content.lines().find(|l| l.starts_with("plan_id: ")).unwrap().trim_start_matches("plan_id: ").to_string();
        assert!(t2.call(&ctx, json!({"action": "apply", "plan_id": id2})).content.contains("failed its dry-run"));
    }

    #[cfg(unix)]
    #[test]
    fn helm_compose_and_systemd_prepare_their_rollbacks() {
        let ctx = crate::testutil::ctx("deploy-misc");
        let bin = ctx.workspace.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let helm = fake(&bin, "helm", "case \"$*\" in *history*) echo '[{\"revision\":7}]';; *\"diff upgrade\"*) echo 'plugin missing' >&2; exit 1;; *) echo rendered;; esac");
        let t = Deploy { cfg: Arc::new(Integrations::new(json!({"deploy": {"helm": helm, "docker": fake(&bin, "docker", "case \"$*\" in *\"ps --format json\"*) echo '{\"Service\":\"api\",\"ID\":\"c1\"}';; *inspect*) echo sha256:old;; *) echo ok;; esac"), "systemctl": fake(&bin, "systemctl", "case \"$*\" in *show*) echo ActiveState=active; echo LoadState=loaded;; *) echo fine;; esac")}}))) };
        let o = t.call(&ctx, json!({"action": "plan", "kind": "helm", "release": "api", "chart": "repo/api", "context": "stg", "set": ["image.tag=v2"]}));
        assert!(!o.is_error && o.content.contains("rollback api 7 --wait") && o.content.contains("--atomic"), "{}", o.content);
        std::fs::write(ctx.workspace.join("compose.yml"), "services: {api: {image: x}}").unwrap();
        let o = t.call(&ctx, json!({"action": "plan", "kind": "compose", "file": "compose.yml", "services": ["api"]}));
        assert!(!o.is_error && o.content.contains("rollback.override.yml"), "{}", o.content);
        let id = o.content.lines().next().unwrap().trim_start_matches("plan_id: ").to_string();
        let over = std::fs::read_to_string(ctx.home.join("deploy").join(&id).join("rollback.override.yml")).unwrap();
        assert!(over.contains("api:\n    image: sha256:old"), "{over}");
        let o = t.call(&ctx, json!({"action": "plan", "kind": "systemd", "unit": "nginx.service", "operation": "stop", "user": true}));
        assert!(!o.is_error && o.content.contains("--user start nginx.service"), "{}", o.content);
        assert!(t.call(&ctx, json!({"action": "plan", "kind": "systemd", "unit": "x", "operation": "mask"})).is_error);
        assert!(t.call(&ctx, json!({"action": "plan", "kind": "helm", "release": "--debug", "chart": "c", "context": "x"})).is_error);
    }
}
