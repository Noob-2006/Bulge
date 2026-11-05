//! Blueprints: shareable plain-language automations layered on skills + cron (Hermes
//! `tools/blueprints.py` + `cron/blueprint_catalog.py`, MIT).
//!
//! Two kinds, one job engine (`ark_kernel::automation` schedules):
//! - a skill whose frontmatter declares `metadata.ark.blueprint` (or `metadata.hermes.blueprint`)
//!   with a non-empty `schedule` (+ optional `prompt`, `model`, `deliver`). Installing one from
//!   the hub registers a *suggestion* (never auto-scheduled); `ark skills blueprint accept`
//!   creates the job, which loads the skill and runs the prompt.
//! - the curated catalog (`share/blueprints.json`, transcribed from Hermes): slot-filled
//!   templates (`time`, `weekdays`, `enum`, `text`) — users never type raw cron.
//!
//! `export` renders a schedule back into a SKILL.md with a blueprint block for `ark skills publish`.

use super::settings::Store;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    pub skill: String,
    pub schedule: String,
    pub deliver: String,
    pub prompt: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub enabled_toolsets: Option<Vec<String>>,
    pub no_agent: bool,
}

/// None when the skill is not a blueprint; Err when the block exists but is malformed.
pub fn parse(skill_md: &str) -> Result<Option<Spec>, String> {
    let (fm, _) = crate::yaml::frontmatter(skill_md);
    let Some(bp) = fm.pointer("/metadata/ark/blueprint").or_else(|| fm.pointer("/metadata/hermes/blueprint")) else { return Ok(None) };
    let Value::Object(b) = bp else { return Err("metadata.ark.blueprint must be a mapping".into()) };
    let schedule = b.get("schedule").map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default().trim().to_string();
    if schedule.is_empty() {
        return Err("blueprint.schedule is required and must be non-empty".into());
    }
    if b.get("enabled_toolsets").is_some_and(|t| !t.is_array()) {
        return Err("blueprint.enabled_toolsets must be a list when present".into());
    }
    Ok(Some(Spec {
        skill: fm.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string(),
        schedule,
        deliver: b.get("deliver").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("origin").to_string(),
        prompt: b.get("prompt").and_then(Value::as_str).map(String::from),
        model: b.get("model").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from),
        provider: b.get("provider").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from),
        enabled_toolsets: b.get("enabled_toolsets").and_then(Value::as_array).map(|a| a.iter().map(|t| t.as_str().map(String::from).unwrap_or_else(|| t.to_string())).collect()),
        no_agent: b.get("no_agent").and_then(Value::as_bool).unwrap_or(false),
    }))
}

/// The prompt a scheduled job runs; the skill rides the job's `skills` field, never the text
/// (Hermes `blueprint_to_job_spec`).
fn job_text(prompt: &str) -> String {
    let p = prompt.trim();
    if p.is_empty() { "Run it now and report the result.".to_string() } else { p.to_string() }
}

/// Point a freshly created job at its skills / name / delivery / no_agent (Hermes job spec).
fn wire_job(data: &std::path::Path, id: &str, name: String, deliver: &str, skills: Vec<String>, no_agent: bool) -> Result<(), String> {
    ark_kernel::automation::with_list::<ark_kernel::automation::Job, _>(&ark_kernel::automation::jobs_path(data), |v| {
        if let Some(j) = v.iter_mut().find(|j| j.id == id) {
            j.ext.skills = skills.clone();
            j.ext.name = Some(name.clone());
            j.ext.deliver = Some(deliver.to_string()).filter(|d| d != "origin");
            j.ext.no_agent = no_agent;
        }
    })
}

fn suggestions_path(st: &Store) -> std::path::PathBuf {
    st.hub().join("blueprint-suggestions.json")
}

pub fn suggestions(st: &Store) -> Vec<Value> {
    std::fs::read_to_string(suggestions_path(st)).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v.as_array().cloned()).unwrap_or_default()
}

fn save_suggestions(st: &Store, v: &[Value]) {
    let _ = std::fs::create_dir_all(st.hub());
    let _ = std::fs::write(suggestions_path(st), serde_json::to_string_pretty(v).unwrap_or_default());
}

/// Register an installed blueprint as a suggested schedule (deduped by skill + schedule;
/// a dismissed one is never re-suggested). Returns false when skipped.
pub fn suggest(st: &Store, s: &Spec) -> bool {
    if s.skill.is_empty() {
        return false;
    }
    let key = format!("blueprint:{}:{}", s.skill, s.schedule);
    let mut v = suggestions(st);
    if v.iter().any(|x| x["key"] == key.as_str()) || v.len() >= 50 {
        return false;
    }
    v.push(json!({"key": key, "skill": s.skill, "schedule": s.schedule, "deliver": s.deliver, "prompt": s.prompt, "model": s.model, "no_agent": s.no_agent, "status": "pending"}));
    save_suggestions(st, &v);
    true
}

/// Accept a pending suggestion: create the cron job. Returns the job id.
pub fn accept(st: &Store, skill: &str, ws: &std::path::Path, offset: i32) -> Result<String, String> {
    let mut v = suggestions(st);
    let i = v.iter().position(|x| x["skill"] == skill && x["status"] == "pending").ok_or_else(|| format!("no pending blueprint suggestion for `{skill}`"))?;
    let prompt = job_text(v[i]["prompt"].as_str().unwrap_or(""));
    let deliver = v[i]["deliver"].as_str().filter(|d| !d.is_empty()).unwrap_or("origin").to_string();
    let job = ark_kernel::automation::add_job(&st.data, v[i]["schedule"].as_str().unwrap_or(""), &prompt, ws, v[i]["model"].as_str().map(String::from), false, offset)?;
    wire_job(&st.data, &job.id, format!("blueprint:{skill}"), &deliver, vec![skill.to_string()], v[i]["no_agent"].as_bool().unwrap_or(false))?;
    v[i]["status"] = json!("accepted");
    v[i]["job"] = json!(job.id);
    save_suggestions(st, &v);
    Ok(job.id)
}

pub fn dismiss(st: &Store, skill: &str) -> bool {
    let mut v = suggestions(st);
    let mut hit = false;
    for x in v.iter_mut().filter(|x| x["skill"] == skill && x["status"] == "pending") {
        x["status"] = json!("dismissed");
        hit = true;
    }
    save_suggestions(st, &v);
    hit
}

/// A valid skill identifier: lowercase, non-[alnum-_] → '-', trimmed, never empty.
fn slug(name: &str) -> String {
    let s: String = name.to_lowercase().chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let t = s.trim_matches(|c| c == '-' || c == '_');
    if t.is_empty() { "shared-blueprint".into() } else { t.to_string() }
}

/// Render a schedule as a SKILL.md with a blueprint block (first body line = description).
pub fn export(name: &str, schedule: &str, prompt: &str, body: &str) -> String {
    export_with(name, schedule, prompt, body, "origin", false)
}

/// `export` carrying the job's delivery bits (Hermes `export_blueprint`: only non-defaults land).
fn export_with(name: &str, schedule: &str, prompt: &str, body: &str, deliver: &str, no_agent: bool) -> String {
    let name = slug(name);
    let body = body.trim();
    let desc = body.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| l.trim_start_matches('#').trim()).filter(|l| !l.is_empty()).map(|l| l.chars().take(200).collect::<String>()).unwrap_or_else(|| "Shared automation blueprint.".to_string());
    let body_text = if body.is_empty() { format!("# {name}\n\nShared automation blueprint.") } else { body.to_string() };
    let mut bp = json!({"schedule": schedule});
    if !prompt.trim().is_empty() {
        bp["prompt"] = json!(prompt);
    }
    if !deliver.is_empty() && deliver != "origin" {
        bp["deliver"] = json!(deliver);
    }
    if no_agent {
        bp["no_agent"] = json!(true);
    }
    let v = json!({"name": name, "description": desc, "version": "1.0.0", "license": "MIT", "metadata": {"ark": {"tags": ["blueprint", "automation"], "blueprint": bp}}});
    format!("---\n{}---\n\n{body_text}\n", crate::yaml::to_yaml(&v))
}

// ───────────── curated catalog ─────────────

pub fn catalog() -> Vec<Value> {
    let Some(d) = crate::skill::share_dir() else { return vec![] };
    std::fs::read_to_string(d.join("blueprints.json")).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v["blueprints"].as_array().cloned()).unwrap_or_default()
}

const WEEKDAY_PRESETS: &[(&str, &str)] = &[("everyday", "*"), ("weekdays", "1-5"), ("weekends", "0,6")];
const DAY_TO_DOW: &[(&str, &str)] = &[("sunday", "0"), ("monday", "1"), ("tuesday", "2"), ("wednesday", "3"), ("thursday", "4"), ("friday", "5"), ("saturday", "6")];

fn day_dow(v: &str) -> Option<String> {
    DAY_TO_DOW.iter().find(|(k, _)| k.eq_ignore_ascii_case(v.trim())).map(|(_, d)| d.to_string())
}

/// Hermes `_TIME_RE` (`^([01]?\d|2[0-3]):([0-5]\d)$`) → (hour, minute).
fn parse_time(v: &str) -> Result<(u32, u32), String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"^([01]?\d|2[0-3]):([0-5]\d)$").unwrap());
    let c = re.captures(v.trim()).ok_or_else(|| format!("invalid time '{v}' — use HH:MM (24h)"))?;
    Ok((c[1].parse().unwrap_or(0), c[2].parse().unwrap_or(0)))
}

/// Fill `schedule_template` (Hermes `_resolve_schedule`): a literal `schedule` slot wins,
/// `time` → {hour}/{minute}, `recurrence`/`day` → {dow}, every other `{slot}` verbatim.
fn resolve_schedule(t: &str, vals: &BTreeMap<String, String>) -> Result<String, String> {
    if let Some(s) = vals.get("schedule").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        return Ok(s.to_string());
    }
    let mut repl = vals.clone();
    if t.contains("{minute}") || t.contains("{hour}") {
        let tv = vals.get("time").map(|v| v.trim()).filter(|v| !v.is_empty()).ok_or("a time is required")?;
        let (h, m) = parse_time(tv)?;
        repl.insert("hour".into(), h.to_string());
        repl.insert("minute".into(), m.to_string());
    }
    if t.contains("{dow}") && !repl.contains_key("dow") {
        let dow = match vals.get("recurrence").map(|v| v.trim().to_lowercase()).filter(|v| !v.is_empty()) {
            Some(rec) => WEEKDAY_PRESETS.iter().find(|(k, _)| k.eq_ignore_ascii_case(&rec)).map(|(_, v)| v.to_string()).or_else(|| day_dow(&rec)).ok_or_else(|| format!("unknown recurrence '{rec}' — one of everyday, weekdays, weekends"))?,
            None => match vals.get("day").map(|v| v.trim().to_lowercase()).filter(|v| !v.is_empty()) {
                Some(day) => day_dow(&day).ok_or_else(|| format!("unknown day '{day}'"))?,
                None => "*".into(),
            },
        };
        repl.insert("dow".into(), dow);
    }
    fill_template(t, &repl)
}

fn fill_template(t: &str, vals: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let j = rest[i..].find('}').ok_or("unbalanced template")? + i;
        let k = &rest[i + 1..j];
        out.push_str(vals.get(k).ok_or_else(|| format!("blueprint template missing value for {k}"))?);
        rest = &rest[j + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// A validated, slot-filled catalog blueprint (Hermes `fill_blueprint` job-spec fields).
#[derive(Debug, Clone, PartialEq)]
pub struct Filled {
    pub title: String,
    pub schedule: String,
    pub prompt: String,
    pub deliver: String,
    pub skills: Vec<String>,
}

/// Validate slot values and return the resolved job fields.
pub fn fill(bp: &Value, values: &BTreeMap<String, String>) -> Result<Filled, String> {
    let slots = bp["slots"].as_array().cloned().unwrap_or_default();
    let known: Vec<&str> = slots.iter().filter_map(|s| s["name"].as_str()).collect();
    let unknown: Vec<&String> = values.keys().filter(|k| !known.contains(&k.as_str())).collect();
    if !unknown.is_empty() {
        return Err(format!("unknown slot{}: {} — valid: {}", if unknown.len() > 1 { "s" } else { "" }, unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "), known.join(", ")));
    }
    let mut r: BTreeMap<String, String> = BTreeMap::new();
    for s in &slots {
        let n = s["name"].as_str().unwrap_or("");
        let raw = values.get(n).cloned().or_else(|| match &s["default"] {
            Value::Null => None,
            Value::String(x) => Some(x.clone()),
            other => Some(other.to_string()),
        });
        let Some(raw) = raw.filter(|x| !x.is_empty()) else {
            if s["optional"].as_bool() == Some(true) {
                r.insert(n.into(), String::new());
                continue;
            }
            return Err(format!("missing required value: {n} ({})", s["label"].as_str().unwrap_or(n)));
        };
        let opts: Vec<String> = s["options"].as_array().map(|a| a.iter().map(|o| o.as_str().map(String::from).unwrap_or_else(|| o.to_string())).collect()).unwrap_or_default();
        if s["type"] == "enum" && s["strict"].as_bool() != Some(false) && !opts.is_empty() && !opts.contains(&raw) {
            return Err(format!("{n}={raw:?} not allowed — one of {}", opts.join(", ")));
        }
        let low = raw.trim().to_lowercase();
        // `time` is validated by `resolve_schedule` (upstream `_TIME_RE`), not here.
        if let Some("weekdays") = s["type"].as_str() {
            // A declared preset set (`options`) is closed for user input, exactly like upstream
            // `_resolve_schedule`; catalog defaults may still be a full weekday name
            // (`competitor-watch`'s `monday`), and a raw cron day set still passes (ark legacy).
            let (closed, given) = (s["strict"].as_bool() != Some(false) && !opts.is_empty(), values.contains_key(n));
            let dow = if let Some((_, v)) = WEEKDAY_PRESETS.iter().find(|(k, _)| k.eq_ignore_ascii_case(&low)) {
                v.to_string()
            } else if !closed || !given {
                day_dow(&low).ok_or_else(|| if given { format!("unknown recurrence '{low}' — one of everyday, weekdays, weekends") } else { format!("unknown day '{raw}'") })?
            } else if low.chars().all(|c| c.is_ascii_digit() || matches!(c, ',' | '-' | '*')) {
                low.clone()
            } else {
                return Err(format!("unknown recurrence '{low}' — one of everyday, weekdays, weekends"));
            };
            r.insert("dow".into(), dow);
        }
        r.insert(n.into(), raw);
    }
    let schedule = resolve_schedule(bp["schedule_template"].as_str().unwrap_or(""), &r)?;
    ark_kernel::cron::Cron::parse(&schedule)?;
    let prompt = fill_template(bp["prompt_template"].as_str().unwrap_or(""), &r)?;
    let deliver = r.get("deliver").map(String::as_str).filter(|d| !d.is_empty()).map(String::from)
        .or_else(|| bp["deliver_default"].as_str().map(str::trim).filter(|d| !d.is_empty()).map(String::from)).unwrap_or_else(|| "origin".into());
    let skills = bp["skills"].as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
    Ok(Filled { title: bp["title"].as_str().unwrap_or("").to_string(), schedule, prompt, deliver, skills })
}

/// `ark skills blueprint list|show|create|suggestions|accept|dismiss|export`.
pub fn cli(st: &Store, ws: &std::path::Path, offset: i32, argv: &[String]) -> Result<String, String> {
    let sub = argv.first().map(String::as_str).unwrap_or("list");
    match sub {
        "list" => Ok(catalog().iter().map(|b| format!("{:<22} {:<10} {}", b["key"].as_str().unwrap_or(""), b["category"].as_str().unwrap_or(""), b["description"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n")),
        "show" => {
            let k = argv.get(1).ok_or("usage: ark skills blueprint show <key>")?;
            let b = catalog().into_iter().find(|b| b["key"] == k.as_str()).ok_or_else(|| format!("no blueprint `{k}`"))?;
            let slots: Vec<String> = b["slots"].as_array().into_iter().flatten().map(|s| format!("  {}={} ({}){}", s["name"].as_str().unwrap_or(""), s["default"], s["label"].as_str().unwrap_or(""), if s["optional"].as_bool() == Some(true) { " optional" } else { "" })).collect();
            Ok(format!("{} — {}\nschedule: {}\nslots:\n{}", b["title"].as_str().unwrap_or(""), b["description"].as_str().unwrap_or(""), b["schedule_template"].as_str().unwrap_or(""), slots.join("\n")))
        }
        "create" => {
            let k = argv.get(1).ok_or("usage: ark skills blueprint create <key> [slot=value …]")?;
            let b = catalog().into_iter().find(|b| b["key"] == k.as_str()).ok_or_else(|| format!("no blueprint `{k}`"))?;
            let vals: BTreeMap<String, String> = argv[2..].iter().filter_map(|a| a.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect();
            let f = fill(&b, &vals)?;
            // Named after the blueprint key (upstream names the job after the blueprint, not the skill it loads).
            let name = format!("blueprint:{k}");
            let job = ark_kernel::automation::add_job(&st.data, &f.schedule, &job_text(&f.prompt), ws, None, false, offset)?;
            wire_job(&st.data, &job.id, name, &f.deliver, f.skills.clone(), b["no_agent"].as_bool().unwrap_or(false))?;
            Ok(format!("created schedule {} \"{}\" ({})", job.id, f.title, f.schedule))
        }
        "suggestions" => Ok(suggestions(st).iter().map(|s| format!("{:<10} {:<24} {} {}", s["status"].as_str().unwrap_or(""), s["skill"].as_str().unwrap_or(""), s["schedule"].as_str().unwrap_or(""), s["job"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n")),
        "accept" => accept(st, argv.get(1).ok_or("usage: ark skills blueprint accept <skill>")?, ws, offset).map(|id| format!("scheduled {id}")),
        "dismiss" => Ok(if dismiss(st, argv.get(1).ok_or("usage: ark skills blueprint dismiss <skill>")?) { "dismissed".into() } else { "nothing pending".into() }),
        "export" => {
            let id = argv.get(1).ok_or("usage: ark skills blueprint export <job-id> [name]")?;
            let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&st.data))?;
            let j = jobs.iter().find(|j| j.id == *id).ok_or_else(|| format!("no schedule `{id}`"))?;
            let name = argv.get(2).cloned().unwrap_or_else(|| format!("blueprint-{}", &j.id[..j.id.len().min(8)]));
            Ok(export_with(&name, &j.cron, &j.prompt, &j.prompt, j.ext.deliver.as_deref().unwrap_or("origin"), j.ext.no_agent))
        }
        other => Err(format!("unknown blueprint subcommand `{other}` (list, show, create, suggestions, accept, dismiss, export)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_suggest_accept_fill_export() {
        let md = "---\nname: daily-digest\ndescription: d\nmetadata:\n  hermes:\n    blueprint:\n      schedule: \"0 8 * * *\"\n      prompt: Summarize news\n---\nbody";
        let s = parse(md).unwrap().unwrap();
        assert_eq!((s.skill.as_str(), s.schedule.as_str(), s.deliver.as_str(), s.prompt.as_deref()), ("daily-digest", "0 8 * * *", "origin", Some("Summarize news")));
        assert_eq!((s.provider.as_deref(), s.enabled_toolsets.as_ref(), s.no_agent), (None, None, false));
        assert!(parse("---\nname: x\n---\n").unwrap().is_none());
        assert!(parse("---\nname: x\nmetadata:\n  ark:\n    blueprint:\n      prompt: p\n---\n").unwrap_err().contains("schedule is required"));
        let d = ark_core::tmp::scratch_path(format!("ark-bp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("ws")).unwrap();
        let st = Store::at(&d);
        assert!(suggest(&st, &s) && !suggest(&st, &s), "deduped");
        let id = accept(&st, "daily-digest", &d.join("ws"), 0).unwrap();
        let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&st.data)).unwrap();
        assert!(jobs.iter().any(|j| j.id == id && j.cron == "0 8 * * *" && j.prompt == "Summarize news" && j.ext.skills == vec!["daily-digest".to_string()] && j.ext.name.as_deref() == Some("blueprint:daily-digest") && j.ext.deliver.is_none()));
        assert!(accept(&st, "daily-digest", &d.join("ws"), 0).is_err());
        let bps = catalog();
        assert!(bps.len() >= 10, "catalog shipped");
        let mb = bps.iter().find(|b| b["key"] == "morning-brief").unwrap();
        let f = fill(mb, &BTreeMap::from([("time".to_string(), "07:15".to_string())])).unwrap();
        assert_eq!((f.schedule.as_str(), f.skills.as_slice(), f.deliver.as_str()), ("15 7 * * *", &["google-workspace".to_string()][..], "origin"));
        assert!(fill(mb, &BTreeMap::from([("tiem".to_string(), "07:15".to_string())])).unwrap_err().contains("unknown slot"));
        assert!(fill(mb, &BTreeMap::from([("time".to_string(), "25:00".to_string())])).is_err());
        let out = cli(&st, &d.join("ws"), 0, &["create".into(), "morning-brief".into(), "time=06:30".into()]).unwrap();
        assert!(out.contains("30 6 * * *"), "{out}");
        let e = export("my-bp", "0 9 * * 1", "Do the thing", "# Weekly thing\nmore");
        let back = parse(&e).unwrap().unwrap();
        assert_eq!((back.skill.as_str(), back.schedule.as_str(), back.prompt.as_deref()), ("my-bp", "0 9 * * 1", Some("Do the thing")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn slots_deliver_and_job_wiring() {
        let bps = catalog();
        let wr = bps.iter().find(|b| b["key"] == "weekly-review").unwrap();
        let f = fill(wr, &BTreeMap::from([("day".to_string(), "monday".to_string())])).unwrap();
        assert_eq!((f.schedule.as_str(), f.deliver.as_str()), ("0 18 * * 1", "origin"), "dow from the day slot + default 18:00");
        let mp = bps.iter().find(|b| b["key"] == "meal-plan").unwrap();
        assert_eq!(fill(mp, &BTreeMap::new()).unwrap().schedule, "0 17 * * 0", "default day=sunday");
        let cw = bps.iter().find(|b| b["key"] == "competitor-watch").unwrap();
        assert_eq!(fill(cw, &BTreeMap::new()).unwrap().schedule, "0 9 * * 1", "catalog default recurrence=monday");
        let open = serde_json::json!({"title": "Open", "schedule_template": "{minute} {hour} * * {dow}", "prompt_template": "go", "slots": [{"name": "time", "type": "time", "label": "t", "default": "08:00"}, {"name": "recurrence", "type": "weekdays", "label": "r", "default": "everyday"}], "skills": []});
        assert_eq!(fill(&open, &BTreeMap::from([("recurrence".to_string(), "monday".to_string())])).unwrap().schedule, "0 8 * * 1", "weekday name -> dow when the slot has no closed set");
        assert_eq!(fill(&open, &BTreeMap::new()).unwrap().schedule, "0 8 * * *", "everyday -> *");
        let e = fill(cw, &BTreeMap::from([("recurrence".to_string(), "tuesday".to_string())])).unwrap_err();
        assert!(e.contains("unknown recurrence 'tuesday' — one of everyday, weekdays, weekends"), "{e}");
        let e = fill(wr, &BTreeMap::from([("day".to_string(), "tuesday".to_string())])).unwrap_err();
        assert!(e.contains("tuesday"), "{e}");
        for t in ["25:00", "7:5"] {
            let e = fill(mp, &BTreeMap::from([("time".to_string(), t.to_string())])).unwrap_err();
            assert!(e.contains("invalid time") && e.contains(t), "{e}");
        }
        assert_eq!(fill(mp, &BTreeMap::from([("deliver".to_string(), "slack-dm".to_string())])).unwrap().deliver, "slack-dm", "strict=false");
        let d = ark_core::tmp::scratch_path(format!("ark-bp2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("ws")).unwrap();
        let st = Store::at(&d);
        let out = cli(&st, &d.join("ws"), 0, &["create".into(), "morning-brief".into(), "time=06:30".into(), "deliver=telegram".into()]).unwrap();
        assert!(out.contains("30 6 * * *"), "{out}");
        let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&st.data)).unwrap();
        let j = jobs.iter().find(|j| j.cron == "30 6 * * *").expect("job stored");
        assert_eq!(j.ext.skills, vec!["google-workspace".to_string()]);
        assert_eq!(j.ext.name.as_deref(), Some("blueprint:morning-brief"));
        assert_eq!(j.ext.deliver.as_deref(), Some("telegram"));
        assert!(!j.ext.no_agent);
        assert!(j.prompt.contains("concise morning briefing") && !j.prompt.contains("Load the `"), "{}", j.prompt);
        let e = export("My Bp!", "0 9 * * 1", "", "# Weekly thing\nmore");
        assert!(e.starts_with("---"), "{e}");
        for want in ["name: my-bp", "version", "license", "tags"] {
            assert!(e.contains(want), "{want} missing in {e}");
        }
        assert!(!e.contains("deliver:") && !e.contains("prompt:"), "{e}");
        let back = parse(&e).unwrap().unwrap();
        assert_eq!((back.skill.as_str(), back.schedule.as_str(), back.prompt.as_deref(), back.deliver.as_str()), ("my-bp", "0 9 * * 1", None, "origin"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Every shipped blueprint must fill from its own defaults into a runnable cron schedule
    /// (Hermes `fill_blueprint` over the whole `CATALOG`).
    #[test]
    fn every_catalog_blueprint_fills_with_its_defaults() {
        let bps = catalog();
        assert!(bps.len() >= 18, "share/blueprints.json carries the whole catalog");
        for key in ["incident-triage", "vuln-triage"] {
            assert!(bps.iter().any(|b| b["key"] == key), "{key}: the DevOps / SecOps example flows (pro-013, pro-029)");
        }
        for b in &bps {
            let f = fill(b, &BTreeMap::new()).unwrap_or_else(|e| panic!("{}: {e}", b["key"]));
            assert!(ark_kernel::cron::Cron::parse(&f.schedule).is_ok(), "{}: {} is not a cron", b["key"], f.schedule);
            assert!(!f.prompt.trim().is_empty() && f.deliver == "origin", "{}: {f:?}", b["key"]);
            let with = fill(b, &BTreeMap::from([("deliver".to_string(), "telegram".to_string())])).unwrap();
            assert_eq!(with.deliver, "telegram", "{}", b["key"]);
        }
    }
}
