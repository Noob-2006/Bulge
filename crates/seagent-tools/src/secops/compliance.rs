//! `compliance_check` (pro-031): executable compliance checklists. Built-in lists: `cis-linux`
//! (a CIS-style Linux host baseline) and `tw-csma` (資通安全管理法 對照: the 資通系統防護基準
//! seven control families plus the organisational evidence items). Operators add their own
//! TOML lists through `[integrations.secops] checklists = ["…"]` or the `checklist` argument.
//!
//! Every technical check runs a fixed argv (no shell) from a short allowlist of read-only
//! programs — `cat`, `grep`, `stat`, `sysctl` (read form only), `findmnt`, `pgrep`, `getent`,
//! `timedatectl show`, `ls`, `dpkg-query`, `rpm -q` — on the local host, with a timeout. Nothing
//! is elevated: an unreadable input is `skip`, never a guessed `pass`. The commands are
//! declared to the gates as one `Exec` effect, so the whole checklist is one decision.

use crate::ops::run::{join, run};
use crate::ops::{arg, arg_list, cap_output, Integrations};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use regex::RegexBuilder;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(windows))]
pub const BUILTIN: &[(&str, &str)] = &[("cis-linux", include_str!("checklists/cis-linux.toml")), ("tw-csma", include_str!("checklists/tw-csma.toml"))];
/// Windows adds `cis-windows` (registry / `net` / `netsh` / `sc` / `auditpol` reads); it is the
/// default list there.
#[cfg(windows)]
pub const BUILTIN: &[(&str, &str)] = &[("cis-linux", include_str!("checklists/cis-linux.toml")), ("tw-csma", include_str!("checklists/tw-csma.toml")), ("cis-windows", include_str!("checklists/cis-windows.toml"))];

/// The list a call without `checklist` runs: this host's baseline.
const DEFAULT_LIST: &str = if cfg!(windows) { "cis-windows" } else { "cis-linux" };

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Check {
    pub id: String,
    pub section: String,
    pub title: String,
    pub severity: String,
    pub cmd: Vec<String>,
    pub cmds: Vec<Vec<String>>,
    pub ok_exit: Option<Vec<i32>>,
    pub on_error: Option<String>,
    #[serde(rename = "match")]
    pub match_: Option<String>,
    pub match_all: Vec<String>,
    pub not_match: Option<String>,
    pub pattern: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub max_matches: Option<usize>,
    pub mode_mask: Option<String>,
    pub first_line: bool,
    pub manual: bool,
    pub evidence: String,
    pub same_as: Option<String>,
    pub fix: String,
    pub refs: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Meta {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Checklist {
    pub meta: Meta,
    pub check: Vec<Check>,
}

/// Programs a check may run, and the argument shapes that keep them read-only.
fn allowed(argv: &[String]) -> Result<(), String> {
    let (p, args) = argv.split_first().ok_or("empty command")?;
    #[cfg(unix)]
    let name = p.rsplit('/').next().unwrap_or(p);
    #[cfg(not(unix))]
    let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
    let ok = match name {
        "cat" | "grep" | "stat" | "findmnt" | "pgrep" | "getent" | "ls" | "dpkg-query" | "uname" | "id" => true,
        "sysctl" => args.iter().all(|a| a == "-n" || (!a.starts_with('-') && !a.contains('='))),
        "timedatectl" => args.first().is_some_and(|a| a == "show" || a == "status"),
        "rpm" => args.iter().all(|a| a == "-q" || a == "-qa" || !a.starts_with('-')) && args.iter().any(|a| a.starts_with("-q")),
        // Windows read-only counterparts (cis-windows): only their query / show forms.
        #[cfg(windows)]
        n if windows_allowed(n, args) => true,
        _ => false,
    };
    if ok { Ok(()) } else { Err(format!("`{}` is not an allowed read-only check command", join(argv))) }
}

/// `reg query`, `net accounts` / `net user <name>` / `net localgroup <name>` (no switches),
/// `netsh … show …`, `sc query|qc`, `auditpol /get`, `findstr`, `whoami`.
#[cfg(windows)]
fn windows_allowed(name: &str, args: &[String]) -> bool {
    let lower: Vec<String> = args.iter().map(|a| a.to_ascii_lowercase()).collect();
    let first = lower.first().map(String::as_str).unwrap_or("");
    match name.to_ascii_lowercase().trim_end_matches(".exe") {
        "findstr" | "whoami" => true,
        "reg" => first == "query",
        "net" => (first == "accounts" && lower.len() == 1) || (matches!(first, "user" | "localgroup") && lower.len() == 2 && !lower[1].starts_with('/')),
        "netsh" => lower.iter().any(|a| a == "show") && !lower.iter().any(|a| matches!(a.as_str(), "set" | "add" | "delete" | "reset" | "import" | "dump")),
        "sc" => matches!(first, "query" | "qc" | "queryex"),
        "auditpol" => first == "/get",
        _ => false,
    }
}

pub fn parse_list(text: &str, name: &str) -> Result<Checklist, String> {
    let mut l: Checklist = toml::from_str(text).map_err(|e| format!("checklist {name}: {e}"))?;
    if l.meta.id.is_empty() {
        l.meta.id = name.to_string();
    }
    for c in &l.check {
        if c.manual || c.same_as.is_some() {
            continue;
        }
        if c.cmd.is_empty() && c.cmds.is_empty() {
            return Err(format!("checklist {name}: check {} has no cmd", c.id));
        }
        for a in std::iter::once(&c.cmd).filter(|c| !c.is_empty()).chain(c.cmds.iter()) {
            allowed(a).map_err(|e| format!("checklist {name}: check {}: {e}", c.id))?;
        }
        for r in c.match_.iter().chain(c.match_all.iter()).chain(c.not_match.iter()).chain(c.pattern.iter()) {
            RegexBuilder::new(r).multi_line(true).build().map_err(|e| format!("checklist {name}: check {}: bad regex: {e}", c.id))?;
        }
    }
    Ok(l)
}

/// Resolve `same_as = "<list>:<id>"` against the built-in lists, keeping the referring check's
/// own id, title and section.
fn resolve(l: &mut Checklist) -> Result<(), String> {
    let mut lib: BTreeMap<String, Checklist> = BTreeMap::new();
    for (n, t) in BUILTIN {
        lib.insert(n.to_string(), parse_list(t, n)?);
    }
    for c in l.check.iter_mut() {
        let Some(r) = c.same_as.clone() else { continue };
        let (list, id) = r.split_once(':').ok_or_else(|| format!("same_as `{r}`: use <list>:<id>"))?;
        let base = lib.get(list).and_then(|x| x.check.iter().find(|k| k.id == id)).ok_or_else(|| format!("same_as `{r}` does not exist"))?;
        let mut b = base.clone();
        b.id = c.id.clone();
        b.section = if c.section.is_empty() { b.section } else { c.section.clone() };
        b.title = if c.title.is_empty() { b.title } else { c.title.clone() };
        b.refs = std::iter::once(r.clone()).chain(c.refs.iter().cloned()).collect();
        b.same_as = None;
        *c = b;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub status: &'static str,
    pub evidence: String,
}

/// Evaluate one check against command output (pure; unit-tested without running anything).
pub fn evaluate(c: &Check, exit: Option<i32>, output: &str) -> Outcome {
    let ok_codes = c.ok_exit.clone().unwrap_or_else(|| vec![0]);
    let text = if c.first_line { output.lines().next().unwrap_or("").to_string() } else { output.to_string() };
    let ev = |s: &str| s.trim().lines().take(3).collect::<Vec<_>>().join(" | ").chars().take(240).collect::<String>();
    if !exit.is_some_and(|e| ok_codes.contains(&e)) {
        let st = match c.on_error.as_deref().unwrap_or("skip") {
            "fail" => "fail",
            "pass" => "pass",
            _ => "skip",
        };
        return Outcome { status: st, evidence: if output.trim().is_empty() { format!("exit {exit:?}") } else { ev(output) } };
    }
    let re = |r: &str| RegexBuilder::new(r).multi_line(true).build().ok();
    let mut pass = true;
    if let Some(r) = c.match_.as_deref().and_then(re) {
        pass &= r.is_match(&text);
    }
    for m in &c.match_all {
        pass &= re(m).is_some_and(|r| r.is_match(&text));
    }
    if let Some(r) = c.not_match.as_deref().and_then(re) {
        pass &= !r.is_match(&text);
    }
    if let Some(r) = c.pattern.as_deref().and_then(re) {
        if let Some(maxm) = c.max_matches {
            pass &= r.find_iter(&text).count() <= maxm;
        } else if c.min.is_some() || c.max.is_some() {
            match r.captures(&text).and_then(|cap| cap.get(1)).and_then(|m| m.as_str().parse::<f64>().ok()) {
                Some(n) => pass &= c.min.is_none_or(|m| n >= m) && c.max.is_none_or(|m| n <= m),
                None => pass = false,
            }
        }
    }
    if let Some(mask) = &c.mode_mask {
        let allowed = u32::from_str_radix(mask, 8).unwrap_or(0);
        pass &= u32::from_str_radix(text.trim(), 8).is_ok_and(|m| m & !allowed & 0o7777 == 0);
    }
    Outcome { status: if pass { "pass" } else { "fail" }, evidence: if text.trim().is_empty() { "(no output)".into() } else { ev(&text) } }
}

pub struct ComplianceCheck {
    pub cfg: Arc<Integrations>,
}

impl ComplianceCheck {
    fn load(&self, ctx: &ToolCtx, input: &Value) -> Result<Vec<Checklist>, String> {
        let mut names = arg_list(input, "checklist");
        if names.is_empty() {
            names.push(DEFAULT_LIST.into());
        }
        let extra = self.cfg.list("secops", "checklists");
        let mut out = vec![];
        for n in names {
            let mut l = if let Some((_, t)) = BUILTIN.iter().find(|(b, _)| *b == n) {
                parse_list(t, &n)?
            } else {
                // A configured list by its meta id or file stem, or a path in the workspace.
                let path = extra.iter().map(|p| ctx.resolve(p)).find(|p| p.file_stem().is_some_and(|s| s.to_string_lossy() == n)).unwrap_or_else(|| ctx.resolve(&n));
                let text = std::fs::read_to_string(&path).map_err(|e| format!("checklist `{n}`: not built in ({}) and {}: {e}", BUILTIN.iter().map(|(b, _)| *b).collect::<Vec<_>>().join(", "), path.display()))?;
                parse_list(&text, &n)?
            };
            resolve(&mut l)?;
            if let Some(sec) = arg(input, "section") {
                l.check.retain(|c| c.section.contains(sec) || c.id.starts_with(sec));
            }
            out.push(l);
        }
        Ok(out)
    }
}

impl Tool for ComplianceCheck {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "compliance_check".into(),
            description: "Run an executable compliance checklist on this host with read-only commands (cat/grep/stat/sysctl/findmnt/pgrep/getent; no root, no changes): `checklist` = cis-linux (CIS-style Linux baseline, default), tw-csma (資通安全管理法 對照：防護基準七構面＋應辦事項證據), or a custom TOML list. Returns pass / fail / skip / manual per item with evidence and the fix; `output` writes a Markdown or JSON report.".into(),
            input_schema: json!({"type":"object","properties":{
                "checklist":{"type":"array","items":{"type":"string"},"description":"cis-linux, tw-csma, or a TOML file"},
                "section":{"type":"string","description":"only checks whose section or id starts with this"},
                "only_failed":{"type":"boolean"},
                "output":{"type":"string","description":"report file (.md or .json)"}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let Ok(lists) = self.load(ctx, input) else { return vec![] };
        let mut cmds: Vec<String> = vec![];
        for c in lists.iter().flat_map(|l| l.check.iter()).filter(|c| !c.manual) {
            for a in std::iter::once(&c.cmd).filter(|a| !a.is_empty()).chain(c.cmds.iter()) {
                let j = join(a);
                if !cmds.contains(&j) {
                    cmds.push(j);
                }
            }
        }
        let mut fx = vec![];
        if !cmds.is_empty() {
            fx.push(Effect::Exec { command: cmds.join(" ; ") });
        }
        if let Some(o) = arg(input, "output") {
            fx.push(Effect::Write { path: ctx.resolve(o) });
        }
        fx
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let lists = match self.load(ctx, &input) {
            Ok(l) => l,
            Err(e) => return ToolOutput::err(e),
        };
        let timeout = Duration::from_secs(self.cfg.u64("secops", "check_timeout_seconds").unwrap_or(10).clamp(1, 120));
        let only_failed = input.get("only_failed").and_then(Value::as_bool) == Some(true);
        let mut cache: BTreeMap<Vec<String>, (Option<i32>, String)> = BTreeMap::new();
        let mut reports = vec![];
        let mut md = String::new();
        for l in &lists {
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            let mut rows = vec![];
            md.push_str(&format!("# {}\n\n| id | section | item | result | evidence | fix |\n|---|---|---|---|---|---|\n", if l.meta.title.is_empty() { &l.meta.id } else { &l.meta.title }));
            for c in &l.check {
                if ctx.cancel.is_cancelled() {
                    return ToolOutput::err("Interrupted");
                }
                let out = if c.manual {
                    Outcome { status: "manual", evidence: c.evidence.clone() }
                } else {
                    let alts: Vec<Vec<String>> = if c.cmds.is_empty() { vec![c.cmd.clone()] } else { c.cmds.clone() };
                    let ok_codes = c.ok_exit.clone().unwrap_or_else(|| vec![0]);
                    let mut last = (None, String::new());
                    for a in &alts {
                        let r = cache.entry(a.clone()).or_insert_with(|| match run(a, None, timeout, &ctx.cancel) {
                            Ok(o) => (if o.timed_out { None } else { o.code }, if o.stdout.trim().is_empty() { o.stderr } else { o.stdout }),
                            Err(e) => (None, e),
                        });
                        last = r.clone();
                        if r.0.is_some_and(|e| ok_codes.contains(&e)) {
                            break;
                        }
                    }
                    evaluate(c, last.0, &last.1)
                };
                *counts.entry(out.status).or_default() += 1;
                if only_failed && out.status != "fail" {
                    continue;
                }
                md.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n", c.id, c.section, c.title, out.status, out.evidence.replace('|', "\\|"), if out.status == "fail" { c.fix.replace('|', "\\|") } else { String::new() }));
                rows.push(json!({"id": c.id, "section": c.section, "title": c.title, "severity": c.severity, "status": out.status, "evidence": out.evidence, "fix": if out.status == "fail" { json!(c.fix) } else { Value::Null }, "refs": c.refs}));
            }
            md.push('\n');
            reports.push(json!({"checklist": l.meta.id, "title": l.meta.title, "summary": counts, "results": rows}));
        }
        let mut written = Value::Null;
        if let Some(o) = arg(&input, "output") {
            let path = ctx.resolve(o);
            let body = if o.ends_with(".json") { serde_json::to_string_pretty(&reports).unwrap_or_default() } else { md };
            if let Err(e) = path.parent().map(std::fs::create_dir_all).unwrap_or(Ok(())).and_then(|_| std::fs::write(&path, body)) {
                return ToolOutput::err(format!("cannot write {}: {e}", path.display()));
            }
            written = json!(path.display().to_string());
        }
        ToolOutput::ok(cap_output(ctx, "compliance_check", serde_json::to_string_pretty(&json!({"host": hostname(), "written": written, "reports": reports})).unwrap_or_default(), 40_000))
    }
}

fn hostname() -> String {
    // Linux: `/proc/sys/kernel/hostname` as before; other systems: their own call.
    seagent_core::platform::sysinfo::hostname()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chk(toml_text: &str) -> Check {
        parse_list(&format!("[[check]]\nid = \"t\"\n{toml_text}"), "t").unwrap().check.remove(0)
    }

    #[test]
    fn builtin_lists_parse_resolve_and_use_only_read_only_commands() {
        for (n, t) in BUILTIN {
            let mut l = parse_list(t, n).unwrap();
            resolve(&mut l).unwrap();
            assert!(l.check.len() >= 25, "{n}: {}", l.check.len());
            for c in l.check.iter().filter(|c| !c.manual) {
                assert!(!c.cmd.is_empty() || !c.cmds.is_empty(), "{n}/{}", c.id);
                assert!(!c.fix.is_empty(), "{n}/{} has no fix text", c.id);
            }
        }
        let mut tw = parse_list(BUILTIN[1].1, "tw-csma").unwrap();
        resolve(&mut tw).unwrap();
        let root = tw.check.iter().find(|c| c.id == "AC-最小權限-root").unwrap();
        assert_eq!(root.section, "存取控制");
        assert!(root.cmd.contains(&"/etc/ssh/sshd_config".to_string()) && root.refs[0] == "cis-linux:5.2.10");
        assert!(tw.check.iter().any(|c| c.manual && c.title.contains("一小時")));
        assert!(parse_list("[[check]]\nid=\"x\"\ncmd=[\"rm\",\"-rf\",\"/\"]", "bad").is_err());
        assert!(parse_list("[[check]]\nid=\"x\"\ncmd=[\"sysctl\",\"-w\",\"a=1\"]", "bad").is_err());
        assert!(parse_list("[[check]]\nid=\"x\"\ncmd=[\"sh\",\"-c\",\"id\"]", "bad").is_err());
        assert!(parse_list("[[check]]\nid=\"x\"\ncmd=[\"cat\",\"/x\"]\nmatch=\"(\"", "bad").is_err());
    }

    #[test]
    fn evaluation_rules() {
        assert_eq!(evaluate(&chk("cmd=[\"sysctl\",\"-n\",\"x\"]\nmatch='^2\\s*$'"), Some(0), "2\n").status, "pass");
        assert_eq!(evaluate(&chk("cmd=[\"sysctl\",\"-n\",\"x\"]\nmatch='^2\\s*$'"), Some(0), "1\n").status, "fail");
        assert_eq!(evaluate(&chk("cmd=[\"cat\",\"/x\"]"), Some(1), "Permission denied").status, "skip", "unreadable never passes");
        assert_eq!(evaluate(&chk("cmd=[\"pgrep\",\"x\"]\non_error=\"fail\""), Some(1), "").status, "fail");
        assert_eq!(evaluate(&chk("cmd=[\"pgrep\",\"x\"]\nok_exit=[1]\non_error=\"fail\""), Some(1), "").status, "pass");
        let c = chk("cmd=[\"grep\",\"x\"]\npattern='MaxAuthTries\\s+(\\d+)'\nmax=4\nfirst_line=true\nok_exit=[0,2]");
        assert_eq!(evaluate(&c, Some(0), "MaxAuthTries 3\nMaxAuthTries 9").status, "pass", "first value wins");
        assert_eq!(evaluate(&c, Some(0), "MaxAuthTries 6").status, "fail");
        let m = chk("cmd=[\"stat\",\"/x\"]\nmode_mask=\"640\"");
        assert_eq!(evaluate(&m, Some(0), "600\n").status, "pass");
        assert_eq!(evaluate(&m, Some(0), "644\n").status, "fail");
        let u = chk("cmd=[\"getent\",\"passwd\"]\npattern='(?m)^[^:]+:[^:]*:0:'\nmax_matches=1");
        assert_eq!(evaluate(&u, Some(0), "root:x:0:0::/root:/bin/sh\nbin:x:1:1::/:/x\n").status, "pass");
        assert_eq!(evaluate(&u, Some(0), "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/:/x\n").status, "fail");
        let a = chk("cmd=[\"findmnt\",\"/tmp\"]\nmatch_all=['(^|,)nodev(,|$)','(^|,)nosuid(,|$)']");
        assert_eq!(evaluate(&a, Some(0), "rw,nosuid,nodev").status, "pass");
        assert_eq!(evaluate(&a, Some(0), "rw,nodev").status, "fail");
    }

    /// Windows counterpart of the custom-list test: `findstr` instead of `grep` / `cat`, a
    /// TOML literal string for the `C:\…` path, and the built-in `cis-windows` list on this host.
    #[cfg(windows)]
    #[test]
    fn the_tool_runs_a_custom_list_declares_one_exec_and_writes_a_report_windows() {
        let ctx = crate::testutil::ctx("secops-compliance-win");
        let f = ctx.workspace.join("conf.txt");
        std::fs::write(&f, "PermitRootLogin no\r\nMaxAuthTries 6\r\n").unwrap();
        let p = f.display();
        let list = format!("[meta]\nid=\"mine\"\ntitle=\"Mine\"\n[[check]]\nid=\"a\"\nsection=\"ssh\"\ntitle=\"root\"\ncmd=[\"findstr\",\"/i\",\"PermitRootLogin\",'{p}']\nmatch='no'\nfix=\"set no\"\n[[check]]\nid=\"b\"\nsection=\"ssh\"\ntitle=\"tries\"\ncmd=[\"findstr\",\"MaxAuthTries\",'{p}']\npattern='(\\d+)'\nmax=4\nfix=\"set 4\"\n[[check]]\nid=\"c\"\nsection=\"org\"\ntitle=\"plan\"\nmanual=true\nevidence=\"the plan\"\n[[check]]\nid=\"d\"\nsection=\"ssh\"\ntitle=\"missing\"\ncmd=[\"findstr\",\".\",'{p}.nope']\nfix=\"x\"\n");
        std::fs::write(ctx.workspace.join("mine.toml"), list).unwrap();
        let t = ComplianceCheck { cfg: Arc::new(Integrations::new(json!({"secops": {"checklists": ["mine.toml"]}}))) };
        let input = json!({"checklist": ["mine"], "output": "reports/c.md"});
        let fx = t.effects(&ctx, &input);
        assert_eq!(fx.len(), 2, "{fx:?}");
        assert!(matches!(&fx[0], Effect::Exec { command } if command.starts_with("findstr /i PermitRootLogin") && command.contains(" ; findstr ")), "{fx:?}");
        let o = t.call(&ctx, input);
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        let s = &v["reports"][0]["summary"];
        assert_eq!((s["pass"].as_u64(), s["fail"].as_u64(), s["manual"].as_u64(), s["skip"].as_u64()), (Some(1), Some(1), Some(1), Some(1)), "{s}");
        let md = std::fs::read_to_string(ctx.workspace.join("reports/c.md")).unwrap();
        assert!(md.contains("| b | ssh | tries | fail | MaxAuthTries 6 | set 4 |"), "{md}");
        // Mutating forms of the Windows tools are refused at parse time.
        for bad in [r#"["reg","add","HKCU\\x"]"#, r#"["net","user","x","/add"]"#, r#"["netsh","advfirewall","set","allprofiles","state","off"]"#, r#"["sc","stop","x"]"#, r#"["auditpol","/set"]"#] {
            assert!(parse_list(&format!("[[check]]\nid=\"x\"\ncmd={bad}"), "bad").is_err(), "{bad}");
        }
        // The default list on Windows is this host's baseline, and it runs without error.
        let o = t.call(&ctx, json!({"section": "3 Network"}));
        assert!(!o.is_error && o.content.contains("Windows Defender Firewall"), "{}", o.content);
    }

    // grep / cat / `/etc` fixtures; Windows: `…_writes_a_report_windows`.
    #[cfg(unix)]
    #[test]
    fn the_tool_runs_a_custom_list_declares_one_exec_and_writes_a_report() {
        let ctx = crate::testutil::ctx("secops-compliance");
        let f = ctx.workspace.join("conf.txt");
        std::fs::write(&f, "PermitRootLogin no\nMaxAuthTries 6\n").unwrap();
        let list = format!(
            "[meta]\nid=\"mine\"\ntitle=\"Mine\"\n[[check]]\nid=\"a\"\nsection=\"ssh\"\ntitle=\"root\"\ncmd=[\"grep\",\"-i\",\"PermitRootLogin\",\"{p}\"]\nmatch='no'\nfix=\"set no\"\n[[check]]\nid=\"b\"\nsection=\"ssh\"\ntitle=\"tries\"\ncmd=[\"grep\",\"MaxAuthTries\",\"{p}\"]\npattern='(\\d+)'\nmax=4\nfix=\"set 4\"\n[[check]]\nid=\"c\"\nsection=\"org\"\ntitle=\"plan\"\nmanual=true\nevidence=\"the plan\"\n[[check]]\nid=\"d\"\nsection=\"ssh\"\ntitle=\"missing\"\ncmd=[\"cat\",\"{p}.nope\"]\nfix=\"x\"\n",
            p = f.display()
        );
        std::fs::write(ctx.workspace.join("mine.toml"), list).unwrap();
        let t = ComplianceCheck { cfg: Arc::new(Integrations::new(json!({"secops": {"checklists": ["mine.toml"]}}))) };
        let input = json!({"checklist": ["mine"], "output": "reports/c.md"});
        let fx = t.effects(&ctx, &input);
        assert_eq!(fx.len(), 2);
        assert!(matches!(&fx[0], Effect::Exec { command } if command.starts_with("grep -i PermitRootLogin") && command.contains(" ; cat ")), "{fx:?}");
        let o = t.call(&ctx, input);
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        let s = &v["reports"][0]["summary"];
        assert_eq!((s["pass"].as_u64(), s["fail"].as_u64(), s["manual"].as_u64(), s["skip"].as_u64()), (Some(1), Some(1), Some(1), Some(1)), "{s}");
        let md = std::fs::read_to_string(ctx.workspace.join("reports/c.md")).unwrap();
        assert!(md.contains("| b | ssh | tries | fail | MaxAuthTries 6 | set 4 |"), "{md}");
        assert!(t.call(&ctx, json!({"checklist": ["nope"]})).is_error);
        // The built-in list runs on this host without error (results depend on the host).
        let o = t.call(&ctx, json!({"checklist": ["cis-linux"], "section": "3 Network"}));
        assert!(!o.is_error && o.content.contains("Reverse path"), "{}", o.content);
    }
}
