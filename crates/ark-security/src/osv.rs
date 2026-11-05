//! OSV.dev checks.
//!
//! - [`check_package_for_malware`] (Hermes `tools/osv_check.py`): before an MCP server
//!   or plugin launches through `npx`/`uvx`/`pipx`, query OSV for MAL-* advisories.
//!   Regular CVEs are ignored; network errors fail open. Verdicts are cached on disk
//!   for an hour.
//! - [`audit`] (Hermes `hermes_cli/security_audit.py`): `querybatch` + `vulns/{id}` for
//!   every pinned component (ark's own crates from the embedded lockfile, pinned MCP
//!   and plugin packages) with severity tiers and fixed versions.
//! - [`audit_at`] / [`vuln_at`] (pro-026): the same general CVE query against any OSV-compatible
//!   endpoint (a mirror, a test server) for the `osv_query` tool — every advisory, not only
//!   MAL-*, with aliases (CVE ⇄ GHSA) and fixed versions; [`pins_from_package_lock`] adds
//!   npm lockfiles to the pin discovery.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_ENDPOINT: &str = "https://api.osv.dev";
const CACHE_TTL_SECS: u64 = 3600;
const CACHE_MAX: usize = 256;
pub const BATCH_MAX: usize = 1000;

/// Base URL (`OSV_ENDPOINT` overrides, for tests and mirrors). Accepts the Hermes form
/// `…/v1/query` too.
pub fn endpoint() -> String {
    let e = std::env::var("OSV_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.into());
    e.trim_end_matches('/').trim_end_matches("/v1/query").trim_end_matches("/v1/querybatch").to_string()
}

fn agent(t: Duration) -> ureq::Agent {
    ark_net::http::builder().http_status_as_error(false).timeout_global(Some(t)).build().into()
}

fn post_json(url: &str, body: &Value, t: Duration) -> Result<Value, String> {
    let mut r = agent(t).post(url).header("content-type", "application/json").header("user-agent", "ark-osv-check/1.0").send(body.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    let text = r.body_mut().with_config().limit(32 << 20).read_to_string().map_err(|e| e.to_string())?;
    if status >= 400 {
        return Err(format!("HTTP {status}: {}", text.chars().take(200).collect::<String>()));
    }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn get_json(url: &str, t: Duration) -> Result<Value, String> {
    let mut r = agent(t).get(url).header("user-agent", "ark-osv-check/1.0").call().map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    let text = r.body_mut().with_config().limit(8 << 20).read_to_string().map_err(|e| e.to_string())?;
    if status >= 400 {
        return Err(format!("HTTP {status}"));
    }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// `security.osv_check`.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Default verdict cache: `$XDG_CACHE_HOME/ark` or `~/.cache/ark`.
pub fn default_cache_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).filter(|p| p.is_absolute()).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache"))).map(|d| d.join("ark"))
}

/// Pre-launch check used when spawning MCP servers / plugins.
pub fn launch_check(command: &str, args: &[String]) -> Option<String> {
    if !ENABLED.load(std::sync::atomic::Ordering::Relaxed) || ecosystem_for(command).is_none() {
        return None;
    }
    check_package_for_malware(command, args, default_cache_dir().as_deref())
}

pub fn ecosystem_for(command: &str) -> Option<&'static str> {
    let name = command.rsplit(['/', '\\']).next().unwrap_or(command).to_ascii_lowercase();
    match name.as_str() {
        "npx" | "npx.cmd" => Some("npm"),
        "uvx" | "uvx.cmd" | "uvx.exe" | "pipx" | "pipx.exe" => Some("PyPI"),
        _ => None,
    }
}

/// `(package, version)` from launcher args (`--package`/`-p` honoured, flags skipped).
pub fn package_from_args(args: &[String], ecosystem: &str) -> Option<(String, Option<String>)> {
    let mut token: Option<String> = None;
    let mut take_next = false;
    for a in args {
        if take_next {
            token = Some(a.clone());
            break;
        }
        if a == "--package" || a == "-p" {
            take_next = true;
            continue;
        }
        if let Some(v) = a.strip_prefix("--package=") {
            token = Some(v.to_string());
            break;
        }
        if a.starts_with('-') {
            continue;
        }
        token = Some(a.clone());
        break;
    }
    let t = token.filter(|t| !t.is_empty())?;
    Some(match ecosystem {
        "npm" => {
            if let Some(rest) = t.strip_prefix('@') {
                match rest.split_once('/').and_then(|(scope, nv)| nv.split_once('@').map(|(n, v)| (format!("@{scope}/{n}"), v.to_string()))) {
                    Some((n, v)) => (n, Some(v).filter(|v| !v.is_empty() && v != "latest")),
                    None => (t, None),
                }
            } else if let Some((n, v)) = t.rsplit_once('@') {
                (n.to_string(), Some(v.to_string()).filter(|v| !v.is_empty() && v != "latest"))
            } else {
                (t, None)
            }
        }
        _ => {
            let base = t.split('[').next().unwrap_or(&t).to_string();
            match t.split_once("==") {
                Some((_, v)) => (base.split("==").next().unwrap_or(&base).to_string(), Some(v.to_string())),
                None => (base, None),
            }
        }
    })
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Cache {
    version: u32,
    entries: BTreeMap<String, (u64, Option<String>)>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// BLOCKED message when the package has MAL-* advisories, else None (also on network errors).
pub fn check_package_for_malware(command: &str, args: &[String], cache_dir: Option<&Path>) -> Option<String> {
    let eco = ecosystem_for(command)?;
    let (pkg, ver) = package_from_args(args, eco)?;
    let key = format!("{eco}|{pkg}|{}", ver.clone().unwrap_or_default());
    let cache_path: Option<PathBuf> = cache_dir.map(|d| d.join("osv_check.json"));
    let mut cache: Cache = cache_path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).filter(|c: &Cache| c.version == 1).unwrap_or_default();
    if let Some((exp, r)) = cache.entries.get(&key) {
        if *exp > now() {
            return r.clone();
        }
    }
    let mut q = json!({"package": {"name": pkg, "ecosystem": eco}});
    if let Some(v) = &ver {
        q["version"] = json!(v);
    }
    let resp = match post_json(&format!("{}/v1/query", endpoint()), &q, Duration::from_secs(10)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ark: OSV check for {eco}/{pkg} failed (allowing): {e}");
            return None;
        }
    };
    let mal: Vec<&Value> = resp["vulns"].as_array().map(|a| a.iter().filter(|v| v["id"].as_str().is_some_and(|i| i.starts_with("MAL-"))).collect()).unwrap_or_default();
    let result = (!mal.is_empty()).then(|| {
        let ids: Vec<&str> = mal.iter().take(3).filter_map(|m| m["id"].as_str()).collect();
        let sums: Vec<String> = mal.iter().take(3).map(|m| m["summary"].as_str().or(m["id"].as_str()).unwrap_or("").chars().take(100).collect()).collect();
        format!("BLOCKED: Package '{pkg}' ({eco}) has known malware advisories: {}. Details: {}", ids.join(", "), sums.join("; "))
    });
    if let Some(p) = cache_path {
        let t = now();
        cache.version = 1;
        cache.entries.retain(|_, (e, _)| *e > t);
        if cache.entries.len() >= CACHE_MAX {
            cache.entries.clear();
        }
        cache.entries.insert(key, (t + CACHE_TTL_SECS, result.clone()));
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(&p, serde_json::to_string(&cache).unwrap_or_default());
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Component {
    pub name: String,
    pub version: String,
    /// As OSV expects: `crates.io`, `npm`, `PyPI`.
    pub ecosystem: String,
    /// `ark`, `mcp:<server>`, `plugin:<name>`.
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Vuln {
    pub id: String,
    pub severity: String,
    pub summary: String,
    pub fixed: Vec<String>,
    /// Other ids of the same advisory (`CVE-…` for a `GHSA-…`, and back).
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub component: Component,
    pub vuln: Vuln,
}

pub fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_uppercase().as_str() {
        "LOW" => 1,
        "MODERATE" | "MEDIUM" => 2,
        "HIGH" => 3,
        "CRITICAL" => 4,
        _ => 0,
    }
}

/// Packages from a `Cargo.lock` (registry crates only; path/git deps are skipped).
pub fn components_from_cargo_lock(lock: &str, source: &str) -> Vec<Component> {
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |k: &str| block.lines().find_map(|l| l.trim().strip_prefix(&format!("{k} = ")).map(|v| v.trim_matches('"').to_string()));
        if let (Some(n), Some(v), Some(src)) = (field("name"), field("version"), field("source")) {
            if src.starts_with("registry+") {
                out.push(Component { name: n, version: v, ecosystem: "crates.io".into(), source: source.into() });
            }
        }
    }
    out
}

/// Exactly pinned launcher packages (`npx pkg@1.2.3`, `uvx pkg==1.2`); unpinned → None.
pub fn component_from_launcher(source: &str, command: &str, args: &[String]) -> Option<Component> {
    let eco = ecosystem_for(command)?;
    let (name, version) = package_from_args(args, eco)?;
    let version = version?;
    Some(Component { name, version, ecosystem: eco.into(), source: source.into() })
}

/// `name==version` pins from requirements.txt text.
pub fn pins_from_requirements(text: &str, source: &str) -> Vec<Component> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|l| {
            let l = l.split(';').next()?.trim();
            let (n, v) = l.split_once("==")?;
            let n = n.split('[').next()?.trim();
            let v = v.trim();
            (!n.is_empty() && !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || "._+!-".contains(c))).then(|| Component { name: n.into(), version: v.into(), ecosystem: "PyPI".into(), source: source.into() })
        })
        .collect()
}

/// Exact versions from a package.json `dependencies` map (ranges are skipped).
pub fn pins_from_package_json(text: &str, source: &str) -> Vec<Component> {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    v["dependencies"].as_object().map(|m| m.iter().filter_map(|(n, ver)| {
        let ver = ver.as_str()?;
        (ver.chars().next().is_some_and(|c| c.is_ascii_digit()) && ver.chars().all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c))).then(|| Component { name: n.clone(), version: ver.into(), ecosystem: "npm".into(), source: source.into() })
    }).collect()).unwrap_or_default()
}

/// Exact versions from an npm `package-lock.json` (lockfileVersion 2/3 `packages`, or v1
/// `dependencies`).
pub fn pins_from_package_lock(text: &str, source: &str) -> Vec<Component> {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    let mut out: Vec<Component> = Vec::new();
    let mut push = |name: &str, ver: &str| {
        if !name.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) && !out.iter().any(|c| c.name == name && c.version == ver) {
            out.push(Component { name: name.into(), version: ver.into(), ecosystem: "npm".into(), source: source.into() });
        }
    };
    if let Some(m) = v["packages"].as_object() {
        for (path, p) in m {
            let Some(name) = path.rsplit_once("node_modules/").map(|(_, n)| n) else { continue };
            if let Some(ver) = p["version"].as_str() {
                push(name, ver);
            }
        }
    } else if let Some(m) = v["dependencies"].as_object() {
        for (name, p) in m {
            if let Some(ver) = p["version"].as_str() {
                push(name, ver);
            }
        }
    }
    out
}

fn severity_of(rec: &Value) -> String {
    let mut cands = vec![rec["database_specific"]["severity"].as_str()];
    if let Some(a) = rec["affected"].as_array() {
        cands.extend(a.iter().map(|e| e["ecosystem_specific"]["severity"].as_str()));
    }
    cands.into_iter().flatten().map(|s| s.trim().to_ascii_uppercase()).find(|s| ["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"].contains(&s.as_str())).unwrap_or_else(|| "UNKNOWN".into())
}

fn fixed_of(rec: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in rec["affected"].as_array().into_iter().flatten() {
        for r in e["ranges"].as_array().into_iter().flatten() {
            for ev in r["events"].as_array().into_iter().flatten() {
                if let Some(f) = ev["fixed"].as_str() {
                    if !out.iter().any(|x| x == f) {
                        out.push(f.into());
                    }
                }
            }
        }
    }
    out
}

/// Query OSV for every component; findings sorted by severity, then source and name.
pub fn audit(components: &[Component]) -> Result<Vec<Finding>, String> {
    audit_at(&endpoint(), components)
}

fn vuln_of(id: &str, rec: &Value) -> Vuln {
    let aliases = rec["aliases"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    Vuln { id: id.to_string(), severity: severity_of(rec), summary: rec["summary"].as_str().or(rec["details"].as_str()).unwrap_or("").trim().chars().take(400).collect(), fixed: fixed_of(rec), aliases }
}

/// One advisory by id (`CVE-…`, `GHSA-…`, `RUSTSEC-…`, `PYSEC-…`) from `base`.
pub fn vuln_at(base: &str, id: &str) -> Result<Vuln, String> {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err(format!("`{id}` is not an advisory id"));
    }
    let rec = get_json(&format!("{}/v1/vulns/{id}", base.trim_end_matches('/')), Duration::from_secs(20)).map_err(|e| format!("OSV lookup of {id} failed: {e}"))?;
    Ok(vuln_of(id, &rec))
}

/// [`audit`] against an explicit OSV endpoint.
pub fn audit_at(base: &str, components: &[Component]) -> Result<Vec<Finding>, String> {
    let base = base.trim_end_matches('/').to_string();
    let mut raw: Vec<(Component, Vec<String>)> = Vec::new();
    for chunk in components.chunks(BATCH_MAX) {
        let queries: Vec<Value> = chunk.iter().map(|c| json!({"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version})).collect();
        let resp = post_json(&format!("{base}/v1/querybatch"), &json!({"queries": queries}), Duration::from_secs(20)).map_err(|e| format!("OSV batch query failed: {e}"))?;
        for (c, r) in chunk.iter().zip(resp["results"].as_array().cloned().unwrap_or_default()) {
            let ids: Vec<String> = r["vulns"].as_array().map(|a| a.iter().filter_map(|v| v["id"].as_str().map(String::from)).collect()).unwrap_or_default();
            if !ids.is_empty() {
                raw.push((c.clone(), ids));
            }
        }
    }
    let mut unique: Vec<String> = raw.iter().flat_map(|(_, ids)| ids.iter().cloned()).collect();
    unique.sort();
    unique.dedup();
    let details: BTreeMap<String, Vuln> = std::thread::scope(|s| {
        let chunks: Vec<Vec<String>> = unique.chunks(unique.len().div_ceil(8).max(1)).map(|c| c.to_vec()).collect();
        let hs: Vec<_> = chunks.into_iter().map(|ids| {
            let base = base.clone();
            s.spawn(move || ids.into_iter().map(|id| {
                let v = match get_json(&format!("{base}/v1/vulns/{id}"), Duration::from_secs(20)) {
                    Ok(rec) => vuln_of(&id, &rec),
                    Err(_) => Vuln { id: id.clone(), severity: "UNKNOWN".into(), ..Default::default() },
                };
                (id, v)
            }).collect::<Vec<_>>())
        }).collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    let mut out: Vec<Finding> = raw.into_iter().flat_map(|(c, ids)| ids.into_iter().map(move |id| (c.clone(), id))).map(|(c, id)| Finding { vuln: details.get(&id).cloned().unwrap_or(Vuln { id, severity: "UNKNOWN".into(), ..Default::default() }), component: c }).collect();
    out.sort_by(|a, b| severity_rank(&b.vuln.severity).cmp(&severity_rank(&a.vuln.severity)).then(a.component.source.cmp(&b.component.source)).then(a.component.name.to_lowercase().cmp(&b.component.name.to_lowercase())).then(a.vuln.id.cmp(&b.vuln.id)));
    Ok(out)
}

pub fn render_human(findings: &[Finding], total: usize) -> String {
    if findings.is_empty() {
        return format!("No known vulnerabilities found across {total} component(s).");
    }
    let mut lines = vec![format!("Found {} known vulnerability finding(s) across {total} component(s):", findings.len()), String::new()];
    let mut last = "";
    for f in findings {
        if f.component.source != last {
            lines.push(format!("[{}]", f.component.source));
            last = &f.component.source;
        }
        lines.push(format!("  {:<8}  {}=={}  {}", f.vuln.severity, f.component.name, f.component.version, f.vuln.id));
        if !f.vuln.summary.is_empty() {
            let s = if f.vuln.summary.chars().count() <= 100 { f.vuln.summary.clone() } else { format!("{}...", f.vuln.summary.chars().take(97).collect::<String>()) };
            lines.push(format!("           {s}"));
        }
        if !f.vuln.fixed.is_empty() {
            lines.push(format!("           fixed in: {}", f.vuln.fixed.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
        }
    }
    lines.join("\n")
}

pub fn render_json(findings: &[Finding], total: usize) -> Value {
    json!({
        "total_components_scanned": total,
        "finding_count": findings.len(),
        "findings": findings.iter().map(|f| json!({"package": f.component.name, "version": f.component.version, "ecosystem": f.component.ecosystem, "source": f.component.source, "vuln_id": f.vuln.id, "severity": f.vuln.severity, "summary": f.vuln.summary, "fixed_versions": f.vuln.fixed})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testserver::serve;

    #[test]
    fn launcher_parsing() {
        assert_eq!(ecosystem_for("/usr/bin/npx"), Some("npm"));
        assert_eq!(ecosystem_for("uvx"), Some("PyPI"));
        assert_eq!(ecosystem_for("node"), None);
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(package_from_args(&a(&["-y", "@scope/pkg@1.2.3"]), "npm"), Some(("@scope/pkg".into(), Some("1.2.3".into()))));
        assert_eq!(package_from_args(&a(&["pkg@latest"]), "npm"), Some(("pkg".into(), None)));
        assert_eq!(package_from_args(&a(&["--package", "x@2", "bin"]), "npm"), Some(("x".into(), Some("2".into()))));
        assert_eq!(package_from_args(&a(&["mcp-server[cli]==0.4"]), "PyPI"), Some(("mcp-server".into(), Some("0.4".into()))));
        assert_eq!(component_from_launcher("mcp:x", "npx", &a(&["pkg"])), None, "unpinned is not auditable");
    }

    #[test]
    fn malware_is_blocked_cves_ignored_errors_fail_open() {
        let (url, hits) = serve(vec![
            ("/v1/query", r#"{"vulns":[{"id":"GHSA-1","summary":"cve"},{"id":"MAL-2026-1","summary":"steals tokens"}]}"#.into()),
            ("/v1/query", r#"{"vulns":[{"id":"GHSA-2"}]}"#.into()),
        ]);
        std::env::set_var("OSV_ENDPOINT", format!("{url}/v1/query"));
        let dir = std::env::temp_dir().join(format!("ark-osv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let args = vec!["-y".to_string(), "evil-mcp@1.0.0".to_string()];
        let r = check_package_for_malware("npx", &args, Some(&dir)).unwrap();
        assert!(r.contains("MAL-2026-1") && r.contains("steals tokens") && !r.contains("GHSA-1"), "{r}");
        // Cached: the next call does not hit the server.
        assert_eq!(check_package_for_malware("npx", &args, Some(&dir)), Some(r));
        assert_eq!(check_package_for_malware("npx", &["benign@2".into()], Some(&dir)), None);
        let bodies = hits.lock().unwrap().clone();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains("\"evil-mcp\"") && bodies[0].contains("\"version\":\"1.0.0\""));
        assert_eq!(check_package_for_malware("node", &args, None), None, "not a launcher");
        std::env::set_var("OSV_ENDPOINT", "http://127.0.0.1:9/v1/query");
        assert_eq!(check_package_for_malware("uvx", &["x==1".into()], None), None, "network error fails open");
        std::env::remove_var("OSV_ENDPOINT");
    }

    #[test]
    fn lockfile_and_pin_discovery() {
        let lock = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"ark-core\"\nversion = \"0.1.0\"\n";
        assert_eq!(components_from_cargo_lock(lock, "ark"), vec![Component { name: "serde".into(), version: "1.0.0".into(), ecosystem: "crates.io".into(), source: "ark".into() }]);
        assert_eq!(pins_from_requirements("requests==2.31.0\nflask>=2\n# c\nx[y]==1 ; python_version>'3'\n", "plugin:p").len(), 2);
        assert_eq!(pins_from_package_json(r#"{"dependencies":{"a":"1.2.3","b":"^2.0.0"}}"#, "plugin:p").len(), 1);
        assert_eq!(severity_rank("critical"), 4);
        let pl = r#"{"lockfileVersion":3,"packages":{"":{"version":"0.0.0"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/@s/b":{"version":"1.0.0"}}}"#;
        let c = pins_from_package_lock(pl, "app");
        let mut got: Vec<String> = c.iter().map(|c| format!("{}@{}", c.name, c.version)).collect();
        got.sort();
        assert_eq!(got, ["@s/b@1.0.0", "lodash@4.17.20"]);
    }

    #[test]
    fn general_cves_with_aliases_from_an_explicit_endpoint() {
        const GHSA: &str = r#"{"id":"GHSA-xxxx","aliases":["CVE-2021-23337"],"summary":"Command injection","database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;
        let (base, _) = serve(vec![
            ("/v1/querybatch", r#"{"results":[{"vulns":[{"id":"GHSA-xxxx"}]},{}]}"#.to_string()),
            ("/v1/vulns/GHSA-xxxx", GHSA.to_string()),
            ("/v1/vulns/GHSA-xxxx", GHSA.to_string()),
        ]);
        let comps = vec![Component { name: "lodash".into(), version: "4.17.20".into(), ecosystem: "npm".into(), source: "app".into() }, Component { name: "left-pad".into(), version: "1.3.0".into(), ecosystem: "npm".into(), source: "app".into() }];
        let f = audit_at(&base, &comps).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln.aliases, ["CVE-2021-23337"]);
        assert_eq!(f[0].vuln.fixed, ["4.17.21"]);
        assert_eq!(f[0].vuln.severity, "HIGH");
        assert_eq!(vuln_at(&base, "GHSA-xxxx").unwrap().summary, "Command injection");
        assert!(vuln_at(&base, "../x").is_err());
    }
}
