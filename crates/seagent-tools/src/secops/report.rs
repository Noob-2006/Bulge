//! `scan_report` (pro-026 / pro-028 / pro-029): parse scanner output — SARIF (Semgrep, CodeQL,
//! Trivy/Grype SARIF, …), Trivy JSON, Grype JSON, Nessus `.nessus` XML and Nessus CSV — into
//! one finding shape, de-duplicate across files and scanners (CVE ⇄ GHSA aliases merge), and
//! rank by exploitability: known-exploited (CISA KEV list, Nessus `exploit_available`, Grype
//! `knownExploited`) > EPSS > CVSS > severity, with "a fix exists" as the tie-breaker.
//! Priorities P1–P4 come with the reason, so the ticket text can say why.

use crate::ops::{arg, arg_list, arg_u64, cap_output, Integrations};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Sev {
    #[default]
    Unknown,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Sev {
    pub fn parse(s: &str) -> Sev {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "4" => Sev::Critical,
            "high" | "error" | "3" => Sev::High,
            "medium" | "moderate" | "warning" | "2" => Sev::Medium,
            "low" | "note" | "negligible" | "1" => Sev::Low,
            "info" | "informational" | "none" | "0" => Sev::Info,
            _ => Sev::Unknown,
        }
    }
    pub fn from_score(s: f64) -> Sev {
        if s >= 9.0 {
            Sev::Critical
        } else if s >= 7.0 {
            Sev::High
        } else if s >= 4.0 {
            Sev::Medium
        } else if s > 0.0 {
            Sev::Low
        } else {
            Sev::Info
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Sev::Critical => "critical",
            Sev::High => "high",
            Sev::Medium => "medium",
            Sev::Low => "low",
            Sev::Info => "info",
            Sev::Unknown => "unknown",
        }
    }
    fn weight(self) -> f64 {
        match self {
            Sev::Critical => 40.0,
            Sev::High => 30.0,
            Sev::Medium => 15.0,
            Sev::Low => 5.0,
            Sev::Info | Sev::Unknown => 0.0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Finding {
    /// Vulnerability / rule / plugin id as the scanner named it.
    pub id: String,
    pub aliases: Vec<String>,
    pub title: String,
    pub severity: Sev,
    pub cvss: Option<f64>,
    pub epss: Option<f64>,
    pub exploited: bool,
    /// Fixed version or remediation text, when the scanner knows one.
    pub fix: String,
    /// `name@version` for package findings; empty for code / host findings.
    pub package: String,
    /// Where: image / file:line / host:port.
    pub assets: Vec<String>,
    pub scanners: Vec<String>,
    pub occurrences: usize,
}

impl Finding {
    /// The id findings are merged on: the CVE when any id is one.
    pub fn canonical(&self) -> String {
        std::iter::once(&self.id).chain(self.aliases.iter()).find(|i| i.starts_with("CVE-")).cloned().unwrap_or_else(|| self.id.clone())
    }
    fn key(&self) -> String {
        if self.package.is_empty() {
            format!("{}|{}", self.canonical(), self.assets.first().cloned().unwrap_or_default())
        } else {
            format!("{}|{}", self.canonical(), self.package)
        }
    }
    pub fn score(&self) -> f64 {
        self.severity.weight() + self.cvss.unwrap_or(0.0).min(10.0) * 2.0 + self.epss.unwrap_or(0.0).clamp(0.0, 1.0) * 30.0 + if self.exploited { 40.0 } else { 0.0 } + if self.fix.is_empty() { 0.0 } else { 3.0 }
    }
    pub fn priority(&self) -> (&'static str, String) {
        let s = self.score();
        let mut why = vec![format!("severity {}", self.severity.as_str())];
        if self.exploited {
            why.insert(0, "known exploited".into());
        }
        if let Some(e) = self.epss.filter(|e| *e >= 0.1) {
            why.push(format!("EPSS {:.0}%", e * 100.0));
        }
        if let Some(c) = self.cvss {
            why.push(format!("CVSS {c:.1}"));
        }
        why.push(if self.fix.is_empty() { "no fix yet".into() } else { "fix available".into() });
        let p = if (self.exploited && self.severity >= Sev::High) || s >= 85.0 {
            "P1"
        } else if s >= 55.0 {
            "P2"
        } else if s >= 25.0 {
            "P3"
        } else {
            "P4"
        };
        (p, why.join(", "))
    }
}

fn f64_of(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").trim().to_string()
}

// ───────────────────────────── parsers ─────────────────────────────

pub fn parse_sarif(v: &Value) -> Vec<Finding> {
    let mut out = vec![];
    for run in v["runs"].as_array().into_iter().flatten() {
        let tool = s(&run["tool"]["driver"]["name"]);
        let mut rules: BTreeMap<String, Value> = BTreeMap::new();
        let ext = run["tool"]["extensions"].as_array().cloned().unwrap_or_default();
        for r in run["tool"]["driver"]["rules"].as_array().into_iter().flatten().chain(ext.iter().flat_map(|e| e["rules"].as_array().cloned().unwrap_or_default()).collect::<Vec<_>>().iter()) {
            rules.insert(s(&r["id"]), r.clone());
        }
        for r in run["results"].as_array().into_iter().flatten() {
            let id = r["ruleId"].as_str().or(r["rule"]["id"].as_str()).unwrap_or("").to_string();
            let rule = rules.get(&id).cloned().unwrap_or(Value::Null);
            let score = f64_of(&rule["properties"]["security-severity"]).or_else(|| f64_of(&r["properties"]["security-severity"]));
            let level = r["level"].as_str().or(rule["defaultConfiguration"]["level"].as_str()).unwrap_or("warning");
            let severity = score.map(Sev::from_score).unwrap_or_else(|| Sev::parse(level));
            let loc = &r["locations"][0]["physicalLocation"];
            let asset = match (loc["artifactLocation"]["uri"].as_str(), loc["region"]["startLine"].as_u64()) {
                (Some(u), Some(l)) => format!("{u}:{l}"),
                (Some(u), None) => u.to_string(),
                _ => String::new(),
            };
            let title = r["message"]["text"].as_str().or(rule["shortDescription"]["text"].as_str()).unwrap_or("").lines().next().unwrap_or("").chars().take(200).collect();
            out.push(Finding { aliases: if id.starts_with("CVE-") { vec![] } else { cve_in(&rule["properties"]["tags"]) }, id, title, severity, cvss: score, assets: vec![asset], scanners: vec![if tool.is_empty() { "sarif".into() } else { tool.clone() }], occurrences: 1, ..Default::default() });
        }
    }
    out
}

fn cve_in(tags: &Value) -> Vec<String> {
    tags.as_array().into_iter().flatten().filter_map(|t| t.as_str()).filter(|t| t.starts_with("CVE-")).map(String::from).collect()
}

pub fn parse_trivy(v: &Value) -> Vec<Finding> {
    let mut out = vec![];
    for r in v["Results"].as_array().into_iter().flatten() {
        let target = s(&r["Target"]);
        for x in r["Vulnerabilities"].as_array().into_iter().flatten() {
            let cvss = ["nvd", "redhat", "ghsa"].iter().find_map(|k| f64_of(&x["CVSS"][k]["V3Score"]));
            out.push(Finding {
                id: s(&x["VulnerabilityID"]),
                title: x["Title"].as_str().or(x["Description"].as_str()).unwrap_or("").chars().take(200).collect(),
                severity: Sev::parse(x["Severity"].as_str().unwrap_or("")),
                cvss,
                fix: s(&x["FixedVersion"]),
                package: format!("{}@{}", s(&x["PkgName"]), s(&x["InstalledVersion"])),
                assets: vec![target.clone()],
                scanners: vec!["trivy".into()],
                occurrences: 1,
                ..Default::default()
            });
        }
        for x in r["Misconfigurations"].as_array().into_iter().flatten().filter(|m| m["Status"].as_str() != Some("PASS")) {
            out.push(Finding { id: x["AVDID"].as_str().or(x["ID"].as_str()).unwrap_or("").into(), title: s(&x["Title"]), severity: Sev::parse(x["Severity"].as_str().unwrap_or("")), fix: s(&x["Resolution"]), assets: vec![target.clone()], scanners: vec!["trivy".into()], occurrences: 1, ..Default::default() });
        }
        for x in r["Secrets"].as_array().into_iter().flatten() {
            let line = x["StartLine"].as_u64().map(|l| format!(":{l}")).unwrap_or_default();
            out.push(Finding { id: s(&x["RuleID"]), title: format!("secret: {}", s(&x["Title"])), severity: Sev::parse(x["Severity"].as_str().unwrap_or("")), fix: "rotate the credential and remove it from the artifact".into(), assets: vec![format!("{target}{line}")], scanners: vec!["trivy".into()], occurrences: 1, ..Default::default() });
        }
    }
    out
}

pub fn parse_grype(v: &Value) -> Vec<Finding> {
    let target = v["source"]["target"]["userInput"].as_str().or(v["source"]["target"].as_str()).unwrap_or("").to_string();
    let mut out = vec![];
    for m in v["matches"].as_array().into_iter().flatten() {
        let vu = &m["vulnerability"];
        let cvss = vu["cvss"].as_array().into_iter().flatten().chain(m["relatedVulnerabilities"].as_array().into_iter().flatten().flat_map(|r| r["cvss"].as_array().cloned().unwrap_or_default()).collect::<Vec<_>>().iter()).filter_map(|c| f64_of(&c["metrics"]["baseScore"])).fold(None, |a: Option<f64>, b| Some(a.map_or(b, |a| a.max(b))));
        let epss = vu["epss"].as_array().into_iter().flatten().filter_map(|e| f64_of(&e["epss"])).fold(None, |a: Option<f64>, b| Some(a.map_or(b, |a| a.max(b))));
        let a = &m["artifact"];
        let loc = a["locations"][0]["path"].as_str().map(|p| format!("{target}:{p}")).unwrap_or_else(|| target.clone());
        out.push(Finding {
            id: s(&vu["id"]),
            aliases: m["relatedVulnerabilities"].as_array().into_iter().flatten().map(|r| s(&r["id"])).filter(|i| !i.is_empty()).collect(),
            title: vu["description"].as_str().unwrap_or("").chars().take(200).collect(),
            severity: Sev::parse(vu["severity"].as_str().unwrap_or("")),
            cvss,
            epss,
            exploited: vu["knownExploited"].as_array().is_some_and(|k| !k.is_empty()),
            fix: if vu["fix"]["state"].as_str() == Some("fixed") { vu["fix"]["versions"].as_array().map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default() } else { String::new() },
            package: format!("{}@{}", s(&a["name"]), s(&a["version"])),
            assets: vec![loc],
            scanners: vec!["grype".into()],
            occurrences: 1,
        });
    }
    out
}

fn unescape(x: &str) -> String {
    x.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&#39;", "'").replace("&amp;", "&")
}

fn attr(tag: &str, name: &str) -> String {
    let pat = format!(" {name}=\"");
    tag.find(&pat).map(|i| &tag[i + pat.len()..]).and_then(|r| r.find('"').map(|j| unescape(&r[..j]))).unwrap_or_default()
}

fn children<'a>(body: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = vec![];
    let mut rest = body;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(&after[..j]);
        rest = &after[j + close.len()..];
    }
    out
}

/// Nessus v2 XML (`.nessus`): one finding per ReportItem with severity ≥ 1.
pub fn parse_nessus_xml(x: &str) -> Vec<Finding> {
    let mut out = vec![];
    for host_block in x.split("<ReportHost ").skip(1) {
        let host = attr(&format!(" {}", &host_block[..host_block.find('>').unwrap_or(0)]), "name");
        let host_block = &host_block[..host_block.find("</ReportHost>").unwrap_or(host_block.len())];
        for item in host_block.split("<ReportItem ").skip(1) {
            let end = item.find('>').unwrap_or(0);
            let tag = format!(" {}", &item[..end]);
            let body = &item[end..item.find("</ReportItem>").unwrap_or(item.len())];
            let sev = Sev::parse(&attr(&tag, "severity"));
            if sev <= Sev::Info {
                continue;
            }
            let child = |t: &str| children(body, t).first().map(|v| unescape(v.trim())).unwrap_or_default();
            let cves: Vec<String> = children(body, "cve").into_iter().map(|c| c.trim().to_string()).collect();
            let port = attr(&tag, "port");
            out.push(Finding {
                id: format!("nessus-{}", attr(&tag, "pluginID")),
                aliases: cves,
                title: attr(&tag, "pluginName"),
                severity: sev,
                cvss: child("cvss3_base_score").parse().ok().or_else(|| child("cvss_base_score").parse().ok()),
                exploited: child("exploit_available") == "true" || child("exploited_by_malware") == "true",
                fix: child("solution").chars().take(300).collect(),
                assets: vec![if port.is_empty() || port == "0" { host.clone() } else { format!("{host}:{port}") }],
                scanners: vec!["nessus".into()],
                occurrences: 1,
                ..Default::default()
            });
        }
    }
    out
}

/// RFC 4180-ish CSV rows (quoted fields, doubled quotes, newlines inside quotes).
pub fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = vec![];
    let (mut row, mut field, mut q) = (vec![], String::new(), false);
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        match (c, q) {
            ('"', true) if it.peek() == Some(&'"') => {
                field.push('"');
                it.next();
            }
            ('"', _) => q = !q,
            (',', false) => row.push(std::mem::take(&mut field)),
            ('\n', false) => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            ('\r', false) => {}
            (c, _) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Nessus CSV export: one row per plugin × host × CVE; rows of the same plugin/host merge.
pub fn parse_nessus_csv(text: &str) -> Vec<Finding> {
    let rows = csv_rows(text);
    let Some(head) = rows.first() else { return vec![] };
    let col = |names: &[&str]| head.iter().position(|h| names.iter().any(|n| h.trim().eq_ignore_ascii_case(n)));
    let (pid, cve, risk, host, port, name, sol) = (col(&["Plugin ID"]), col(&["CVE"]), col(&["Risk", "Severity"]), col(&["Host", "IP Address"]), col(&["Port"]), col(&["Name", "Plugin Name"]), col(&["Solution"]));
    let cvss = col(&["CVSS v3.0 Base Score", "CVSS v3 Base Score", "CVSS v2.0 Base Score", "CVSS"]);
    let exp = col(&["Exploit?", "Exploit Available"]);
    let mut out: Vec<Finding> = vec![];
    for r in rows.iter().skip(1) {
        let g = |i: Option<usize>| i.and_then(|i| r.get(i)).map(|s| s.trim().to_string()).unwrap_or_default();
        let sev = Sev::parse(&g(risk));
        if sev <= Sev::Info {
            continue;
        }
        let p = g(port);
        let asset = if p.is_empty() || p == "0" { g(host) } else { format!("{}:{p}", g(host)) };
        let id = format!("nessus-{}", g(pid));
        let c = g(cve);
        if let Some(f) = out.iter_mut().find(|f| f.id == id && f.assets[0] == asset) {
            if !c.is_empty() && !f.aliases.contains(&c) {
                f.aliases.push(c);
            }
            continue;
        }
        out.push(Finding { id, aliases: if c.is_empty() { vec![] } else { vec![c] }, title: g(name), severity: sev, cvss: g(cvss).parse().ok(), exploited: g(exp).eq_ignore_ascii_case("true") || g(exp).eq_ignore_ascii_case("yes"), fix: g(sol).chars().take(300).collect(), assets: vec![asset], scanners: vec!["nessus".into()], occurrences: 1, ..Default::default() });
    }
    out
}

/// Detect the format of one report and parse it.
pub fn parse_any(text: &str) -> Result<(&'static str, Vec<Finding>), String> {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with('<') {
        if t.contains("NessusClientData_v2") {
            return Ok(("nessus", parse_nessus_xml(t)));
        }
        return Err("XML that is not a Nessus v2 report".into());
    }
    if t.starts_with('{') {
        let v: Value = serde_json::from_str(t).map_err(|e| format!("not JSON: {e}"))?;
        if v.get("runs").is_some() {
            return Ok(("sarif", parse_sarif(&v)));
        }
        if v.get("Results").is_some() || v.get("ArtifactName").is_some() {
            return Ok(("trivy", parse_trivy(&v)));
        }
        if v.get("matches").is_some() {
            return Ok(("grype", parse_grype(&v)));
        }
        return Err("JSON that is not SARIF, Trivy or Grype output".into());
    }
    let first = t.lines().next().unwrap_or("");
    if first.contains("Plugin ID") {
        return Ok(("nessus-csv", parse_nessus_csv(t)));
    }
    Err("unrecognised report format (SARIF, Trivy JSON, Grype JSON, .nessus or Nessus CSV)".into())
}

fn fmax(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    }
}

/// Merge duplicates (same CVE/rule on the same package or asset) and apply the KEV set.
pub fn dedup(all: Vec<Finding>, kev: &BTreeSet<String>) -> Vec<Finding> {
    let mut map: BTreeMap<String, Finding> = BTreeMap::new();
    for mut f in all {
        f.exploited |= std::iter::once(&f.id).chain(f.aliases.iter()).any(|i| kev.contains(i));
        match map.get_mut(&f.key()) {
            Some(m) => {
                m.occurrences += f.occurrences;
                m.severity = m.severity.max(f.severity);
                m.cvss = fmax(m.cvss, f.cvss);
                m.epss = fmax(m.epss, f.epss);
                m.exploited |= f.exploited;
                if m.fix.is_empty() {
                    m.fix = f.fix;
                }
                if m.title.is_empty() {
                    m.title = f.title;
                }
                for a in f.aliases.into_iter().chain(std::iter::once(f.id)) {
                    if a != m.id && !m.aliases.contains(&a) {
                        m.aliases.push(a);
                    }
                }
                for x in f.assets {
                    if !m.assets.contains(&x) && m.assets.len() < 20 {
                        m.assets.push(x);
                    }
                }
                for x in f.scanners {
                    if !m.scanners.contains(&x) {
                        m.scanners.push(x);
                    }
                }
            }
            None => {
                map.insert(f.key(), f);
            }
        }
    }
    let mut v: Vec<Finding> = map.into_values().collect();
    v.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap_or(std::cmp::Ordering::Equal).then(a.canonical().cmp(&b.canonical())));
    v
}

/// CVE ids of a CISA KEV catalog (`known_exploited_vulnerabilities.json`) or a plain list.
pub fn load_kev(text: &str) -> BTreeSet<String> {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => v["vulnerabilities"].as_array().into_iter().flatten().filter_map(|x| x["cveID"].as_str().map(String::from)).collect(),
        Err(_) => text.lines().map(str::trim).filter(|l| l.starts_with("CVE-")).map(String::from).collect(),
    }
}

pub fn to_json(f: &Finding) -> Value {
    let (p, why) = f.priority();
    json!({"priority": p, "why": why, "id": f.canonical(), "ids": std::iter::once(f.id.clone()).chain(f.aliases.iter().cloned()).collect::<BTreeSet<_>>(), "title": f.title, "severity": f.severity.as_str(),
           "cvss": f.cvss, "epss": f.epss, "known_exploited": f.exploited, "fix": f.fix, "package": f.package, "assets": f.assets, "scanners": f.scanners, "occurrences": f.occurrences, "score": (f.score() * 10.0).round() / 10.0})
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

pub fn to_csv(v: &[Finding]) -> String {
    let mut o = String::from("priority,id,severity,cvss,epss,known_exploited,package,fix,assets,scanners,occurrences,title,why\n");
    for f in v {
        let (p, why) = f.priority();
        let row = [p.to_string(), f.canonical(), f.severity.as_str().into(), f.cvss.map(|c| c.to_string()).unwrap_or_default(), f.epss.map(|c| c.to_string()).unwrap_or_default(), f.exploited.to_string(), f.package.clone(), f.fix.clone(), f.assets.join(" "), f.scanners.join(" "), f.occurrences.to_string(), f.title.clone(), why];
        o.push_str(&row.iter().map(|x| csv_field(x)).collect::<Vec<_>>().join(","));
        o.push('\n');
    }
    o
}

pub struct ScanReport {
    pub cfg: Arc<Integrations>,
}

impl ScanReport {
    fn kev_path(&self, ctx: &ToolCtx, input: &Value) -> Option<PathBuf> {
        arg(input, "kev_file").map(|p| ctx.resolve(p)).or_else(|| self.cfg.str("secops", "kev_file").map(|p| ctx.resolve(&p)))
    }
}

impl Tool for ScanReport {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "scan_report".into(),
            description: "Parse vulnerability / SAST scanner reports (SARIF, Trivy JSON, Grype JSON, Nessus .nessus XML or CSV), de-duplicate across files and scanners (CVE/GHSA aliases merge) and rank by exploitability: known-exploited (KEV list, exploit available) > EPSS > CVSS > severity; each finding gets P1–P4 and the reason. `output` writes the full ranked list as .json or .csv for ticketing. Local files only, nothing is sent anywhere.".into(),
            input_schema: json!({"type":"object","properties":{
                "paths":{"type":"array","items":{"type":"string"},"description":"report files"},
                "min_severity":{"type":"string","enum":["info","low","medium","high","critical"]},
                "top":{"type":"integer","description":"findings shown (default 30)"},
                "kev_file":{"type":"string","description":"CISA KEV JSON (known_exploited_vulnerabilities.json) or a list of CVE ids"},
                "output":{"type":"string","description":"write the full ranked list here (.json or .csv)"}},"required":["paths"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut fx: Vec<Effect> = arg_list(input, "paths").iter().map(|p| Effect::Read { path: ctx.resolve(p) }).collect();
        if let Some(k) = self.kev_path(ctx, input) {
            fx.push(Effect::Read { path: k });
        }
        if let Some(o) = arg(input, "output") {
            fx.push(Effect::Write { path: ctx.resolve(o) });
        }
        fx
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let paths = arg_list(&input, "paths");
        if paths.is_empty() {
            return ToolOutput::err("`paths` (report files) is required");
        }
        let mut all = vec![];
        let mut files = vec![];
        for p in &paths {
            let path = ctx.resolve(p);
            let text = match std::fs::read(&path) {
                Ok(b) if b.len() <= 256 << 20 => String::from_utf8_lossy(&b).into_owned(),
                Ok(_) => return ToolOutput::err(format!("{} is larger than 256 MiB", path.display())),
                Err(e) => return ToolOutput::err(format!("cannot read {}: {e}", path.display())),
            };
            match parse_any(&text) {
                Ok((fmt, f)) => {
                    files.push(json!({"file": p, "format": fmt, "findings": f.len()}));
                    all.extend(f);
                }
                Err(e) => return ToolOutput::err(format!("{p}: {e}")),
            }
        }
        let raw = all.len();
        let kev = match self.kev_path(ctx, &input) {
            Some(k) => match std::fs::read_to_string(&k) {
                Ok(t) => load_kev(&t),
                Err(e) => return ToolOutput::err(format!("cannot read KEV file {}: {e}", k.display())),
            },
            None => BTreeSet::new(),
        };
        let min = arg(&input, "min_severity").map(Sev::parse).unwrap_or(Sev::Unknown);
        let ranked: Vec<Finding> = dedup(all, &kev).into_iter().filter(|f| f.severity >= min || f.exploited).collect();
        let mut by_p: BTreeMap<&str, usize> = BTreeMap::new();
        let mut by_s: BTreeMap<&str, usize> = BTreeMap::new();
        for f in &ranked {
            *by_p.entry(f.priority().0).or_default() += 1;
            *by_s.entry(f.severity.as_str()).or_default() += 1;
        }
        let mut written = Value::Null;
        if let Some(o) = arg(&input, "output") {
            let path = ctx.resolve(o);
            let body = if o.ends_with(".csv") { to_csv(&ranked) } else { serde_json::to_string_pretty(&ranked.iter().map(to_json).collect::<Vec<_>>()).unwrap_or_default() };
            if let Err(e) = path.parent().map(std::fs::create_dir_all).unwrap_or(Ok(())).and_then(|_| std::fs::write(&path, body)) {
                return ToolOutput::err(format!("cannot write {}: {e}", path.display()));
            }
            written = json!(path.display().to_string());
        }
        let top = arg_u64(&input, "top").unwrap_or(30).clamp(1, 500) as usize;
        let out = json!({"files": files, "raw_findings": raw, "unique_findings": ranked.len(), "duplicates_merged": raw.saturating_sub(ranked.len()), "kev_entries": kev.len(),
                         "by_priority": by_p, "by_severity": by_s, "written": written, "top": ranked.iter().take(top).map(to_json).collect::<Vec<_>>()});
        ToolOutput::ok(cap_output(ctx, "scan_report", serde_json::to_string_pretty(&out).unwrap_or_default(), 40_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const TRIVY: &str = r#"{"SchemaVersion":2,"ArtifactName":"api:1.2","Results":[{"Target":"api:1.2 (debian 12)","Vulnerabilities":[
        {"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","InstalledVersion":"3.0.1","FixedVersion":"3.0.9","Severity":"HIGH","Title":"openssl bug","CVSS":{"nvd":{"V3Score":7.5}}},
        {"VulnerabilityID":"CVE-2024-0002","PkgName":"zlib","InstalledVersion":"1.2","Severity":"LOW","Title":"zlib nit"}]},
        {"Target":"Dockerfile","Misconfigurations":[{"AVDID":"AVD-DS-0002","Title":"Image user should not be root","Severity":"HIGH","Status":"FAIL","Resolution":"Add USER"}]}]}"#;
    pub const GRYPE: &str = r#"{"source":{"target":{"userInput":"api:1.2"}},"matches":[
        {"vulnerability":{"id":"GHSA-aaaa","severity":"High","fix":{"state":"fixed","versions":["3.0.9"]},"epss":[{"cve":"CVE-2024-0001","epss":0.42}],"cvss":[{"metrics":{"baseScore":8.1}}]},
         "relatedVulnerabilities":[{"id":"CVE-2024-0001"}],"artifact":{"name":"openssl","version":"3.0.1","locations":[{"path":"/usr/lib/libssl.so"}]}},
        {"vulnerability":{"id":"CVE-2023-9999","severity":"Medium","fix":{"state":"not-fixed"},"knownExploited":[{"cve":"CVE-2023-9999"}]},"artifact":{"name":"curl","version":"8.0"}}]}"#;
    pub const SARIF: &str = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","rules":[{"id":"python.sqli","properties":{"security-severity":"9.1"}}]}},
        "results":[{"ruleId":"python.sqli","level":"warning","message":{"text":"SQL injection"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"},"region":{"startLine":12}}}]},
                   {"ruleId":"python.sqli","level":"warning","message":{"text":"SQL injection"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"},"region":{"startLine":12}}}]}]}]}"#;
    pub const NESSUS: &str = r#"<?xml version="1.0" ?><NessusClientData_v2><Report name="scan"><ReportHost name="10.0.0.5"><HostProperties></HostProperties>
        <ReportItem port="443" svc_name="www" protocol="tcp" severity="4" pluginID="12345" pluginName="Apache &lt;2.4.58 RCE"><cve>CVE-2023-1111</cve><cvss3_base_score>9.8</cvss3_base_score><exploit_available>true</exploit_available><solution>Upgrade to 2.4.58</solution></ReportItem>
        <ReportItem port="0" severity="0" pluginID="19506" pluginName="Scan info"></ReportItem></ReportHost></Report></NessusClientData_v2>"#;

    #[test]
    fn every_format_parses_and_duplicates_merge_across_scanners() {
        let (f1, t) = parse_any(TRIVY).unwrap();
        let (f2, g) = parse_any(GRYPE).unwrap();
        let (f3, s) = parse_any(SARIF).unwrap();
        let (f4, n) = parse_any(NESSUS).unwrap();
        assert_eq!((f1, f2, f3, f4), ("trivy", "grype", "sarif", "nessus"));
        assert_eq!((t.len(), g.len(), s.len(), n.len()), (3, 2, 2, 1));
        assert_eq!(s[0].severity, Sev::Critical, "security-severity 9.1 wins over level=warning");
        assert_eq!(n[0].assets[0], "10.0.0.5:443");
        assert_eq!(n[0].title, "Apache <2.4.58 RCE");
        let kev: BTreeSet<String> = load_kev(r#"{"vulnerabilities":[{"cveID":"CVE-2024-0002"}]}"#);
        let all = dedup(t.into_iter().chain(g).chain(s).chain(n).collect(), &kev);
        // Trivy CVE-2024-0001 and Grype GHSA-aaaa (alias CVE-2024-0001) on openssl@3.0.1 are one finding.
        let ssl = all.iter().find(|f| f.package == "openssl@3.0.1").unwrap();
        assert_eq!(ssl.canonical(), "CVE-2024-0001");
        assert_eq!(ssl.scanners, ["trivy", "grype"]);
        assert_eq!((ssl.cvss, ssl.epss, ssl.occurrences), (Some(8.1), Some(0.42), 2));
        assert_eq!(all.iter().find(|f| f.id == "python.sqli").unwrap().occurrences, 2);
        assert_eq!(all.len(), 6);
        // Known-exploited first: the Nessus RCE (critical + exploit) is P1, the KEV-listed low zlib bug outranks its severity.
        assert_eq!(all[0].canonical(), "CVE-2023-1111");
        assert_eq!(all[0].priority().0, "P1");
        let zlib = all.iter().find(|f| f.package.starts_with("zlib")).unwrap();
        assert!(zlib.exploited && zlib.priority().1.starts_with("known exploited"));
        assert!(zlib.score() > all.iter().find(|f| f.id == "AVD-DS-0002").unwrap().score());
        assert!(to_csv(&all).lines().count() == 7);
    }

    #[test]
    fn nessus_csv_rows_merge_cves_per_plugin_and_host() {
        let csv = "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Solution\n1,CVE-1,7.5,High,h1,tcp,22,\"OpenSSH, old\",Upgrade\n1,CVE-2,7.5,High,h1,tcp,22,\"OpenSSH, old\",Upgrade\n2,,,None,h1,tcp,0,Info,\n";
        let f = parse_nessus_csv(csv);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].aliases, ["CVE-1", "CVE-2"]);
        assert_eq!(f[0].title, "OpenSSH, old");
        assert!(parse_any("hello").is_err() && parse_any("{\"x\":1}").is_err());
    }

    #[test]
    fn the_tool_reads_files_writes_the_ranked_list_and_declares_both() {
        let ctx = crate::testutil::ctx("secops-report");
        std::fs::write(ctx.workspace.join("trivy.json"), TRIVY).unwrap();
        std::fs::write(ctx.workspace.join("grype.json"), GRYPE).unwrap();
        std::fs::write(ctx.workspace.join("kev.txt"), "CVE-2024-0002\n").unwrap();
        let t = ScanReport { cfg: Arc::new(Integrations::default()) };
        let input = json!({"paths": ["trivy.json", "grype.json"], "kev_file": "kev.txt", "min_severity": "medium", "output": "out/ranked.csv"});
        let fx = t.effects(&ctx, &input);
        assert_eq!(fx.len(), 4);
        assert!(matches!(&fx[3], Effect::Write { path } if path.ends_with("out/ranked.csv")));
        let o = t.call(&ctx, input);
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["raw_findings"], 5);
        assert_eq!(v["duplicates_merged"], 1);
        assert!(v["top"].as_array().unwrap().iter().any(|f| f["id"] == "CVE-2024-0002"), "KEV keeps a low finding above min_severity");
        assert!(std::fs::read_to_string(ctx.workspace.join("out/ranked.csv")).unwrap().starts_with("priority,id"));
        assert!(t.call(&ctx, json!({"paths": ["missing.json"]})).is_error);
    }
}
