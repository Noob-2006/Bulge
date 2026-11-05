//! Advisory NVIDIA SkillEvaluator Tier 1 scan on install (Hermes `tools/skillevaluator_scan.py`,
//! MIT) — alongside, never instead of, Skills Guard. Warn, don't block; a missing, crashing,
//! timed-out or unparseable scanner is a no-op. `[skills] tier1_advisory` (default on).

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const SCANNER_BIN: &str = "skillevaluator";
pub const TIER1_CHECKS: &str = "pii,unicode,lint,license,security";
/// Default per-scan timeout (Hermes `SCAN_TIMEOUT_SECONDS`).
pub const SCAN_TIMEOUT_SECONDS: u64 = 120;
const SECRETS_CLASS: &[&str] = &["database_credentials", "hardcoded_secrets", "jwt_tokens", "webhook_urls", "aws_identifiers", "github_tokens", "private_keys"];

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub check: String,
    pub validator: String,
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

impl Finding {
    /// A possible REAL credential (pii_patterns.yaml category), as opposed to PII hygiene noise.
    pub fn secrets_class(&self) -> bool {
        SECRETS_CLASS.contains(&self.check.as_str())
    }
    pub fn location(&self) -> String {
        match (self.file.is_empty(), self.line) {
            (false, l) if l > 0 => format!("{}:{l}", self.file),
            (false, _) => self.file.clone(),
            _ => "?".into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    /// The scanner ran and produced a parseable report. `false` means "no opinion" — callers must
    /// not treat `passed` as a pass in that case (`format` renders nothing and nothing is claimed).
    pub available: bool,
    pub passed: bool,
    pub findings: Vec<Finding>,
    pub incomplete: Vec<String>,
    pub error: String,
}

impl Report {
    /// Secrets-class findings, in report order (upstream `secrets_findings`).
    pub fn secrets_findings(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.secrets_class()).collect()
    }
    /// Everything else (upstream `advisory_findings`).
    pub fn advisory_findings(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| !f.secrets_class()).collect()
    }
}

fn unavailable(why: &str) -> Report {
    Report { available: false, passed: true, error: why.into(), ..Default::default() }
}

pub fn parse(report: &Value) -> Report {
    let (mut findings, mut incomplete, mut failed) = (Vec::new(), Vec::new(), false);
    for r in report["results"].as_array().into_iter().flatten() {
        let v = r["validator"].as_str().unwrap_or("unknown").to_string();
        if r["status"].as_str().unwrap_or("").eq_ignore_ascii_case("incomplete") {
            incomplete.push(v.clone());
        } else {
            failed |= !r["passed"].as_bool().unwrap_or(true);
        }
        for f in r["findings"].as_array().into_iter().flatten().filter(|f| f.is_object()) {
            let st = |k: &str| f[k].as_str().unwrap_or("").to_string();
            findings.push(Finding { check: st("check_name"), validator: v.clone(), severity: f["severity"].as_str().unwrap_or("info").to_lowercase(), message: st("message").chars().take(200).collect(), file: st("file_path"), line: f["line_number"].as_u64().unwrap_or(0) });
        }
    }
    Report { available: true, passed: !failed && findings.is_empty(), findings, incomplete, error: String::new() }
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    // `shutil.which`: only an executable regular file counts, so a non-executable stub earlier in
    // PATH cannot shadow a working scanner further down.
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|c| is_executable(c)))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

pub fn run(dir: &Path, timeout: u64) -> Report {
    match which(SCANNER_BIN) {
        Some(bin) => run_with(&bin, dir, timeout),
        None => unavailable("scanner not on PATH"),
    }
}

pub fn run_with(bin: &Path, dir: &Path, timeout: u64) -> Report {
    // Guard: the report directory goes away on every exit path, early returns included.
    let guard = seagent_core::tmp::TempDir::new("se-tier1");
    let out = guard.path().to_path_buf();
    if !out.is_dir() {
        return unavailable("no temp dir");
    }
    let child = Command::new(bin).arg("validate").arg(dir).args(["--checks", TIER1_CHECKS, "--no-dedup", "-r", "json", "-o"]).arg(&out).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&out);
            return unavailable(&format!("scanner failed to launch: {e}"));
        }
    };
    let deadline = Instant::now() + Duration::from_secs(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&out);
                return unavailable(&format!("scan timed out after {timeout}s"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return unavailable(&e.to_string()),
        }
    }
    let mut reports: Vec<_> = std::fs::read_dir(&out).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("skillevaluator-output-") && n.to_string_lossy().ends_with(".json"))).collect();
    reports.sort();
    let r = match reports.last().and_then(|p| std::fs::read_to_string(p).ok()) {
        None => unavailable("scanner produced no JSON report"),
        // Upstream reads the report as `utf-8-sig`; a BOM must not turn a real report into "unparseable".
        Some(t) => match serde_json::from_str::<Value>(t.trim_start_matches('\u{feff}')) {
            Ok(v @ Value::Object(_)) => parse(&v),
            Ok(_) => unavailable("unexpected report shape"),
            Err(e) => unavailable(&format!("unparseable report: {e}")),
        },
    };
    let _ = std::fs::remove_dir_all(&out);
    r
}

/// Console summary ("" when unavailable); secrets-class findings first, then the red-flag line the
/// hub install prints (Hermes `_print_tier1_advisory`).
pub fn format(r: &Report, limit: usize) -> String {
    if !r.available {
        return String::new();
    }
    let mut l = Vec::new();
    if r.findings.is_empty() {
        l.push(if r.incomplete.is_empty() { "SkillEvaluator Tier 1: no findings.".to_string() } else { "SkillEvaluator Tier 1: no findings from completed checks.".to_string() });
    } else {
        l.push(format!("SkillEvaluator Tier 1 (advisory): {} finding(s) — informational, verify before relying on this skill.", r.findings.len()));
        let secrets = r.secrets_findings();
        let shown: Vec<&Finding> = secrets.iter().copied().chain(r.advisory_findings()).collect();
        for f in shown.iter().take(limit) {
            l.push(format!("  [{}] {} — {}", if f.secrets_class() { "SECRETS".to_string() } else { f.severity.to_uppercase() }, f.location(), f.message));
        }
        if shown.len() > limit {
            l.push(format!("  … and {} more", shown.len() - limit));
        }
    }
    if !r.incomplete.is_empty() {
        l.push(format!("  (not run: {} — no opinion from these checks)", r.incomplete.join(", ")));
    }
    if !r.secrets_findings().is_empty() {
        l.push("Possible credentials detected above. Review the flagged lines before using this skill.".into());
    }
    l.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_format_and_fake_binary() {
        let r = parse(&json!({"results": [
            {"validator": "PII Scan", "passed": false, "findings": [{"check_name": "emails", "severity": "LOW", "message": "email found", "file_path": "SKILL.md", "line_number": 3}]},
            {"validator": "Security", "status": "incomplete", "findings": [{"check_name": "private_keys", "severity": "critical", "message": "key"}]}
        ]}));
        assert!(r.available && !r.passed && r.incomplete == ["Security"]);
        let t = format(&r, 10);
        assert!(t.contains("2 finding(s)") && t.find("[SECRETS]").unwrap() < t.find("[LOW] SKILL.md:3").unwrap() && t.contains("not run: Security"), "{t}");
        assert_eq!(format(&unavailable("x"), 10), "");
        // A fake scanner on PATH writes the JSON report.
        let d = seagent_core::tmp::scratch_path(format!("seagent-se-{}", std::process::id()));
        std::fs::create_dir_all(d.join("bin")).unwrap();
        let script = d.join("bin/skillevaluator");
        std::fs::write(&script, "#!/bin/sh\nfor a; do last=$a; done\necho '{\"results\":[{\"validator\":\"Lint\",\"passed\":true,\"findings\":[]}]}' > \"$last/skillevaluator-output-1.json\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(run_with(&script, &d, 10).passed);
        std::fs::write(&script, "#!/bin/sh\nsleep 5\n").unwrap();
        assert!(!run_with(&script, &d, 1).available, "timeout is a no-op");
        assert!(!run_with(&d.join("bin/missing"), &d, 1).available);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn secrets_class_ordering_and_red_flag_line() {
        let r = parse(&json!({"results": [{"validator": "PII Scan", "passed": false, "findings": [
            {"check_name": "emails", "severity": "low", "message": "mail", "file_path": "SKILL.md", "line_number": 2},
            {"check_name": "private_keys", "severity": "critical", "message": "key", "file_path": "keys.py", "line_number": 9}
        ]}]}));
        assert_eq!(r.secrets_findings().len(), 1, "only pii_patterns credential categories are secrets-class");
        assert_eq!(r.advisory_findings().len(), 1);
        assert_eq!(r.secrets_findings()[0].location(), "keys.py:9");
        let t = format(&r, 10);
        assert!(t.ends_with("Possible credentials detected above. Review the flagged lines before using this skill."), "{t}");
        assert!(t.find("[SECRETS] keys.py:9").unwrap() < t.find("[LOW] SKILL.md:2").unwrap(), "{t}");
        // No secrets-class finding → no red-flag line.
        let clean = parse(&json!({"results": [{"validator": "PII Scan", "passed": true, "findings": [
            {"check_name": "emails", "severity": "low", "message": "mail"}]}]}));
        assert!(!format(&clean, 10).contains("Possible credentials"));
    }

    #[test]
    fn limit_truncates_after_secrets_first_order() {
        let r = parse(&json!({"results": [{"validator": "PII Scan", "findings": [
            {"check_name": "emails", "severity": "low", "message": "a"},
            {"check_name": "emails", "severity": "low", "message": "b"},
            {"check_name": "private_keys", "severity": "critical", "message": "c"}
        ]}]}));
        let t = format(&r, 2);
        assert!(t.contains("[SECRETS] ? — c") && t.contains("… and 1 more"), "{t}");
    }

    /// A scanner that is not on PATH, not executable, hangs, crashes or writes garbage must report
    /// "unavailable" — never a silent pass (`passed` is meaningless when `available` is false).
    #[test]
    fn unavailable_is_never_a_silent_pass() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-se-unavail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let r = run_with(&d.join("nope"), &d, 1);
        assert!(!r.available && !r.error.is_empty() && format(&r, 10).is_empty(), "{r:?}");
        // An executable that produces no report at all.
        let script = d.join("skillevaluator-noop");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = run_with(&script, &d, 10);
        assert!(!r.available && r.error.contains("no JSON report"), "{r:?}");
        // Garbage instead of JSON, and a BOM-prefixed report (upstream reads `utf-8-sig`).
        let script = d.join("skillevaluator-garbage");
        std::fs::write(&script, "#!/bin/sh\nfor a; do last=$a; done\nprintf 'not json' > \"$last/skillevaluator-output-1.json\"\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!run_with(&script, &d, 10).available);
        let script = d.join("skillevaluator-bom");
        std::fs::write(&script, "#!/bin/sh\nfor a; do last=$a; done\nprintf '\\357\\273\\277{\"results\":[{\"validator\":\"Lint\",\"passed\":true}]}' > \"$last/skillevaluator-output-1.json\"\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = run_with(&script, &d, 10);
        assert!(r.available && r.passed, "BOM-prefixed report must parse: {r:?}");
        // A non-executable file is not a scanner (shutil.which semantics).
        let stub = d.join("plain-file");
        std::fs::write(&stub, "x").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable(&stub) && is_executable(&script));
        let _ = std::fs::remove_dir_all(&d);
    }
}
