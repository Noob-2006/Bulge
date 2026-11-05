//! Security guidance on file writes: a fast, local, pattern-matched advisory appended to the
//! result of the `write` / `edit` / `patch` / `apply_patch` tools. The file is still written and
//! the warning rides back to the model so it can self-correct next turn. Port of Hermes
//! `plugins/security-guidance` (`__init__.py`, MIT); the rule table is a verbatim fork of
//! Anthropic's `claude-plugins-official` `plugins/security-guidance/hooks/patterns.py`
//! (commit `0bde168`), Apache-2.0 — see `THIRD_PARTY_NOTICES.md`.
//!
//! Warn by default; `SECURITY_GUIDANCE_BLOCK=1` refuses the write instead and
//! `SECURITY_GUIDANCE_DISABLE=1` is a kill switch (both as upstream). Hosts gate the whole thing
//! with `files.security_guidance`. One divergence: Hermes re-warns on every write, here a rule
//! fires at most once per (session, file, rule) so a repeated edit does not repeat the essay.

use fancy_regex::Regex;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

/// Above this the scan is skipped: matching a multi-MB blob has poor signal and slows the loop.
pub const MAX_SCAN_BYTES: usize = 256 * 1024;

const JS_EXTS: &[&str] = &[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"];
const PY_EXTS: &[&str] = &[".py", ".pyi", ".ipynb"];
const DOC_EXTS: &[&str] = &[".md", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml"];

/// Which writes a rule applies to (upstream `path_filter` / `path_check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// Every file.
    Any,
    /// JavaScript / TypeScript only (keeps bare `exec(` off Python's `exec()` and prose).
    Js,
    /// Python only (pickle, `os.system`).
    Py,
    /// Everything except documentation / data files (the `eval(` rule).
    NotDocs,
    /// Only `.github/workflows/*.yml|yaml`; fires on the path alone and never scans content.
    GithubWorkflow,
}

/// One rule: a name, the essay shown when it fires, a file gate and its triggers.
struct Rule {
    name: &'static str,
    reminder: &'static str,
    gate: Gate,
    /// Literal triggers (`in` beats a literal regex, as upstream).
    substrings: &'static [&'static str],
    /// Optional regex trigger; rules with neither substrings nor a regex never fire.
    regex: Option<&'static str>,
}

impl Rule {
    fn applies_to(&self, path: &str) -> bool {
        let ends = |exts: &[&str]| exts.iter().any(|e| path.ends_with(e));
        match self.gate {
            Gate::Any => true,
            Gate::Js => ends(JS_EXTS),
            Gate::Py => ends(PY_EXTS),
            Gate::NotDocs => !ends(DOC_EXTS),
            Gate::GithubWorkflow => path.contains(".github/workflows/") && (path.ends_with(".yml") || path.ends_with(".yaml")),
        }
    }
}

/// The 25 rules in upstream order; findings are reported in this order.
static RULES: &[Rule] = &[
    Rule { name: "github_actions_workflow", gate: Gate::GithubWorkflow, substrings: &[], regex: None, reminder: r#"⚠️ Security Warning: You are editing a GitHub Actions workflow file. Be aware of these security risks:

1. **Command Injection**: Never use untrusted input (like issue titles, PR descriptions, commit messages) directly in run: commands without proper escaping
2. **Use environment variables**: Instead of ${{ github.event.issue.title }}, use env: with proper quoting
3. **Review the guide**: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/

Example of UNSAFE pattern to avoid:
run: echo "${{ github.event.issue.title }}"

Example of SAFE pattern:
env:
  TITLE: ${{ github.event.issue.title }}
run: echo "$TITLE"

Other risky inputs to be careful with:
- github.event.issue.body
- github.event.pull_request.title
- github.event.pull_request.body
- github.event.comment.body
- github.event.review.body
- github.event.review_comment.body
- github.event.pages.*.page_name
- github.event.commits.*.message
- github.event.head_commit.message
- github.event.head_commit.author.email
- github.event.head_commit.author.name
- github.event.commits.*.author.email
- github.event.commits.*.author.name
- github.event.pull_request.head.ref
- github.event.pull_request.head.label
- github.event.pull_request.head.repo.default_branch
- github.event.client_payload.* (repository_dispatch events — attacker can set any field)

4. **Ref injection**: Never use untrusted input in `ref:` parameters of `actions/checkout`. For `client_payload.pr_number`, validate it matches `^[0-9]+$` before using in `ref: refs/pull/${{ ... }}/head`
- github.head_ref"# },
    Rule { name: "child_process_exec", gate: Gate::Js, substrings: &["child_process.exec", "execSync("], regex: Some(r#"(?<![a-zA-Z0-9_\.])exec\("#), reminder: r#"⚠️ Security Warning: Using child_process.exec() can lead to command injection vulnerabilities.

exec() runs the command string through a shell, so any user input interpolated into it can inject arbitrary commands. Prefer child_process.execFile() (or spawn()) with an argument array instead of building a shell string.

Instead of:
  exec(`command ${userInput}`)

Use:
  import { execFile } from 'node:child_process'
  execFile('command', [userInput], callback)

Why execFile/spawn with an argument array is safer:
- No shell is involved, so shell metacharacters in arguments are not interpreted
- Arguments are passed directly to the program rather than interpolated into a command string

Only use exec() if you absolutely need shell features and the input is guaranteed to be safe."# },
    Rule { name: "new_function_injection", gate: Gate::Any, substrings: &["new Function"], regex: None, reminder: r#"⚠️ Security Warning: Using new Function() with string interpolation is a CODE INJECTION vulnerability. If any variable is concatenated or interpolated into the function body string, an attacker controlling that variable can execute arbitrary code. Use safe alternatives: for property access use obj[key] or array.reduce((o, k) => o[k], root); for computation use a safe expression parser. NEVER interpolate untrusted strings into new Function() bodies."# },
    Rule { name: "eval_injection", gate: Gate::NotDocs, substrings: &[], regex: Some(r#"(?<![a-zA-Z0-9_\.])eval\("#), reminder: r#"⚠️ Security Warning: eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data, ast.literal_eval() for Python literals, or a safe expression parser. If this is safe or is explicitly needed, briefly document that in a comment before continuing."# },
    Rule { name: "react_dangerously_set_html", gate: Gate::Any, substrings: &["dangerouslySetInnerHTML"], regex: None, reminder: r#"⚠️ Security Warning: dangerouslySetInnerHTML can lead to XSS vulnerabilities if used with untrusted content. Ensure all content is properly sanitized using an HTML sanitizer library like DOMPurify, or use safe alternatives."# },
    Rule { name: "document_write_xss", gate: Gate::Any, substrings: &["document.write"], regex: None, reminder: r#"⚠️ Security Warning: document.write() can be exploited for XSS attacks and has performance issues. Use DOM manipulation methods like createElement() and appendChild() instead."# },
    Rule { name: "innerHTML_xss", gate: Gate::Any, substrings: &[".innerHTML =", ".innerHTML="], regex: None, reminder: r#"⚠️ Security Warning: Setting innerHTML with untrusted content can lead to XSS vulnerabilities. Use textContent for plain text or safe DOM methods for HTML content. If you need HTML support, consider using an HTML sanitizer library such as DOMPurify."# },
    Rule { name: "pickle_deserialization", gate: Gate::Py, substrings: &[], regex: Some(r#"(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b|(?<![a-zA-Z0-9_])pkl_load\("#), reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."# },
    Rule { name: "os_system_injection", gate: Gate::Py, substrings: &["from os import system"], regex: Some(r#"\bos\.system\s*\("#), reminder: r#"⚠️ Security Warning: os.system() runs a shell and is a command-injection sink. Use subprocess.run([...]) with a list of arguments instead. If this is safe or is explicitly needed, briefly document that in a comment before continuing."# },
    Rule { name: "python_subprocess_shell", gate: Gate::Any, substrings: &[], regex: Some(r#"subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True"#), reminder: r#"⚠️ Security Warning: Using subprocess with shell=True enables command injection.

UNSAFE:
  subprocess.run(f"ls {user_input}", shell=True)
  subprocess.call("grep " + pattern, shell=True)

SAFE - pass arguments as a list without shell:
  subprocess.run(["ls", user_input])
  subprocess.call(["grep", pattern])

When arguments are passed as a list without shell=True, special characters cannot be interpreted as shell metacharacters."# },
    Rule { name: "go_exec_shell_injection", gate: Gate::Any, substrings: &[], regex: Some(r#"exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)""#), reminder: r#"⚠️ Security Warning: Using exec.Command with a shell interpreter (sh/bash) enables command injection.

UNSAFE:
  exec.Command("sh", "-c", "ping -c 1 " + host)
  exec.Command("bash", "-c", fmt.Sprintf("df -h %s", path))

SAFE - pass arguments directly without a shell:
  exec.Command("ping", "-c", "1", host)
  exec.Command("df", "-h", path)

When arguments are passed directly (not through a shell), special characters in user input cannot be interpreted as shell metacharacters. This prevents command injection entirely.

Additionally, validate user inputs:
- For hostnames/IPs: use net.ParseIP() or a hostname regex
- For file paths: use filepath.Clean() and verify the result is within an allowed directory
- For numeric values: parse to int/float first"# },
    Rule { name: "unsafe_yaml_load", gate: Gate::Any, substrings: &[], regex: Some(r#"\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)"#), reminder: r#"⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.

Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types."# },
    Rule { name: "node_createcipher_no_iv", gate: Gate::Any, substrings: &[], regex: Some(r#"\bcrypto\.(createCipher|createDecipher)\b"#), reminder: r#"⚠️ Security Warning: Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22 and derives the key insecurely (no IV, MD5-based KDF)."# },
    Rule { name: "aes_ecb_mode", gate: Gate::Any, substrings: &[], regex: Some(r#"\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|[\x22\x27]aes-\d+-ecb[\x22\x27]"#), reminder: r#"⚠️ Security Warning: Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure (identical blocks encrypt to identical ciphertext)."# },
    Rule { name: "tls_verification_disabled", gate: Gate::Any, substrings: &[], regex: Some(r#"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\x22\x27]?0|ssl\._create_unverified_context|check_hostname\s*=\s*False"#), reminder: r#"⚠️ Security Warning: Don't disable TLS verification. This allows MITM attacks. For self-signed dev certs, add the CA to your trust store or use a properly-issued cert."# },
    Rule { name: "marshal_loads", gate: Gate::Any, substrings: &[], regex: Some(r#"\bmarshal\.loads?\s*\("#), reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."# },
    Rule { name: "shelve_open", gate: Gate::Any, substrings: &[], regex: Some(r#"\bshelve\.open\s*\("#), reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."# },
    Rule { name: "xml_unsafe_parse", gate: Gate::Any, substrings: &[], regex: Some(r#"\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b"#), reminder: r#"⚠️ Security Warning: Use defusedxml.ElementTree. Python's stdlib XML parsers are vulnerable to XXE (external entity) and billion-laughs attacks by default."# },
    Rule { name: "pickle_variants_load", gate: Gate::Any, substrings: &[], regex: Some(r#"\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\("#), reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."# },
    Rule { name: "outerHTML_xss", gate: Gate::Any, substrings: &[".outerHTML =", ".outerHTML="], regex: None, reminder: r#"⚠️ Security Warning: Use textContent or sanitize with DOMPurify. outerHTML assignment is an XSS sink equivalent to innerHTML."# },
    Rule { name: "insertAdjacentHTML_xss", gate: Gate::Any, substrings: &[".insertAdjacentHTML("], regex: None, reminder: r#"⚠️ Security Warning: Use insertAdjacentText() or sanitize with DOMPurify. insertAdjacentHTML is an XSS sink."# },
    Rule { name: "script_src_without_sri", gate: Gate::Any, substrings: &[], regex: Some(r#"<script\s+(?![^>]{0,400}integrity\s*=)[^>]{0,200}src\s*=\s*[\x22\x27](?:https?:)?//[^\x22\x27]{1,300}[\x22\x27][^>]{0,100}>"#), reminder: r#"⚠️ Security Warning: Add integrity="sha384-..." crossorigin="anonymous" to external script tags. Loading scripts without Subresource Integrity exposes you to CDN compromise."# },
    Rule { name: "torch_unsafe_load", gate: Gate::Any, substrings: &[], regex: Some(r#"(?:\btorch\.load|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)"#), reminder: r#"⚠️ Security Warning: torch.load() defaults to weights_only=False, which unpickles arbitrary Python objects and allows arbitrary code execution.

If the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1)."# },
    Rule { name: "yaml_unsafe_load_variants", gate: Gate::Any, substrings: &[], regex: Some(r#"(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\("#), reminder: r#"⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.

Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types."# },
    Rule { name: "pickle_wrapper_load", gate: Gate::Any, substrings: &[], regex: Some(r#"\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(|\b(?:np|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True"#), reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."# },
];

/// Compiled rules; an uncompilable pattern drops its rule (upstream logs and skips).
fn compiled() -> &'static [(usize, Option<Regex>)] {
    static C: OnceLock<Vec<(usize, Option<Regex>)>> = OnceLock::new();
    C.get_or_init(|| RULES.iter().enumerate().filter_map(|(i, r)| Some((i, Regex::new(r.regex?).ok()))).collect())
}

/// A rule that fired on one write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    pub name: &'static str,
    pub reminder: &'static str,
}

/// Every rule matching `content` written to `path`, each at most once.
pub fn scan(path: &str, content: &str) -> Vec<Finding> {
    if content.is_empty() || content.len() > MAX_SCAN_BYTES {
        return vec![];
    }
    let re = compiled();
    let mut out = Vec::new();
    for (i, rule) in RULES.iter().enumerate() {
        if !rule.applies_to(path) {
            continue;
        }
        // `path_check` rules fire on the path alone and never look at the content.
        if rule.gate == Gate::GithubWorkflow || rule.substrings.iter().any(|s| content.contains(s)) {
            out.push(Finding { name: rule.name, reminder: rule.reminder });
            continue;
        }
        if let Some((_, Some(rx))) = re.iter().find(|(j, _)| *j == i) {
            if rx.is_match(content).unwrap_or(false) {
                out.push(Finding { name: rule.name, reminder: rule.reminder });
            }
        }
    }
    out
}

/// The Markdown block appended to the tool result (upstream `_format_warning_block`).
pub fn format_block(findings: &[Finding]) -> String {
    let names: Vec<&str> = findings.iter().map(|f| f.name).collect();
    let mut out = format!("⚠️ Security guidance — {} pattern{} matched ({})", findings.len(), if findings.len() == 1 { "" } else { "s" }, names.join(", "));
    for f in findings {
        out.push_str("\n\n");
        out.push_str(f.reminder);
    }
    out.push_str(
        "\n\nPattern matches can be false positives. If the construct is safe in this context, briefly document why in a code comment and continue. Otherwise, fix the code before moving on.",
    );
    out
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Environment switches (upstream `_env_flag`).
fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| truthy(&v)).unwrap_or(false)
}

/// `SECURITY_GUIDANCE_DISABLE=1`: the plugin loads but does nothing.
pub fn disabled() -> bool {
    env_flag("SECURITY_GUIDANCE_DISABLE")
}

/// `SECURITY_GUIDANCE_BLOCK=1`: refuse the write instead of warning.
pub fn blocking() -> bool {
    env_flag("SECURITY_GUIDANCE_BLOCK")
}

/// How the write path treats a match (upstream's three modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `SECURITY_GUIDANCE_DISABLE=1`: scan nothing.
    Off,
    /// Default: append the guidance block, write the file.
    Warn,
    /// `SECURITY_GUIDANCE_BLOCK=1`: refuse the write.
    Block,
}

impl Mode {
    pub fn from_env() -> Mode {
        if disabled() {
            Mode::Off
        } else if blocking() {
            Mode::Block
        } else {
            Mode::Warn
        }
    }
}

// ───────────────────── once-per-file-per-session dedup ─────────────────────

type Key = (String, String, &'static str);

fn seen() -> &'static Mutex<Option<HashSet<Key>>> {
    static S: Mutex<Option<HashSet<Key>>> = Mutex::new(None);
    &S
}

/// Drop this session's warnings (a compaction may hide the earlier result).
pub fn reset_session(session: &str) {
    if let Some(set) = seen().lock().unwrap().as_mut() {
        set.retain(|(s, _, _)| s != session);
    }
}

fn fresh(session: &str, path: &str, findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }
    let mut guard = seen().lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);
    findings.into_iter().filter(|f| set.insert((session.to_string(), path.to_string(), f.name))).collect()
}

// ───────────────────── write-path entry points ─────────────────────

/// The text a patch-style write added: new files wholesale, otherwise the lines that were not
/// there before (empty when the edit only removed or reordered lines).
pub fn added_text(before: Option<&str>, after: &str) -> String {
    let Some(before) = before else { return after.to_string() };
    let old: HashSet<&str> = before.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    after.lines().filter(|l| !l.trim().is_empty() && !old.contains(l.trim())).collect::<Vec<_>>().join("\n")
}

/// Warn-mode suffix for a tool result: the guidance block when something matched that this
/// session has not already been told about, otherwise empty. Block mode is handled by
/// [`refusal`], so nothing is appended there (the write never happened).
pub fn suffix(session: &str, path: &str, new_text: &str) -> String {
    suffix_in(Mode::from_env(), session, path, new_text)
}

/// [`suffix`] with the mode forced (hosts that already know it, tests).
pub fn suffix_in(mode: Mode, session: &str, path: &str, new_text: &str) -> String {
    if mode != Mode::Warn {
        return String::new();
    }
    let findings = fresh(session, path, scan(path, new_text));
    if findings.is_empty() {
        return String::new();
    }
    format!("\n\n---\n{}", format_block(&findings))
}

/// Block-mode refusal (`SECURITY_GUIDANCE_BLOCK=1`), `None` when the write may proceed.
pub fn refusal(session: &str, path: &str, new_text: &str) -> Option<String> {
    refusal_in(Mode::from_env(), session, path, new_text)
}

/// [`refusal`] with the mode forced (hosts that already know it, tests).
pub fn refusal_in(mode: Mode, session: &str, path: &str, new_text: &str) -> Option<String> {
    if mode != Mode::Block {
        return None;
    }
    let findings = fresh(session, path, scan(path, new_text));
    if findings.is_empty() {
        return None;
    }
    Some(format!(
        "security-guidance refused this write: {}\n\nTo override, unset SECURITY_GUIDANCE_BLOCK and retry.",
        format_block(&findings)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (file, content, expected rule) — one per rule in the table.
    fn positives() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (".github/workflows/ci.yml", "on: push\n", "github_actions_workflow"),
            ("src/app.ts", "import cp from 'child_process';\nexec(`ls ${userInput}`);", "child_process_exec"),
            ("src/app.js", "const f = new Function('return ' + x);", "new_function_injection"),
            ("src/app.py", "result = eval(user_input)", "eval_injection"),
            ("src/App.tsx", "return <div dangerouslySetInnerHTML={{__html: html}} />;", "react_dangerously_set_html"),
            ("src/app.js", "document.write(html);", "document_write_xss"),
            ("src/app.js", "el.innerHTML = userInput;", "innerHTML_xss"),
            ("src/app.py", "import pickle\ndata = pickle.loads(blob)", "pickle_deserialization"),
            ("src/app.py", "import os\nos.system('ls ' + d)", "os_system_injection"),
            ("src/app.py", "subprocess.run(cmd, shell=True)", "python_subprocess_shell"),
            ("main.go", "exec.Command(\"sh\", \"-c\", cmd)", "go_exec_shell_injection"),
            ("src/app.py", "cfg = yaml.load(stream)", "unsafe_yaml_load"),
            ("src/app.js", "const c = crypto.createCipher('aes192', key);", "node_createcipher_no_iv"),
            ("src/app.py", "cipher = AES.MODE_ECB", "aes_ecb_mode"),
            ("src/app.py", "requests.get(url, verify=False)", "tls_verification_disabled"),
            ("src/app.py", "obj = marshal.loads(blob)", "marshal_loads"),
            ("src/app.py", "db = shelve.open('cache')", "shelve_open"),
            ("src/app.py", "tree = ET.parse(path)", "xml_unsafe_parse"),
            ("src/app.py", "obj = cloudpickle.loads(blob)", "pickle_variants_load"),
            ("src/app.js", "el.outerHTML = userInput;", "outerHTML_xss"),
            ("src/app.js", "el.insertAdjacentHTML('beforeend', html);", "insertAdjacentHTML_xss"),
            ("public/index.html", "<script src=\"https://cdn.example.com/x.js\"></script>", "script_src_without_sri"),
            ("src/model.py", "ckpt = torch.load(path)", "torch_unsafe_load"),
            ("src/app.py", "cfg = yaml.unsafe_load(stream)", "yaml_unsafe_load_variants"),
            ("src/app.py", "joblib.load(path)", "pickle_wrapper_load"),
        ]
    }

    #[test]
    fn every_rule_fires_on_its_own_class() {
        for (path, content, rule) in positives() {
            let names: Vec<&str> = scan(path, content).iter().map(|f| f.name).collect();
            assert!(names.contains(&rule), "{rule} did not fire on {path}: {names:?}");
        }
        // The table is exactly the 25 upstream rules and every pattern compiles.
        assert_eq!(RULES.len(), 25);
        assert_eq!(compiled().len(), RULES.iter().filter(|r| r.regex.is_some()).count());
    }

    #[test]
    fn near_misses_do_not_fire() {
        let cases = [
            ("src/app.py", "loss = model.eval()"),
            ("src/app.js", "redis.eval('return 1', 1)"),
            ("src/app.py", "cfg = yaml.safe_load(stream)"),
            ("src/app.py", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)"),
            ("src/model.py", "ckpt = torch.load(path, weights_only=True)"),
            ("public/index.html", "<script integrity=\"sha384-abc\" src=\"https://cdn.example.com/x.js\"></script>"),
            ("src/app.py", "pickle.dump(obj, f)"),
            ("src/app.js", "os.system('ls')"),
            ("src/app.py", "code = 'cp.exec(cmd)'"),
            ("src/app.py", "subprocess.run(cmd, shell=False)"),
            ("src/app.py", "open(path).read()"),
        ];
        for (path, content) in cases {
            assert!(scan(path, content).is_empty(), "{path} fired on {content}: {:?}", scan(path, content));
        }
        // Docs and data files are skipped by the `eval(` rule; the whole scan ignores them.
        assert!(scan("README.md", "never call eval(x) in prose").is_empty());
        assert!(scan("data.json", "{\"a\": \"eval(x)\"}").is_empty());
        // A workflow path alone fires, a lookalike does not.
        assert_eq!(scan("repo/.github/workflows/nightly.yaml", "on: schedule\n").len(), 1);
        assert!(scan("repo/.github/ci.yml", "on: push\n").is_empty());
        // Oversized payloads are skipped outright.
        let big = format!("eval(x)\n{}", "a".repeat(MAX_SCAN_BYTES));
        assert!(scan("src/app.py", &big).is_empty());
    }

    #[test]
    fn findings_are_deduped_per_file_and_session_and_render_once() {
        reset_session("s-dedup");
        let p = "src/dedup_case.py";
        let content = "import os\nos.system(cmd)";
        let first = suffix("s-dedup", p, content);
        assert!(first.starts_with("\n\n---\n⚠️ Security guidance — 1 pattern matched (os_system_injection)"), "{first}");
        assert!(first.contains("os.system() runs a shell"));
        assert!(first.ends_with("fix the code before moving on."));
        assert_eq!(suffix("s-dedup", p, content), "", "second write is silent");
        assert!(suffix("s-other", p, content).contains("os_system_injection"), "other session still warns");
        reset_session("s-dedup");
        assert!(suffix("s-dedup", p, content).contains("os_system_injection"), "reset re-arms");
        assert_eq!(suffix("s-dedup", "src/clean.py", "x = 1"), "");
        let two = format_block(&scan("src/app.py", "os.system(c)\nresult = eval(x)\nmarshal.loads(b)"));
        assert!(two.contains("⚠️ Security guidance — 3 patterns matched (eval_injection, os_system_injection, marshal_loads)"), "{two}");
    }

    #[test]
    fn block_mode_and_kill_switch() {
        let p = "src/blocked.py";
        let content = "eval(user_input)";
        // Warn mode: a suffix, no refusal.
        assert!(suffix_in(Mode::Warn, "s-warn", p, content).contains("eval_injection"));
        assert!(refusal_in(Mode::Warn, "s-warn", p, content).is_none());
        // Block mode: the refusal, and no suffix (the tool never ran, as upstream).
        let r = refusal_in(Mode::Block, "s-block", p, content).unwrap_or_default();
        assert!(r.starts_with("security-guidance refused this write: ⚠️ Security guidance — 1 pattern matched (eval_injection)"), "{r}");
        assert!(r.contains("unset SECURITY_GUIDANCE_BLOCK and retry"));
        assert_eq!(suffix_in(Mode::Block, "s-block", p, content), "");
        // Off: nothing at all.
        assert_eq!((suffix_in(Mode::Off, "s-off", p, content), refusal_in(Mode::Off, "s-off", p, content)), (String::new(), None));
        // The env spelling upstream uses.
        assert!(truthy("1") && truthy("TRUE") && truthy(" yes ") && truthy("on"));
        assert!(!truthy("0") && !truthy("") && !truthy("nope"));
    }

    #[test]
    fn added_text_reports_only_new_lines() {
        assert_eq!(added_text(None, "a\nb\n"), "a\nb\n");
        let before = "x = 1\nkeep = 2\n";
        let after = "x = 1\nkeep = 2\nnew = eval(y)\n";
        assert_eq!(added_text(Some(before), after), "new = eval(y)");
        assert_eq!(added_text(Some("a\nb\n"), "a\n"), "", "pure deletions add nothing");
    }
}
