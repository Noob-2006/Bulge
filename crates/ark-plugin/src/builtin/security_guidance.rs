//! `security-guidance` — fast, pattern-matched security warnings on file writes.
//!
//! Port of Hermes `plugins/security-guidance` (`__init__.py` glue, MIT) whose `patterns.py` is a
//! verbatim fork of Anthropic's `claude-plugins-official`
//! `plugins/security-guidance/hooks/patterns.py` (commit `0bde168`), Apache-2.0. The rule table
//! below is a verbatim port: **25 rules**, the same `ruleName`s, the same reminder text, the same
//! substrings/regexes and the same per-rule path gating. Pattern data: Anthropic (Apache-2.0) via
//! Hermes — see `THIRD_PARTY_NOTICES.md`.
//!
//! Upstream hooks `write_file` / `patch` / `skill_manage`, scans the new content for known
//! dangerous patterns and appends a `⚠️ Security guidance` block to the tool result; the file is
//! still written and the model self-corrects next turn. Warn-by-default because the patterns have
//! a real false-positive rate (`eval(` in a tokenizer, ECB in a test fixture);
//! `SECURITY_GUIDANCE_BLOCK=1` refuses the write instead. Here: a built-in plugin, opt-in via
//! `[builtin_plugins.security-guidance] enabled = true`, modes selected by
//! `[builtin_plugins.security-guidance] block = true` (see [`crate::builtin::guidance_block`]).
//! There is no `SECURITY_GUIDANCE_DISABLE` kill switch: not enabling the plugin is the switch.
//!
//! | upstream hook | ark event | meaning |
//! |---|---|---|
//! | `transform_tool_result` | [`HookEvent::TransformToolResult`] | warn: append the block ([`HookDecision::Modify`]) |
//! | `pre_tool_call` | [`HookEvent::PreTool`] | block: refuse the write ([`HookDecision::Block`]) |
//!
//! ## Tool mapping
//!
//! ark's file tools live in `crates/ark-tools/src/{fs.rs,plan.rs}` and are shaped differently, so
//! the upstream `tool name -> (path key, content keys)` table is re-expressed against them. A hook
//! sees `tool_input` **as the model sent it** (before each tool folds its aliases in with
//! `util::alias`), so every alias the tool accepts is checked as well as the canonical key.
//!
//! | upstream | ark tool | path | content scanned |
//! |---|---|---|---|
//! | `write_file` | `write` | `path` (`file`, `file_path`, `filename`) | `content` (`text`, `contents`, `data`) |
//! | `patch` (single edit) | `edit` | `path` (`file`, `file_path`, `filename`) | `new_string` (`new`, `new_str`, `replace`, `replacement`) |
//! | `patch` | `patch` | each `edits[].path` (falling back to the shared top-level `path`); for a V4A text in `patch` (`edits`/`input` as a string): every path that text names (`*** Update File:`, `*** Add File:`, `*** Move File: a -> b`) | that edit's `new_string`, or the whole V4A text |
//! | `patch` | `apply_patch` | the V4A paths inside `input` | `input` (`patch`, `text`, `diff`) |
//! | `skill_manage` | `skill` | `skills/<name>/SKILL.md` (the only file that tool writes) | `body` (`content`, `steps`, `instructions`, `text`) |
//!
//! Only these five tools are scanned; every other tool is ignored ([`wants`](Hook::wants)).
//!
//! ## Fidelity notes / deliberate divergences
//!
//! * A rule fires at most once per call. Upstream guaranteed that per scanned field, so a `patch`
//!   carrying the same construct in both `new_string` and `patch` could report it twice; here the
//!   findings are deduplicated by rule name across all fields of one call.
//! * `_format_warning_block` upstream began with `"\n---"` and its caller prepended `"\n\n"`
//!   (three newlines before the rule of dashes). The block starts `"\n\n---\n"` here — one
//!   blank line fewer, same rendering.
//! * The block reason's escape hatch names the config key instead of
//!   `SECURITY_GUIDANCE_BLOCK` (ark has no such env var).
//! * Rules whose regex does not compile are dropped with a warning on stderr (never a panic),
//!   as upstream logs and skips them. All 25 compile today.
//! * `script_src_without_sri`'s `integrity=` lookahead, `unsafe_yaml_load`'s `Safe` suppression
//!   and `torch_unsafe_load`'s `weights_only=True` suppression are upstream's (same windows:
//!   `<script` tag, 80 and 200 chars); the eval/exec look-behinds still exclude `.` so
//!   `model.eval()` / `redis.eval()` do not fire.

use ark_kernel::config::Config;
use ark_kernel::hooks::{Hook, HookDecision, HookEvent};
use fancy_regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Above this the scan is skipped: matching a multi-MB blob has poor signal and slows the loop
/// (upstream `_MAX_SCAN_BYTES`).
pub const MAX_SCAN_BYTES: usize = 256 * 1024;

const JS_EXTS: &[&str] = &[
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte",
];
const PY_EXTS: &[&str] = &[".py", ".pyi", ".ipynb"];
const DOC_EXTS: &[&str] = &[".md", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml"];

/// Which writes a rule applies to (upstream `path_filter` / `path_check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Every file (upstream: no path filter).
    Any,
    /// JS/TS only (`_JS_ONLY`): keeps bare `exec(` off Python's `exec()` and off prose.
    JsOnly,
    /// Python only (`_PY_ONLY`): keeps the pickle/`os.system` rules off other languages.
    PyOnly,
    /// Everything except documentation/data files (`_NOT_DOCS`): the `eval(` rule.
    NotDocs,
    /// Only `.github/workflows/*.yml|yaml`; fires on the path ALONE and never scans content.
    GithubWorkflow,
}

impl Gate {
    /// Upstream `path_filter` / `path_check` as a predicate on the written path.
    pub fn applies_to(self, path: &str) -> bool {
        let ends = |exts: &[&str]| exts.iter().any(|e| path.ends_with(e));
        match self {
            Gate::Any => true,
            Gate::JsOnly => ends(JS_EXTS),
            Gate::PyOnly => ends(PY_EXTS),
            Gate::NotDocs => !ends(DOC_EXTS),
            Gate::GithubWorkflow => {
                path.contains(".github/workflows/")
                    && (path.ends_with(".yml") || path.ends_with(".yaml"))
            }
        }
    }
}

/// One upstream rule: a name, the essay shown when it fires, a path gate and its triggers.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Upstream `ruleName`.
    pub name: &'static str,
    /// Upstream `reminder` — the warning markdown, verbatim.
    pub reminder: &'static str,
    /// Upstream `path_filter` / `path_check`.
    pub gate: Gate,
    /// Upstream `substrings` (a literal `in` beats a literal regex).
    pub substrings: &'static [&'static str],
    /// Upstream `regex`, as a source string; `fancy-regex` because the rules use look-behind.
    pub regex: Option<&'static str>,
}

/// The 25 rules, in upstream order — findings are reported in this order.
pub fn rules() -> &'static [Rule] {
    RULES
}

static RULES: &[Rule] = &[
    Rule {
        name: r#"github_actions_workflow"#,
        gate: Gate::GithubWorkflow,
        substrings: &[],
        regex: None,
        reminder: r#"⚠️ Security Warning: You are editing a GitHub Actions workflow file. Be aware of these security risks:

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
- github.head_ref"#,
    },
    Rule {
        name: r#"child_process_exec"#,
        gate: Gate::JsOnly,
        substrings: &[r#"child_process.exec"#, r#"execSync("#],
        regex: Some(r#"(?<![a-zA-Z0-9_\.])exec\("#),
        reminder: r#"⚠️ Security Warning: Using child_process.exec() can lead to command injection vulnerabilities.

exec() runs the command string through a shell, so any user input interpolated into it can inject arbitrary commands. Prefer child_process.execFile() (or spawn()) with an argument array instead of building a shell string.

Instead of:
  exec(`command ${userInput}`)

Use:
  import { execFile } from 'node:child_process'
  execFile('command', [userInput], callback)

Why execFile/spawn with an argument array is safer:
- No shell is involved, so shell metacharacters in arguments are not interpreted
- Arguments are passed directly to the program rather than interpolated into a command string

Only use exec() if you absolutely need shell features and the input is guaranteed to be safe."#,
    },
    Rule {
        name: r#"new_function_injection"#,
        gate: Gate::Any,
        substrings: &[r#"new Function"#],
        regex: None,
        reminder: r#"⚠️ Security Warning: Using new Function() with string interpolation is a CODE INJECTION vulnerability. If any variable is concatenated or interpolated into the function body string, an attacker controlling that variable can execute arbitrary code. Use safe alternatives: for property access use obj[key] or array.reduce((o, k) => o[k], root); for computation use a safe expression parser. NEVER interpolate untrusted strings into new Function() bodies."#,
    },
    Rule {
        name: r#"eval_injection"#,
        gate: Gate::NotDocs,
        substrings: &[],
        regex: Some(r#"(?<![a-zA-Z0-9_\.])eval\("#),
        reminder: r#"⚠️ Security Warning: eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data, ast.literal_eval() for Python literals, or a safe expression parser. If this is safe or is explicitly needed, briefly document that in a comment before continuing."#,
    },
    Rule {
        name: r#"react_dangerously_set_html"#,
        gate: Gate::Any,
        substrings: &[r#"dangerouslySetInnerHTML"#],
        regex: None,
        reminder: r#"⚠️ Security Warning: dangerouslySetInnerHTML can lead to XSS vulnerabilities if used with untrusted content. Ensure all content is properly sanitized using an HTML sanitizer library like DOMPurify, or use safe alternatives."#,
    },
    Rule {
        name: r#"document_write_xss"#,
        gate: Gate::Any,
        substrings: &[r#"document.write"#],
        regex: None,
        reminder: r#"⚠️ Security Warning: document.write() can be exploited for XSS attacks and has performance issues. Use DOM manipulation methods like createElement() and appendChild() instead."#,
    },
    Rule {
        name: r#"innerHTML_xss"#,
        gate: Gate::Any,
        substrings: &[r#".innerHTML ="#, r#".innerHTML="#],
        regex: None,
        reminder: r#"⚠️ Security Warning: Setting innerHTML with untrusted content can lead to XSS vulnerabilities. Use textContent for plain text or safe DOM methods for HTML content. If you need HTML support, consider using an HTML sanitizer library such as DOMPurify."#,
    },
    Rule {
        name: r#"pickle_deserialization"#,
        gate: Gate::PyOnly,
        substrings: &[],
        regex: Some(r#"(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b|(?<![a-zA-Z0-9_])pkl_load\("#),
        reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."#,
    },
    Rule {
        name: r#"os_system_injection"#,
        gate: Gate::PyOnly,
        substrings: &[r#"from os import system"#],
        regex: Some(r#"\bos\.system\s*\("#),
        reminder: r#"⚠️ Security Warning: os.system() runs a shell and is a command-injection sink. Use subprocess.run([...]) with a list of arguments instead. If this is safe or is explicitly needed, briefly document that in a comment before continuing."#,
    },
    Rule {
        name: r#"python_subprocess_shell"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(
            r#"subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True"#,
        ),
        reminder: r#"⚠️ Security Warning: Using subprocess with shell=True enables command injection.

UNSAFE:
  subprocess.run(f"ls {user_input}", shell=True)
  subprocess.call("grep " + pattern, shell=True)

SAFE - pass arguments as a list without shell:
  subprocess.run(["ls", user_input])
  subprocess.call(["grep", pattern])

When arguments are passed as a list without shell=True, special characters cannot be interpreted as shell metacharacters."#,
    },
    Rule {
        name: r#"go_exec_shell_injection"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)""#),
        reminder: r#"⚠️ Security Warning: Using exec.Command with a shell interpreter (sh/bash) enables command injection.

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
- For numeric values: parse to int/float first"#,
    },
    Rule {
        name: r#"unsafe_yaml_load"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)"#),
        reminder: r#"⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.

Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types."#,
    },
    Rule {
        name: r#"node_createcipher_no_iv"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"\bcrypto\.(createCipher|createDecipher)\b"#),
        reminder: r#"⚠️ Security Warning: Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22 and derives the key insecurely (no IV, MD5-based KDF)."#,
    },
    Rule {
        name: r#"aes_ecb_mode"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|[\x22\x27]aes-\d+-ecb[\x22\x27]"#),
        reminder: r#"⚠️ Security Warning: Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure (identical blocks encrypt to identical ciphertext)."#,
    },
    Rule {
        name: r#"tls_verification_disabled"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(
            r#"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\x22\x27]?0|ssl\._create_unverified_context|check_hostname\s*=\s*False"#,
        ),
        reminder: r#"⚠️ Security Warning: Don't disable TLS verification. This allows MITM attacks. For self-signed dev certs, add the CA to your trust store or use a properly-issued cert."#,
    },
    Rule {
        name: r#"marshal_loads"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"\bmarshal\.loads?\s*\("#),
        reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."#,
    },
    Rule {
        name: r#"shelve_open"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"\bshelve\.open\s*\("#),
        reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."#,
    },
    Rule {
        name: r#"xml_unsafe_parse"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(
            r#"\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b"#,
        ),
        reminder: r#"⚠️ Security Warning: Use defusedxml.ElementTree. Python's stdlib XML parsers are vulnerable to XXE (external entity) and billion-laughs attacks by default."#,
    },
    Rule {
        name: r#"pickle_variants_load"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\("#),
        reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."#,
    },
    Rule {
        name: r#"outerHTML_xss"#,
        gate: Gate::Any,
        substrings: &[r#".outerHTML ="#, r#".outerHTML="#],
        regex: None,
        reminder: r#"⚠️ Security Warning: Use textContent or sanitize with DOMPurify. outerHTML assignment is an XSS sink equivalent to innerHTML."#,
    },
    Rule {
        name: r#"insertAdjacentHTML_xss"#,
        gate: Gate::Any,
        substrings: &[r#".insertAdjacentHTML("#],
        regex: None,
        reminder: r#"⚠️ Security Warning: Use insertAdjacentText() or sanitize with DOMPurify. insertAdjacentHTML is an XSS sink."#,
    },
    Rule {
        name: r#"script_src_without_sri"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(
            r#"<script\s+(?![^>]{0,400}integrity\s*=)[^>]{0,200}src\s*=\s*[\x22\x27](?:https?:)?//[^\x22\x27]{1,300}[\x22\x27][^>]{0,100}>"#,
        ),
        reminder: r#"⚠️ Security Warning: Add integrity="sha384-..." crossorigin="anonymous" to external script tags. Loading scripts without Subresource Integrity exposes you to CDN compromise."#,
    },
    Rule {
        name: r#"torch_unsafe_load"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(
            r#"(?:\btorch\.load|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)"#,
        ),
        reminder: r#"⚠️ Security Warning: torch.load() defaults to weights_only=False, which unpickles arbitrary Python objects and allows arbitrary code execution.

If the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1)."#,
    },
    Rule {
        name: r#"yaml_unsafe_load_variants"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(r#"(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\("#),
        reminder: r#"⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.

Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types."#,
    },
    Rule {
        name: r#"pickle_wrapper_load"#,
        gate: Gate::Any,
        substrings: &[],
        regex: Some(
            r#"\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(|\b(?:np|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True"#,
        ),
        reminder: r#"⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."#,
    },
];

/// A rule with its regex compiled (`None` = substring-only or path-only, as upstream).
struct Compiled {
    rule: &'static Rule,
    regex: Option<Regex>,
}

/// The regexes, compiled once. A rule whose regex does not compile is dropped with a warning on
/// stderr — upstream logs and skips it, and a broken pattern must never take the session down.
fn compiled() -> &'static [Compiled] {
    static COMPILED: OnceLock<Vec<Compiled>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .filter_map(|rule| {
                let regex = match rule.regex {
                    None => None,
                    Some(pattern) => match Regex::new(pattern) {
                        Ok(re) => Some(re),
                        Err(e) => {
                            eprintln!("ark: security-guidance: skipping rule {} — invalid regex {pattern:?}: {e}", rule.name);
                            return None;
                        }
                    },
                };
                Some(Compiled { rule, regex })
            })
            .collect()
    })
}

impl Compiled {
    /// Upstream `_rule_matches`: the path gate first, then substrings OR the regex.
    fn matches(&self, path: &str, content: &str) -> bool {
        let rule = self.rule;
        if !rule.gate.applies_to(path) {
            return false;
        }
        if rule.gate == Gate::GithubWorkflow {
            // upstream `path_check`: the workflow path alone is the finding, content is ignored.
            return true;
        }
        rule.substrings.iter().any(|s| content.contains(s))
            || self
                .regex
                .as_ref()
                .is_some_and(|re| re.is_match(content).unwrap_or(false))
    }
}

/// Every rule matching `content` written to `path`, each at most once, in rule order
/// (upstream `_scan_content`). Content over [`MAX_SCAN_BYTES`] is skipped outright.
pub fn scan_content(path: &str, content: &str) -> Vec<(String, String)> {
    if content.is_empty() || content.len() > MAX_SCAN_BYTES {
        return Vec::new();
    }
    compiled()
        .iter()
        .filter(|c| c.matches(path, content))
        .map(|c| (c.rule.name.to_string(), c.rule.reminder.to_string()))
        .collect()
}

/// The file tools this hook scans — upstream `_TARGET_TOOLS` keys, mapped to ark's builtin tools.
pub const TARGET_TOOLS: &[&str] = &["write", "edit", "patch", "apply_patch", "skill"];

/// Is `tool` one of the file tools whose writes are scanned?
pub fn is_target_tool(tool: &str) -> bool {
    TARGET_TOOLS.contains(&tool)
}

/// Path keys a file tool accepts: the canonical `path` plus the aliases its `call` folds in.
/// `skill` has no path input — the only file it writes is derived from `name`.
const PATH_KEYS: &[&str] = &["path", "file", "file_path", "filename"];
/// `write` content keys.
const WRITE_CONTENT: &[&str] = &["content", "text", "contents", "data"];
/// `edit` content keys (also used for one `edits[]` entry of `patch`).
const EDIT_CONTENT: &[&str] = &["new_string", "new", "new_str", "replace", "replacement"];
/// `apply_patch` / V4A text keys.
const PATCH_TEXT: &[&str] = &["input", "patch", "text", "diff"];
/// `skill` body keys (the text that becomes `SKILL.md`).
const SKILL_CONTENT: &[&str] = &["body", "content", "steps", "instructions", "text"];

fn path_in(v: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

fn contents_in<'a>(v: &'a Value, keys: &[&str]) -> Vec<&'a str> {
    keys.iter()
        .filter_map(|k| v.get(*k).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Does this text look like a V4A patch (`*** Begin Patch` / `*** Update File: p`)? ark's `patch`
/// accepts one either in `patch` or, when `edits` is a string, in `edits`/`input`.
fn looks_like_v4a(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with("*** Begin Patch")
        || t.starts_with("*** Add File:")
        || t.starts_with("*** Update File:")
        || t.starts_with("*** Delete File:")
}

fn v4a_text(args: &Value) -> Option<&str> {
    ["patch", "edits", "input"]
        .iter()
        .filter_map(|k| args.get(*k).and_then(Value::as_str))
        .find(|s| looks_like_v4a(s))
}

/// Paths a V4A patch text writes (`*** Update File: p`, `*** Add File: p`, `*** Delete File: p`,
/// `*** Move to: p`, `*** Move File: a -> b`), deduplicated.
fn v4a_paths(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |p: &str| {
        let p = p.trim();
        if !p.is_empty() && !out.iter().any(|seen| seen == p) {
            out.push(p.to_string());
        }
    };
    for line in text.lines() {
        let t = line.trim();
        for pre in [
            "*** Add File: ",
            "*** Update File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ] {
            if let Some(p) = t.strip_prefix(pre) {
                push(p);
            }
        }
        if let Some(rest) = t.strip_prefix("*** Move File: ") {
            match rest.split_once("->") {
                Some((from, to)) => {
                    push(from);
                    push(to);
                }
                None => push(rest),
            }
        }
    }
    out
}

/// Scan a V4A text once per path it names (so the per-path gates apply); with no declared path we
/// scan it as a path-less write, like upstream scanning a raw `patch` field.
fn scan_v4a<'a>(out: &mut Vec<(String, &'a str)>, text: &'a str) {
    let paths = v4a_paths(text);
    if paths.is_empty() {
        out.push((String::new(), text));
    } else {
        for p in paths {
            out.push((p, text));
        }
    }
}

/// The (path, content) pairs one call writes — the ark equivalent of upstream's
/// `{tool: (path_key, content_keys)}` table (documented in the module header).
fn jobs<'a>(tool: &str, args: &'a Value) -> Vec<(String, &'a str)> {
    let mut out: Vec<(String, &'a str)> = Vec::new();
    match tool {
        "write" => {
            let path = path_in(args, PATH_KEYS);
            for content in contents_in(args, WRITE_CONTENT) {
                out.push((path.clone(), content));
            }
        }
        "edit" => {
            let path = path_in(args, PATH_KEYS);
            for content in contents_in(args, EDIT_CONTENT) {
                out.push((path.clone(), content));
            }
        }
        "skill" => {
            // `skill` writes `<home>/skills/<name>/SKILL.md`, nothing else.
            let path = format!("skills/{}/SKILL.md", path_in(args, &["name"]));
            for content in contents_in(args, SKILL_CONTENT) {
                out.push((path.clone(), content));
            }
        }
        "patch" => {
            let shared = path_in(args, PATH_KEYS);
            for edit in args
                .get("edits")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let path = match path_in(edit, PATH_KEYS) {
                    p if p.is_empty() => shared.clone(),
                    p => p,
                };
                for content in contents_in(edit, EDIT_CONTENT) {
                    out.push((path.clone(), content));
                }
            }
            if let Some(text) = v4a_text(args) {
                scan_v4a(&mut out, text);
            }
        }
        "apply_patch" => {
            for text in contents_in(args, PATCH_TEXT) {
                scan_v4a(&mut out, text);
            }
        }
        _ => {}
    }
    out
}

/// Findings `[(ruleName, reminder)]` for one tool call (upstream `_scan_args`). A rule fires at
/// most once per call, so the same construct in two content fields is reported once.
pub fn scan_args(tool: &str, args: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (path, content) in jobs(tool, args) {
        for (name, reminder) in scan_content(&path, content) {
            if !out.iter().any(|(seen, _)| *seen == name) {
                out.push((name, reminder));
            }
        }
    }
    out
}

/// The `⚠️ Security guidance` markdown for these findings, without the leading blank lines
/// (upstream `_format_warning_block`).
pub fn format_findings(findings: &[(String, String)]) -> String {
    let names: Vec<&str> = findings.iter().map(|(name, _)| name.as_str()).collect();
    let mut out = format!(
        "⚠️ Security guidance — {} pattern{} matched ({})\n\n",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        names.join(", ")
    );
    for (_, reminder) in findings {
        out.push_str(reminder);
        out.push_str("\n\n");
    }
    out.push_str(
        "Pattern matches can be false positives. If the construct is safe in this context, briefly document why in a code comment and continue. Otherwise, fix the code before moving on.",
    );
    out
}

/// The text appended to a tool result in warn mode: `"\n\n---\n"` + [`format_findings`].
pub fn format_block(findings: &[(String, String)]) -> String {
    format!("\n\n---\n{}", format_findings(findings))
}

/// The `pre_tool` refusal reason for block mode. Upstream ends with "unset
/// SECURITY_GUIDANCE_BLOCK and retry"; ark has no such env var, so the override names the config.
pub fn refusal(findings: &[(String, String)]) -> String {
    format!(
        "security-guidance refused this write: {}\n\nTo override, set `block = false` in `[builtin_plugins.security-guidance]` and retry.",
        format_findings(findings)
    )
}

/// An error result must not be decorated: the model already has bigger problems (upstream
/// `_on_transform_tool_result`). Accepts both spellings the kernel gives us — `tool_response`
/// carries `is_error`, and a JSON result that is an error object has only `error` (+1 key).
fn is_error_result(payload: &Value, result: &str) -> bool {
    if payload
        .get("tool_response")
        .and_then(|r| r.get("is_error"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    match serde_json::from_str::<Value>(result) {
        Ok(Value::Object(o)) => o.contains_key("error") && o.len() <= 2,
        _ => false,
    }
}

/// The hook: warn on `TransformToolResult` (default) or refuse on `PreTool` (`block = true`).
pub struct Guidance {
    block: bool,
}

impl Guidance {
    pub fn new(cfg: &Config) -> Guidance {
        Guidance {
            block: crate::builtin::guidance_block(cfg),
        }
    }

    /// Block mode (upstream `SECURITY_GUIDANCE_BLOCK=1`).
    pub fn blocking(&self) -> bool {
        self.block
    }
}

impl Hook for Guidance {
    fn name(&self) -> String {
        "builtin:security-guidance".into()
    }

    fn wants(&self, event: HookEvent, tool: Option<&str>) -> bool {
        matches!(event, HookEvent::PreTool | HookEvent::TransformToolResult)
            && tool.is_some_and(is_target_tool)
    }

    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        let tool = payload
            .get("tool_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let null = Value::Null;
        let args = payload.get("tool_input").unwrap_or(&null);
        match event {
            HookEvent::PreTool => {
                // Upstream `_on_pre_tool_call`: a refusal in block mode, otherwise nothing to do.
                if !self.block {
                    return Ok(HookDecision::Allow);
                }
                let findings = scan_args(tool, args);
                if findings.is_empty() {
                    Ok(HookDecision::Allow)
                } else {
                    Ok(HookDecision::Block(refusal(&findings)))
                }
            }
            HookEvent::TransformToolResult => {
                // Upstream `_on_transform_tool_result`: warn mode only — in block mode the tool
                // never ran, so there is no result to wrap.
                if self.block {
                    return Ok(HookDecision::Allow);
                }
                let Some(result) = payload.get("result").and_then(Value::as_str) else {
                    return Ok(HookDecision::Allow);
                };
                if is_error_result(payload, result) {
                    return Ok(HookDecision::Allow);
                }
                let findings = scan_args(tool, args);
                if findings.is_empty() {
                    Ok(HookDecision::Allow)
                } else {
                    Ok(HookDecision::Modify(Value::String(format!(
                        "{result}{}",
                        format_block(&findings)
                    ))))
                }
            }
            _ => Ok(HookDecision::Allow),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A `Config` with `[builtin_plugins.security-guidance] enabled = true, block = …`.
    fn cfg(block: bool) -> Config {
        let mut cfg = Config::default();
        let mut table = toml::Table::new();
        table.insert("enabled".into(), toml::Value::Boolean(true));
        table.insert("block".into(), toml::Value::Boolean(block));
        cfg.builtin_plugins
            .insert("security-guidance".into(), toml::Value::Table(table));
        cfg
    }

    fn payload(tool: &str, input: Value, result: &str) -> Value {
        json!({
            "session_id": "s-security-guidance",
            "cwd": "/tmp",
            "tool_name": tool,
            "tool_input": input,
            "tool_response": {"is_error": false},
            "result": result,
        })
    }

    fn names(tool: &str, args: &Value) -> Vec<String> {
        scan_args(tool, args)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    fn modified(decision: HookDecision) -> String {
        match decision {
            HookDecision::Modify(Value::String(text)) => text,
            other => panic!("expected Modify(String), got {other:?}"),
        }
    }

    fn blocked(decision: HookDecision) -> String {
        match decision {
            HookDecision::Block(reason) => reason,
            other => panic!("expected Block, got {other:?}"),
        }
    }

    /// (path, content, expected rule) — one sample per upstream rule.
    fn positives() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (
                "repo/.github/workflows/ci.yml",
                "on: push\n",
                "github_actions_workflow",
            ),
            (
                "src/app.ts",
                "import cp from 'child_process';\nexec(`ls ${userInput}`);",
                "child_process_exec",
            ),
            (
                "src/app.js",
                "const f = new Function('return ' + x);",
                "new_function_injection",
            ),
            ("src/app.py", "result = eval(user_input)", "eval_injection"),
            (
                "src/App.tsx",
                "return <div dangerouslySetInnerHTML={{__html: html}} />;",
                "react_dangerously_set_html",
            ),
            ("src/app.js", "document.write(html);", "document_write_xss"),
            ("src/app.js", "el.innerHTML = userInput;", "innerHTML_xss"),
            (
                "src/app.py",
                "import pickle\ndata = pickle.loads(blob)",
                "pickle_deserialization",
            ),
            (
                "src/app.py",
                "import os\nos.system('ls ' + d)",
                "os_system_injection",
            ),
            (
                "src/app.py",
                "subprocess.run(cmd, shell=True)",
                "python_subprocess_shell",
            ),
            (
                "main.go",
                "exec.Command(\"sh\", \"-c\", cmd)",
                "go_exec_shell_injection",
            ),
            ("src/app.py", "cfg = yaml.load(stream)", "unsafe_yaml_load"),
            (
                "src/app.js",
                "const c = crypto.createCipher('aes192', key);",
                "node_createcipher_no_iv",
            ),
            ("src/app.py", "cipher = AES.MODE_ECB", "aes_ecb_mode"),
            (
                "src/app.py",
                "requests.get(url, verify=False)",
                "tls_verification_disabled",
            ),
            ("src/app.py", "obj = marshal.loads(blob)", "marshal_loads"),
            ("src/app.py", "db = shelve.open('cache')", "shelve_open"),
            ("src/app.py", "tree = ET.parse(path)", "xml_unsafe_parse"),
            (
                "src/app.py",
                "obj = cloudpickle.loads(blob)",
                "pickle_variants_load",
            ),
            ("src/app.js", "el.outerHTML = userInput;", "outerHTML_xss"),
            (
                "src/app.js",
                "el.insertAdjacentHTML('beforeend', html);",
                "insertAdjacentHTML_xss",
            ),
            (
                "public/index.html",
                "<script src=\"https://cdn.example.com/x.js\"></script>",
                "script_src_without_sri",
            ),
            (
                "src/model.py",
                "ckpt = torch.load(path)",
                "torch_unsafe_load",
            ),
            (
                "src/app.py",
                "cfg = yaml.unsafe_load(stream)",
                "yaml_unsafe_load_variants",
            ),
            ("src/app.py", "joblib.load(path)", "pickle_wrapper_load"),
        ]
    }

    #[test]
    fn all_rules_compile_and_count_matches_upstream() {
        // 25 rules in upstream order, 18 of them regex-driven, every regex compiles.
        assert_eq!(rules().len(), 25);
        assert_eq!(rules().iter().filter(|r| r.regex.is_some()).count(), 18);
        assert_eq!(
            compiled().len(),
            rules().len(),
            "a rule's regex failed to compile"
        );
        let expected = [
            "github_actions_workflow",
            "child_process_exec",
            "new_function_injection",
            "eval_injection",
            "react_dangerously_set_html",
            "document_write_xss",
            "innerHTML_xss",
            "pickle_deserialization",
            "os_system_injection",
            "python_subprocess_shell",
            "go_exec_shell_injection",
            "unsafe_yaml_load",
            "node_createcipher_no_iv",
            "aes_ecb_mode",
            "tls_verification_disabled",
            "marshal_loads",
            "shelve_open",
            "xml_unsafe_parse",
            "pickle_variants_load",
            "outerHTML_xss",
            "insertAdjacentHTML_xss",
            "script_src_without_sri",
            "torch_unsafe_load",
            "yaml_unsafe_load_variants",
            "pickle_wrapper_load",
        ];
        assert_eq!(rules().iter().map(|r| r.name).collect::<Vec<_>>(), expected);
        for rule in rules() {
            assert!(
                rule.reminder.starts_with('⚠'),
                "{} lost its warning markdown",
                rule.name
            );
            assert!(
                rule.substrings.iter().all(|s| !s.is_empty()),
                "{}",
                rule.name
            );
            if rule.gate == Gate::GithubWorkflow {
                assert_eq!(
                    (rule.substrings.len(), rule.regex.is_some()),
                    (0, false),
                    "path_check rules never scan content"
                );
            }
        }
        // The gates are upstream's.
        let gate = |name: &str| rules().iter().find(|r| r.name == name).map(|r| r.gate);
        assert_eq!(gate("pickle_deserialization"), Some(Gate::PyOnly));
        assert_eq!(gate("os_system_injection"), Some(Gate::PyOnly));
        assert_eq!(gate("child_process_exec"), Some(Gate::JsOnly));
        assert_eq!(gate("eval_injection"), Some(Gate::NotDocs));
        assert_eq!(gate("unsafe_yaml_load"), Some(Gate::Any));
    }

    #[test]
    fn each_rule_fires_on_a_sample() {
        for (path, content, rule) in positives() {
            let got = names("write", &json!({"path": path, "content": content}));
            assert!(
                got.iter().any(|n| n == rule),
                "{rule} did not fire on {path}: {got:?}"
            );
            assert_eq!(
                scan_content(path, content).len(),
                got.len(),
                "scan_content and scan_args disagree"
            );
        }
    }

    #[test]
    fn path_gating_keeps_python_rules_off_javascript_and_docs() {
        // `_PY_ONLY`: no Python rules on JS/TS or on prose/data.
        for path in ["src/app.js", "src/app.tsx", "README.md", "config.yaml"] {
            let got = names(
                "write",
                &json!({"path": path, "content": "pickle.loads(blob)\nos.system(cmd)"}),
            );
            assert!(got.is_empty(), "{path}: {got:?}");
        }
        // `_JS_ONLY`: the bare-`exec(` rule stays off Python and prose.
        for path in ["src/app.py", "notes.md"] {
            let got = names(
                "write",
                &json!({"path": path, "content": "exec(`ls ${x}`)"}),
            );
            assert!(
                !got.contains(&"child_process_exec".to_string()),
                "{path}: {got:?}"
            );
        }
        // `_NOT_DOCS`: the eval rule skips docs/data files but any-gated rules still fire there.
        assert!(names("write", &json!({"path": "notes.md", "content": "eval(x)"})).is_empty());
        assert!(names("write", &json!({"path": "data.json", "content": "eval(x)"})).is_empty());
        assert_eq!(
            names("write", &json!({"path": "src/a.js", "content": "eval(x)"})),
            ["eval_injection"]
        );
        // github-actions `path_check`: the workflow path alone fires; lookalikes do not.
        assert_eq!(
            names(
                "write",
                &json!({"path": "repo/.github/workflows/ci.yml", "content": "on: push\n"})
            ),
            ["github_actions_workflow"]
        );
        assert_eq!(
            names(
                "write",
                &json!({"path": ".github/workflows/nightly.yaml", "content": "on: schedule\n"})
            ),
            ["github_actions_workflow"]
        );
        // an empty write is not scanned at all (upstream's `if not content`), `path_check` included
        assert!(names(
            "write",
            &json!({"path": ".github/workflows/nightly.yaml", "content": ""})
        )
        .is_empty());
        assert!(names(
            "write",
            &json!({"path": "repo/.github/ci.yml", "content": "on: push\n"})
        )
        .is_empty());
        assert!(names(
            "write",
            &json!({"path": "repo/.github/workflows/ci.sh", "content": "on: push\n"})
        )
        .is_empty());
        // The gates hold through the other tools' keys too.
        assert_eq!(
            names(
                "edit",
                &json!({"path": "src/app.py", "old_string": "", "new_string": "os.system(cmd)"})
            ),
            ["os_system_injection"]
        );
        assert!(names(
            "edit",
            &json!({"path": "src/app.js", "old_string": "", "new_string": "os.system(cmd)"})
        )
        .is_empty());
    }

    #[test]
    fn suppressions_and_lookbehind_avoid_false_positives() {
        let clean = [
            // look-behind excludes `.` so method calls are not `eval(`/`exec(` sinks
            ("src/model.py", "loss = model.eval()"),
            ("src/app.js", "redis.eval('return 1', 1)"),
            // yaml.load is `Safe`-suppressed within 80 chars
            ("src/app.py", "cfg = yaml.safe_load(stream)"),
            (
                "src/app.py",
                "cfg = yaml.load(stream, Loader=yaml.SafeLoader)",
            ),
            // torch.load is `weights_only=True`-suppressed within 200 chars
            ("src/model.py", "ckpt = torch.load(path, weights_only=True)"),
            // `<script` with an SRI hash in the tag is fine
            (
                "public/index.html",
                "<script integrity=\"sha384-abc\" src=\"https://cdn.example.com/x.js\"></script>",
            ),
            // near-misses
            ("src/app.py", "pickle.dump(obj, f)"),
            ("src/app.js", "el.textContent = user_input;"),
            ("src/app.py", "subprocess.run(cmd, shell=False)"),
            ("src/app.py", "open(path).read()"),
            ("src/app.py", "code = 'cp.exec(cmd)'"),
        ];
        for (path, content) in clean {
            let got = names("write", &json!({"path": path, "content": content}));
            assert!(got.is_empty(), "{path} fired on {content:?}: {got:?}");
        }
        // …while the suppressed constructs fire when the escape hatch is absent.
        assert_eq!(
            names(
                "write",
                &json!({"path": "src/app.py", "content": "cfg = yaml.load(stream)"})
            ),
            ["unsafe_yaml_load"]
        );
        assert_eq!(
            names(
                "write",
                &json!({"path": "src/m.py", "content": "ckpt = torch.load(path)"})
            ),
            ["torch_unsafe_load"]
        );
        assert_eq!(
            names(
                "write",
                &json!({"path": "index.html", "content": "<script src=\"//cdn.example.com/x.js\"></script>"})
            ),
            ["script_src_without_sri"]
        );
    }

    #[test]
    fn warn_mode_appends_the_guidance_block() {
        let g = Guidance::new(&cfg(false));
        assert!(!g.blocking());
        let input = json!({"path": "src/app.py", "content": "import os\nos.system(cmd)"});
        let text = modified(
            g.run(
                HookEvent::TransformToolResult,
                &payload("write", input.clone(), "wrote src/app.py"),
            )
            .unwrap(),
        );
        let findings = scan_args("write", &input);
        assert_eq!(text, format!("wrote src/app.py{}", format_block(&findings)));
        assert!(text.starts_with("wrote src/app.py\n\n---\n⚠️ Security guidance — 1 pattern matched (os_system_injection)\n\n"), "{text}");
        assert!(text.contains("os.system() runs a shell and is a command-injection sink"));
        assert!(text.ends_with("fix the code before moving on."), "{text}");
        // Plural header, names in upstream rule order.
        let two = json!({"path": "src/app.py", "content": "result = eval(x)\nos.system(cmd)"});
        let t2 = modified(
            g.run(HookEvent::TransformToolResult, &payload("write", two, "ok"))
                .unwrap(),
        );
        assert!(t2.contains("⚠️ Security guidance — 2 patterns matched (eval_injection, os_system_injection)\n\n"), "{t2}");
        assert!(
            t2.contains("eval() executes arbitrary code")
                && t2.contains("os.system() runs a shell")
        );
        // Nothing to say: clean content, non-target tools, other events.
        for p in [
            payload(
                "write",
                json!({"path": "src/a.py", "content": "x = 1"}),
                "ok",
            ),
            payload("read", json!({"path": "src/a.py"}), "os.system(cmd)"),
            payload(
                "shell",
                json!({"command": "os.system(cmd)"}),
                "os.system(cmd)",
            ),
        ] {
            assert_eq!(
                g.run(HookEvent::TransformToolResult, &p).unwrap(),
                HookDecision::Allow
            );
        }
        assert_eq!(
            g.run(
                HookEvent::PostTool,
                &payload(
                    "write",
                    json!({"path": "a.py", "content": "os.system(1)"}),
                    "ok"
                )
            )
            .unwrap(),
            HookDecision::Allow
        );
        // Warn mode never refuses.
        assert_eq!(
            g.run(
                HookEvent::PreTool,
                &payload(
                    "write",
                    json!({"path": "a.py", "content": "os.system(1)"}),
                    ""
                )
            )
            .unwrap(),
            HookDecision::Allow
        );
    }

    #[test]
    fn block_mode_refuses_the_write() {
        let g = Guidance::new(&cfg(true));
        assert!(g.blocking());
        let reason = blocked(
            g.run(
                HookEvent::PreTool,
                &payload(
                    "write",
                    json!({"path": "src/app.py", "content": "eval(user_input)"}),
                    "",
                ),
            )
            .unwrap(),
        );
        assert!(
            reason.starts_with("security-guidance refused this write: ⚠️ Security guidance — 1 pattern matched (eval_injection)\n\n"),
            "{reason}"
        );
        assert!(reason.contains("eval() executes arbitrary code"));
        assert!(
            reason.ends_with("fix the code before moving on.\n\nTo override, set `block = false` in `[builtin_plugins.security-guidance]` and retry."),
            "{reason}"
        );
        // Clean writes pass, and block mode leaves results alone (the tool never ran).
        assert_eq!(
            g.run(
                HookEvent::PreTool,
                &payload("write", json!({"path": "src/a.py", "content": "x = 1"}), "")
            )
            .unwrap(),
            HookDecision::Allow
        );
        assert_eq!(
            g.run(
                HookEvent::TransformToolResult,
                &payload(
                    "write",
                    json!({"path": "src/a.py", "content": "eval(x)"}),
                    "wrote"
                )
            )
            .unwrap(),
            HookDecision::Allow
        );
        // A refused `edit` / `patch` is refused the same way.
        assert!(blocked(
            g.run(
                HookEvent::PreTool,
                &payload(
                    "edit",
                    json!({"path": "a.py", "old_string": "x", "new_string": "pickle.loads(b)"}),
                    ""
                )
            )
            .unwrap()
        )
        .contains("(pickle_deserialization)"));
        let v4a =
            "*** Begin Patch\n*** Update File: src/a.py\n@@\n-x\n+os.system(cmd)\n*** End Patch";
        assert!(blocked(
            g.run(
                HookEvent::PreTool,
                &payload("apply_patch", json!({"input": v4a}), "")
            )
            .unwrap()
        )
        .contains("(os_system_injection)"));
        // The failure path is a decision, never an error.
        assert!(g.run(HookEvent::PreTool, &Value::Null).is_ok());
    }

    #[test]
    fn error_results_are_not_decorated() {
        let g = Guidance::new(&cfg(false));
        let input = json!({"path": "src/app.py", "content": "os.system(cmd)"});
        // `tool_response.is_error`
        let mut p = payload("write", input.clone(), "Error: no space left on device");
        p["tool_response"]["is_error"] = json!(true);
        assert_eq!(
            g.run(HookEvent::TransformToolResult, &p).unwrap(),
            HookDecision::Allow
        );
        // a JSON error object: `error` plus at most one other key
        for result in [
            r#"{"error": "refusing to overwrite"}"#,
            r#"{"error": "e", "path": "a.py"}"#,
        ] {
            assert_eq!(
                g.run(
                    HookEvent::TransformToolResult,
                    &payload("write", input.clone(), result)
                )
                .unwrap(),
                HookDecision::Allow,
                "{result}"
            );
        }
        // a real result that merely carries an `error` field among others is still decorated
        let text = modified(
            g.run(
                HookEvent::TransformToolResult,
                &payload(
                    "write",
                    input,
                    r#"{"error": "e", "path": "a.py", "wrote": true}"#,
                ),
            )
            .unwrap(),
        );
        assert!(text.contains("(os_system_injection)"), "{text}");
        // non-JSON results are decorated as usual
        assert!(modified(
            g.run(
                HookEvent::TransformToolResult,
                &payload(
                    "write",
                    json!({"path": "a.py", "content": "eval(x)"}),
                    "not json"
                )
            )
            .unwrap()
        )
        .contains("(eval_injection)"));
    }

    #[test]
    fn wants_covers_only_the_file_tools_and_the_two_events() {
        let g = Guidance::new(&cfg(false));
        for &tool in TARGET_TOOLS {
            assert!(g.wants(HookEvent::PreTool, Some(tool)), "{tool}");
            assert!(
                g.wants(HookEvent::TransformToolResult, Some(tool)),
                "{tool}"
            );
            assert!(!g.wants(HookEvent::PostTool, Some(tool)), "{tool}");
            assert!(!g.wants(HookEvent::ToolRequest, Some(tool)), "{tool}");
            assert!(!g.wants(HookEvent::UserPrompt, Some(tool)), "{tool}");
        }
        for tool in ["read", "shell", "grep", "patch_other"] {
            assert!(!g.wants(HookEvent::PreTool, Some(tool)), "{tool}");
            assert!(
                !g.wants(HookEvent::TransformToolResult, Some(tool)),
                "{tool}"
            );
            assert!(!is_target_tool(tool), "{tool}");
        }
        assert!(!g.wants(HookEvent::PreTool, None));
        assert!(!g.wants(HookEvent::TransformToolResult, None));
        assert_eq!(g.name(), "builtin:security-guidance");
    }

    #[test]
    fn patch_apply_patch_and_skill_inputs_are_scanned() {
        // V4A: the path inside the text decides the gate.
        let py = "*** Begin Patch\n*** Update File: src/app.py\n@@\n-old\n+os.system(cmd)\n*** End Patch";
        assert_eq!(
            names("apply_patch", &json!({"input": py})),
            ["os_system_injection"]
        );
        let doc = "*** Begin Patch\n*** Update File: notes.md\n+pickle.loads(b)\n*** End Patch";
        assert!(names("apply_patch", &json!({"input": doc})).is_empty());
        let js =
            "*** Begin Patch\n*** Add File: public/app.js\n+el.innerHTML = data;\n*** End Patch";
        assert_eq!(names("patch", &json!({"patch": js})), ["innerHTML_xss"]);
        // `patch` with `edits`: each edit is gated by its own path.
        let edits = json!({"edits": [
            {"path": "src/app.py", "old_string": "a", "new_string": "os.system(cmd)"},
            {"path": "src/a.ts", "old_string": "b", "new_string": "el.innerHTML = x"},
        ]});
        assert_eq!(
            names("patch", &edits),
            ["os_system_injection", "innerHTML_xss"]
        );
        // one rule in two edits is reported once per call
        let dup = json!({"edits": [
            {"path": "a.py", "old_string": "", "new_string": "os.system(x)"},
            {"path": "b.py", "old_string": "", "new_string": "os.system(y)"},
        ]});
        assert_eq!(names("patch", &dup), ["os_system_injection"]);
        // `skill`: the body becomes SKILL.md (a doc), so any-gated rules fire and `_NOT_DOCS` does not
        let body = "return <div dangerouslySetInnerHTML={{__html: h}} />;";
        assert_eq!(
            names(
                "skill",
                &json!({"action": "create", "name": "x", "body": body})
            ),
            ["react_dangerously_set_html"]
        );
        assert!(names(
            "skill",
            &json!({"action": "create", "name": "x", "body": "eval(q)"})
        )
        .is_empty());
        // `write` aliases are honoured
        assert_eq!(
            names(
                "write",
                &json!({"file": "src/a.py", "text": "os.system(cmd)"})
            ),
            ["os_system_injection"]
        );
        // oversized content and non-file tools are skipped
        let big = format!("os.system(x){}", "a".repeat(MAX_SCAN_BYTES));
        assert!(names("write", &json!({"path": "a.py", "content": big})).is_empty());
        assert!(names("read", &json!({"path": "a.py", "content": "os.system(x)"})).is_empty());
    }
}
