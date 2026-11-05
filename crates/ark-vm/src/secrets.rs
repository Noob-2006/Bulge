//! The "no key ever reaches the guest" enforcer (plan A4, H11; it is also where
//! B5's workspace separation is checked, one path at a time).
//!
//! A VM has no host socket, no NIC and no `{{secret:NAME}}` resolver: secrets are
//! substituted host-side at the broker (A2/A3/A4) and nowhere else. This module
//! is the last gate in front of that boundary, and it is deliberately a *filter*:
//! §0 forbids protecting the user by asking them, so nothing here prompts or
//! waits — credential-shaped environment variables are dropped, credential files
//! are refused in the workspace sync, and guest output is redacted before it is
//! logged. Isolation and dropping, never a question.
//!
//! Name matching is regex-free on purpose (no dependency, no catastrophic
//! backtracking on an attacker-supplied variable name) and copies the *idea* of
//! `ark-security`'s classifier: exact names for credential stores and sockets,
//! provider prefixes, and over-broad substrings for `KEY`/`TOKEN`/`SECRET`/… A
//! guest needs none of those, so a false positive costs a rebuild of a command's
//! environment, not correctness.

use crate::config::VmConfig;

/// One credential-looking environment variable name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NameRule {
    /// The whole name, e.g. `SSH_AUTH_SOCK`.
    Exact(&'static str),
    /// A provider/ark namespace, e.g. `OPENAI_`.
    Prefix(&'static str),
    /// A credential-shaped ending, e.g. `_PROXY` (a proxy URL may carry a login).
    Suffix(&'static str),
    /// A substring no guest variable needs, e.g. `SECRET`.
    Contains(&'static str),
}

impl NameRule {
    fn matches(&self, upper: &str) -> bool {
        match self {
            NameRule::Exact(n) => upper == *n,
            NameRule::Prefix(p) => upper.starts_with(*p),
            NameRule::Suffix(s) => upper.ends_with(*s),
            NameRule::Contains(s) => upper.contains(*s),
        }
    }

    fn reason(&self) -> String {
        match self {
            NameRule::Exact(n) => format!("`{n}` names a host credential store or socket"),
            NameRule::Prefix(p) => format!("`{p}*` is a provider/ark namespace the VM never needs"),
            NameRule::Suffix(s) => format!("name ends in `{s}` (credential-shaped)"),
            NameRule::Contains(s) => format!("name contains `{s}` (credential-shaped)"),
        }
    }
}

/// Credential stores and sockets that are named by *location*, not by content.
const EXACT_CREDENTIAL_NAMES: &[&str] =
    &["SSH_AUTH_SOCK", "GIT_ASKPASS", "GPG_AGENT_INFO", "KRB5CCNAME", "KUBECONFIG", "DOCKER_CONFIG", "NETRC"];

/// Provider namespaces: the guest reaches providers only through the broker, so a
/// guest program has no business seeing any of these (over-broad by design).
const PROVIDER_PREFIXES: &[&str] = &[
    "OPENAI_",
    "OPENROUTER_",
    "ANTHROPIC_",
    "AWS_",
    "GITHUB_",
    "GH_",
    "SLACK_",
    "DISCORD_",
    "TELEGRAM_",
    "GOOGLE_",
    "GEMINI_",
    "VERTEX_",
    "AZURE_",
    "GROQ_",
    "MISTRAL_",
    "DEEPSEEK_",
    "XAI_",
    "COHERE_",
    "TOGETHER_",
    "FIREWORKS_",
    "PERPLEXITY_",
    "TAVILY_",
    "BRAVE_",
    "SERPAPI_",
    "ELEVENLABS_",
    "MODAL_",
    "DAYTONA_",
    "VERCEL_",
    "DASHSCOPE_",
    "MOONSHOT_",
    "MINIMAX_",
    "SILICONFLOW_",
    "ZHIPU_",
    "QWEN_",
    "STRIPE_",
    "TWILIO_",
    "SENDGRID_",
    "MAILGUN_",
];

/// Host state whose *value* is a host path the guest cannot reach (the guest has
/// its own `/tmp` and cwd), so forwarding it would only mislead a build.
const HOST_ONLY_NAMES: &[&str] = &["TMPDIR", "TEMP", "TMP"];

/// `exec.vm.deny_paths` entries that are always denied, even if the config list
/// was emptied: these are credential stores, never project files (H11/A4).
const BUILTIN_DENY_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gh",
    ".config/gcloud",
    ".kube",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".htpasswd",
];

/// File names that are credentials wherever they appear (`.env` covers the whole
/// `.env*` family, so `.env.local` cannot slip past the check).
const DENY_FILE_NAMES: &[&str] = &[
    "credentials",
    "credentials.json",
    "credentials.yaml",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "netrc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
];

/// Extensions that are (almost) always key material.
const DENY_EXTENSIONS: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".pkcs12"];

/// A removed environment variable and why it was removed (for the log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub name: String,
    pub reason: String,
}

/// The filter every guest-facing environment, workspace sync and log line goes
/// through.
#[derive(Debug, Clone)]
pub struct SecretGuard {
    deny_names: Vec<NameRule>,
    deny_paths: Vec<String>,
}

impl SecretGuard {
    /// `cfg.deny_paths` plus the built-in credential names and paths.
    pub fn new(cfg: &VmConfig) -> SecretGuard {
        let mut deny_names = Vec::new();
        for n in EXACT_CREDENTIAL_NAMES {
            deny_names.push(NameRule::Exact(n));
        }
        // ARK_* first: ark's own state is never a guest concern.
        deny_names.push(NameRule::Prefix("ARK_"));
        for p in PROVIDER_PREFIXES {
            deny_names.push(NameRule::Prefix(p));
        }
        for s in ["_PROXY", "_DSN", "_COOKIE", "_AUTH", "_PASS"] {
            deny_names.push(NameRule::Suffix(s));
        }
        for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "CREDS", "PRIVATE"] {
            deny_names.push(NameRule::Contains(s));
        }

        let mut deny_paths: Vec<String> = BUILTIN_DENY_PATHS.iter().map(|s| s.to_string()).collect();
        for p in &cfg.deny_paths {
            let p = p.trim().trim_start_matches("~/").trim_matches('/');
            if !p.is_empty() && !deny_paths.iter().any(|d| d == p) {
                deny_paths.push(p.to_string());
            }
        }
        SecretGuard { deny_names, deny_paths }
    }

    /// Filter an environment vector on its way into the VM.
    ///
    /// Kept: the ordinary variables a command needs (`PATH`, `LANG`, `TERM`,
    /// `HOME`, `LC_*`, `TZ`, …). Dropped: credential-shaped names, ark-internal
    /// `ARK_*`, provider namespaces, host-only paths, proxy variables, values that
    /// still contain an unresolved `{{secret:…}}` placeholder, and values that
    /// *look* like a known token shape (an innocent name must not smuggle one in).
    pub fn filter_env(&self, env: Vec<(String, String)>) -> (Vec<(String, String)>, Vec<Dropped>) {
        let mut kept = Vec::with_capacity(env.len());
        let mut dropped = Vec::new();
        for (name, value) in env {
            if name.trim().is_empty() {
                dropped.push(Dropped { name, reason: "empty variable name".into() });
                continue;
            }
            let upper = name.to_ascii_uppercase();
            if HOST_ONLY_NAMES.contains(&upper.as_str()) {
                dropped.push(Dropped {
                    name,
                    reason: "host-only path: the guest has its own /tmp and working directory".into(),
                });
                continue;
            }
            if let Some(rule) = self.deny_names.iter().find(|r| r.matches(&upper)) {
                dropped.push(Dropped { name, reason: format!("{}: keys never enter the VM (A4/H11)", rule.reason()) });
                continue;
            }
            if value.contains("{{secret:") {
                dropped.push(Dropped {
                    name,
                    reason: "value holds an unresolved {{secret:…}} placeholder; secrets are substituted at the host broker only (A2/A4)"
                        .into(),
                });
                continue;
            }
            if let Some(shape) = secret_shape_in(&value) {
                dropped.push(Dropped {
                    name,
                    reason: format!("value looks like a {shape}; keys never enter the VM (H11)"),
                });
                continue;
            }
            kept.push((name, value));
        }
        (kept, dropped)
    }

    /// May this workspace-relative path be synced into a VM?
    ///
    /// `Some(reason)` means no. Used by the pool's before-exec sync, so a
    /// workspace that happens to contain `~/.ssh` (or a stray `key.pem`) cannot
    /// turn into a guest-readable copy of the owner's credentials.
    pub fn path_denied(&self, rel: &str) -> Option<String> {
        let mut rel = rel.trim();
        while let Some(rest) = rel.strip_prefix("./") {
            rel = rest;
        }
        if rel.is_empty() {
            return Some("empty path".into());
        }
        if rel.starts_with('/') {
            return Some(format!("`{rel}` is absolute; a VM only ever sees workspace-relative paths"));
        }
        if rel.split('/').any(|c| c == "..") {
            return Some(format!("`{rel}` leaves the workspace (`..`); it is never synced into a VM"));
        }
        let name = rel.rsplit('/').next().unwrap_or(rel);
        let lower_name = name.to_ascii_lowercase();
        if lower_name.starts_with(".env") {
            return Some(format!("`{rel}` is an environment file (`.env*` often holds keys); not synced into a VM (H11)"));
        }
        if DENY_FILE_NAMES.contains(&lower_name.as_str()) {
            return Some(format!("`{rel}` is a credential file (H11: keys never enter the VM)"));
        }
        if DENY_EXTENSIONS.iter().any(|e| lower_name.ends_with(e)) {
            return Some(format!("`{rel}` looks like key material (`{lower_name}`); not synced into a VM (H11)"));
        }
        let rel_lower = rel.to_ascii_lowercase();
        for d in &self.deny_paths {
            let d = d.to_ascii_lowercase();
            if rel_lower == d || rel_lower.starts_with(&format!("{d}/")) || rel_lower.contains(&format!("/{d}")) {
                return Some(format!("`{rel}` is under `{d}`, a host credential path that is never synced (exec.vm.deny_paths, H11/A4)"));
            }
        }
        None
    }

    /// Mask secret-shaped material in guest output before it reaches the log.
    ///
    /// Covers the token shapes ark itself handles (`sk-…`, `ghp_…`, `AKIA…`,
    /// `xoxb-…`, Google/GitLab/npm keys) and PEM private-key blocks. Ordinary text
    /// is passed through unchanged.
    pub fn redact(&self, text: &str) -> String {
        redact_tokens(&redact_pem(text))
    }

    /// Is a `{{secret:NAME}}` placeholder allowed to be resolved *inside* the
    /// guest? Never: substitution happens host-side at the broker (A2/A3/A4), so
    /// this is `false` for every name. It exists as a total function so callers
    /// can assert the rule instead of asking the user anything.
    pub fn resolve_allowed(&self, _name: &str) -> bool {
        false
    }

    /// The paths this guard refuses to sync (built-ins first, then config).
    pub fn deny_paths(&self) -> &[String] {
        &self.deny_paths
    }
}

/// `Some(description)` when `token` has the shape of a well-known credential.
fn secret_shape_in(text: &str) -> Option<&'static str> {
    for token in text.split(|c: char| !is_token_char(c)) {
        if let Some(shape) = token_shape(token) {
            return Some(shape);
        }
    }
    None
}

fn token_shape(token: &str) -> Option<&'static str> {
    let len = token.len();
    if token.starts_with("sk-") && len >= 20 {
        return Some("model-provider API key (sk-…)");
    }
    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"].iter().any(|p| token.starts_with(p)) && len >= 24 {
        return Some("GitHub token (ghp_…)");
    }
    if token.starts_with("github_pat_") && len >= 30 {
        return Some("GitHub token (github_pat_…)");
    }
    if (token.starts_with("AKIA") || token.starts_with("ASIA")) && len == 20 && token[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return Some("AWS access key id (AKIA…)");
    }
    if ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"].iter().any(|p| token.starts_with(p)) && len >= 20 {
        return Some("Slack token (xoxb-…)");
    }
    if token.starts_with("AIza") && len >= 30 {
        return Some("Google API key (AIza…)");
    }
    if token.starts_with("glpat-") && len >= 20 {
        return Some("GitLab token (glpat-…)");
    }
    if token.starts_with("npm_") && len >= 30 {
        return Some("npm token (npm_…)");
    }
    None
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Replace every token that has a known credential shape.
fn redact_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for c in text.chars() {
        if is_token_char(c) {
            token.push(c);
            continue;
        }
        flush_token(&mut out, &mut token);
        out.push(c);
    }
    flush_token(&mut out, &mut token);
    out
}

fn flush_token(out: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }
    if token_shape(token).is_some() {
        out.push_str("[REDACTED]");
    } else {
        out.push_str(token);
    }
    token.clear();
}

/// Replace PEM private-key blocks (including the single-line form) with one
/// marker; the block body is never copied.
fn redact_pem(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_block = false;
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = body.trim();
        if in_block {
            if trimmed.starts_with("-----END") && trimmed.contains("PRIVATE KEY-----") {
                in_block = false;
                out.push_str("[REDACTED PRIVATE KEY]");
                if line.ends_with('\n') {
                    out.push('\n');
                }
            }
            continue;
        }
        if trimmed.starts_with("-----BEGIN") && trimmed.contains("PRIVATE KEY-----") {
            let single_line = trimmed.find("-----END").map(|e| trimmed[e..].contains("PRIVATE KEY-----")).unwrap_or(false);
            if single_line {
                out.push_str("[REDACTED PRIVATE KEY]");
                if line.ends_with('\n') {
                    out.push('\n');
                }
            } else {
                in_block = true;
            }
            continue;
        }
        out.push_str(line);
    }
    if in_block {
        out.push_str("[REDACTED PRIVATE KEY]");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> SecretGuard {
        SecretGuard::new(&VmConfig::default())
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    #[test]
    fn filter_env_keeps_a_plain_environment_and_drops_credentials() {
        let (kept, dropped) = guard().filter_env(env(&[
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("LANG", "en_US.UTF-8"),
            ("TERM", "xterm-256color"),
            ("HOME", "/home/agent"),
            ("OPENAI_API_KEY", "placeholder"),
            ("GITHUB_TOKEN", "ghp_value"),
            ("MY_PRIVATE_THING", "x"),
            ("AWS_SECRET_ACCESS_KEY", "y"),
            ("ARK_HOME", "/home/noob/.ark"),
            ("SERVICE_URL", "https://example.test/?k={{secret:SERVICE_TOKEN}}"),
            ("HTTP_PROXY", "http://user:pass@proxy.test:3128"),
        ]));
        let names: Vec<&str> = kept.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["PATH", "LANG", "TERM", "HOME"], "only the ordinary variables survive");
        let dropped_names: Vec<&str> = dropped.iter().map(|d| d.name.as_str()).collect();
        for n in ["OPENAI_API_KEY", "GITHUB_TOKEN", "MY_PRIVATE_THING", "AWS_SECRET_ACCESS_KEY", "ARK_HOME", "SERVICE_URL", "HTTP_PROXY"] {
            assert!(dropped_names.contains(&n), "{n} must not reach the guest (dropped: {dropped_names:?})");
        }
        let placeholder = dropped.iter().find(|d| d.name == "SERVICE_URL").unwrap();
        assert!(placeholder.reason.contains("placeholder"), "the reason explains the rule: {}", placeholder.reason);
        let token = dropped.iter().find(|d| d.name == "GITHUB_TOKEN").unwrap();
        assert!(token.reason.contains("GITHUB"), "the reason names the match: {}", token.reason);
    }

    #[test]
    fn path_denied_refuses_credentials_and_allows_source() {
        let g = guard();
        for rel in [".ssh/id_ed25519", ".aws/credentials", "sub/.env", "key.pem", ".env.local", "config/id_rsa", ".git-credentials", "sub/.ssh/known_hosts"] {
            assert!(g.path_denied(rel).is_some(), "{rel} must never be synced into a VM");
        }
        assert!(g.path_denied("../outside").is_some(), "no path may leave the workspace");
        assert!(g.path_denied("/etc/passwd").is_some(), "no absolute paths");
        for rel in ["src/main.rs", "README.md", "docs/key.pem.md", "src/keys.rs", "tests/credentials_test.rs"] {
            assert!(g.path_denied(rel).is_none(), "{rel} is ordinary project code: {:?}", g.path_denied(rel));
        }
        assert!(g.path_denied(".ssh/id_ed25519").unwrap().contains(".ssh"), "the reason names the deny path");
    }

    #[test]
    fn redact_masks_token_shapes_and_pem_but_not_prose() {
        let g = guard();
        let text = concat!(
            "ordinary sentence: the quick brown fox jumps over the lazy dog.\n",
            "openai sk-abc123def456ghi789jkl012 end\n",
            "github ghp_abcdefghijklmnopqrstuvwxyz0123 end\n",
            "aws AKIAIOSFODNN7EXAMPLE end\n",
            "slack xoxb-1234-5678-abcdefghij end\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n",
            "-----END OPENSSH PRIVATE KEY-----\n",
            "after the block\n"
        );
        let out = g.redact(text);
        for secret in ["sk-abc123def456ghi789jkl012", "ghp_abcdefghijklmnopqrstuvwxyz0123", "AKIAIOSFODNN7EXAMPLE", "xoxb-1234-5678-abcdefghij", "b3BlbnNzaC1rZXktdjE"] {
            assert!(!out.contains(secret), "{secret} must not survive redaction:\n{out}");
        }
        assert!(out.contains("the quick brown fox jumps over the lazy dog."), "prose is untouched:\n{out}");
        assert!(out.contains("after the block"));
        assert_eq!(out.matches("[REDACTED PRIVATE KEY]").count(), 1, "one marker for the whole block:\n{out}");
        assert_eq!(g.redact("plain ../src/main.rs and KEY=value"), "plain ../src/main.rs and KEY=value");
    }

    #[test]
    fn resolve_allowed_is_false_for_every_name() {
        let g = guard();
        assert!(!g.resolve_allowed("OPENAI_API_KEY"));
        assert!(!g.resolve_allowed("PATH"));
        assert!(!g.resolve_allowed(""));
    }

    #[test]
    fn an_innocent_name_cannot_smuggle_a_token_value() {
        let (kept, dropped) = guard().filter_env(env(&[("BUILD_TAG", "sk-abc123def456ghi789jkl012"), ("NOTE", "hello")]));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, "NOTE");
        assert!(dropped[0].reason.contains("looks like"));
    }
}
