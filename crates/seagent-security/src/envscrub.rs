//! Secret scrubbing for child-process environments (Hermes
//! `tools/environments/local_env_policy.py`).
//!
//! Children the agent spawns (shell, background jobs, code mode, hooks, MCP servers,
//! plugins) inherit the user's environment minus the credentials seagent itself manages:
//! model-provider keys and base URLs, messaging bot tokens and seagent's internal tokens.
//! Tier-1 secrets (GitHub tokens, bot tokens, infrastructure secrets) are stripped on
//! every surface. `security.env_passthrough` / `[exec] env_passthrough` is the operator
//! opt-in for the *credential-shape* heuristic only — a variable whose name ends in
//! `_TOKEN` but whose value is ordinary data (an id, a build tag) — and can never re-allow
//! a credential: a Tier-1 name, a registered provider/bot key, a `env_strip` name or an
//! `AUXILIARY_*_API_KEY`-style internal secret is removed whatever the passthrough says
//! ([`passthrough_allows`]).
//!
//! Callers apply the scrub BEFORE adding their own `.env(...)` values, so a value a
//! tool sets on purpose (e.g. code mode's `SEAGENT_CALL_TOKEN`) still reaches the child.
//!
//! With `[security.egress_proxy] enabled = true`, [`set_proxy`] additionally points every
//! child at the local proxy (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`) and drops
//! `NO_PROXY`; the `egress_proxy` module explains why the exemption has to go.

use std::collections::{BTreeSet, HashSet};
use std::process::Command;
use std::sync::{Mutex, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// `shell` / background jobs: the user's operator shell.
    Terminal,
    /// Code mode scripts.
    Code,
    /// Lifecycle hooks configured by the user.
    Hook,
    /// MCP servers and plugins (third-party code).
    Server,
    /// OS sandboxes and containers (`[exec]` backends, OpenClaw `validateEnvVarValue`):
    /// `Server` plus the credential-shape heuristic (Hermes local_env_policy). Virtualenv
    /// markers pass: a sandbox's own venv must keep working across commands.
    Sandbox,
}

/// Provider / tool / gateway credentials seagent manages (Tier 2).
const PROVIDER_BLOCKLIST: &[&str] = &[
    "OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_API_BASE", "OPENAI_ORG_ID", "OPENAI_ORGANIZATION", "OPENROUTER_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN", "LLM_MODEL",
    "GOOGLE_API_KEY", "GEMINI_API_KEY", "VERTEX_CREDENTIALS_PATH", "GOOGLE_APPLICATION_CREDENTIALS", "DEEPSEEK_API_KEY", "MISTRAL_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY", "PERPLEXITY_API_KEY",
    "COHERE_API_KEY", "FIREWORKS_API_KEY", "XAI_API_KEY", "HELICONE_API_KEY", "PARALLEL_API_KEY", "FIRECRAWL_API_KEY", "FIRECRAWL_API_URL", "DASHSCOPE_API_KEY", "MOONSHOT_API_KEY", "MINIMAX_API_KEY",
    "SILICONFLOW_API_KEY", "ZHIPU_API_KEY", "NOUS_API_KEY", "QWEN_API_KEY", "AWS_BEARER_TOKEN_BEDROCK", "TAVILY_API_KEY", "BRAVE_API_KEY", "EXA_API_KEY", "SERPAPI_API_KEY", "ELEVENLABS_API_KEY",
    "TELEGRAM_HOME_CHANNEL", "DISCORD_HOME_CHANNEL", "SLACK_HOME_CHANNEL", "SLACK_ALLOWED_USERS", "SIGNAL_HTTP_URL", "SIGNAL_ACCOUNT", "EMAIL_ADDRESS", "EMAIL_PASSWORD", "EMAIL_IMAP_HOST", "EMAIL_SMTP_HOST",
    "GATEWAY_ALLOWED_USERS", "GH_TOKEN", "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_APP_INSTALLATION_ID", "MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "DAYTONA_API_KEY", "VERCEL_OIDC_TOKEN", "VERCEL_TOKEN",
    "SEAGENT_APP_TOKEN", "APP_TOKEN", "SEAGENT_CALL_TOKEN", "SEAGENT_WHATSAPP_BRIDGE_TOKEN", "PHOTON_PROJECT_SECRET", "PHOTON_SIDECAR_TOKEN", "RAFT_CHANNEL_TOKEN", "ZALOUSER_BRIDGE_TOKEN",
];

/// Tier 1: stripped everywhere, the highest-value secrets no child needs.
const ALWAYS_STRIP: &[&str] = &[
    "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_APP_INSTALLATION_ID", "TELEGRAM_BOT_TOKEN", "TELEGRAM_TOKEN", "DISCORD_BOT_TOKEN", "DISCORD_TOKEN", "SLACK_BOT_TOKEN",
    "SLACK_APP_TOKEN", "SLACK_SIGNING_SECRET", "GATEWAY_ALLOWED_USERS", "GATEWAY_ALLOW_ALL_USERS", "GATEWAY_RELAY_ID", "GATEWAY_RELAY_SECRET", "GATEWAY_RELAY_DELIVERY_KEY", "EMAIL_PASSWORD", "MODAL_TOKEN_ID",
    "MODAL_TOKEN_SECRET", "DAYTONA_API_KEY", "SEAGENT_APP_TOKEN",
];

/// Active-venv markers that make child `uv`/`poetry` act on the wrong project.
pub const VENV_MARKERS: &[&str] = &["VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONHOME"];

/// Credential-shaped names (`DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, `X_ACCESS_KEY`): no
/// sandbox needs them, whatever their prefix (Hermes local_env_policy heuristic).
const CREDENTIAL_SUFFIXES: &[&str] = &[
    "API_KEY", "APIKEY", "TOKEN", "PASSWORD", "PASSWD", "PRIVATE_KEY", "SECRET", "SECRET_KEY", "ACCESS_KEY", "ADMIN_KEY", "CREDENTIAL", "CREDENTIALS",
];

/// Credentials the suffix rule misses: they name a location, an id or a socket.
const NAMED_CREDENTIALS: &[&str] = &[
    "MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "DAYTONA_API_KEY", "VERCEL_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "SEAGENT_CALL_TOKEN", "SEAGENT_CALL_SOCK", "ANTHROPIC_AUTH_TOKEN", "AZURE_OPENAI_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS", "SSH_AUTH_SOCK", "SLACK_SIGNING_SECRET",
];

/// Substrings that mark a credential name on every surface (Hermes
/// `code_execution_env._SECRET_SUBSTRINGS`). "PASS" is intentionally absent: it false-positives
/// on `BYPASS_CACHE` / `COMPASS_DIR`.
const SECRET_SUBSTRINGS: &[&str] = &["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PASSWD", "AUTH", "DSN", "WEBHOOK", "CREDS", "BEARER", "APIKEY", "COOKIE"];

fn credential_shaped(upper: &str) -> bool {
    upper == "AWS_SESSION_TOKEN" || NAMED_CREDENTIALS.contains(&upper) || CREDENTIAL_SUFFIXES.iter().any(|s| upper.ends_with(s))
}

/// THE credential-name classifier: is `name` a secret whatever surface it is about to reach?
///
/// The union of the three rules the child-environment code used to keep apart:
/// * the Tier-1 list ([`ALWAYS_STRIP`]) and seagent's internal secrets (`AUXILIARY_*_API_KEY`,
///   `GATEWAY_RELAY_*_SECRET`);
/// * the sandbox credential-*shape* rules ([`CREDENTIAL_SUFFIXES`], [`NAMED_CREDENTIALS`]);
/// * the code-mode substring rule ([`SECRET_SUBSTRINGS`]: `DATABASE_DSN`, `SEAGENT_SECRET_HOME`).
///
/// Code mode (`seagent_kernel::coderun::env`) uses this as its whole name rule. The exec-sandbox
/// surface deliberately applies the narrower [`credential_shaped`] rule through [`is_blocked`],
/// so operator data that merely ends in `_KEY` (`MY_OWN_KEY`) still reaches a sandbox: every
/// name [`is_blocked`] removes is a secret name here, not the other way round.
pub fn is_secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if upper.is_empty() {
        return false;
    }
    ALWAYS_STRIP.contains(&upper.as_str()) || internal_secret(&upper) || credential_shaped(&upper) || SECRET_SUBSTRINGS.iter().any(|s| upper.contains(s))
}

/// Gate-shaped suffixes of platform authorization variables (`DISCORD_ALLOWED_CHANNELS`).
const GATE_MARKERS: &[&str] = &["_ALLOWED_", "_ALLOW_ALL_", "_ALLOW_FROM", "_ALLOW_BOTS", "_ALLOW_PUBLIC_", "_IGNORED_CHANNELS", "_NO_THREAD_CHANNELS", "_FREE_RESPONSE_CHANNELS", "_GROUP_ALLOWED"];
const GATE_PREFIXES: &[&str] = &["GATEWAY", "QQ", "TELEGRAM", "DISCORD", "SLACK", "WHATSAPP", "SIGNAL", "MATRIX", "MATTERMOST", "EMAIL", "SMS", "LINE", "FEISHU", "DINGTALK", "WECOM", "WEIXIN", "IRC", "TEAMS", "MSTEAMS", "GOOGLECHAT", "BLUEBUBBLES", "IMESSAGE"];

#[derive(Default)]
struct Policy {
    disabled: bool,
    /// Names registered at startup (provider `api_key_env`, channel token envs, secrets).
    registered: HashSet<String>,
    /// `security.env_strip`: extra names / `PREFIX_*` globs to remove.
    strip: Vec<String>,
    passthrough: Vec<String>,
}

static POLICY: RwLock<Option<Policy>> = RwLock::new(None);

fn with<R>(f: impl FnOnce(&Policy) -> R) -> R {
    let g = POLICY.read().unwrap_or_else(|p| p.into_inner());
    match g.as_ref() {
        Some(p) => f(p),
        None => f(&Policy::default()),
    }
}

fn with_mut(f: impl FnOnce(&mut Policy)) {
    let mut g = POLICY.write().unwrap_or_else(|p| p.into_inner());
    f(g.get_or_insert_with(Policy::default))
}

/// `[security] scrub_env / env_strip / env_passthrough`.
pub fn configure(enabled: bool, strip: &[String], passthrough: &[String]) {
    with_mut(|p| {
        p.disabled = !enabled;
        p.strip = strip.to_vec();
        p.passthrough = passthrough.to_vec();
    });
}

/// Register credential env names discovered from config (provider keys, channel tokens).
pub fn register<I: IntoIterator<Item = S>, S: AsRef<str>>(names: I) {
    with_mut(|p| {
        for n in names {
            let n = n.as_ref().trim();
            if !n.is_empty() {
                p.registered.insert(n.to_ascii_uppercase());
            }
        }
    });
}

/// Names a sandbox may forward (`security.env_passthrough`), never a blocked one.
pub fn passthrough() -> Vec<String> {
    with(|p| p.passthrough.clone()).into_iter().filter(|n| !is_blocked(n, Surface::Server)).collect()
}

/// May `security.env_passthrough` / `[exec] env_passthrough` forward `name` into a child?
///
/// `Surface::Sandbox` is `Surface::Server` plus the credential-*shape* heuristic, and the
/// passthrough is the operator's opt-in for exactly that gap: a variable that merely looks
/// like a credential (`BUILD_TOKEN` holding a build tag) can be forwarded. Everything the
/// narrower surface already blocks — Tier-1 secrets, registered provider / bot credentials,
/// `security.env_strip` names, platform authorization gates — is an seagent-managed credential
/// and is never re-allowed, whatever the config says.
pub fn passthrough_allows(name: &str) -> bool {
    !is_blocked(name, Surface::Server)
}

/// Environment names a *loaded skill* declared for its own commands (`seagent-skills`
/// `setup::prepare`): the per-skill opt-in the exec backends add to `[exec] env_passthrough`.
///
/// A skill declares `required_environment_variables` in its frontmatter; the value comes from
/// the operator's environment, `[skills.env.<skill>]` or the vault, so nothing is ever asked at
/// run time. Registration refuses every name blocked for third-party code ([`Surface::Code`]) —
/// `OPENAI_API_KEY` never enters here — and the exec side still runs the value through
/// [`passthrough_allows`], so an seagent-managed credential stays scrubbed even if a skill names it.
fn skill_env() -> &'static Mutex<BTreeSet<String>> {
    static SKILL: std::sync::OnceLock<Mutex<BTreeSet<String>>> = std::sync::OnceLock::new();
    SKILL.get_or_init(Default::default)
}

/// Register a skill's declared names; returns `(accepted, refused)` (refused = seagent-managed).
pub fn register_skill_env<I: IntoIterator<Item = S>, S: AsRef<str>>(names: I) -> (Vec<String>, Vec<String>) {
    let (mut ok, mut refused) = (Vec::new(), Vec::new());
    let mut set = skill_env().lock().unwrap_or_else(|p| p.into_inner());
    for n in names {
        let n = n.as_ref().trim().to_string();
        if n.is_empty() || ok.contains(&n) || refused.contains(&n) || set.contains(&n) {
            continue;
        }
        if is_blocked(&n, Surface::Code) {
            refused.push(n);
        } else {
            set.insert(n.clone());
            ok.push(n);
        }
    }
    (ok, refused)
}

/// Names a skill registered in this process (sorted).
pub fn skill_env_names() -> Vec<String> {
    skill_env().lock().unwrap_or_else(|p| p.into_inner()).iter().cloned().collect()
}

/// `passthrough` (the operator's `[exec]` / `[security] env_passthrough`) plus the names loaded
/// skills declared — what an exec call actually forwards, still filtered by
/// [`passthrough_allows`] because [`crate::envscrub::passthrough_allows`] runs at the sanitizer.
pub fn passthrough_with_skills(passthrough: &[String]) -> Vec<String> {
    let mut out: Vec<String> = passthrough.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    for n in skill_env_names() {
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out.sort();
    out
}

/// Dynamic seagent/Hermes-style internal secrets: `AUXILIARY_<TASK>_API_KEY|_BASE_URL`, relay secrets.
fn internal_secret(upper: &str) -> bool {
    (upper.starts_with("AUXILIARY_") && (upper.ends_with("_API_KEY") || upper.ends_with("_BASE_URL"))) || (upper.starts_with("GATEWAY_RELAY_") && (upper.ends_with("_SECRET") || upper.ends_with("_KEY") || upper.ends_with("_TOKEN")))
}

/// Platform authorization gate (`TELEGRAM_ALLOW_ALL_USERS`): profile policy, not data.
pub fn is_gate_env(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    if u.starts_with("SEAGENT_") || u.starts_with("HERMES_") || u.starts_with('_') || !GATE_MARKERS.iter().any(|m| u.contains(m)) {
        return false;
    }
    GATE_PREFIXES.iter().any(|p| u.starts_with(&format!("{p}_")))
}

fn glob_hit(pat: &str, upper: &str) -> bool {
    let pat = pat.trim().to_ascii_uppercase();
    match pat.strip_suffix('*') {
        Some(pre) => !pre.is_empty() && upper.starts_with(pre),
        None => pat == upper,
    }
}

/// Should `name` be removed from a child's environment on `surface`?
pub fn is_blocked(name: &str, surface: Surface) -> bool {
    let upper = name.to_ascii_uppercase();
    if ALWAYS_STRIP.contains(&upper.as_str()) || internal_secret(&upper) || (surface == Surface::Sandbox && credential_shaped(&upper)) {
        return true;
    }
    with(|p| {
        if p.disabled {
            return false;
        }
        if p.strip.iter().any(|s| glob_hit(s, &upper)) || p.registered.contains(&upper) || PROVIDER_BLOCKLIST.contains(&upper.as_str()) || is_gate_env(&upper) {
            return true;
        }
        // Venv markers redirect other projects' tooling; scripts and servers never need ours.
        // A sandbox may: it runs the project's own tooling.
        surface != Surface::Hook && surface != Surface::Sandbox && VENV_MARKERS.contains(&upper.as_str())
    })
}

/// Names in `env` that would be stripped on `surface`.
pub fn blocked_names<'a, I: IntoIterator<Item = &'a str>>(env: I, surface: Surface) -> Vec<String> {
    env.into_iter().filter(|k| is_blocked(k, surface)).map(String::from).collect()
}

/// Egress proxy URL (`http://127.0.0.1:<port>`) children get, set by
/// [`crate::egress_proxy::ensure_started`] when `[security.egress_proxy] enabled = true`.
static PROXY: RwLock<Option<String>> = RwLock::new(None);

/// Names the proxy is published under. Uppercase: curl, wget, git, python-requests and
/// node all read at least `HTTPS_PROXY`/`HTTP_PROXY`.
const PROXY_VARS: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"];
/// Values that would defeat the proxy: `NO_PROXY` exempts hosts (see the `egress_proxy`
/// module docs), and curl/wget prefer the lowercase names over the uppercase ones.
const PROXY_CLEAR: &[&str] = &["NO_PROXY", "no_proxy", "http_proxy", "https_proxy", "all_proxy"];

/// Point children at the local egress proxy, or clear it (`None`). The proxy itself is
/// started by `[security.egress_proxy]`, not here; the URL is not a secret.
///
/// The value is published twice: into the policy read by [`apply`] / [`filter_map`], and
/// into seagent's own environment. The second copy is what covers children that inherit the
/// environment instead of rebuilding it — the shell tool, background jobs, the `[exec]`
/// backends' local children and hooks all spawn with `Command`'s default environment, so
/// they pick the proxy up without any code of their own. (`ureq` is built with
/// `default-features = false` and reads no proxy variables, so seagent's own provider
/// traffic is untouched.)
pub fn set_proxy(url: Option<&str>) {
    let url = url.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    {
        let mut g = PROXY.write().unwrap_or_else(|p| p.into_inner());
        *g = url.clone();
    }
    let Some(url) = url else { return };
    // A stale `NO_PROXY` (or a lowercase `http_proxy`, which curl/wget prefer over the
    // uppercase name) would hand a child a direct path out.
    for k in PROXY_CLEAR {
        std::env::remove_var(k);
    }
    for k in PROXY_VARS {
        std::env::set_var(k, &url);
    }
}

/// The URL [`apply`] puts in `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, if a proxy is running.
pub fn proxy_url() -> Option<String> {
    PROXY.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Remove every inherited blocked variable from `cmd`, then point it at the local egress
/// proxy when one is running.
pub fn apply(cmd: &mut Command, surface: Surface) {
    for (k, _) in std::env::vars_os() {
        if let Some(k) = k.to_str() {
            if is_blocked(k, surface) {
                cmd.env_remove(k);
            }
        }
    }
    let Some(url) = proxy_url() else { return };
    // A tool that sets its own value after this still wins (callers apply the scrub first).
    for k in PROXY_CLEAR {
        cmd.env_remove(*k);
    }
    for k in PROXY_VARS {
        cmd.env(*k, &url);
    }
}

/// Scrub a plain map (sandbox backends building an env from scratch).
pub fn filter_map<V: From<String>>(env: &mut std::collections::BTreeMap<String, V>, surface: Surface) {
    env.retain(|k, _| !is_blocked(k, surface));
    let Some(url) = proxy_url() else { return };
    for k in PROXY_CLEAR {
        env.remove(*k);
    }
    for k in PROXY_VARS {
        env.insert((*k).to_string(), V::from(url.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_and_bot_secrets_are_blocked_user_vars_are_not() {
        assert!(is_blocked("OPENAI_API_KEY", Surface::Terminal));
        assert!(is_blocked("openai_api_key", Surface::Terminal), "case-folded");
        assert!(is_blocked("TELEGRAM_TOKEN", Surface::Terminal));
        assert!(is_blocked("AUXILIARY_VISION_API_KEY", Surface::Code));
        assert!(is_blocked("GATEWAY_RELAY_X_SECRET", Surface::Hook));
        assert!(is_blocked("DISCORD_ALLOWED_CHANNELS", Surface::Terminal), "auth gate");
        assert!(!is_blocked("DEMO_ALLOWED_SENDER", Surface::Terminal), "operator var is data");
        assert!(!is_blocked("PATH", Surface::Terminal));
        assert!(!is_blocked("MY_OWN_KEY", Surface::Terminal));
        assert!(is_blocked("VIRTUAL_ENV", Surface::Terminal) && !is_blocked("VIRTUAL_ENV", Surface::Hook));
        // Global policy changes live in this one test so parallel tests never see them.
        register(["MYPROVIDER_KEY"]);
        assert!(is_blocked("MYPROVIDER_KEY", Surface::Server));
        configure(true, &["CORP_*".into()], &["OPENAI_API_KEY".into(), "BUILD_ID".into()]);
        assert!(is_blocked("CORP_VAULT", Surface::Terminal));
        assert_eq!(passthrough(), vec!["BUILD_ID".to_string()], "a blocked name can never pass through");
        // Disabling keeps Tier 1.
        configure(false, &[], &[]);
        assert!(!is_blocked("OPENAI_API_KEY", Surface::Terminal));
        assert!(is_blocked("GITHUB_TOKEN", Surface::Terminal));
        configure(true, &[], &[]);
    }

    #[test]
    fn passthrough_relaxes_the_shape_rule_but_never_a_credential() {
        // The operator opt-in exists for names the credential-*shape* heuristic would drop
        // although their value is ordinary data. Hermes/OpenClaw parity: a skill or exec
        // allowlist forwards *its own* variables, never the credentials seagent manages.
        for n in ["BUILD_TOKEN", "X_TOKEN", "DB_PASSWORD", "DEPLOY_SECRET"] {
            assert!(passthrough_allows(n), "{n}: shape only, metadata may be forwarded");
        }
        for n in ["GITHUB_TOKEN", "OPENAI_API_KEY", "TELEGRAM_BOT_TOKEN", "MODAL_TOKEN_ID", "AUXILIARY_VISION_API_KEY", "GATEWAY_RELAY_SECRET"] {
            assert!(!passthrough_allows(n), "{n}: an seagent-managed credential is never re-allowed");
        }
        assert_eq!(passthrough_allows("BUILD_TOKEN"), !is_blocked("BUILD_TOKEN", Surface::Server));
    }

    #[test]
    fn sandbox_surface_adds_the_credential_shape_rule() {
        // What the exec backends strip (`sandbox::sanitize_forwarded`): credential-shaped names
        // plus the non-suffix credentials, and the venv markers pass (a sandbox runs the
        // project's own tooling).
        for n in ["DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "X_TOKEN", "SOME_APIKEY", "AZURE_OPENAI_KEY", "SSH_AUTH_SOCK", "SEAGENT_CALL_SOCK", "VERCEL_TOKEN", "MODAL_TOKEN_ID", "GITHUB_TOKEN"] {
            assert!(is_blocked(n, Surface::Sandbox), "{n}");
        }
        for n in ["PATH", "HOME", "LANG", "LC_ALL", "EDITOR", "VIRTUAL_ENV", "CONDA_PREFIX", "MY_OWN_KEY", "DEMO_ALLOWED_SENDER"] {
            assert!(!is_blocked(n, Surface::Sandbox), "{n}");
        }
    }

    #[test]
    fn skill_declared_env_is_a_per_skill_opt_in_and_never_a_credential() {
        // What `seagent-skills setup::prepare` registers: the skill's own declared names, e.g. a
        // third-party API key the operator supplied in `[skills.env.<skill>]` or the vault.
        let (ok, refused) = register_skill_env(["SEAGENT_TEST_SKILL_TENOR_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN"]);
        assert_eq!(ok, ["SEAGENT_TEST_SKILL_TENOR_KEY"], "a skill's own name is accepted");
        assert_eq!(refused, ["OPENAI_API_KEY", "GITHUB_TOKEN"], "seagent-managed credentials are refused at registration");
        assert!(skill_env_names().contains(&"SEAGENT_TEST_SKILL_TENOR_KEY".to_string()));
        // The exec side adds them to the operator list; the sanitizer's own rule still decides.
        let merged = passthrough_with_skills(&["BUILD_ID".into()]);
        assert!(merged.contains(&"SEAGENT_TEST_SKILL_TENOR_KEY".to_string()) && merged.contains(&"BUILD_ID".to_string()));
        assert!(!merged.iter().any(|n| n == "OPENAI_API_KEY" || n == "GITHUB_TOKEN"));
        // Registering twice is idempotent.
        assert_eq!(register_skill_env(["SEAGENT_TEST_SKILL_TENOR_KEY"]).0, Vec::<String>::new());
    }

    #[test]
    fn apply_removes_inherited_secret_from_child() {
        // An always-stripped internal-secret shape, so the policy toggles in the other test can't race it.
        std::env::set_var("AUXILIARY_ARKTEST9F_API_KEY", "s3cret");
        let mut c = Command::new("sh");
        c.arg("-c").arg("printf %s \"${AUXILIARY_ARKTEST9F_API_KEY:-gone}\"");
        apply(&mut c, Surface::Terminal);
        let out = c.output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "gone");
        let mut c = Command::new("sh");
        c.arg("-c").arg("printf %s \"$AUXILIARY_ARKTEST9F_API_KEY\"");
        apply(&mut c, Surface::Terminal);
        c.env("AUXILIARY_ARKTEST9F_API_KEY", "explicit");
        assert_eq!(String::from_utf8_lossy(&c.output().unwrap().stdout), "explicit", "an explicit value set afterwards still reaches the child");
    }

    #[test]
    fn one_secret_name_classifier_covers_every_surface() {
        for n in [
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "MODAL_TOKEN_ID",
            "SSH_AUTH_SOCK",
            "VERCEL_TOKEN",
            "DATABASE_DSN",
            "SEAGENT_SECRET_HOME",
            "MY_TOKEN",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AUXILIARY_X_API_KEY",
            "SLACK_WEBHOOK",
            "HTTP_COOKIE",
        ] {
            assert!(is_secret_env_name(n), "{n}: a credential name");
        }
        for n in ["PATH", "HOME", "LC_ALL", "EDITOR", "VIRTUAL_ENV", "CONDA_PREFIX", "SEAGENT_HOME", "BYPASS_CACHE", "PROJECT_FLAG", "COMPASS_DIR"] {
            assert!(!is_secret_env_name(n), "{n}: ordinary environment data");
        }
        // Every name the child-process surfaces strip is also a secret name here.
        for n in ["GITHUB_TOKEN", "OPENAI_API_KEY", "TELEGRAM_BOT_TOKEN", "DB_PASSWORD", "VERCEL_TOKEN", "SSH_AUTH_SOCK", "AUXILIARY_VISION_API_KEY"] {
            assert!(is_blocked(n, Surface::Sandbox) || is_blocked(n, Surface::Server));
            assert!(is_secret_env_name(n), "{n}: the sandbox/server rules are a subset");
        }
        // The sandbox surface deliberately keeps the narrower shape rule.
        assert!(is_secret_env_name("MY_OWN_KEY") && !is_blocked("MY_OWN_KEY", Surface::Sandbox));
    }
}
