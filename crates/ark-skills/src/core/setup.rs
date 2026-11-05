//! Skill readiness: required environment variables, secret capture and setup notes (Hermes
//! `tools/skills_tool_setup.py` + `tools/env_passthrough.py`, MIT).
//!
//! A skill declares what it needs in frontmatter — `required_environment_variables` (names or
//! `{name, prompt, help, required_for, optional}`), `setup.collect_secrets` (`{env_var, prompt,
//! provider_url}`) or legacy `prerequisites.env_vars` — merged first-wins into one list. A name
//! is satisfied by the process environment or a vault secret of the same name. Missing ones
//! yield `setup_needed` plus a setup note the skill message carries; `ark skills setup <name>`
//! prompts for each and stores it in the vault (`secrets.toml`). Loading a skill registers its
//! declared names for sandbox passthrough and hands the values it can resolve to the skill's
//! commands (`prepare`), except ark-managed provider credentials (GHSA-rhgp-j443-p4rf: a skill
//! must not tunnel `OPENAI_API_KEY` into a code child).

use ark_kernel::config::Config;
use ark_kernel::vault::Vault;
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq)]
pub struct EnvReq {
    pub name: String,
    pub prompt: String,
    pub help: Option<String>,
    pub required_for: Option<String>,
    pub optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    Available,
    SetupNeeded,
    Unsupported,
}

impl Readiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Readiness::Available => "available",
            Readiness::SetupNeeded => "setup_needed",
            Readiness::Unsupported => "unsupported",
        }
    }
}

fn env_name_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap())
}

fn as_list(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        Some(o @ Value::Object(_)) => vec![o.clone()],
        _ => vec![],
    }
}

fn clean(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

/// Merge the three declaration styles into one deduped, validated list (first entry wins).
pub fn required_env(front: &Value) -> Vec<EnvReq> {
    let setup = front.get("setup").filter(|s| s.is_object()).cloned().unwrap_or(json!({}));
    let setup_help = clean(setup.get("help"));
    let mut entries: Vec<Value> = Vec::new();
    for i in as_list(front.get("required_environment_variables")) {
        match i {
            Value::String(s) => entries.push(json!({"name": s})),
            o @ Value::Object(_) => entries.push(o),
            _ => {}
        }
    }
    for i in as_list(setup.get("collect_secrets")) {
        if i.is_object() {
            let url = clean(i.get("provider_url")).or_else(|| clean(i.get("url")));
            entries.push(json!({"name": i.get("env_var"), "prompt": i.get("prompt"), "url": url}));
        }
    }
    match front.get("prerequisites").and_then(|p| p.get("env_vars")) {
        Some(Value::String(s)) => entries.push(json!({"name": s})),
        Some(Value::Array(a)) => entries.extend(a.iter().filter_map(|v| v.as_str()).filter(|s| !s.trim().is_empty()).map(|s| json!({"name": s}))),
        _ => {}
    }
    let mut out: Vec<EnvReq> = Vec::new();
    for e in entries {
        let name = clean(e.get("name")).or_else(|| clean(e.get("env_var"))).unwrap_or_default();
        if name.is_empty() || out.iter().any(|o| o.name == name) || !env_name_re().is_match(&name) {
            continue;
        }
        let prompt = clean(e.get("prompt")).unwrap_or_else(|| format!("Enter value for {name}"));
        let help = clean(e.get("help")).or_else(|| clean(e.get("provider_url"))).or_else(|| clean(e.get("url"))).or_else(|| setup_help.clone());
        out.push(EnvReq { name, prompt, help, required_for: clean(e.get("required_for")), optional: e.get("optional").and_then(Value::as_bool).unwrap_or(false) });
    }
    out
}

/// Present in the environment or the vault (non-empty).
pub fn is_set(name: &str, vault_names: &[String]) -> bool {
    std::env::var(name).is_ok_and(|v| !v.is_empty()) || vault_names.iter().any(|n| n == name)
}

/// (readiness, missing required names) for a skill's frontmatter.
pub fn readiness(front: &Value, vault_names: &[String]) -> (Readiness, Vec<String>) {
    let missing: Vec<String> = required_env(front).into_iter().filter(|r| !r.optional && !is_set(&r.name, vault_names)).map(|r| r.name).collect();
    (if missing.is_empty() { Readiness::Available } else { Readiness::SetupNeeded }, missing)
}

/// `Setup needed before using this skill: missing env $A, env $B. <setup.help>` (None when
/// ready). The `env $NAME` spelling is the upstream `_build_setup_note` one.
pub fn setup_note(front: &Value, vault_names: &[String]) -> Option<String> {
    let (r, missing) = readiness(front, vault_names);
    if r != Readiness::SetupNeeded {
        return None;
    }
    let note = format!(
        "Setup needed before using this skill: missing {}.",
        if missing.is_empty() { "required prerequisites".to_string() } else { missing.iter().map(|n| format!("env ${n}")).collect::<Vec<_>>().join(", ") }
    );
    let help = front.get("setup").and_then(|s| clean(s.get("help")));
    Some(match help {
        Some(h) => format!("{note} {h}"),
        None => format!("{note} Run `ark skills setup <skill>` or `ark secrets set <NAME>` to provide them."),
    })
}

/// Register a loaded skill's declared names for sandbox passthrough. Ark-managed provider
/// credentials and other blocked names are refused (returned in the second list).
///
/// The registry lives in `ark_security::envscrub` because the consumers are the `[exec]`
/// backends (`ark-tools`), which sit *below* this crate: they add these names to
/// `[exec] env_passthrough` through the same sanitizer, so a credential can never ride in.
pub fn register_passthrough(reqs: &[EnvReq]) -> (Vec<String>, Vec<String>) {
    ark_security::envscrub::register_skill_env(reqs.iter().map(|r| r.name.as_str()))
}

/// Names skills registered this process (sandbox backends forward these).
pub fn passthrough_names() -> Vec<String> {
    ark_security::envscrub::skill_env_names()
}

/// A name the process environment already holds (an operator-set value always wins).
fn external(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// A vault value without exposing the vault map: substitute the name's own placeholder.
fn vault_value(vault: &Vault, name: &str) -> Option<String> {
    let placeholder = format!("{{{{secret:{name}}}}}");
    let value = vault.substitute(&placeholder);
    (value != placeholder && !value.is_empty()).then_some(value)
}

/// `[skills.env.<skill>]` — an explicit value per declared name (`{{secret:NAME}}` resolves);
/// the OpenClaw `skills.entries.<key>.env` / `.apiKey` counterpart.
fn config_value(cfg: &Config, skill: &str, name: &str, vault: &Vault) -> Option<String> {
    let v = cfg.skills.get("env")?.get(skill)?.get(name)?;
    let s = match v {
        toml::Value::String(s) => vault.substitute(s),
        other => other.to_string(),
    };
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Make a loaded skill's declared environment available before its body runs: the process
/// environment wins (never overwritten), else `[skills.env.<skill>]`, else the vault; those names
/// are registered for sandbox passthrough so `shell`/`execute`/exec backends forward them too
/// (OpenClaw `skills/runtime/env-overrides.ts`, Hermes `tools/env_passthrough.py`). Ark-managed
/// provider credentials are refused on both counts. Returns `(supplied, refused)`.
pub fn prepare(front: &Value, skill: &str, cfg: &Config, vault: &Vault) -> (Vec<String>, Vec<String>) {
    let mut supplied = Vec::new();
    let mut refused = Vec::new();
    let mut reqs = Vec::new();
    for r in required_env(front) {
        if ark_security::envscrub::is_blocked(&r.name, ark_security::envscrub::Surface::Code) {
            refused.push(r.name);
            continue;
        }
        let value = external(&r.name).or_else(|| config_value(cfg, skill, &r.name, vault)).or_else(|| vault_value(vault, &r.name));
        let Some(v) = value else { continue };
        if std::env::var_os(&r.name).is_none() {
            std::env::set_var(&r.name, &v);
        }
        supplied.push(r.name.clone());
        reqs.push(r);
    }
    refused.extend(register_passthrough(&reqs).1);
    (supplied, refused)
}

/// Interactive capture for `ark skills setup`: `ask(name, prompt, help)` returns the value
/// (None = skipped). Captured values go to the vault; returns the names still missing.
pub fn capture(reqs: &[EnvReq], vault: &ark_kernel::vault::Vault, mut ask: impl FnMut(&EnvReq) -> Option<String>) -> Result<Vec<String>, String> {
    let names = vault.names();
    let mut remaining = Vec::new();
    for r in reqs.iter().filter(|r| !is_set(&r.name, &names)) {
        match ask(r).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            Some(v) => vault.set(&r.name, &v)?,
            None if r.optional => {}
            None => remaining.push(r.name.clone()),
        }
    }
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_readiness_note_and_passthrough() {
        let fm = crate::yaml::frontmatter("---\nname: x\nrequired_environment_variables:\n  - TENOR_API_KEY\n  - name: OPT_X\n    optional: true\n  - name: bad-name\nsetup:\n  help: Get a key at tenor.com\n  collect_secrets:\n    - env_var: TENOR_API_KEY\n      prompt: dup ignored\n    - env_var: GIF_REGION\n      provider_url: https://example.com\nprerequisites:\n  env_vars: [LEGACY_VAR]\n---\n").0;
        let r = required_env(&fm);
        let names: Vec<_> = r.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["TENOR_API_KEY", "OPT_X", "GIF_REGION", "LEGACY_VAR"]);
        assert_eq!(r[0].prompt, "Enter value for TENOR_API_KEY");
        assert_eq!(r[0].help.as_deref(), Some("Get a key at tenor.com"));
        assert_eq!(r[2].help.as_deref(), Some("https://example.com"));
        let (st, missing) = readiness(&fm, &["GIF_REGION".into()]);
        assert_eq!((st, missing), (Readiness::SetupNeeded, vec!["TENOR_API_KEY".to_string(), "LEGACY_VAR".to_string()]));
        let note = setup_note(&fm, &[]).unwrap();
        assert!(note.starts_with("Setup needed before using this skill: missing env $TENOR_API_KEY, env $GIF_REGION, env $LEGACY_VAR.") && note.ends_with("tenor.com"), "{note}");
        assert!(setup_note(&serde_json::json!({}), &[]).is_none());
        let (ok, refused) = register_passthrough(&[EnvReq { name: "TENOR_API_KEY".into(), prompt: String::new(), help: None, required_for: None, optional: false }, EnvReq { name: "OPENAI_API_KEY".into(), prompt: String::new(), help: None, required_for: None, optional: false }]);
        assert_eq!((ok, refused), (vec!["TENOR_API_KEY".to_string()], vec!["OPENAI_API_KEY".to_string()]));
        assert!(passthrough_names().contains(&"TENOR_API_KEY".to_string()));
        let d = std::env::temp_dir().join(format!("ark-setup-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let v = ark_kernel::vault::Vault::load(&d.join("secrets.toml")).unwrap();
        let left = capture(&r, &v, |e| (e.name == "TENOR_API_KEY").then(|| "k123".to_string())).unwrap();
        assert_eq!(left, ["GIF_REGION", "LEGACY_VAR"]);
        assert!(v.names().contains(&"TENOR_API_KEY".to_string()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn prepare_supplies_values_and_refuses_credentials() {
        // One name from the process environment (operator value), one from `[skills.env.<skill>]`
        // (a `{{secret:NAME}}` reference), one from the vault, one provider credential.
        std::env::set_var("ARK_T_EXTERNAL", "operator");
        let fm = crate::yaml::frontmatter("---\nname: prep\nrequired_environment_variables: [ARK_T_EXTERNAL, ARK_T_CONFIG, ARK_T_VAULT, OPENAI_API_KEY]\n---\n").0;
        let mut cfg = Config::default();
        cfg.skills.insert("env".into(), toml::from_str("[prep]\nARK_T_EXTERNAL = \"from-config\"\nARK_T_CONFIG = \"{{secret:ARK_T_SECRET}}\"").unwrap());
        let vault = Vault::empty();
        vault.set("ARK_T_SECRET", "cfg-secret").unwrap();
        vault.set("ARK_T_VAULT", "vault-value").unwrap();
        let (supplied, refused) = prepare(&fm, "prep", &cfg, &vault);
        assert_eq!(supplied, ["ARK_T_EXTERNAL", "ARK_T_CONFIG", "ARK_T_VAULT"]);
        assert_eq!(refused, ["OPENAI_API_KEY"], "provider credentials are never handed to a skill");
        assert_eq!(std::env::var("ARK_T_EXTERNAL").as_deref(), Ok("operator"), "an operator value is never overwritten");
        assert_eq!(std::env::var("ARK_T_CONFIG").as_deref(), Ok("cfg-secret"), "{{secret:}} resolved into the skill's env");
        assert_eq!(std::env::var("ARK_T_VAULT").as_deref(), Ok("vault-value"), "collected secret reaches the skill");
        let names = passthrough_names();
        assert!(names.contains(&"ARK_T_CONFIG".to_string()) && names.contains(&"ARK_T_VAULT".to_string()));
        assert!(!names.contains(&"OPENAI_API_KEY".to_string()));
        // The link the sandbox reads: the `[exec]` backends add these names to
        // `[exec] env_passthrough` through the shared registry (a container rebuilds the
        // environment, so before this the declared key never reached a sandboxed command).
        let env = ark_tools::exec::ExecEnv::new(ark_tools::exec::ExecConfig::default()).child_env_for(&[]);
        assert!(env.iter().any(|(k, v)| k == "ARK_T_CONFIG" && v == "cfg-secret"), "a declared key reaches the exec environment: {env:?}");
        assert!(env.iter().any(|(k, v)| k == "ARK_T_VAULT" && v == "vault-value"), "{env:?}");
        assert!(!env.iter().any(|(k, _)| k == "OPENAI_API_KEY"), "ark-managed credentials are still refused: {env:?}");
        // A skill with nothing to supply leaves the environment alone.
        assert_eq!(prepare(&serde_json::json!({}), "prep", &cfg, &vault), (vec![], vec![]));
    }
}
