//! Child environment for code mode (Hermes `tools/code_execution_env.py`): an allowlist, not a
//! blocklist. Names that look like credentials are dropped first; what remains must match a safe
//! prefix or an exact ark runtime name. `security.env_passthrough` names are the explicit opt-in
//! (never a Tier-1 secret); the RPC socket/token, UTF-8 stdio and TZ are added afterwards.

const SAFE_PREFIXES: [&str; 15] = ["PATH", "HOME", "USER", "LANG", "LC_", "TERM", "TMPDIR", "TMP", "TEMP", "SHELL", "LOGNAME", "XDG_", "PYTHONPATH", "VIRTUAL_ENV", "CONDA"];
/// Non-secret runtime locations a script may need (Hermes `_HERMES_CHILD_ALLOWED`).
const ARK_ALLOWED: [&str; 5] = ["ARK_HOME", "ARK_PROFILE", "ARK_CONFIG", "ARK_DATA_DIR", "ARK_BIN"];

/// Credential-shaped names are one rule for every child (`ark_security::envscrub`): the code-mode
/// substring list, the sandbox credential-shape list and the Tier-1 names.
pub fn is_secret_name(name: &str) -> bool {
    ark_security::envscrub::is_secret_env_name(name)
}

/// Scrub `source` into the code-mode child environment.
pub fn scrub<I: IntoIterator<Item = (String, String)>>(source: I, passthrough: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in source {
        let tier1 = ark_security::envscrub::is_blocked(&k, ark_security::envscrub::Surface::Code);
        if passthrough.iter().any(|p| p.eq_ignore_ascii_case(&k)) && !tier1 {
            out.push((k, v));
            continue;
        }
        if tier1 || is_secret_name(&k) {
            continue;
        }
        if SAFE_PREFIXES.iter().any(|p| k.starts_with(p)) || ARK_ALLOWED.contains(&k.as_str()) {
            out.push((k, v));
        }
    }
    out.push(("PYTHONDONTWRITEBYTECODE".into(), "1".into()));
    out.push(("PYTHONIOENCODING".into(), "utf-8".into()));
    out.push(("PYTHONUTF8".into(), "1".into()));
    out.sort();
    out
}

/// The environment of this process, scrubbed.
pub fn child_env() -> Vec<(String, String)> {
    let src = std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    scrub(src, &ark_security::envscrub::passthrough())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_drops_secrets_and_unknowns() {
        let src = [("PATH", "/bin"), ("HOME", "/h"), ("LC_ALL", "C"), ("OPENAI_API_KEY", "sk"), ("MY_TOKEN", "t"), ("DATABASE_DSN", "x"), ("RANDOM_CONFIG", "y"), ("ARK_HOME", "/a"), ("ARK_SECRET_HOME", "z"), ("BYPASS_CACHE", "1"), ("PROJECT_FLAG", "on"), ("GITHUB_TOKEN", "g")].map(|(a, b)| (a.to_string(), b.to_string()));
        let env = scrub(src.clone(), &[]);
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["ARK_HOME", "HOME", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING", "PYTHONUTF8"]);
        let env = scrub(src, &["PROJECT_FLAG".into(), "GITHUB_TOKEN".into(), "MY_TOKEN".into()]);
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PROJECT_FLAG") && names.contains(&"MY_TOKEN"), "explicit passthrough");
        assert!(!names.contains(&"GITHUB_TOKEN"), "a Tier-1 secret can never be passed through");
    }
}
