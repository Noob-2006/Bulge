//! Key rotation (ent-085): the vault master key, the app server's tokens and provider keys.
//!
//! * `seagent secrets rekey [--new-backend B]` — re-encrypt `secrets.enc` under a new passphrase
//!   (`SEAGENT_VAULT_NEW_PASSPHRASE_FILE` / `SEAGENT_VAULT_NEW_PASSPHRASE`), a new raw key
//!   (`SEAGENT_VAULT_NEW_KEY`), a fresh keyring / TPM key, or another backend. The old key comes
//!   from the usual `SEAGENT_VAULT_*`; a failed rekey restores the previous file.
//! * `seagent secrets rotate NAME (--value-stdin | --generate | --rotate-command CMD)` — store a new
//!   value. When the `vault` secret source binds NAME, the new version is written to HashiCorp
//!   Vault (KV v2) so every host picks it up; otherwise the local vault is updated.
//! * `seagent secrets rotation [status|set NAME --every-days N [--rotate-command CMD]|run]` — the
//!   schedule: `run` rotates every due key that has a command (put it in cron / a systemd timer:
//!   `seagent cron add "0 3 * * *" -- seagent secrets rotation run`), `status` shows ages and overdue
//!   keys (also in `seagent doctor`).
//! * `seagent app token rotate [--token-name NAME]` — a fresh random app token in the vault secret
//!   that `[app] token` (or the named `[app] tokens` entry) references.
//!
//! Values never reach stdout, logs or the audit stream; the audit event names the secret and
//! where it was written.

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

pub const COMMANDS: &[&str] = &[];
pub const VALUE_FLAGS: &[&str] = &["every-days", "max-age-days", "rotate-command", "new-backend", "token-name"];
pub const BOOL_FLAGS: &[&str] = &["value-stdin", "generate"];

fn state_path(paths: &Paths) -> PathBuf {
    paths.data.join("secrets").join("rotation.json")
}

fn load(paths: &Paths) -> serde_json::Map<String, Value> {
    std::fs::read_to_string(state_path(paths)).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

fn save(paths: &Paths, m: &serde_json::Map<String, Value>) -> Result<(), String> {
    let p = state_path(paths);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    seagent_kernel::util::atomic_write(&p, serde_json::to_string_pretty(m).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())
}

/// Key material for the local vault. Tests use a fixed in-memory key so they never reach the OS
/// keyring, the TPM or a passphrase prompt.
fn vault_options() -> seagent_kernel::secretstore::Options {
    #[cfg(test)]
    return seagent_kernel::secretstore::Options { backend: Some(seagent_kernel::secretstore::Backend::Env), key: Some([9u8; 32]), ..Default::default() };
    #[cfg(not(test))]
    seagent_kernel::secretstore::Options::from_env()
}

fn local_vault(paths: &Paths) -> Result<seagent_kernel::vault::Vault, String> {
    seagent_kernel::vault::Vault::load_with(&paths.secrets(), &vault_options())
}

fn now() -> i64 {
    seagent_kernel::util::unix_now()
}

fn audit(paths: &Paths, target: &str, outcome: &str, detail: Value) {
    seagent_security::audit::record(&paths.data, seagent_security::audit::Event::new("secret.rotate", seagent_security::audit::Actor::local(), target, outcome).detail(detail));
}

/// Record a rotation of `name` (no value).
pub fn mark_rotated(paths: &Paths, name: &str, to: &str) -> Result<(), String> {
    let mut m = load(paths);
    let e = m.entry(name.to_string()).or_insert_with(|| json!({}));
    e["rotated_at"] = json!(now());
    e["store"] = json!(to);
    save(paths, &m)
}

/// The `vault` source's `path#field` for `name`, if it binds it.
fn vault_binding(paths: &Paths, name: &str) -> Option<(toml::Table, String, String)> {
    let t = super::secretsrc::load_config(paths);
    let c = t.get("vault").and_then(|v| v.as_table()).cloned()?;
    if !c.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        return None;
    }
    let r = c.get("env").and_then(|e| e.get(name)).and_then(|v| v.as_str())?.to_string();
    let (p, f) = r.split_once('#').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((r, "value".into()));
    Some((c, p, f))
}

/// Store `value` for `name` (HashiCorp Vault when bound there, else the local vault).
pub fn store_new_value(paths: &Paths, name: &str, value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("the new value is empty".into());
    }
    let env: HashMap<String, String> = std::env::vars().collect();
    let to = if let Some((c, path, field)) = vault_binding(paths, name) {
        // Keep the other fields of the secret: read, replace one, write a new version.
        let token = super::secretsrc::cloud::vault_token(&c, &env).map_err(|e| e.0)?;
        let mut data = super::secretsrc::cloud::vault_read(&c, &env, &token, &path).unwrap_or_default();
        data.insert(field.clone(), json!(value));
        let v = super::secretsrc::cloud::vault_write(&c, &env, &path, &data)?;
        super::secretsrc::clear_caches(&paths.data);
        format!("vault:{path}#{field} (version {v})")
    } else {
        let v = local_vault(paths)?;
        v.set(name, value)?;
        "local vault".to_string()
    };
    mark_rotated(paths, name, &to)?;
    audit(paths, name, "ok", json!({"store": to}));
    Ok(to)
}

fn new_value(a: &Args, name: &str) -> Result<String, String> {
    if a.flag("generate") {
        return Ok(seagent_net::crypto::random_token(32));
    }
    if let Some(cmd) = a.val("rotate-command") {
        return run_command(cmd, name);
    }
    if a.flag("value-stdin") {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| e.to_string())?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    Err("give the new value with --value-stdin, --generate or --rotate-command CMD".into())
}

/// A rotation helper prints the new value on stdout (e.g. a script calling the provider's
/// admin API). Same limits as the `command` secret source: no shell env leak, 30 s, 1 MiB.
fn run_command(cmd: &str, name: &str) -> Result<String, String> {
    let env: HashMap<String, String> = std::env::vars().collect();
    let out = super::secretsrc::run_helper(cmd, name, 30.0, &env)?;
    let v = out.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string();
    if v.is_empty() {
        return Err(format!("rotation command for {name} printed nothing"));
    }
    Ok(v)
}

/// `(name, age_days, every_days, overdue)` for every tracked secret.
pub fn status(paths: &Paths, max_age_days: i64) -> Vec<(String, Option<i64>, Option<i64>, bool)> {
    let m = load(paths);
    // Only the tracked names: `status` must not unlock the vault (doctor, status pages).
    m.keys()
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .map(|n| {
            let e = m.get(&n).cloned().unwrap_or(json!({}));
            let age = e["rotated_at"].as_i64().map(|t| (now() - t) / 86_400);
            let every = e["every_days"].as_i64();
            let limit = every.unwrap_or(max_age_days);
            let overdue = age.is_some_and(|a| a >= limit) || (age.is_none() && every.is_some());
            (n, age, every, overdue)
        })
        .collect()
}

/// One line for `seagent doctor`.
pub fn doctor_line(paths: &Paths) -> Result<String, String> {
    let st = status(paths, 90);
    let overdue: Vec<String> = st.iter().filter(|s| s.3).map(|s| s.0.clone()).collect();
    if overdue.is_empty() {
        Ok(format!("{} tracked, none overdue", st.iter().filter(|s| s.1.is_some() || s.2.is_some()).count()))
    } else {
        Err(format!("overdue: {} (`seagent secrets rotation run`, or `seagent secrets rotate NAME`)", overdue.join(", ")))
    }
}

fn run_due(paths: &Paths) -> Result<String, String> {
    let m = load(paths);
    let mut out = vec![];
    for (name, _, every, overdue) in status(paths, i64::MAX) {
        if !overdue || every.is_none() {
            continue;
        }
        let Some(cmd) = m.get(&name).and_then(|e| e["command"].as_str()).map(String::from) else {
            out.push(format!("{name}: due, no rotation command — rotate by hand"));
            continue;
        };
        match run_command(&cmd, &name).and_then(|v| store_new_value(paths, &name, &v)) {
            Ok(to) => out.push(format!("{name}: rotated → {to}")),
            Err(e) => {
                audit(paths, &name, "error", json!({"error": e}));
                out.push(format!("{name}: FAILED: {e}"));
            }
        }
    }
    if out.is_empty() {
        out.push("nothing due".into());
    }
    Ok(out.join("\n"))
}

fn rekey(paths: &Paths, a: &Args) -> Result<String, String> {
    use seagent_kernel::secretstore::{rekey, Backend, Options};
    let old = Options::from_env();
    let mut new = Options::from_map(|k| match k {
        "SEAGENT_VAULT_KEY" => std::env::var("SEAGENT_VAULT_NEW_KEY").ok(),
        "SEAGENT_VAULT_PASSPHRASE" => std::env::var("SEAGENT_VAULT_NEW_PASSPHRASE").ok(),
        "SEAGENT_VAULT_PASSPHRASE_FILE" => std::env::var("SEAGENT_VAULT_NEW_PASSPHRASE_FILE").ok(),
        "SEAGENT_VAULT_BACKEND" => None,
        other => std::env::var(other).ok(),
    });
    new.backend = match a.val("new-backend") {
        Some(b) => Some(Backend::parse(b).ok_or(format!("unknown backend `{b}`"))?),
        None => None,
    };
    let (n, b, notes) = rekey(&paths.secrets(), &old, &new)?;
    mark_rotated(paths, "vault-master-key", b.as_str())?;
    audit(paths, "vault-master-key", "ok", json!({"backend": b.as_str(), "secrets": n}));
    let mut o = format!("re-encrypted {n} secret{} under a new key ({})", if n == 1 { "" } else { "s" }, b.explain());
    for note in notes {
        o += &format!("\nnote: {note}");
    }
    Ok(o)
}

/// The `{{secret:NAME}}` an `[app]` token entry references.
fn app_token_secret(paths: &Paths, token_name: Option<&str>) -> Result<String, String> {
    let t: toml::Table = std::fs::read_to_string(paths.user_config()).ok().and_then(|s| s.parse().ok()).unwrap_or_default();
    let app = t.get("app").and_then(|v| v.as_table()).cloned().unwrap_or_default();
    let raw = match token_name {
        None => app.get("token").and_then(|v| v.as_str()).map(String::from),
        Some(n) => app.get("tokens").and_then(|v| v.as_array()).and_then(|a| a.iter().find(|e| e.get("name").and_then(|x| x.as_str()) == Some(n))).and_then(|e| e.get("token")).and_then(|v| v.as_str()).map(String::from),
    }
    .unwrap_or_else(|| "{{secret:APP_TOKEN}}".into());
    raw.trim().strip_prefix("{{secret:").and_then(|r| r.strip_suffix("}}")).map(|s| s.trim().to_string()).ok_or_else(|| "the app token is written literally in the config — change it to `token = \"{{secret:APP_TOKEN}}\"` so it can be rotated".to_string())
}

fn app_token_rotate(paths: &Paths, a: &Args) -> Result<String, String> {
    let secret = app_token_secret(paths, a.val("token-name"))?;
    let to = store_new_value(paths, &secret, &seagent_net::crypto::random_token(32))?;
    Ok(format!("rotated app token {secret} → {to}; restart the daemon (`seagent daemon restart`) so the old token stops working, and hand the new value out with `seagent secrets get {secret}`"))
}

pub fn run(paths: &Paths, a: &Args) -> Result<String, String> {
    match a.pos(0) {
        Some("rekey") => rekey(paths, a),
        Some("rotate") => {
            let name = a.need(1, "NAME")?.to_string();
            if !seagent_kernel::secretstore::valid_name(&name) {
                return Err(format!("`{name}` is not a valid secret name"));
            }
            let v = new_value(a, &name)?;
            Ok(format!("rotated {name} → {}", store_new_value(paths, &name, &v)?))
        }
        Some("rotation") => match a.pos(1).unwrap_or("status") {
            "status" => {
                let max = a.val("max-age-days").and_then(|v| v.parse().ok()).unwrap_or(90);
                let st = status(paths, max);
                if a.flag("json") {
                    return Ok(serde_json::to_string_pretty(&st.iter().map(|s| json!({"name": s.0, "age_days": s.1, "every_days": s.2, "overdue": s.3})).collect::<Vec<_>>()).unwrap_or_default());
                }
                Ok(st.iter().map(|(n, age, every, od)| format!("{n:<32} {:<14} {:<12} {}", age.map(|a| format!("{a} days ago")).unwrap_or_else(|| "never".into()), every.map(|e| format!("every {e}d")).unwrap_or_else(|| "-".into()), if *od { "OVERDUE" } else { "ok" })).collect::<Vec<_>>().join("\n"))
            }
            "set" => {
                let name = a.need(2, "NAME")?.to_string();
                let every: i64 = a.val("every-days").ok_or("usage: seagent secrets rotation set NAME --every-days N [--rotate-command CMD]")?.parse().map_err(|_| "--every-days takes a number")?;
                let mut m = load(paths);
                let e = m.entry(name.clone()).or_insert_with(|| json!({}));
                e["every_days"] = json!(every);
                if let Some(c) = a.val("rotate-command") {
                    e["command"] = json!(c);
                }
                save(paths, &m)?;
                Ok(format!("{name}: rotate every {every} days{}", if a.val("rotate-command").is_some() { " (automatic with `seagent secrets rotation run`)" } else { " (reminder only)" }))
            }
            "run" => run_due(paths),
            o => Err(format!("unknown `seagent secrets rotation {o}` (status|set|run)")),
        },
        _ => Err("usage: seagent secrets rekey|rotate|rotation …".into()),
    }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    let paths = Paths::from_env();
    let r = match (cmd, a.pos(0), a.pos(1)) {
        ("secrets" | "secret", Some("rekey" | "rotate" | "rotation"), _) => run(&paths, a),
        ("app", Some("token"), Some("rotate")) => app_token_rotate(&paths, a),
        _ => return None,
    };
    Some(match r {
        Ok(t) => {
            println!("{t}");
            Ok(0)
        }
        Err(e) => Err(e.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn paths(root: &Path) -> Paths {
        Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() }
    }

    #[test]
    fn schedule_status_and_due_rotation_through_a_command() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-rotate");
        let p = paths(tmp.path());
        std::fs::create_dir_all(&p.config_dir).unwrap();
        // Local (plaintext test) vault: write and rotate.
        assert!(store_new_value(&p, "OPENAI_API_KEY", " ").is_err());
        store_new_value(&p, "OPENAI_API_KEY", "sk-1").unwrap();
        let st = status(&p, 90);
        assert!(st.iter().any(|s| s.0 == "OPENAI_API_KEY" && s.1 == Some(0) && !s.3));
        // A schedule with a helper command; backdate the last rotation so it is due.
        let mut m = load(&p);
        m.insert("OPENAI_API_KEY".into(), json!({"rotated_at": now() - 40 * 86_400, "every_days": 30, "command": "echo sk-rotated-by-cmd"}));
        save(&p, &m).unwrap();
        assert!(doctor_line(&p).unwrap_err().contains("OPENAI_API_KEY"));
        let out = run_due(&p).unwrap();
        assert!(out.contains("OPENAI_API_KEY: rotated → local vault"), "{out}");
        assert!(!out.contains("sk-rotated"), "values never printed: {out}");
        assert_eq!(local_vault(&p).unwrap().substitute("{{secret:OPENAI_API_KEY}}"), "sk-rotated-by-cmd");
        assert!(doctor_line(&p).is_ok());
        assert_eq!(run_due(&p).unwrap(), "nothing due");
    }

    #[test]
    fn rotation_writes_through_to_hashicorp_vault_when_bound() {
        let (srv, _log, store) = super::super::secretsrc::cloud::tests::fake_vault();
        let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-rotatev");
        let p = paths(tmp.path());
        std::fs::create_dir_all(&p.config_dir).unwrap();
        let cfg = format!("[vault]\nenabled = true\naddr = \"http://{}\"\ntoken_env = \"SEAGENT_TEST_VAULT_TOKEN_ROT\"\nenv = {{ OPENAI_API_KEY = \"seagent/providers#openai\" }}\n", srv.local_addr());
        std::fs::write(super::super::secretsrc::config_path(&p), cfg).unwrap();
        std::env::set_var("SEAGENT_TEST_VAULT_TOKEN_ROT", "t-root");
        let to = store_new_value(&p, "OPENAI_API_KEY", "sk-new").unwrap();
        assert!(to.starts_with("vault:seagent/providers#openai"), "{to}");
        let s = store.lock().unwrap();
        assert_eq!(s["seagent/providers"]["openai"], "sk-new");
        assert_eq!(s["seagent/providers"]["anthropic"], "ant-from-vault", "other fields are kept");
    }

    #[test]
    fn app_token_reference_is_required() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-rotatea");
        let p = paths(tmp.path());
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.user_config(), "[app]\ntoken = \"literal\"\ntokens = [{ token = \"{{secret:WEB_READ}}\", scope = \"read\", name = \"status\" }]\n").unwrap();
        assert!(app_token_secret(&p, None).unwrap_err().contains("literally"));
        assert_eq!(app_token_secret(&p, Some("status")).unwrap(), "WEB_READ");
        std::fs::write(p.user_config(), "").unwrap();
        assert_eq!(app_token_secret(&p, None).unwrap(), "APP_TOKEN");
    }
}
