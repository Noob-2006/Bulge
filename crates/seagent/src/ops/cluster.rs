//! `seagent ha …`, `seagent workers …`, `seagent cluster …`: the CLI of daemon high availability
//! (ent-095/096), the worker pool (ent-097) and the central console (ent-062). Design:
//! docs/ARCHITECTURE.md §7. Live state comes from the local daemon over its owner-only
//! socket (`ha.*`, `workers.*`, `cluster.*` ARP methods, `seagent_kernel::cluster`); key
//! generation and bundle signing are local and never touch the daemon — the signing seed
//! stays in the administrator's file and nothing in seagent's runtime ever reads it.

use crate::args::Args;
use crate::R;
use seagent_kernel::cluster::{self, Bundle};
use seagent_kernel::config::Paths;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["ha", "workers", "cluster"];
pub const VALUE_FLAGS: &[&str] = &["token-secret", "admin-secret", "node", "fingerprint"];
pub const BOOL_FLAGS: &[&str] = &[];

fn daemon(method: &str, params: Value) -> Result<Value, String> {
    seagent_kernel::daemon::call(&Paths::from_env().socket(), method, params)
}

fn print(a: &Args, v: &Value, human: impl FnOnce(&Value) -> String) {
    if a.flag("json") {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    } else {
        println!("{}", human(v));
    }
}

fn when(ms: &Value) -> String {
    let ms = ms.as_u64().unwrap_or(0);
    if ms == 0 {
        return "—".into();
    }
    let ago = seagent_kernel::event::now_ms().saturating_sub(ms) / 1000;
    format!("{ago}s ago")
}

fn ha_human(v: &Value) -> String {
    if v["enabled"] != true {
        return format!("HA is off on {} ([ha] enabled = false): this daemon always leads", v["node"].as_str().unwrap_or("?"));
    }
    let l = &v["leader"];
    let mut out = format!("node {} · {} · epoch {} · lease {}s · store {}", v["node"].as_str().unwrap_or("?"), v["role"].as_str().unwrap_or("?"), v["epoch"], v["lease_secs"], v["store"].as_str().unwrap_or(""));
    if l.is_object() {
        out.push_str(&format!("\nleader: {} (epoch {}, renewed #{} {}){}", l["node"].as_str().unwrap_or("?"), l["epoch"], l["renewed"], when(&l["renewed_ms"]), l["advertise"].as_str().filter(|s| !s.is_empty()).map(|s| format!(" at {s}")).unwrap_or_default()));
    }
    if let Some(e) = v["error"].as_str() {
        out.push_str(&format!("\nerror: {e}"));
    }
    out
}

fn workers_human(v: &Value) -> String {
    let mut out = format!("workers: {} · dispatch {} · completed {} · re-dispatched {} · queued {}", v["count"], v["dispatch"].as_str().unwrap_or("—"), v["completed"].as_u64().unwrap_or(0), v["redispatched"].as_u64().unwrap_or(0), v["queue"].as_array().map(|q| q.len()).unwrap_or(0));
    if let Some(n) = v["note"].as_str() {
        out.push_str(&format!("\n{n}"));
    }
    for w in v["workers"].as_array().into_iter().flatten() {
        out.push_str(&format!("\n  #{} pid {} {} restarts {}{}", w["index"], w["pid"], w["session"].as_str().map(|s| format!("running {s}")).unwrap_or_else(|| if w["alive"] == true { "idle".into() } else { "down".into() }), w["restarts"], w["last_exit"].as_str().map(|e| format!(" (last exit: {e})")).unwrap_or_default()));
    }
    out
}

fn nodes_human(v: &Value) -> String {
    let mut out = String::new();
    for n in v.as_array().into_iter().flatten() {
        out.push_str(&format!(
            "{} {:<16} {:<8} epoch {:<3} running {:<3} v{} {} {}{}\n",
            if n["alive"] == true { "●" } else { "○" },
            n["node"].as_str().unwrap_or("?"),
            n["role"].as_str().unwrap_or("—"),
            n["epoch"].as_u64().unwrap_or(0),
            n["running"].as_array().map(|a| a.len()).unwrap_or(0),
            n["version"].as_str().unwrap_or("?"),
            n["source"].as_str().unwrap_or(""),
            n["advertise"].as_str().or(n["url"].as_str()).unwrap_or(""),
            n["error"].as_str().map(|e| format!(" ({e})")).unwrap_or_default()
        ));
    }
    if out.is_empty() {
        "no nodes".into()
    } else {
        out.trim_end().to_string()
    }
}

fn sessions_human(v: &Value) -> String {
    let rows: Vec<String> = v
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| format!("{} {:<34} {:<12} {}", if s["running"] == true { "▶" } else { " " }, s["id"].as_str().unwrap_or("?"), s["node"].as_str().unwrap_or("—"), s["title"].as_str().unwrap_or("")))
        .collect();
    if rows.is_empty() {
        "no sessions".into()
    } else {
        rows.join("\n")
    }
}

fn read_seed(p: &Path) -> Result<String, String> {
    let m = crate::ops::hostos::mode_of(p).map_err(|e| format!("{}: {e} (create one with `seagent cluster keygen`)", p.display()))?;
    if m & 0o077 != 0 {
        return Err(format!("{}: the signing seed must not be readable by group/other (chmod 600)", p.display()));
    }
    Ok(std::fs::read_to_string(p).map_err(|e| e.to_string())?.trim().to_string())
}

fn default_seed() -> PathBuf {
    Paths::from_env().config_dir.join("cluster").join("signing.seed")
}

/// A fresh 32-byte Ed25519 seed (base64) in a new 0600 file; returns the public key.
pub fn keygen(out: &Path) -> Result<String, String> {
    use base64::Engine;
    use ring::rand::SecureRandom;
    let mut seed = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut seed).map_err(|_| "no system randomness".to_string())?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    if let Some(d) = out.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    crate::ops::hostos::create_private(out, b64.as_bytes()).map_err(|e| format!("{}: {e} (refusing to overwrite an existing seed)", out.display()))?;
    seagent_security::signing::public_of(&b64)
}

fn bundle_from(path: &str) -> Result<Bundle, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: not a policy bundle: {e}"))
}

fn run(a: &Args) -> R {
    let cmd = a.pos(0).unwrap_or("");
    let rest = |i: usize| a.pos(i).unwrap_or("");
    let usage = |m: &str| -> R { Err(crate::Fail::Usage(m.to_string())) };
    match (cmd, rest(1)) {
        ("ha", "" | "status") => {
            let v = daemon("ha.status", json!({}))?;
            print(a, &v, ha_human);
        }
        ("ha", "stepdown") => {
            let v = daemon("ha.stepdown", json!({}))?;
            print(a, &v, |v| if v["stepped_down"] == true { "released the lease; a standby takes over on its next tick".into() } else { "this node was not the leader".into() });
        }
        ("ha", other) => return usage(&format!("unknown `ha {other}`; use status or stepdown")),
        ("workers", "" | "status" | "list") => {
            let v = daemon("workers.status", json!({}))?;
            print(a, &v, workers_human);
        }
        ("workers", "dispatch") => {
            let id = a.need(2, "session")?;
            let v = daemon("workers.dispatch", json!({"id": id}))?;
            print(a, &v, |v| if v["queued"] == true { format!("{id} queued for a worker") } else { format!("{id} is already queued or running on a worker") });
        }
        ("workers", other) => return usage(&format!("unknown `workers {other}`; use status or dispatch SESSION")),
        ("cluster", "" | "status") => {
            let v = daemon("cluster.status", json!({}))?;
            print(a, &v, |v| {
                let p = &v["policy"];
                format!(
                    "{}\n\n{}\n\npolicy: pinned key {} · active v{} · installed v{} · published v{}{}",
                    nodes_human(&v["nodes"]),
                    sessions_human(&json!(v["sessions"].as_array().map(|s| s.iter().filter(|x| x["running"] == true).cloned().collect::<Vec<_>>()).unwrap_or_default())),
                    p["pinned_key_id"].as_str().unwrap_or("none"),
                    p["active_version"].as_u64().map(|v| v.to_string()).unwrap_or("—".into()),
                    p["installed"]["version"].as_u64().map(|v| v.to_string()).unwrap_or("—".into()),
                    p["published"]["version"].as_u64().map(|v| v.to_string()).unwrap_or("—".into()),
                    if p["restart_required"] == true { " · restart to apply" } else { "" }
                )
            });
        }
        ("cluster", "nodes") => print(a, &daemon("cluster.nodes.list", json!({}))?, nodes_human),
        ("cluster", "sessions") => print(a, &daemon("cluster.sessions.list", json!({"limit": a.num::<u64>("limit").map_err(crate::Fail::Usage)?.unwrap_or(200)}))?, sessions_human),
        ("cluster", "agents") => print(a, &daemon("cluster.agents.list", json!({}))?, |v| {
            v.as_array().into_iter().flatten().map(|n| format!("{} · running {} · agents: {}", n["node"].as_str().unwrap_or("?"), n["running"], n["agents"].as_array().map(|x| x.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(", ")).filter(|s| !s.is_empty()).unwrap_or("(default)".into()))).collect::<Vec<_>>().join("\n")
        }),
        ("cluster", "node") => match rest(2) {
            "add" => {
                let name = a.need(3, "name")?;
                let url = a.need(4, "url")?;
                let tok = a.val("token-secret").ok_or_else(|| crate::Fail::Usage("--token-secret NAME is required (a vault secret holding a read token for that node)".into()))?;
                // `--fingerprint`: a LAN peer's self-signed certificate (`seagent nodes discover` /
                // `seagent lan connect` fill it in), reached over pinned TLS.
                let v = daemon("cluster.node.add", json!({"name": name, "url": url, "token_secret": tok, "admin_secret": a.val("admin-secret").unwrap_or(""), "fingerprint": a.val("fingerprint").unwrap_or("")}))?;
                print(a, &v, |_| format!("registered node {name} at {url}"));
            }
            "remove" | "rm" => {
                let name = a.need(3, "name")?;
                let v = daemon("cluster.node.remove", json!({"name": name}))?;
                print(a, &v, |v| if v["removed"] == true { format!("removed {name}") } else { format!("no registered node {name}") });
            }
            other => return usage(&format!("unknown `cluster node {other}`; use add NAME URL --token-secret S or remove NAME")),
        },
        ("cluster", "keygen") => {
            let out = a.val("out").map(PathBuf::from).unwrap_or_else(default_seed);
            let public = keygen(&out)?;
            print(a, &json!({"seed_file": out, "public_key": public}), |_| {
                format!("signing seed written to {} (0600; keep it off the nodes)\npublic key: {public}\n\nPin it on every node in {}/managed.toml:\n  [managed]\n  cluster_key = \"{public}\"", out.display(), seagent_kernel::managed::SYSTEM_DIR)
            });
        }
        ("cluster", "policy") => match rest(2) {
            "sign" => {
                let file = a.need(3, "policy.toml")?;
                let version = a.num::<u64>("version").map_err(crate::Fail::Usage)?.ok_or_else(|| crate::Fail::Usage("--version N is required (strictly increasing)".into()))?;
                let seed = read_seed(&a.val("seed").map(PathBuf::from).unwrap_or_else(default_seed))?;
                let policy = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
                let b = cluster::sign_bundle(&seed, &policy, version)?;
                let text = serde_json::to_string_pretty(&b).map_err(|e| e.to_string())?;
                match a.val("out") {
                    Some(o) => {
                        std::fs::write(o, &text).map_err(|e| format!("{o}: {e}"))?;
                        eprintln!("signed v{version} → {o}");
                    }
                    None => println!("{text}"),
                }
            }
            "verify" => {
                let b = bundle_from(a.need(3, "bundle.json")?)?;
                let pin = seagent_kernel::config::Config::load(Some(&Paths::from_env().user_config()), None, &[]).ok().and_then(|c| c.managed.cluster_key);
                cluster::verify_bundle(&b, pin.as_deref())?;
                println!("bundle v{} verifies{}", b.version, if pin.is_some() { " against the pinned key" } else { " (signature only: no key is pinned here)" });
            }
            "publish" => {
                let b = bundle_from(a.need(3, "bundle.json")?)?;
                let v = daemon("cluster.policy.publish", json!({"bundle": b}))?;
                print(a, &v, |v| format!("published v{}", v["published"]));
            }
            "push" => {
                let v = daemon("cluster.policy.push", json!({"node": a.val("node").unwrap_or("")}))?;
                print(a, &v, |v| v["nodes"].as_array().into_iter().flatten().map(|n| format!("{}: {}", n["node"].as_str().unwrap_or("?"), if n["ok"] == true { "applied".to_string() } else { n["error"].as_str().unwrap_or("error").to_string() })).collect::<Vec<_>>().join("\n"));
            }
            "pull" => {
                let v = daemon("cluster.policy.pull", json!({}))?;
                print(a, &v, |v| v["installed"].as_u64().map(|n| format!("installed v{n}; restart seagentd to apply it")).unwrap_or_else(|| "already current".into()));
            }
            "" | "status" => print(a, &daemon("cluster.policy.status", json!({}))?, |v| serde_json::to_string_pretty(v).unwrap_or_default()),
            other => return usage(&format!("unknown `cluster policy {other}`; use sign, verify, publish, push, pull or status")),
        },
        ("cluster", other) => return usage(&format!("unknown `cluster {other}`; use status, nodes, sessions, agents, node, keygen or policy")),
        _ => return Ok(2),
    }
    Ok(0)
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some(run(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn keygen_sign_and_verify_round_trip_without_a_daemon() {
        let d = seagent_core::tmp::TempDir::new("seagent-cluster-cli");
        let seed = d.path().join("k").join("signing.seed");
        let public = keygen(&seed).unwrap();
        assert!(public.starts_with("ed25519:"));
        assert!(keygen(&seed).unwrap_err().contains("refusing to overwrite"));
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&seed).unwrap().permissions().mode() & 0o777, 0o600);
        let b = cluster::sign_bundle(&read_seed(&seed).unwrap(), "[model]\nallow = [\"local/*\"]\n", 1).unwrap();
        assert_eq!(b.key, public);
        assert!(cluster::verify_bundle(&b, Some(&public)).is_ok());
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_seed(&seed).unwrap_err().contains("chmod 600"));
    }

    /// The console's method names ride on the app server's existing scope rules (no new auth
    /// table): reads are metadata an operator / auditor may see, every change is admin-only.
    #[test]
    fn rbac_reads_are_metadata_and_changes_are_admin_only() {
        use seagent_app::identity::{Access, Role};
        let (op, aud, user, admin) = (Access::Roles(vec![Role::Operator]), Access::Roles(vec![Role::Auditor]), Access::Roles(vec![Role::User]), Access::admin());
        for m in ["cluster.status", "cluster.nodes.list", "cluster.sessions.list", "cluster.agents.list", "cluster.self.status", "cluster.policy.status", "cluster.policy.get", "ha.status", "workers.status"] {
            assert!(cluster::METHODS.contains(&m), "{m}");
            assert!(op.permits(m).is_ok() && aud.permits(m).is_ok() && user.permits(m).is_ok(), "{m} is a read");
        }
        for m in ["cluster.node.add", "cluster.node.remove", "cluster.policy.publish", "cluster.policy.apply", "cluster.policy.push", "cluster.policy.pull", "ha.stepdown", "workers.dispatch"] {
            assert!(cluster::METHODS.contains(&m), "{m}");
            assert!(op.permits(m).is_err() && aud.permits(m).is_err() && user.permits(m).is_err(), "{m} must be admin-only");
            assert!(admin.permits(m).is_ok());
            assert_eq!(seagent_app::exposure::required_scope(m), seagent_app::exposure::Scope::Admin);
        }
    }

    #[test]
    fn renders_status_without_panicking_on_partial_data() {
        assert!(ha_human(&json!({"enabled": false, "node": "x"})).contains("HA is off"));
        assert!(ha_human(&json!({"enabled": true, "node": "a", "role": "leader", "epoch": 3, "leader": {"node": "a", "epoch": 3, "renewed": 7}})).contains("epoch 3"));
        assert!(nodes_human(&json!([{"node": "a", "alive": true, "role": "leader", "running": ["s"]}, {"node": "far", "alive": false, "source": "remote", "error": "timeout"}])).contains("timeout"));
        assert!(workers_human(&json!({"count": 2, "workers": [{"index": 0, "pid": 9, "alive": true, "session": "s1", "restarts": 1}]})).contains("running s1"));
        assert_eq!(sessions_human(&json!([])), "no sessions");
    }
}
