//! Developer-workflow commands: `seagent lsp` (Hermes `agent/lsp/cli.py`), `seagent verify`
//! (`hermes_cli/verify_cmd.py`), and the prompt commands `seagent init` / `seagent plan`.

use crate::args::Args;
use crate::{usage, Fail, R};
use seagent_kernel::config::Config;
use seagent_kernel::verify;
use seagent_tools::lsp::{self, LspConfig};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `[lsp]` from the kernel config, as seagent-tools reads it.
pub fn lsp_config(cfg: &Config) -> Result<LspConfig, String> {
    let v = serde_json::to_value(&cfg.lsp).map_err(|e| format!("[lsp]: {e}"))?;
    LspConfig::from_json(&v)
}

/// Install the process-wide LSP service (post-edit diagnostics for write/edit/patch).
pub fn configure_lsp(cfg: &Config) {
    match lsp_config(cfg) {
        Ok(c) => lsp::configure(c),
        Err(e) => eprintln!("seagent: warning: {e}; LSP diagnostics off"),
    }
}

fn status_of(cfg: &LspConfig, s: &lsp::ServerDef) -> &'static str {
    if lsp::command_for(cfg, s).is_some() {
        "installed"
    } else if cfg.servers.contains_key(&s.id) && !s.extensions.is_empty() && !lsp::builtin_servers().iter().any(|b| b.id == s.id) {
        "manual-only"
    } else {
        "missing"
    }
}

pub fn cmd_lsp(a: &Args, cfg: &Config) -> R {
    let lc = lsp_config(cfg).map_err(Fail::Msg)?;
    let servers = lsp::all_servers(&lc);
    match a.pos(0).unwrap_or("status") {
        "status" => {
            let svc = lsp::Service::new(lc.clone());
            let info = svc.status();
            if a.flag("json") {
                let reg: Vec<Value> = servers.iter().map(|s| json!({"server_id": s.id, "extensions": s.extensions, "description": s.description, "binary_status": status_of(&lc, s)})).collect();
                println!("{}", serde_json::to_string_pretty(&json!({"service": info, "registry": reg})).unwrap_or_default());
                return Ok(0);
            }
            println!("LSP Service\n===========");
            println!("  enabled:         {}", lc.enabled);
            println!("  wait_mode:       {}", lc.wait_mode);
            println!("  wait_timeout:    {}s", lc.wait());
            println!("  install_strategy:{} (seagent never auto-installs)", lc.install_strategy);
            println!("  idle_timeout:    {}s", lc.idle_timeout);
            let disabled: Vec<&String> = lc.servers.iter().filter(|(_, o)| o.disabled).map(|(n, _)| n).collect();
            if !disabled.is_empty() {
                println!("  disabled in cfg: {}", disabled.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            }
            println!("\nRegistered Servers\n==================");
            for s in &servers {
                let st = status_of(&lc, s);
                let mark = match st {
                    "installed" => "✓",
                    "missing" => "·",
                    _ => "?",
                };
                let mut exts = s.extensions.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
                if s.extensions.len() > 5 {
                    exts.push_str(&format!(", … (+{})", s.extensions.len() - 5));
                }
                println!("  {mark} {:24} [{st:11}] {exts}", s.id);
                println!("      {}{}", s.description, if s.untrusted_safe { "" } else { "  [trusted workspaces only]" });
            }
            Ok(0)
        }
        "list" => {
            for s in &servers {
                let st = status_of(&lc, s);
                if a.flag("installed-only") && st != "installed" {
                    continue;
                }
                println!("{:24} [{st:11}] {}", s.id, s.extensions.join(","));
            }
            Ok(0)
        }
        "which" => {
            let id = a.need(1, "server")?;
            let s = servers.iter().find(|s| s.id == id).ok_or_else(|| Fail::Msg(format!("unknown server `{id}` (see `seagent lsp list`)")))?;
            match lsp::command_for(&lc, s) {
                Some(c) => {
                    println!("{}", c[0]);
                    Ok(0)
                }
                None => Err(Fail::Msg(format!("{id}: not found on PATH"))),
            }
        }
        "check" => {
            let f = a.need(1, "file")?;
            let ws = crate::workspace(a)?;
            let file = ws.join(f);
            let file = file.canonicalize().map_err(|e| Fail::Msg(format!("{}: {e}", file.display())))?;
            let svc = lsp::Service::new(lc);
            let r = svc.check_file(&ws, &file);
            svc.shutdown();
            let diags = r.map_err(Fail::Msg)?;
            if a.flag("json") {
                println!("{}", Value::Array(diags));
                return Ok(0);
            }
            if diags.is_empty() {
                println!("no diagnostics");
            }
            for d in &diags {
                println!("{}", lsp::format_diagnostic(d));
            }
            Ok(if diags.iter().any(|d| d["severity"].as_u64().unwrap_or(1) == 1) { 1 } else { 0 })
        }
        "restart" => {
            lsp::shutdown();
            println!("LSP clients torn down (the next edit re-spawns them)");
            Ok(0)
        }
        "install" | "install-all" => Err(Fail::Msg("seagent does not download or install language servers; install the server with your system package manager (e.g. `rustup component add rust-analyzer`, `npm i -g pyright`) and it is picked up from PATH, or set lsp.servers.<id>.command".into())),
        other => usage(format!("unknown `lsp {other}` (status | list [--installed-only] | which <server> | check <file> | restart)")),
    }
}

fn secs(a: &Args, k: &str, def: f64) -> Result<Duration, Fail> {
    let v = a.num::<f64>(k).map_err(Fail::Usage)?.unwrap_or(def);
    if !(v.is_finite() && v > 0.0) {
        return usage(format!("--{k} must be > 0"));
    }
    Ok(Duration::from_secs_f64(v))
}

pub fn cmd_verify(a: &Args) -> R {
    let root: PathBuf = match a.pos(0) {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir().map_err(|e| Fail::Msg(e.to_string()))?,
    };
    let root = root.canonicalize().unwrap_or(root);
    if !root.is_dir() {
        eprintln!("error: not a directory: {}", root.display());
        return Ok(2);
    }
    let json_out = a.flag("json");
    let (recipe, source) = verify::load_or_detect(&root);
    let Some(mut recipe) = recipe else {
        if json_out {
            println!("{}", json!({"ok": false, "error": "no-recipe", "root": root}));
        } else {
            eprintln!("No recognizable project found at {}.\nCreate {} to define a recipe manually.", root.display(), verify::manifest_path(&root).display());
        }
        return Ok(1);
    };
    let port = a.num::<u16>("port").map_err(Fail::Usage)?;
    if let Some(p) = port {
        recipe.port = Some(p);
    }
    if a.flag("save") {
        let p = verify::save_manifest(&root, &recipe).map_err(Fail::Msg)?;
        if !json_out {
            println!("Saved manifest: {}", p.display());
        }
    }
    if a.flag("detect-only") || a.flag("list") {
        let v = json!({"source": source, "recipe": recipe});
        println!("{}", if json_out { v.to_string() } else { serde_json::to_string_pretty(&v).unwrap_or_default() });
        return Ok(0);
    }
    let phases = a.vals("phase");
    if let Some(bad) = phases.iter().find(|p| !["bootstrap", "build", "test", "start"].contains(&p.as_str())) {
        return usage(format!("--phase {bad}: use bootstrap, build, test or start"));
    }
    let opts = verify::Opts { phases, phase_timeout: secs(a, "timeout", verify::DEFAULT_PHASE_TIMEOUT)?, ready_timeout: secs(a, "ready-timeout", verify::DEFAULT_READY_TIMEOUT)?, skip_start: a.flag("skip-start"), port, stop_on_failure: true };
    let res = verify::run_verify(&root, &recipe, &opts);
    if json_out {
        let mut v = serde_json::to_value(&res).unwrap_or_default();
        v["source"] = json!(source);
        println!("{v}");
    } else {
        print!("{}", verify::human_report(&recipe, source, &res));
    }
    Ok(if res.ok { 0 } else { 1 })
}

/// `/init` and `/plan` text for a workspace.
pub fn builtin_prompt(name: &str, args: &str, ws: &Path, cfg: &Config) -> Option<String> {
    seagent_kernel::devprompts::expand_builtin(name, args, ws, cfg.schedule.utc_offset_minutes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn lsp_config_from_kernel_table() {
        let mut cfg = Config::default();
        assert!(lsp_config(&cfg).unwrap().enabled);
        cfg.lsp = "enabled = false\nwait_timeout = 2.5\n[servers.pyright]\ndisabled = true\n".parse().unwrap();
        let c = lsp_config(&cfg).unwrap();
        assert!(!c.enabled && c.wait() == 2.5 && c.servers["pyright"].disabled);
        cfg.lsp = "wait_mode = \"slow\"".parse().unwrap();
        assert!(lsp_config(&cfg).is_err());
    }

    /// `seagent lsp status|list [--installed-only]|which <server>|restart|install` (Hermes
    /// `agent/lsp/cli.py`): every documented verb is dispatched, and install refuses instead of
    /// downloading (seagent never auto-installs).
    #[test]
    fn lsp_verbs_are_dispatched_and_install_refuses() {
        let mut cfg = Config::default();
        assert_eq!(cmd_lsp(&args(&["status"]), &cfg).unwrap(), 0);
        assert_eq!(cmd_lsp(&args(&["status", "--json"]), &cfg).unwrap(), 0);
        assert_eq!(cmd_lsp(&args(&["list"]), &cfg).unwrap(), 0);
        assert_eq!(cmd_lsp(&args(&["list", "--installed-only"]), &cfg).unwrap(), 0);
        assert_eq!(cmd_lsp(&args(&["restart"]), &cfg).unwrap(), 0);
        // `status` is the default verb, and a disabled server only changes the report.
        assert_eq!(cmd_lsp(&args(&[]), &cfg).unwrap(), 0);
        cfg.lsp = "[servers.pyright]\ndisabled = true\n".parse().unwrap();
        assert_eq!(cmd_lsp(&args(&["status", "--json"]), &cfg).unwrap(), 0);

        let which = cmd_lsp(&args(&["which", "not-a-language-server"]), &Config::default()).unwrap_err().to_string();
        assert!(which.contains("unknown server") && which.contains("seagent lsp list"), "{which}");
        let install = cmd_lsp(&args(&["install", "rust-analyzer"]), &Config::default()).unwrap_err().to_string();
        assert!(install.contains("does not download") && install.contains("rust-analyzer"), "{install}");
        assert!(cmd_lsp(&args(&["install-all"]), &Config::default()).is_err());
        let bad = cmd_lsp(&args(&["bogus"]), &Config::default()).unwrap_err().to_string();
        assert!(bad.contains("unknown `lsp bogus`") && bad.contains("which <server>"), "{bad}");
    }

    /// `seagent verify [dir] --detect-only|--save|--phase P|--skip-start|--json` (Hermes
    /// `hermes_cli/verify_cmd.py`): no recipe → 1, not a directory → 2, a manifest recipe runs and
    /// its phase exit status becomes the command's status.
    #[test]
    fn verify_detects_saves_and_runs_a_manifest_recipe() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-verify-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(root.join(".seagent")).unwrap();
        let dir = root.display().to_string();

        assert_eq!(cmd_verify(&args(&[&dir, "--json"])).unwrap(), 1, "no recipe → exit 1");
        assert_eq!(cmd_verify(&args(&["/no/such/seagent-verify-dir"])).unwrap(), 2, "not a directory → exit 2");

        // detection (package.json) + `--detect-only` peeks at the recipe …
        std::fs::write(root.join("package.json"), r#"{"name":"demo","version":"1.0.0","scripts":{"build":"true","test":"true"}}"#).unwrap();
        assert_eq!(cmd_verify(&args(&[&dir, "--detect-only", "--json"])).unwrap(), 0);
        // … and `--save` writes `.seagent/environment.json`.
        assert_eq!(cmd_verify(&args(&[&dir, "--save", "--detect-only"])).unwrap(), 0);
        let manifest = verify::manifest_path(&root);
        assert!(manifest.exists(), "--save wrote {}", manifest.display());

        // a hand-written manifest wins over detection; a phase subset + --skip-start never binds a port.
        std::fs::write(&manifest, r#"{"version":1,"recipe":{"name":"demo","kind":"node","test":["true"]}}"#).unwrap();
        assert_eq!(cmd_verify(&args(&[&dir, "--phase", "test", "--skip-start", "--json"])).unwrap(), 0);
        std::fs::write(&manifest, r#"{"version":1,"recipe":{"name":"demo","kind":"node","test":["exit 3"]}}"#).unwrap();
        assert_eq!(cmd_verify(&args(&[&dir, "--phase", "test", "--skip-start", "--json"])).unwrap(), 1, "a red phase → exit 1");

        // argument errors are rejected before anything runs.
        assert!(cmd_verify(&args(&[&dir, "--phase", "deploy"])).is_err());
        assert!(cmd_verify(&args(&[&dir, "--timeout", "0"])).is_err());
    }
}
