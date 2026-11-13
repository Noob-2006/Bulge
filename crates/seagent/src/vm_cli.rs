//! `seagent vm desktop …`: the graphical desktop VMs of `[desktop_vm]` (behaviour in
//! `seagent_vm::desktop`; this module only parses flags, loads the config and prints).
//!
//! ```text
//! seagent vm desktop build [--force]            download + verify the pinned image, provision Xfce + Chromium
//! seagent vm desktop start [name]               boot (default: [desktop_vm] default)
//! seagent vm desktop stop [name]
//! seagent vm desktop reset [name]              stop and delete the disk overlay (next start = fresh image)
//! seagent vm desktop status [name] [--json]
//! seagent vm desktop list [--json]
//! seagent vm desktop screenshot [name] -o FILE.png
//! seagent vm desktop input [name] '<event json>'   e.g. '{"type":"click","x":640,"y":90}'
//! ```

use seagent_kernel::config::{Config, Paths};
use seagent_vm::desktop::{DesktopConfig, DesktopVms, Input};

pub fn register_route() {
    seagent_core::registry::register_command_route("vm", Some(|sub| sub == "desktop"), route);
    seagent_core::registry::register_config_validator("desktop_vm", |cfg, out| {
        let Some(c) = cfg.downcast_ref::<Config>() else { return };
        if let Err(e) = DesktopConfig::parse(&c.desktop_vm) {
            out.push(e);
        }
    });
}

/// The desktop VMs of this seagent home under `cfg`.
pub fn vms(cfg: &Config, paths: &Paths) -> Result<DesktopVms, String> {
    let dcfg = seagent_vm::bundle::apply_desktop(&DesktopConfig::parse(&cfg.desktop_vm)?);
    Ok(DesktopVms::new(dcfg, &paths.data, &paths.cache_dir(), &paths.runtime))
}

const USAGE: &str = "usage: seagent vm desktop build [--force] | start [name] | stop [name] | reset [name] | status [name] [--json] | list [--json] | screenshot [name] -o FILE.png | input [name] '<event json>'";

fn route(_cmd: &str, argv: &[String]) -> Result<i32, String> {
    let a = crate::args::Args::parse(&[])?;
    let paths = Paths::from_env();
    let cfg = crate::load_config(&a, &crate::workspace(&a).map_err(|e| e.to_string())?, &paths).map_err(|e| e.to_string())?;
    let v = vms(&cfg, &paths)?;
    cli(&v, &argv[1..], &mut |l| println!("{l}"))
}

/// `argv` excludes `vm desktop`.
pub fn cli(v: &DesktopVms, argv: &[String], out: &mut dyn FnMut(&str)) -> Result<i32, String> {
    let mut pos: Vec<&str> = vec![];
    let (mut json, mut force, mut file) = (false, false, None::<String>);
    let mut it = argv.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--json" => json = true,
            "--force" => force = true,
            "-o" | "--out" => file = Some(it.next().ok_or("-o needs a file")?.clone()),
            "-h" | "--help" => {
                out(USAGE);
                return Ok(0);
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}\n{USAGE}")),
            s => pos.push(s),
        }
    }
    let sub = pos.first().copied().unwrap_or("");
    let name = |i: usize| pos.get(i).map(|s| s.to_string()).unwrap_or_else(|| v.cfg.default.clone());
    let show = |s: &seagent_vm::desktop::VmStatus, out: &mut dyn FnMut(&str)| {
        if json {
            out(&serde_json::to_string_pretty(s).unwrap_or_default());
            return;
        }
        let state = if s.running { format!("running (pid {}, {}, {}x{})", s.pid.unwrap_or(0), s.accel, s.width, s.height) } else { "stopped".into() };
        out(&format!("{}: {state}", s.name));
        out(&format!("  disk {}{}", s.disk, if s.disk_exists { "" } else { " (created on first start)" }));
        out(&format!("  image {}{}", s.image, if s.image_built { "" } else { " (not built: seagent vm desktop build)" }));
        if s.running {
            out(&format!("  qmp {}", s.qmp));
            // Windows QEMU runs without a VNC server (frames come over QMP).
            if cfg!(unix) {
                out(&format!("  vnc {}", s.vnc));
            }
        }
        if let Some(w) = &s.warning {
            out(&format!("  warning: {w}"));
        }
    };
    match sub {
        "build" => {
            let p = v.build(force, &mut |l| out(l))?;
            out(&format!("image: {}", p.display()));
            Ok(0)
        }
        "start" => {
            let s = v.start(&name(1))?;
            show(&s, out);
            Ok(0)
        }
        "reset" => {
            let n = name(1);
            v.reset(&n)?;
            out(&format!("{n}: disk overlay removed; the next start boots the current image"));
            Ok(0)
        }
        "stop" => {
            let n = name(1);
            out(&format!("{n}: {}", if v.stop(&n)? { "stopped" } else { "was not running" }));
            Ok(0)
        }
        "status" => {
            show(&v.status(&name(1)), out);
            Ok(0)
        }
        "list" | "ls" => {
            v.reap();
            let l = v.list();
            if json {
                out(&serde_json::to_string_pretty(&l).unwrap_or_default());
            } else {
                for s in &l {
                    out(&format!("{:<16} {:<8} {}x{} {}", s.name, if s.running { "running" } else { "stopped" }, s.width, s.height, if s.running { s.accel.as_str() } else { "" }));
                }
            }
            Ok(0)
        }
        "screenshot" | "frame" => {
            let f = file.ok_or("screenshot needs -o FILE.png")?;
            let png = v.screenshot(&name(1))?;
            std::fs::write(&f, &png).map_err(|e| format!("write {f}: {e}"))?;
            out(&format!("wrote {f} ({} bytes)", png.len()));
            Ok(0)
        }
        "input" => {
            let (n, raw) = match pos.len() {
                2 => (v.cfg.default.clone(), pos[1]),
                3 => (pos[1].to_string(), pos[2]),
                _ => return Err(format!("input needs an event\n{USAGE}")),
            };
            let ev: serde_json::Value = serde_json::from_str(raw).map_err(|e| format!("event is not JSON: {e}"))?;
            let r = v.input(&n, &Input::from_json(&ev)?)?;
            out(&r.to_string());
            Ok(0)
        }
        "" => {
            out(USAGE);
            Ok(2)
        }
        o => Err(format!("unknown subcommand `{o}`\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_desktop_cli_reports_and_refuses_cleanly() {
        let d = seagent_core::tmp::TempDir::new("seagent-vmcli");
        let v = DesktopVms::new(DesktopConfig::default(), &d.join("data"), &d.join("cache"), &d.join("run"));
        let mut lines = vec![];
        let run = |args: &[&str], lines: &mut Vec<String>| cli(&v, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &mut |l| lines.push(l.to_string()));
        assert_eq!(run(&[], &mut lines).unwrap(), 2);
        assert_eq!(run(&["list"], &mut lines).unwrap(), 0);
        assert!(lines.last().unwrap().starts_with("desk") && lines.last().unwrap().contains("stopped"), "{lines:?}");
        run(&["status", "--json"], &mut lines).unwrap();
        let s: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!((s["name"].as_str(), s["running"].as_bool(), s["width"].as_u64()), (Some("desk"), Some(false), Some(1280)));
        assert!(run(&["start"], &mut lines).unwrap_err().contains("seagent vm desktop build"));
        assert!(run(&["screenshot"], &mut lines).unwrap_err().contains("-o"));
        assert!(run(&["screenshot", "-o", "x.png"], &mut lines).unwrap_err().contains("not running"));
        assert!(run(&["input", "{\"type\":\"warp\"}"], &mut lines).unwrap_err().contains("unknown event type"));
        assert!(run(&["frobnicate"], &mut lines).is_err());
        assert!(run(&["--nope"], &mut lines).is_err());
        assert_eq!(run(&["stop"], &mut lines).unwrap(), 0);
        assert!(lines.last().unwrap().contains("was not running"));
    }
}
