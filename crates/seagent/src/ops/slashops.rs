//! Chat slash commands backed by ops modules (rows merged into `slash::defs()`).

use crate::slash::{Ctx, Def, Reply};

fn text(t: impl Into<String>) -> Result<Reply, String> {
    Ok(Reply { text: Some(t.into()), ..Default::default() })
}

pub const SLASH: &[Def] = &[
    Def { name: "profile", aliases: &[], args: "", help: "Show the active profile and its home directory", category: "Info", admin: false, local: false, run: cmd_profile },
    Def { name: "snapshot", aliases: &["snap"], args: "[create [label]|list|restore <id>]", help: "Create or restore snapshots of config and state", category: "Session", admin: true, local: false, run: |c, a| text(crate::ops::backup::snapshot_command(&c.k.paths, a)?) },
    Def { name: "export", aliases: &[], args: "[profile]", help: "Export a profile (config, skills, memory) to a shareable archive", category: "Configuration", admin: true, local: false, run: cmd_export },
    Def { name: "import", aliases: &[], args: "<archive> [name]", help: "Import a profile archive as a new profile", category: "Configuration", admin: true, local: false, run: cmd_import },
    Def { name: "reload", aliases: &[], args: "", help: "Reload .env variables into the running process", category: "Tools", admin: true, local: false, run: |c, _| text(crate::ops::envfile::reload(&c.k.paths, &c.workspace)?) },
    Def { name: "diagnostics", aliases: &[], args: "[note]", help: "Write a diagnostics bundle (sensitive; owner DMs only)", category: "Info", admin: true, local: false, run: crate::ops::controlcmds::cmd_diagnostics },
    Def { name: "seagent", aliases: &["rescue"], args: "[status|models|config get <k>|set model <m>|config set <k> <v>|restart|yes|no]", help: "Setup and repair helper (deterministic; changes need /seagent yes)", category: "Configuration", admin: true, local: false, run: crate::ops::controlcmds::cmd_rescue },
    Def { name: "restart", aliases: &[], args: "[now|<drain seconds>]", help: "Restart the seagent daemon once running turns finish", category: "Configuration", admin: true, local: false, run: crate::ops::controlcmds::cmd_restart },
    Def { name: "pair", aliases: &[], args: "[qr|pending|approve [code]|reject <code>|cleanup]", help: "Generate device setup codes and approve device pairing", category: "Configuration", admin: true, local: false, run: crate::ops::controlcmds::cmd_pair },
    Def { name: "controlui", aliases: &[], args: "", help: "Open the Control UI as a Telegram Mini App (owner DM)", category: "Info", admin: false, local: false, run: crate::ops::controlcmds::cmd_controlui },
    Def { name: "update", aliases: &[], args: "[now]", help: "Check for a newer seagent release, or install it (the daemon restarts on the new binary)", category: "Info", admin: true, local: false, run: |c, a| text(update(c, a, spawn_update)?) },
    Def { name: "worktree", aliases: &[], args: "[new [name]|list|prune [--dry-run]]", help: "Show, list, create, or prune isolated git worktrees", category: "Session", admin: true, local: true, run: crate::ops::worktree::slash },
    Def { name: "debug", aliases: &[], args: "[local|share] | show|set path=value|unset path|reset", help: "Debug report (local/upload) or runtime debug overrides", category: "Info", admin: true, local: false, run: crate::ops::debugdump::slash },
];

fn cmd_profile(c: &Ctx, _: &str) -> Result<Reply, String> {
    let name = crate::ops::profile::current();
    text(format!("profile {name}\nconfig {}\ndata {}", c.k.paths.config_dir.display(), c.k.paths.data.display()))
}

fn cmd_export(_: &Ctx, a: &str) -> Result<Reply, String> {
    let name = a.split_whitespace().next().map(String::from).unwrap_or_else(crate::ops::profile::current);
    let p = crate::ops::profile::export(&name, None)?;
    text(format!("exported {name} → {} (no secrets, sessions or channels)", p.display()))
}

fn cmd_import(_: &Ctx, a: &str) -> Result<Reply, String> {
    let mut w = a.split_whitespace();
    let path = w.next().ok_or("usage: /import <archive> [name]")?;
    let n = crate::ops::profile::import(std::path::Path::new(path), w.next())?;
    text(format!("imported profile {n}; switch with `seagent -p {n} …` or `seagent profile use {n}`"))
}

// ───────────────────────── /update ─────────────────────────

/// How `/update now` hands off the install (swappable in tests).
pub type Spawn = fn(&[&str]) -> Result<String, String>;

/// A detached `seagent update`: it stops the daemon, verifies and swaps the binary, then starts
/// the daemon again on the new version (see `ops::update`), exactly as the CLI would.
fn spawn_update(args: &[&str]) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut c = seagent_core::platform::proc::command(exe);
    c.args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    crate::ops::hostos::detach(&mut c);
    Ok(format!("pid {}", c.spawn().map_err(|e| e.to_string())?.id()))
}

/// `/update [now]` (Hermes `commands.py` `/update`, OpenClaw `commands-update.ts`): a chat can
/// start the host's self-update, not just check. The bare command is a read-only check; `now`
/// installs. Package-managed installs (nix, /usr/bin) refuse and say where to update instead.
pub fn update(c: &Ctx, a: &str, spawn: Spawn) -> Result<String, String> {
    let now = env!("CARGO_PKG_VERSION");
    let channel = &c.k.cfg.update.channel;
    match a.trim().to_ascii_lowercase().as_str() {
        "" | "check" | "status" => match crate::ops::update::check(&c.k.cfg, None)? {
            Some(r) => Ok(format!("seagent {} is available (you have {now}). Send `/update now` to install it here — running turns finish first and the daemon restarts on the new binary.", r.tag)),
            // The daemon's start-up check prints the same sentence.
            None => Ok(crate::ops::update::check_text(&c.k.cfg)),
        },
        "now" | "install" | "yes" => {
            let Some(r) = crate::ops::update::check(&c.k.cfg, None)? else {
                return Ok(format!("seagent {now} is already up to date ({channel} channel)"));
            };
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            if let Some(why) = crate::ops::update::managed(&exe) {
                return Err(why.into());
            }
            let at = spawn(&["update"])?;
            Ok(format!("updating seagent {now} → {} in the background ({at}); the daemon restarts on the new binary. `seagent update --rollback` restores this one.", r.tag))
        }
        other => Err(format!("unknown `{other}` (usage: /update [now])")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::net::fake;
    use crate::slash::Surface;
    use std::sync::{Arc, Mutex};

    fn ctx<'a>(t: &'a crate::testkit::Kit) -> Ctx<'a> {
        Ctx { k: &t.k, ext: None, session: None, workspace: t.ws.clone(), surface: Surface::Cli, sender: None, notify: None }
    }

    fn say(t: &crate::testkit::Kit, line: &str) -> String {
        crate::slash::run(&ctx(t), line).and_then(|r| r.text).unwrap_or_default()
    }

    static SPAWNED: Mutex<Vec<String>> = Mutex::new(Vec::new());
    fn record(args: &[&str]) -> Result<String, String> {
        SPAWNED.lock().unwrap().push(args.join(" "));
        Ok("pid 4242".into())
    }

    #[test]
    fn update_checks_then_installs_through_a_detached_runner() {
        let (base, _log) = fake::serve(Arc::new(move |r: &fake::Req| match r.path.as_str() {
            p if p.starts_with("/repos/o/r/releases") => (200, "application/json".into(), serde_json::json!([
                {"tag_name": "v99.0.0", "prerelease": false, "body": "big", "assets": []},
                {"tag_name": "v0.0.1", "prerelease": false, "assets": []}
            ]).to_string().into_bytes()),
            _ => (404, "text/plain".into(), vec![]),
        }));
        let t = crate::testkit::kit_with(|cfg| cfg.update.url = format!("{base}/repos/o/r"));
        SPAWNED.lock().unwrap().clear();
        // Bare `/update`: a read-only check that names the release and the confirmation.
        let check = say(&t, "/update");
        assert!(check.contains("seagent v99.0.0 is available") && check.contains("/update now"), "{check}");
        assert!(SPAWNED.lock().unwrap().is_empty(), "a bare /update must not install anything");
        // `/update now`: hands off to a detached `seagent update` and says the daemon restarts.
        // (The table's row is exercised for the read-only check above; installing is driven
        // through the same function with a recording runner so no process is spawned here.)
        let done = update(&ctx(&t), "now", record).unwrap();
        assert_eq!(*SPAWNED.lock().unwrap(), vec!["update".to_string()], "{done}");
        assert!(done.contains("updating seagent") && done.contains("v99.0.0") && done.contains("restarts"), "{done}");
        assert!(update(&ctx(&t), "soon", record).unwrap_err().contains("usage: /update [now]"));
        assert!(say(&t, "/update soon").starts_with("/update: unknown `soon`"));
        // Nothing newer on the channel: "already up to date", no spawn.
        SPAWNED.lock().unwrap().clear();
        let (base2, _l) = fake::serve(Arc::new(|_: &fake::Req| (200, "application/json".into(), b"[]".to_vec())));
        let t2 = crate::testkit::kit_with(|cfg| cfg.update.url = format!("{base2}/repos/o/r"));
        assert!(say(&t2, "/update").contains("up to date"));
        assert!(update(&ctx(&t2), "now", record).unwrap().contains("already up to date"));
        assert!(SPAWNED.lock().unwrap().is_empty());
    }

    #[test]
    fn restart_is_registered_admin_only_and_parses_the_drain() {
        let t = crate::testkit::kit();
        let d = crate::slash::find("restart").expect("/restart is in the table");
        assert!(d.admin && !d.local, "restarting the host is an admin, non-local command");
        assert_eq!(d.args, "[now|<drain seconds>]");
        // A bad argument fails before anything is spawned; the happy path is `restart_parses_drain`.
        assert!(say(&t, "/restart soon").contains("usage: /restart [now|<drain seconds>]"));
        // Channels without an admin list refuse it (the sender's `allow_admin_from` is checked).
        let mut c = ctx(&t);
        c.surface = Surface::Channel;
        c.sender = Some(crate::slash::Sender { channel: "tg".into(), chat: "1".into(), sender: "u1".into(), ..Default::default() });
        let out = crate::slash::run(&c, "/restart").and_then(|r| r.text).unwrap_or_default();
        assert!(out.contains("allow_admin_from"), "{out}");
    }

    #[test]
    fn profile_rows_are_wired() {
        let t = crate::testkit::kit();
        let p = say(&t, "/profile");
        assert!(p.starts_with("profile ") && p.contains(&t.paths.config_dir.display().to_string()), "{p}");
        assert_eq!(crate::slash::find("snap").map(|d| d.name), Some("snapshot"));
        let r = crate::slash::run(&ctx(&t), "/snapshot create before-change").and_then(|r| r.action);
        assert!(r.is_none(), "snapshot answers with text, no surface action");
    }

}
