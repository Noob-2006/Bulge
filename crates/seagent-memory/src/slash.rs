//! Native slash commands of the memory subsystem (Hermes `hermes_cli/commands.py` /memory,
//! /journey, /learning; OpenClaw commands-registry /dreaming, /active-memory). Registered with
//! `Kernel::add_slash`, so every surface (`seagent run`/`chat`, TUI, web, channels) reaches them.
//!
//! - `/memory …` — the `seagent memory` command set (show/add/review/pending/accept/reject/
//!   approval/setup/status/off/reset/index/search/promote/dreaming/events/query/wiki/…).
//! - `/journey` (`/learning`) — the learning graph: list, timeline, delete.
//! - `/dreaming [status|on|off|run [phase]]`.
//! - `/active-memory [on|off|status]`.

use crate::Host;
use seagent_kernel::slash::{Slash, SlashCtx, SlashReply};
use std::path::PathBuf;
use std::sync::Arc;

pub struct MemorySlash {
    host: Arc<Host>,
    ws: PathBuf,
}

impl MemorySlash {
    pub fn new(host: Arc<Host>, ws: PathBuf) -> MemorySlash {
        MemorySlash { host, ws }
    }
    pub fn host(&self) -> &Arc<Host> {
        &self.host
    }
    /// The workspace the command was typed in (fallback: the one the kernel was attached to).
    fn ws(&self, ctx: &SlashCtx) -> PathBuf {
        ctx.session
            .as_deref()
            .and_then(|s| ctx.kernel.store.read(s).ok())
            .map(|e| PathBuf::from(seagent_kernel::projection::project(&e).workspace))
            .filter(|p| p.is_dir())
            .unwrap_or_else(|| self.ws.clone())
    }
}

impl Slash for MemorySlash {
    fn commands(&self) -> Vec<(String, String)> {
        vec![
            ("memory".into(), "Durable memory: show, add, review, accept, reject, approval, setup, status, search, index, dreaming, wiki".into()),
            ("journey".into(), "Learning graph: what seagent has learned (alias /learning)".into()),
            ("dreaming".into(), "Background consolidation: status | on | off | run [light|rem|deep]".into()),
            ("active-memory".into(), "Pre-reply recall: on | off | status".into()),
        ]
    }

    fn run(&self, ctx: &SlashCtx, name: &str, args: &str) -> Option<Result<SlashReply, String>> {
        let session = ctx.session.clone().unwrap_or_default();
        let ws = self.ws(ctx);
        let out = match name {
            // `/journey` learns about the workspace it was typed in, so go through the CLI with
            // that workspace's skill roots instead of the attach-time ones.
            "journey" | "learning" => crate::journey::run(
                &self.host,
                &seagent_kernel::commands::split_args(args),
                &[(String::from("base"), ws.join(".seagent/skills")), (String::from("profile"), self.host.data.join("skills"))],
            ),
            _ => crate::slash(&self.host, name, args, &session)?,
        };
        Some(out.map(SlashReply::text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(h: &Arc<Host>, name: &str, args: &str) -> Result<String, String> {
        crate::slash(h, name, args, "s1").unwrap_or_else(|| Err(format!("`/{name}` is not ours")))
    }

    #[test]
    fn commands_cover_the_memory_family() {
        let h = crate::test_host("slash-commands", |_| {});
        let s = MemorySlash::new(h, std::path::PathBuf::from("."));
        let names: Vec<String> = s.commands().into_iter().map(|(n, _)| n).collect();
        for want in ["memory", "journey", "dreaming", "active-memory"] {
            assert!(names.contains(&want.to_string()), "{names:?}");
        }
    }

    #[test]
    fn routes_the_four_commands() {
        let h = crate::test_host("slash-routes", |_| {});
        assert!(reply(&h, "dreaming", "status").unwrap().contains("Dreaming status"));
        assert!(reply(&h, "active-memory", "status").is_ok());
        assert!(reply(&h, "memory", "status").unwrap().contains("provider:"));
        assert!(reply(&h, "memory", "accept").is_err(), "missing <n|all> is a usage error");
        assert!(reply(&h, "journey", "list").is_ok());
        assert!(reply(&h, "memory", "bogus").unwrap_err().contains("usage: seagent memory"));
        assert!(reply(&h, "skills", "").is_err(), "not a memory command");
    }
}
