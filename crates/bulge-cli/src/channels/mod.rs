//! `bulge channels`: talk to bulge from chat apps.
//!
//! `bulge channels serve` connects every account in `~/.bulge/channels.json`,
//! admits messages through the access policy (owner allow-list, pairing codes,
//! group mention gating), and runs each admitted message as a turn of that
//! chat's bulge conversation — in the sandbox VM, like any other job — then
//! replies with the result. Messages from one chat run in order; different
//! chats run side by side up to `max_parallel_jobs`.
//!
//! Chat jobs default to full-auto in a dedicated workspace: there is nobody at
//! the computer to approve a diff, so changes are written back under a
//! snapshot and `/undo` in the chat rolls the newest one back.
//!
//! Tokens live in `~/.bulge/keys/<name>` (mode 600, checked); the config only
//! names them. They are used on the host for the app's own API and never
//! reach the VM.

mod config;
mod files;
mod hub;
mod runner;
mod serve;

pub use config::*;
use files::*;
pub use hub::*;
pub use runner::*;
pub use serve::*;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bulge_channels::access::{PairingStore, now_secs};

/// Write a fresh random secret (64 hex chars) to `~/.bulge/keys/<name>`, mode
/// 600, refusing to overwrite an existing key.
fn genkey(home: &Path, name: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return Err(format!("bad key name {name:?}"));
    }
    let dir = home.join(".bulge/keys");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("random: {e}"))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("{}: {e} (keys are never overwritten; remove it first to rotate)", path.display()))?;
    file.write_all(hex.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    println!("wrote {} (mode 600)", path.display());
    Ok(())
}

const USAGE: &str = "\
usage:
    bulge channels serve                 connect the accounts in ~/.bulge/channels.json and serve
    bulge channels pending               list pairing codes waiting for approval
    bulge channels approve <code>        let the sender of a pairing code use bulge
    bulge channels revoke <channel> <sender-id>
    bulge channels allowed               list approved senders
    bulge channels genkey <name>         write a random 256-bit secret to ~/.bulge/keys/<name>
                                         (e.g. the LINE webhook path secret)
";

/// `bulge channels …`. Returns the process exit code.
pub fn dispatch(args: &[String]) -> i32 {
    let Ok(home) = std::env::var("HOME").map(PathBuf::from) else {
        eprintln!("error: HOME is not set");
        return 2;
    };
    let pairing_path = home.join(".bulge/channels/pairing.json");
    let pairing = || PairingStore::load(&pairing_path);
    let result: Result<(), String> = match args.first().map(String::as_str) {
        Some("serve") => (|| {
            let config = load_config(&home.join(".bulge/channels.json"))?;
            let runner = Arc::new(VmRunner::new(config.clone()));
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(serve(&home, config, runner.clone(), runner))
        })(),
        Some("pending") => pairing().and_then(|p| p.pending(now_secs())).map(|pending| {
            if pending.is_empty() {
                println!("no pairing codes are waiting");
            }
            for item in pending {
                println!("{}  {}  {} ({})  expires in {} min", item.code, item.channel, item.sender_name, item.sender_id, item.expires_at.saturating_sub(now_secs()) / 60);
            }
        }),
        Some("approve") => match args.get(1) {
            Some(code) => pairing().and_then(|mut p| p.approve(code, now_secs())).map(|item| {
                println!("approved {} ({}) on {}", item.sender_name, item.sender_id, item.channel);
            }),
            None => Err("approve needs a code".into()),
        },
        Some("revoke") => match (args.get(1), args.get(2)) {
            (Some(channel), Some(sender)) => pairing().and_then(|mut p| p.revoke(channel, sender)).map(|removed| {
                println!("{}", if removed { "revoked" } else { "that sender was not approved" });
            }),
            _ => Err("revoke needs <channel> <sender-id>".into()),
        },
        Some("genkey") => match args.get(1) {
            Some(name) => genkey(&home, name),
            None => Err("genkey needs a key name".into()),
        },
        Some("allowed") => pairing().and_then(|p| p.approved_senders()).map(|approved| {
            for (channel, ids) in approved {
                println!("{channel}: {}", ids.join(", "));
            }
        }),
        _ => {
            eprint!("{USAGE}");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests;
