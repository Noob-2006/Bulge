//! Per-agent workspace slots.
//!
//! A slot is a private copy-on-write view of the main workspace: an overlay
//! whose lower layers are a snapshot of the main upper dir plus the read-only
//! host share, its own uid, mount namespace, home and `/tmp`. Everything that
//! needs root is done by the privileged `--slot-helper` process (started before
//! `sandboxd` drops privileges); tools inside a slot are served by a
//! `--slot-server` process that is this same binary re-executed inside the
//! slot's namespace as the slot uid.

mod client;
mod helper;
mod merge;
mod protocol;
mod server;

pub use client::*;
pub use helper::*;
pub use merge::*;
pub use protocol::*;
pub use server::*;

use std::path::{Component, Path, PathBuf};

/// Matches `bulge-cli`'s `MAX_CONCURRENT_SUBAGENTS`.
pub const MAX_SLOTS: u8 = 8;
/// Root-owned 0700: `<n>/{snap,upper,work,merged,home,tmp}`.
pub const SLOTS_ROOT: &str = "/run/bulge/slots";
/// Owned by the base uid, 0700: `slot<n>.sock`.
pub const CTL_DIR: &str = "/run/bulge/ctl";

pub fn validate_slot(slot: u8) -> Result<u8, String> {
    if slot < MAX_SLOTS {
        Ok(slot)
    } else {
        Err(format!("slot {slot} is out of range (must be < {MAX_SLOTS})"))
    }
}

/// Validate the two slots of a staging copy: both must be valid and distinct.
pub fn validate_stage_slots(slot: u8, from: u8) -> Result<(u8, u8), String> {
    let slot = validate_slot(slot)?;
    let from = validate_slot(from)?;
    if slot == from {
        return Err("stage source and destination must be different slots".into());
    }
    Ok((slot, from))
}

/// Validate a workspace-relative path used for export/merge. Returns the
/// normalised relative path.
pub fn validate_rel_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("path is empty".into());
    }
    if path.as_bytes().contains(&0) {
        return Err("path contains NUL".into());
    }
    let raw = Path::new(path);
    if raw.is_absolute() {
        return Err(format!("path must be relative: {path}"));
    }
    let mut normal = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(part) => {
                if part.as_encoded_bytes().starts_with(b".overlay") {
                    return Err(format!("reserved overlay path component in {path}"));
                }
                normal.push(part);
            }
            Component::CurDir => return Err(format!("path must not contain '.' components: {path}")),
            Component::ParentDir => return Err(format!("path must not contain '..' components: {path}")),
            Component::RootDir | Component::Prefix(_) => return Err(format!("path must be relative: {path}")),
        }
    }
    if normal.as_os_str().is_empty() {
        return Err(format!("path does not name a file: {path}"));
    }
    Ok(normal)
}

#[cfg(test)]
mod tests;
