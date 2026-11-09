//! Operations surface: CLI subcommands that are not tied to one agent feature —
//! profiles, backup/restore, self-update, migration importers, doctor/service,
//! logs/telemetry, external secret sources, batch runs/evals, Control UI methods.
//!
//! Every submodule owns its command names (`COMMANDS`), its extra flags and a
//! `dispatch` that returns `None` for commands it does not handle, so `main.rs`
//! only needs `ops::early` + `ops::dispatch` and the daemon `ops::ui_methods`.

use crate::args::Args;
use crate::R;

pub mod appcli;
pub mod archive;
pub mod backup;
pub mod batch;
pub mod cluster;
pub mod completion;
pub mod enterprise;
pub mod tenancy;
pub mod context;
pub mod confcli;
pub mod doctor;
pub mod envfile;
pub mod distill;
pub mod evalkit;
pub mod evals;
pub mod logs;
pub mod migrate;
pub mod miniswe;
pub mod net;
pub mod opsview;
pub mod profile;
pub mod secretsrc;
pub mod rotate;
pub mod service;
pub mod service_os;
pub mod winservice;
pub mod hostos;
pub mod lan;
pub mod slashops;
pub mod status;
pub mod telemetry;
pub mod trajcomp;
pub mod ui_methods;
pub mod ui_term;
pub mod miniapp;
pub mod controlcmds;
pub mod update;
pub mod multiplex;
pub mod directory;
pub mod proxy;
pub mod dns;
pub mod wizard;
pub mod worker;
pub mod worktree;
pub mod project;
pub mod debugdump;
pub mod console;
pub mod users;
pub mod audit;
pub mod storage;
pub mod triage;
pub mod termcli;
pub mod rooms;
pub mod dock;
pub mod hatchgen;
pub mod partial;
pub mod recap;
pub mod webui;
pub mod chat_ux;
pub mod model_keys;
pub mod connectors;
pub mod connectors_live;
pub mod connectors_extra;
pub mod channels_setup;
pub mod toolcfg;
pub mod toollog;
pub mod docker;

pub use slashops::SLASH;

type Dispatch = fn(&str, &Args, &[String]) -> Option<R>;

/// (command names, extra value flags, extra bool flags, dispatcher).
type Module = (&'static [&'static str], &'static [&'static str], &'static [&'static str], Dispatch);

/// One entry per module.
const MODULES: &[Module] = &[
    (profile::COMMANDS, profile::VALUE_FLAGS, profile::BOOL_FLAGS, profile::dispatch),
    (backup::COMMANDS, backup::VALUE_FLAGS, backup::BOOL_FLAGS, backup::dispatch),
    (update::COMMANDS, update::VALUE_FLAGS, update::BOOL_FLAGS, update::dispatch),
    (migrate::COMMANDS, migrate::VALUE_FLAGS, migrate::BOOL_FLAGS, migrate::dispatch),
    (completion::COMMANDS, completion::VALUE_FLAGS, completion::BOOL_FLAGS, completion::dispatch),
    (confcli::COMMANDS, confcli::VALUE_FLAGS, confcli::BOOL_FLAGS, confcli::dispatch),
    (envfile::COMMANDS, envfile::VALUE_FLAGS, envfile::BOOL_FLAGS, envfile::dispatch),
    (doctor::COMMANDS, doctor::VALUE_FLAGS, doctor::BOOL_FLAGS, doctor::dispatch),
    (service::COMMANDS, service::VALUE_FLAGS, service::BOOL_FLAGS, service::dispatch),
    (logs::COMMANDS, logs::VALUE_FLAGS, logs::BOOL_FLAGS, logs::dispatch),
    (telemetry::COMMANDS, telemetry::VALUE_FLAGS, telemetry::BOOL_FLAGS, telemetry::dispatch),
    (rotate::COMMANDS, rotate::VALUE_FLAGS, rotate::BOOL_FLAGS, rotate::dispatch),
    (secretsrc::COMMANDS, secretsrc::VALUE_FLAGS, secretsrc::BOOL_FLAGS, secretsrc::dispatch),
    (status::COMMANDS, status::VALUE_FLAGS, status::BOOL_FLAGS, status::dispatch),
    (batch::COMMANDS, batch::VALUE_FLAGS, batch::BOOL_FLAGS, batch::dispatch),
    (evals::COMMANDS, evals::VALUE_FLAGS, evals::BOOL_FLAGS, evals::dispatch),
    (&[], evalkit::VALUE_FLAGS, evalkit::BOOL_FLAGS, no_commands),
    (distill::COMMANDS, distill::VALUE_FLAGS, distill::BOOL_FLAGS, distill::dispatch),
    (worktree::COMMANDS, worktree::VALUE_FLAGS, worktree::BOOL_FLAGS, worktree::dispatch),
    (project::COMMANDS, project::VALUE_FLAGS, project::BOOL_FLAGS, project::dispatch),
    (debugdump::COMMANDS, debugdump::VALUE_FLAGS, debugdump::BOOL_FLAGS, debugdump::dispatch),
    (console::COMMANDS, console::VALUE_FLAGS, console::BOOL_FLAGS, console::dispatch),
    (users::COMMANDS, users::VALUE_FLAGS, users::BOOL_FLAGS, users::dispatch),
    (audit::COMMANDS, audit::VALUE_FLAGS, audit::BOOL_FLAGS, audit::dispatch),
    (enterprise::COMMANDS, enterprise::VALUE_FLAGS, enterprise::BOOL_FLAGS, enterprise::dispatch),
    (tenancy::COMMANDS, tenancy::VALUE_FLAGS, tenancy::BOOL_FLAGS, tenancy::dispatch),
    (storage::COMMANDS, storage::VALUE_FLAGS, storage::BOOL_FLAGS, storage::dispatch),
    (triage::COMMANDS, triage::VALUE_FLAGS, triage::BOOL_FLAGS, triage::dispatch),
    (worker::COMMANDS, worker::VALUE_FLAGS, worker::BOOL_FLAGS, worker::dispatch),
    (cluster::COMMANDS, cluster::VALUE_FLAGS, cluster::BOOL_FLAGS, cluster::dispatch),
    (lan::COMMANDS, lan::VALUE_FLAGS, lan::BOOL_FLAGS, lan::dispatch),
    (dns::COMMANDS, dns::VALUE_FLAGS, dns::BOOL_FLAGS, dns::dispatch),
    (proxy::COMMANDS, proxy::VALUE_FLAGS, proxy::BOOL_FLAGS, proxy::dispatch),
    (directory::COMMANDS, directory::VALUE_FLAGS, directory::BOOL_FLAGS, directory::dispatch),
    (multiplex::COMMANDS, multiplex::VALUE_FLAGS, multiplex::BOOL_FLAGS, multiplex::dispatch),
    (termcli::COMMANDS, termcli::VALUE_FLAGS, termcli::BOOL_FLAGS, termcli::dispatch),
    (rooms::COMMANDS, rooms::VALUE_FLAGS, rooms::BOOL_FLAGS, rooms::dispatch),
    (partial::COMMANDS, partial::VALUE_FLAGS, partial::BOOL_FLAGS, partial::dispatch),
    (toolcfg::COMMANDS, toolcfg::VALUE_FLAGS, toolcfg::BOOL_FLAGS, toolcfg::dispatch),
    (docker::COMMANDS, docker::VALUE_FLAGS, docker::BOOL_FLAGS, docker::dispatch),
    (channels_setup::COMMANDS, channels_setup::VALUE_FLAGS, channels_setup::BOOL_FLAGS, channels_setup::dispatch),
    (crate::slash::COMMANDS, crate::slash::VALUE_FLAGS, crate::slash::BOOL_FLAGS, crate::slash::dispatch),
];

/// Flag-only entries (their commands are dispatched by another module).
fn no_commands(_: &str, _: &Args, _: &[String]) -> Option<R> {
    None
}

pub fn modules() -> &'static [Module] {
    MODULES
}

/// Top-level names owned here (plugins cannot take them).
pub fn owns(cmd: &str) -> bool {
    MODULES.iter().any(|m| m.0.contains(&cmd))
}

pub fn is_value_flag(name: &str) -> bool {
    MODULES.iter().any(|m| m.1.contains(&name))
}

pub fn is_bool_flag(name: &str) -> bool {
    MODULES.iter().any(|m| m.2.contains(&name))
}

/// Offer `seagent <cmd> …` to each module; `None` = fall through to `main.rs`.
/// Modules may also claim subcommands of existing commands (e.g. `config set`).
pub fn dispatch(cmd: &str, a: &Args, raw: &[String]) -> Option<R> {
    MODULES.iter().find_map(|m| (m.3)(cmd, a, raw))
}

/// Process-wide setup before argument parsing: profile selection (`-p NAME`,
/// `--profile NAME`, `SEAGENT_PROFILE`, sticky `seagent profile use`) and `.env` loading.
/// Runs single-threaded at the very start of `main`.
pub fn early(raw: &mut Vec<String>) {
    profile::early(raw);
    envfile::early();
    secretsrc::early();
    triage::early(raw);
}
