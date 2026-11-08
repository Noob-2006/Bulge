//! macOS only: the hidden `seagent __watch-parent <ppid> <pid> <start>` command, the opt-in
//! substitute for Linux's PDEATHSIG (`SEAGENT_MACOS_WATCHDOG=1`). The logic lives in
//! `seagent_core::platform::proc` (see its module docs); this file only names the binary as the
//! watchdog executable and claims the command word.

use seagent_core::platform::proc;

pub fn register_route() {
    if let Ok(exe) = std::env::current_exe() {
        if proc::set_parent_watchdog(exe) {
            seagent_core::registry::register_command_route(proc::WATCH_PARENT_CMD, None, |_, argv| Ok(proc::run_parent_watchdog(argv)));
        }
    }
}
