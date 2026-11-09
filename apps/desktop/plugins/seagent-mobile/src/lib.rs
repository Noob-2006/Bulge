//! Native glue the SE Agent app needs on phones. Called from the app's Rust code only (no JS
//! commands, so no ACL surface):
//!
//! | call | Android (Kotlin, `android/`) | iOS (Swift, `ios/` + Rust here) | desktop |
//! |---|---|---|---|
//! | `info` | `{exe, env}`: `libseagent.so` in nativeLibraryDir + `SEAGENT_HOME` etc. | unsupported (no executables) | unsupported |
//! | `start_agent` / `stop_agent` | Foreground Service running `libseagent.so daemon run` | — | unsupported |
//! | `agent_env` | – | `{home, share, vaultKey}`: Application Support dir, bundled `share/`, vault key from the Keychain | – |
//! | `start_local` / `stop_local` | – | the whole agent **in this process** (`seagent::embed`, linked here) | – |
//! | `schedule_background` | – | BGProcessingTask request for cron / heartbeat work | – |
//! | `set_autostart` / `autostart` | start the service after boot | – | – |
//! | `discover` | NsdManager `_seagent._tcp` (+ multicast lock) | NWBrowser `_seagent._tcp` | empty |
//!
//! iOS allows no child processes, so the agent is not a sidecar there: this crate links the
//! `seagent` library for `target_os = "ios"` only and runs it on background threads of the app
//! (`seagent::embed`). The Swift side calls back into it through the `extern "C"` functions in
//! [`ios`] — the BGTaskScheduler handler and the foreground / background notifications.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, Runtime};

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_seagent_mobile);

/// How to run the bundled agent on this device (Android).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentInfo {
    pub exe: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Where the in-process agent lives (iOS): `SEAGENT_HOME`, the bundled `share/` and the vault key
/// the Keychain holds for it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentEnv {
    pub home: String,
    #[serde(default)]
    pub share: Option<String>,
    #[serde(default)]
    pub vault_key: Option<String>,
}

/// The local console of the in-process agent.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LocalConsole {
    pub base: String,
    pub url: String,
    pub setup: bool,
}

/// A host found on the LAN (`_seagent._tcp`). TXT carries only `v` (protocol), `id` and `fp`
/// (fingerprint prefix) — never a token.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Discovered {
    pub name: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub txt: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct DiscoverReply {
    #[serde(default)]
    hosts: Vec<Discovered>,
}

pub struct SeagentMobile<R: Runtime> {
    #[cfg(mobile)]
    handle: tauri::plugin::PluginHandle<R>,
    #[cfg(not(mobile))]
    _r: std::marker::PhantomData<fn() -> R>,
}

impl<R: Runtime> SeagentMobile<R> {
    #[cfg(mobile)]
    fn call<T: serde::de::DeserializeOwned>(&self, cmd: &str, args: serde_json::Value) -> Result<T, String> {
        self.handle.run_mobile_plugin(cmd, args).map_err(|e| e.to_string())
    }
    #[cfg(not(mobile))]
    fn call<T: serde::de::DeserializeOwned>(&self, cmd: &str, _args: serde_json::Value) -> Result<T, String> {
        Err(format!("`{cmd}` is only available on Android/iOS"))
    }

    pub fn info(&self) -> Result<AgentInfo, String> {
        self.call("info", serde_json::json!({}))
    }
    pub fn start_agent(&self) -> Result<(), String> {
        self.call::<serde_json::Value>("startAgent", serde_json::json!({})).map(|_| ())
    }
    pub fn stop_agent(&self) -> Result<(), String> {
        self.call::<serde_json::Value>("stopAgent", serde_json::json!({})).map(|_| ())
    }
    pub fn set_autostart(&self, enabled: bool) -> Result<(), String> {
        self.call::<serde_json::Value>("setAutostart", serde_json::json!({"enabled": enabled})).map(|_| ())
    }
    pub fn autostart(&self) -> Result<bool, String> {
        self.call::<serde_json::Value>("getAutostart", serde_json::json!({})).map(|v| v["enabled"].as_bool().unwrap_or(false))
    }
    pub fn discover(&self, timeout_ms: u64) -> Result<Vec<Discovered>, String> {
        if cfg!(not(mobile)) {
            return Ok(vec![]);
        }
        self.call::<DiscoverReply>("discover", serde_json::json!({"timeoutMs": timeout_ms})).map(|r| r.hosts.into_iter().filter(|h| !h.host.is_empty() && h.port != 0).collect())
    }

    /// iOS: the agent's home, bundled share dir and Keychain-held vault key.
    pub fn agent_env(&self) -> Result<AgentEnv, String> {
        self.call("agentEnv", serde_json::json!({}))
    }

    /// iOS: start the whole agent in this process (idempotent) and return its console.
    pub fn start_local(&self) -> Result<LocalConsole, String> {
        #[cfg(target_os = "ios")]
        {
            let env = self.agent_env()?;
            let c = ios::start(&env)?;
            // Cron / heartbeat work keeps a background slot booked while the app is away.
            let _ = self.schedule_background(seagent::embed::next_due());
            return Ok(c);
        }
        #[allow(unreachable_code)]
        Err("the in-process agent exists on iOS only (Android and desktop run `seagent daemon run`)".into())
    }

    /// iOS: drain and stop the in-process agent.
    pub fn stop_local(&self) -> Result<bool, String> {
        #[cfg(target_os = "ios")]
        return Ok(seagent::embed::stop(std::time::Duration::from_secs(10)));
        #[allow(unreachable_code)]
        Err("the in-process agent exists on iOS only".into())
    }

    /// iOS: ask BGTaskScheduler for a processing slot at (or after) `earliest_unix`.
    pub fn schedule_background(&self, earliest_unix: Option<i64>) -> Result<(), String> {
        self.call::<serde_json::Value>("scheduleBackground", serde_json::json!({"earliestUnix": earliest_unix})).map(|_| ())
    }
}

/// The in-process agent on iOS, and the C functions the Swift side calls.
#[cfg(target_os = "ios")]
pub mod ios {
    use super::{AgentEnv, LocalConsole};
    use std::ffi::{c_char, CStr};
    use std::path::PathBuf;
    use std::time::Duration;

    fn options(env: &AgentEnv) -> seagent::embed::Options {
        seagent::embed::Options {
            home: PathBuf::from(&env.home),
            vault_key: env.vault_key.clone().filter(|k| !k.is_empty()),
            share_dir: env.share.clone().filter(|s| !s.is_empty()).map(PathBuf::from),
            ..Default::default()
        }
    }

    pub fn start(env: &AgentEnv) -> Result<LocalConsole, String> {
        let c = seagent::embed::start(options(env))?;
        Ok(LocalConsole { base: c.base, url: c.url, setup: c.setup })
    }

    fn arg(p: *const c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: the Swift caller passes NUL-terminated strings that outlive the call.
        unsafe { CStr::from_ptr(p) }.to_str().ok().map(String::from)
    }

    /// BGProcessingTask handler: start the agent if the app was launched for the task, let the
    /// scheduler run what came due, wait up to `budget_secs`. Returns the next due time (unix
    /// seconds) for the next request, `0` for none, `-1` when the agent could not start.
    #[no_mangle]
    pub extern "C" fn seagent_mobile_bg_run(home: *const c_char, share: *const c_char, vault_key: *const c_char, budget_secs: u32) -> i64 {
        let Some(home) = arg(home) else { return -1 };
        let env = AgentEnv { home, share: arg(share), vault_key: arg(vault_key) };
        if !seagent::embed::running() && start(&env).is_err() {
            return -1;
        }
        let p = seagent::embed::background_pass(Duration::from_secs(budget_secs.clamp(5, 1800) as u64));
        p.next_due.unwrap_or(0)
    }

    /// The task's expiration handler fired: interrupt and stop (open turns resume next launch).
    #[no_mangle]
    pub extern "C" fn seagent_mobile_bg_expired() {
        seagent::embed::stop(Duration::from_secs(3));
    }

    /// The app is going to the background: the next due job (unix seconds, `0` = none).
    #[no_mangle]
    pub extern "C" fn seagent_mobile_next_due() -> i64 {
        seagent::embed::next_due().unwrap_or(0)
    }

    /// Back in the foreground: iOS may have reclaimed the App Server's listening socket while the
    /// app was suspended. If nothing answers any more, restart the agent. `1` = restarted.
    #[no_mangle]
    pub extern "C" fn seagent_mobile_foreground(home: *const c_char, share: *const c_char, vault_key: *const c_char) -> i32 {
        let Some(home) = arg(home) else { return 0 };
        if !seagent::embed::running() {
            return 0;
        }
        let alive = seagent::embed::console().ok().and_then(|c| c.base.strip_prefix("http://").and_then(|h| h.parse::<std::net::SocketAddr>().ok())).is_some_and(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_ok());
        if alive {
            return 0;
        }
        seagent::embed::stop(Duration::from_secs(5));
        let env = AgentEnv { home, share: arg(share), vault_key: arg(vault_key) };
        start(&env).map(|_| 1).unwrap_or(0)
    }
}

pub trait SeagentMobileExt<R: Runtime> {
    fn seagent_mobile(&self) -> &SeagentMobile<R>;
}

impl<R: Runtime, T: Manager<R>> SeagentMobileExt<R> for T {
    fn seagent_mobile(&self) -> &SeagentMobile<R> {
        self.state::<SeagentMobile<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("seagent-mobile")
        .setup(|app, _api| {
            #[cfg(target_os = "android")]
            let handle = _api.register_android_plugin("dev.seagent.mobile", "SeagentPlugin")?;
            #[cfg(target_os = "ios")]
            let handle = _api.register_ios_plugin(init_plugin_seagent_mobile)?;
            #[cfg(mobile)]
            app.manage(SeagentMobile { handle });
            #[cfg(not(mobile))]
            app.manage(SeagentMobile::<R> { _r: std::marker::PhantomData });
            Ok(())
        })
        .build()
}
