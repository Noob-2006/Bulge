//! Native glue the SE Agent app needs on phones. Called from the app's Rust code only (no JS
//! commands, so no ACL surface):
//!
//! | call | Android (Kotlin, `android/`) | iOS (Swift, `ios/`) | desktop |
//! |---|---|---|---|
//! | `info` | `{exe, env}`: `libseagent.so` in nativeLibraryDir + `SEAGENT_HOME` etc. | unsupported | unsupported |
//! | `start_agent` / `stop_agent` | Foreground Service running `libseagent.so daemon run` | unsupported (no subprocesses on iOS) | unsupported |
//! | `set_autostart` / `autostart` | start the service after boot | – | – |
//! | `discover` | NsdManager `_seagent._tcp` (+ multicast lock) | NWBrowser `_seagent._tcp` | empty |

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
