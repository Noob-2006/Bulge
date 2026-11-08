//! Local desktop control (Hermes `computer_use`, OpenClaw `computer`) without a paired node.
//!
//! Two model-facing tools share one `[computer_use]` table and one choice of driver:
//! - `computer_use` ([`hermes`]): Hermes' capture → act-by-element-index → verdict ladder.
//! - `computer` ([`openclaw`]): OpenClaw's gateway-desktop surface (frameId-bound screenshot
//!   coordinates, windowRef / elementRef / observationId targets, zoom, menus, recordings).
//!
//! Drivers: cua-driver over stdio MCP ([`cua`]) when installed (or forced
//! with `backend = "cua"`), else the native xdotool / ydotool + AT-SPI path ([`native`]) the
//! paired-node `computer.act` already uses. Both act on the Bot Desktop when one runs for this
//! home, and every call is refused while a human holds its lease.

pub mod backend;
pub mod config;
pub mod cua;
pub mod hermes;
pub mod native;
pub mod openclaw;
pub mod vm;

#[cfg(test)]
pub(crate) mod fake_driver;
#[cfg(test)]
mod tests_real;

pub use config::ComputerUseConfig;

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// PNG of the display computer_use acts on (the Bot Desktop when running, else $DISPLAY / Wayland).
/// Contract used by the web UI desktop view; keep this signature.
pub fn screenshot_png(_home: &Path) -> Result<Vec<u8>, String> {
    crate::node::snapshot(std::time::Duration::from_secs(10))
}

/// `[computer_use] backend` values this runtime knows; anything else is a config mistake the
/// tools report instead of silently falling back to a different driver.
const BACKENDS: &[&str] = &["auto", "native", "xdotool", "ydotool", "cua"];

/// A clear refusal for an unknown `[computer_use] backend` (None when it is known).
pub fn backend_error(cfg: &ComputerUseConfig) -> Option<String> {
    (!BACKENDS.contains(&cfg.backend.as_str())).then(|| format!("[computer_use] backend `{}` is not a driver on this host (auto, native, xdotool, ydotool, cua)", cfg.backend))
}

/// "cua" or "native": the driver `[computer_use] backend` selects on this host.
pub fn driver_kind(cfg: &ComputerUseConfig, home: &Path) -> &'static str {
    match cfg.backend.as_str() {
        "cua" => "cua",
        "auto" if cua::resolve_driver(cfg, home).is_some() => "cua",
        _ => "native",
    }
}

/// `enabled = "auto"`: some driver can act on some display from here.
pub fn available(cfg: &ComputerUseConfig, home: &Path) -> bool {
    if driver_kind(cfg, home) == "cua" {
        return cua::resolve_driver(cfg, home).is_some();
    }
    // Windows / macOS: the logged-in desktop is the display and input is OS-native.
    if native::os_input() && matches!(cfg.backend.as_str(), "auto" | "native") {
        return true;
    }
    let env = seagent_browser::control::screen::Desktop::new(home).published_env();
    let display = !env.is_empty() || std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() || cfg.bot_desktop.auto_start;
    display && native::input_tool(&cfg.backend, &env).is_some()
}

/// Env for commands that act on the agent's screen: the running Bot Desktop's published
/// DISPLAY / XAUTHORITY / bus (so input never lands on a seat a human sits at), starting
/// it first when `bot_desktop.auto_start` is on and this host has no display of its own.
pub fn desktop_env(cfg: &ComputerUseConfig, home: &Path) -> Vec<(String, String)> {
    let mut d = seagent_browser::control::screen::Desktop::new(home);
    let env = d.published_env();
    if !env.is_empty() || !cfg.bot_desktop.auto_start || std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return env;
    }
    d.geometry = cfg.bot_desktop.geometry.clone();
    d.min_free_mb = cfg.bot_desktop.min_free_memory_mb;
    match d.start() {
        Ok(_) => d.published_env(),
        Err(_) => vec![],
    }
}

/// The DISPLAY a backend spawned under `env` acts on (a cached backend is rebuilt when it moves).
pub fn display_of(env: &[(String, String)]) -> String {
    native::env_get(env, "DISPLAY").or_else(|| native::env_get(env, "WAYLAND_DISPLAY")).unwrap_or_default()
}

/// The `[computer_use]` tools (`tools = ["computer_use", "computer"]`), or none when disabled.
pub fn tools(t: &toml::Table) -> Result<Vec<Arc<dyn seagent_core::Tool>>, String> {
    tools_with(t, &toml::Table::new())
}

/// [`tools`] plus the `[desktop_vm]` table: `computer_use` can then act on desktop VMs
/// (`target = "vm:<name>"`), and with `[computer_use] target = "vm:…"` it is offered even on a
/// host without a display of its own.
pub fn tools_with(t: &toml::Table, desktop_vm: &toml::Table) -> Result<Vec<Arc<dyn seagent_core::Tool>>, String> {
    let cfg = ComputerUseConfig::parse(t)?;
    let dcfg = seagent_vm::desktop::DesktopConfig::parse(desktop_vm)?;
    let paths = seagent_kernel::config::Paths::from_env();
    let home = paths.data.clone();
    let vm_default = cfg.target.starts_with("vm:") && dcfg.enabled;
    let on = cfg.enabled().unwrap_or_else(|| vm_default || available(&cfg, &home));
    if !on {
        return Ok(vec![]);
    }
    let vms = Arc::new(seagent_vm::desktop::DesktopVms::new(dcfg, &paths.data, &paths.cache_dir(), &paths.runtime));
    let cfg = Arc::new(cfg);
    let kind = driver_kind(&cfg, &home);
    let mut v: Vec<Arc<dyn seagent_core::Tool>> = vec![];
    if cfg.tools.iter().any(|t| t == "computer_use") {
        let mut t = hermes::ComputerUseTool::new(cfg.clone());
        t.vms = Some(vms);
        v.push(Arc::new(t));
    }
    if cfg.tools.iter().any(|t| t == "computer") {
        v.push(Arc::new(openclaw::ComputerTool::new(cfg.clone(), kind)));
    }
    Ok(v)
}

/// The `[browser]` table the browser tools get. With `[computer_use] target = "vm:<name>"`
/// (and `[desktop_vm]` on) the agent's browser is that VM's Chromium — the window a person
/// watches and can take over — unless `[browser]` names its own backend or CDP endpoint.
pub fn browser_table(browser: &toml::Table, computer_use: &toml::Table, desktop_vm: &toml::Table) -> toml::Table {
    let mut b = browser.clone();
    let own = |k: &str| b.get(k).and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty());
    if own("backend") || own("cdp_url") || own("desktop_vm") {
        return b;
    }
    let vm = ComputerUseConfig::parse(computer_use).ok().and_then(|c| c.target.strip_prefix("vm:").map(str::to_string));
    let on = seagent_vm::desktop::DesktopConfig::parse(desktop_vm).is_ok_and(|d| d.enabled);
    if let (Some(vm), true) = (vm, on) {
        b.insert("desktop_vm".into(), toml::Value::String(vm));
    }
    b
}

/// The human-takeover refusal both tools return (Hermes `human_has_control`).
pub(crate) fn refused(action: &str, e: &str) -> String {
    serde_json::json!({"ok": false, "action": action, "code": "human_has_control", "error": e}).to_string()
}

pub(crate) const TAKEOVER: &str = "A human took over this desktop while the action ran; its result was discarded. Tell the user what you need and re-capture once they hand back.";

/// A new file under `<home>/<subdir>` (owner-only dir); the oldest `prefix*` files beyond `cap - 1` are removed.
pub(crate) fn cache_file(home: &Path, subdir: &str, name: &str, prefix: &str, cap: usize) -> Option<PathBuf> {
    let dir = home.join(subdir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).ok()?;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    seagent_core::platform::fs_private::create_dir_private(&dir).ok()?;
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&dir).ok()?.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(prefix)).filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path()))).collect();
    files.sort();
    let excess = files.len().saturating_sub(cap.saturating_sub(1));
    for (_, p) in files.into_iter().take(excess) {
        let _ = std::fs::remove_file(p);
    }
    Some(dir.join(name))
}

/// Write `data` owner-only (0600): a capture is as sensitive as the screen it came from.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> Option<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).ok()?
    };
    #[cfg(not(unix))]
    let mut f = seagent_core::platform::fs_private::open_private(path, seagent_core::platform::fs_private::OpenMode::Truncate).ok()?;
    f.write_all(data).ok()
}

/// Persist a screenshot under `<home>/cache/images` (bounded trail of 20).
pub(crate) fn persist_image(home: &Path, tag: &str, bytes: &[u8], mime: &str) -> Option<PathBuf> {
    let ext = if mime == "image/jpeg" { "jpg" } else { "png" };
    let p = cache_file(home, "cache/images", &format!("{tag}_{}.{ext}", seagent_net::crypto::random_token(16)), &format!("{tag}_"), 20)?;
    write_private(&p, bytes).map(|_| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(enabled: toml::Value, tools: &[&str]) -> toml::Table {
        let mut t = toml::Table::new();
        t.insert("enabled".into(), enabled);
        t.insert("tools".into(), toml::Value::Array(tools.iter().map(|s| toml::Value::String((*s).into())).collect()));
        t
    }

    fn names(t: &toml::Table) -> Vec<String> {
        tools(t).unwrap().iter().map(|x| x.spec().name).collect()
    }

    /// `[computer_use]` registers the two model-facing tools (`computer_use`, `computer`) and
    /// nothing when it is off: this is what `build_agent` hands the model.
    #[test]
    fn tools_register_both_local_desktop_tools() {
        assert_eq!(names(&table(toml::Value::Boolean(true), &["computer_use", "computer"])), ["computer_use", "computer"]);
        assert_eq!(names(&table(toml::Value::Boolean(true), &["computer"])), ["computer"]);
        assert!(names(&table(toml::Value::Boolean(false), &["computer_use", "computer"])).is_empty(), "enabled = false registers nothing");
        let auto = table(toml::Value::String("auto".into()), &["computer_use", "computer"]);
        let cfg = ComputerUseConfig::parse(&auto).unwrap();
        let home = seagent_kernel::config::Paths::from_env().data;
        assert_eq!(names(&auto).len(), if available(&cfg, &home) { 2 } else { 0 }, "auto = a usable display and input tool");
    }

    /// `backend` picks the driver: forced `cua` even without a driver, else native without one.
    #[test]
    fn backend_selects_the_cua_or_native_driver() {
        let mut t = table(toml::Value::Boolean(true), &["computer_use"]);
        t.insert("backend".into(), toml::Value::String("cua".into()));
        let home = seagent_kernel::config::Paths::from_env().data;
        assert_eq!(driver_kind(&ComputerUseConfig::parse(&t).unwrap(), &home), "cua");
        let native = table(toml::Value::Boolean(true), &["computer_use"]);
        assert_eq!(driver_kind(&ComputerUseConfig::parse(&native).unwrap(), &home), "native");
    }
}

#[cfg(test)]
mod browser_table_tests {
    use super::browser_table;

    fn t(s: &str) -> toml::Table {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn a_vm_target_puts_the_agent_browser_on_that_vm() {
        let (cu, on) = (t("target = \"vm:desk\""), t("enabled = true"));
        assert_eq!(browser_table(&t(""), &cu, &on).get("desktop_vm").and_then(|v| v.as_str()), Some("desk"));
        // Its own backend / endpoint wins; a host target or a disabled [desktop_vm] changes nothing.
        for own in ["backend = \"local\"", "cdp_url = \"http://127.0.0.1:9222\""] {
            assert!(browser_table(&t(own), &cu, &on).get("desktop_vm").is_none(), "{own}");
        }
        assert!(browser_table(&t(""), &t("target = \"host\""), &on).get("desktop_vm").is_none());
        assert!(browser_table(&t(""), &cu, &t("enabled = false")).get("desktop_vm").is_none());
        // The browser crate reads the VM's endpoint where the VM writes it.
        let vms = seagent_vm::desktop::DesktopVms::new(Default::default(), std::path::Path::new("/d"), std::path::Path::new("/c"), std::path::Path::new("/r"));
        assert_eq!(vms.vm_dir("desk").join(seagent_vm::desktop::CDP_FILE), seagent_browser::manager::vm_home(std::path::Path::new("/d"), "desk").join(seagent_browser::manager::VM_CDP_FILE));
        assert_eq!(vms.lease_home("desk"), seagent_browser::manager::lease_home(std::path::Path::new("/d"), "vm:desk"));
    }
}
