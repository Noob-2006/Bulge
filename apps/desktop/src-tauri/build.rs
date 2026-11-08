use std::path::Path;

/// Commands the app's own pages may call. Declaring them makes Tauri check every app command
/// against the capabilities in `capabilities/` (local pages: `main.json`; the agent's console and
/// setup wizard served from 127.0.0.1: `console.json`, autostart only).
const COMMANDS: &[&str] = &["app_info", "boot_start", "boot_state", "set_mode", "autostart_get", "autostart_set", "discover_hosts", "parse_setup_code", "probe_host", "pair_host", "hosts_list", "host_open", "host_forget", "show_local"];

fn main() {
    // The splash pages use the project's shared theme (ui/theme.css + the star mask); copy it in
    // so `frontendDist` stays self-contained. src/vendor/ is git-ignored.
    let ui = Path::new("../../../ui");
    let vendor = Path::new("../src/vendor");
    let _ = std::fs::create_dir_all(vendor);
    for f in ["theme.css", "star.svg", "icon.svg"] {
        let from = ui.join(f);
        println!("cargo:rerun-if-changed={}", from.display());
        if from.is_file() {
            std::fs::copy(&from, vendor.join(f)).unwrap_or_else(|e| panic!("copy {}: {e}", from.display()));
        }
    }
    println!("cargo:rustc-env=SEAGENT_TARGET_TRIPLE={}", std::env::var("TARGET").unwrap_or_default());
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS))).expect("tauri build script");
}
