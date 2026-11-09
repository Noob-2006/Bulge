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
    // iOS bundles the WASI tools (`tauri.ios.conf.json` resources → share/wasi). They are built
    // by scripts/prepare-ios.sh; the directory must exist for tauri-build even before that.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("apple-ios") {
        let _ = std::fs::create_dir_all("wasi-tools");
        // Only a real app build (on a Mac) needs them; a cross type-check elsewhere skips quietly.
        if cfg!(target_os = "macos") && !Path::new("wasi-tools/tools.json").is_file() {
            println!("cargo:warning=src-tauri/wasi-tools has no tools.json: the app would have no shell commands; run scripts/prepare-ios.sh");
        }
    }
    println!("cargo:rustc-env=SEAGENT_TARGET_TRIPLE={target}");
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS))).expect("tauri build script");
}
