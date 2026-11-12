//! `seagent app`: the web console's token, opening it, and its status.

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;

/// App server helpers: token, open the UI, status.
pub fn cmd_app(a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = crate::workspace(a)?;
    let cfg = crate::load_config(a, &ws, &paths)?;
    let vault = crate::load_vault(&paths)?;
    let app = seagent_app::AppConfig::parse(&cfg.app)?;
    let token = app.token.as_deref().map(|t| vault.substitute(t)).filter(|t| !t.contains("{{secret:")).unwrap_or_default();
    let url = format!("http://{}", app.listen);
    match a.pos(0).unwrap_or("status") {
        // `--json` (desktop shell): `{"token","url"}`, or `{"error"}` and exit 1 without a token.
        "token" if a.flag("json") => {
            if token.is_empty() {
                println!("{}", serde_json::json!({"error": "no [app] token is configured (run `seagent setup bootstrap`)"}));
                return Ok(1);
            }
            println!("{}", serde_json::json!({"token": token, "url": format!("{}/#token={token}", crate::setup_web::base_url(&app.listen))}));
            Ok(0)
        }
        "token" => {
            if token.is_empty() {
                let t = seagent_net::crypto::random_token(24);
                println!("尚未設定 token。最簡單是執行 `seagent setup`；或手動：\n  echo {t} | seagent secrets set APP_TOKEN\n然後在 config.toml 加上：\n  [app]\n  enabled = true\n  token = \"{{{{secret:APP_TOKEN}}}}\"");
            } else {
                println!("{token}");
            }
            Ok(0)
        }
        "open" => {
            if token.is_empty() {
                return Err("set [app] token first (`seagent app token`)".into());
            }
            // The token travels in the fragment, which browsers never send to servers or logs.
            let link = format!("{url}/#token={token}");
            // Windows: Edge / Chrome `--app=`, else the default browser; macOS: `open -na`.
            #[cfg(any(windows, target_os = "macos"))]
            crate::ops::hostos::open_app_window(&link);
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                let opened = ["chromium", "google-chrome", "brave-browser"].iter().any(|b| seagent_core::platform::proc::command(b).arg(format!("--app={link}")).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().is_ok());
                if !opened {
                    let _ = seagent_core::platform::proc::command("xdg-open").arg(&link).spawn();
                }
            }
            println!("{url}");
            Ok(0)
        }
        "status" => {
            println!("[app] {} on {url} · ui {} · openai api {} · nodes {} · a2a {}", if app.enabled { "enabled" } else { "disabled" }, app.ui, app.openai_api, app.nodes, app.a2a.enabled);
            Ok(0)
        }
        "accounts" | "service-accounts" => crate::ops::enterprise::accounts(&paths, a, 1),
        other => Err(format!("unknown app subcommand `{other}` (token, open, status, accounts)").into()),
    }
}
