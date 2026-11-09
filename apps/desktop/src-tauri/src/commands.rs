//! Commands for the app's own pages (`src/`: splash + connect). The agent's setup wizard and
//! console (served from 127.0.0.1) may only call `autostart_get` / `autostart_set`
//! (`capabilities/console.json`).

use crate::pair::{self, Address, Host, SetupCode};
use crate::{boot, tls, AppState, Mode};
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, Runtime, State};

type R<T> = Result<T, String>;

fn platform() -> &'static str {
    if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        std::env::consts::OS
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[tauri::command]
pub fn app_info(st: State<'_, AppState>) -> Value {
    let hosts: Vec<Value> = st.hosts().load().iter().map(Host::public).collect();
    json!({
        "platform": platform(),
        "version": env!("CARGO_PKG_VERSION"),
        // Everywhere: on iOS in-process (no VMs / native shell there; commands use the WASM sandbox).
        "canRunLocal": true,
        "mode": st.mode(),
        "hosts": hosts,
        "zh": crate::zh(),
    })
}

#[tauri::command]
pub fn boot_start<Rt: Runtime>(app: AppHandle<Rt>, st: State<'_, AppState>) -> R<boot::Snapshot> {
    if st.mode() != Some(Mode::Local) {
        return Err("this device is set up as a client of another host".into());
    }
    boot::start(app);
    Ok(st.boot.lock().unwrap().clone())
}

#[tauri::command]
pub fn boot_state(st: State<'_, AppState>) -> boot::Snapshot {
    st.boot.lock().unwrap().clone()
}

/// Phones: run the agent on this phone (`local`) or use another host (`remote`).
#[tauri::command]
pub fn set_mode(st: State<'_, AppState>, mode: Mode) -> R<()> {
    if cfg!(desktop) && mode != Mode::Local {
        return Err("desktop installs always run the agent locally".into());
    }
    st.set_mode(mode)
}

#[tauri::command]
pub fn autostart_get<Rt: Runtime>(app: AppHandle<Rt>) -> bool {
    #[cfg(desktop)]
    return crate::desktop::autostart(&app);
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_seagent_mobile::SeagentMobileExt;
        return app.seagent_mobile().autostart().unwrap_or(false);
    }
    #[allow(unreachable_code)]
    {
        let _ = app;
        false
    }
}

/// The wizard's "start automatically" step calls this when it runs inside the app, so the
/// login item (desktop) / boot receiver (Android) matches what the user ticked.
#[tauri::command]
pub fn autostart_set<Rt: Runtime>(app: AppHandle<Rt>, enabled: bool) -> R<bool> {
    #[cfg(desktop)]
    crate::desktop::set_autostart(&app, enabled)?;
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_seagent_mobile::SeagentMobileExt;
        app.seagent_mobile().set_autostart(enabled)?;
    }
    #[cfg(target_os = "ios")]
    let _ = (&app, enabled);
    Ok(enabled)
}

#[tauri::command]
pub async fn discover_hosts<Rt: Runtime>(app: AppHandle<Rt>) -> R<Vec<Value>> {
    use tauri_plugin_seagent_mobile::SeagentMobileExt;
    let app2 = app.clone();
    let found = tauri::async_runtime::spawn_blocking(move || app2.seagent_mobile().discover(3500)).await.map_err(|e| e.to_string())??;
    Ok(found
        .into_iter()
        .map(|d| {
            let addr = Address { host: d.host.clone(), port: d.port, tls: true };
            json!({"name": d.name, "address": addr.authority(), "id": d.txt.get("id"), "fpPrefix": d.txt.get("fp"), "version": d.txt.get("v")})
        })
        .collect())
}

/// A scanned QR / pasted link → what the UI needs to confirm the pairing.
#[tauri::command]
pub fn parse_setup_code(text: String) -> R<Value> {
    let sc = SetupCode::decode(&text, now_ms())?;
    let addr = sc.address()?;
    Ok(json!({
        "address": addr.authority(),
        "tls": addr.tls,
        "fingerprint": sc.tls_fingerprint,
        "short": sc.tls_fingerprint.as_deref().map(pair::short_fingerprint),
        "expiresAtMs": sc.expires_at_ms,
    }))
}

/// Trust on first use: connect without a pin and report the certificate fingerprint.
#[tauri::command]
pub async fn probe_host(address: String) -> R<Value> {
    let addr = Address::parse(&address)?;
    if !addr.tls {
        return Err("SE Agent hosts on the network are reached over TLS only".into());
    }
    let fp = tls::probe(&addr).await?;
    Ok(json!({"address": addr.authority(), "fingerprint": fp, "short": pair::short_fingerprint(&fp)}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairArgs {
    /// The full setup code (QR / link): carries the address, bootstrap token and maybe the pin.
    setup_code: Option<String>,
    /// Typed flow: address + the 8-character code shown on the host.
    address: Option<String>,
    code: Option<String>,
    /// The fingerprint the user confirmed (from `probe_host`), when the code carried none.
    fingerprint: Option<String>,
    /// From discovery TXT `fp`: the probed fingerprint must start with it.
    fp_prefix: Option<String>,
    device_name: Option<String>,
}

fn device_id(st: &AppState) -> String {
    let p = st.data_dir.join("device-id");
    if let Some(id) = std::fs::read_to_string(&p).ok().map(|s| s.trim().to_string()).filter(|s| s.len() >= 16) {
        return id;
    }
    let mut b = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let _ = std::fs::write(&p, &id);
    id
}

/// Pair with a host: `POST /pair/client` over pinned TLS (see apps/desktop/MOBILE.md and
/// `crates/seagent-app/src/devices.rs`) → a per-device console token, stored with the pin.
#[tauri::command]
pub async fn pair_host(st: State<'_, AppState>, args: PairArgs) -> R<Value> {
    let (addr, bootstrap, code, pin) = match &args.setup_code {
        Some(text) => {
            let sc = SetupCode::decode(text, now_ms())?;
            let pin = sc.tls_fingerprint.clone().or_else(|| args.fingerprint.as_deref().and_then(pair::normalize_fingerprint));
            (sc.address()?, Some(sc.bootstrap_token.clone()), None, pin)
        }
        None => {
            let a = Address::parse(args.address.as_deref().ok_or("enter the host address")?)?;
            let c = args.code.clone().ok_or("enter the pairing code shown on the host")?;
            if !pair::valid_pair_code(&c) {
                return Err("the pairing code has 8 letters or digits (no 0, O, 1 or I)".into());
            }
            (a, None, Some(c), args.fingerprint.as_deref().and_then(pair::normalize_fingerprint))
        }
    };
    if !addr.tls {
        return Err("SE Agent hosts on the network are reached over TLS only (wss:// setup codes)".into());
    }
    let pin = pin.ok_or("confirm the host's fingerprint first")?;
    if let Some(prefix) = args.fp_prefix.as_deref().map(|p| p.to_ascii_lowercase().replace(':', "")).filter(|p| !p.is_empty()) {
        if !pin.starts_with(&prefix) {
            return Err("the host's certificate does not match what it announced on the network; not pairing".into());
        }
    }
    let name = args.device_name.clone().unwrap_or_else(|| format!("SE Agent ({})", platform()));
    let id = device_id(&st);
    let mut body = pair::claim_body(bootstrap.as_deref(), code.as_deref(), &id, &name, platform());
    // Bind the pairing to this install's key: the console token alone will not open the host.
    body["device"]["publicKey"] = crate::devkey::DeviceKey::load_or_create(&st.data_dir)?.public_b64().into();
    // A typed code waits for the host's approval: 202 + requestId, poll (the host long-polls
    // up to 15 s per request) until 200, a refusal, or 15 minutes.
    let (mut status, mut v) = tls::post_json(&addr, &pin, "/pair/client", &body).await?;
    let until = std::time::Instant::now() + std::time::Duration::from_secs(15 * 60);
    while status == 202 && std::time::Instant::now() < until {
        let rid = v["requestId"].as_str().unwrap_or("").to_string();
        tokio::time::sleep(std::time::Duration::from_millis(v["retryAfterMs"].as_u64().unwrap_or(1000).min(5000))).await;
        (status, v) = tls::post_json(&addr, &pin, "/pair/client", &pair::with_request_id(body.clone(), &rid)).await?;
    }
    if status == 202 {
        return Err("the host did not approve this device in time; create a new pairing code there".into());
    }
    if status == 404 {
        return Err("this host's SE Agent is too old for app pairing (no /pair/client); update it".into());
    }
    if status != 200 {
        return Err(v["error"].as_str().map(String::from).unwrap_or_else(|| format!("pairing refused (HTTP {status})")));
    }
    let token = v["consoleToken"].as_str().filter(|t| !t.is_empty()).ok_or("the host returned no console token")?;
    let host = Host {
        id: v["hostId"].as_str().map(String::from).unwrap_or_else(|| pin[..16].to_string()),
        name: v["name"].as_str().map(String::from).unwrap_or_else(|| addr.host.clone()),
        address: addr,
        fingerprint: pin,
        token: token.to_string(),
        local_port: 0,
        paired_at_ms: now_ms(),
    };
    st.hosts().upsert(host.clone())?;
    Ok(host.public())
}

#[tauri::command]
pub fn hosts_list(st: State<'_, AppState>) -> Vec<Value> {
    st.hosts().load().iter().map(Host::public).collect()
}

#[tauri::command]
pub fn host_forget(st: State<'_, AppState>, id: String) -> R<()> {
    st.hosts().forget(&id)
}

/// Open a paired host's console through the pinned tunnel.
#[tauri::command]
pub async fn host_open<Rt: Runtime>(app: AppHandle<Rt>, id: String) -> R<()> {
    let st = app.state::<AppState>();
    let store = st.hosts();
    let mut h = store.get(&id).ok_or("unknown host")?;
    let mut slot = st.tunnel.lock().await;
    let reuse = slot.as_ref().is_some_and(|t| t.host_id == h.id);
    if !reuse {
        *slot = None;
        let t = tls::Tunnel::start(&h.id, h.address.clone(), h.fingerprint.clone(), h.local_port).await?;
        if t.port != h.local_port {
            h.local_port = t.port;
            store.upsert(h.clone())?;
        }
        *slot = Some(t);
    }
    let port = slot.as_ref().map(|t| t.port).unwrap_or(h.local_port);
    drop(slot);
    let (token, _) = access_token(&st, &h).await?;
    crate::open_url(&app, &format!("http://127.0.0.1:{port}/#token={token}"), true)
}

/// A short-lived access token for host `h`: `GET /pair/info` (host id + clock), then
/// `POST /pair/refresh` with the console token and a signature by this install's key (which
/// also binds the key the first time: hosts paired by an older version migrate here). A host
/// without `/pair/info` predates device keys: the console token is used as before.
pub async fn access_token(st: &AppState, h: &Host) -> R<(String, u64)> {
    let (status, info) = tls::request_json(&h.address, &h.fingerprint, "GET", "/pair/info", None, None).await?;
    if status == 404 || info["hostId"].as_str().is_none() {
        return Ok((h.token.clone(), 0));
    }
    let key = crate::devkey::DeviceKey::load_or_create(&st.data_dir)?;
    let ts = info["nowMs"].as_u64().unwrap_or_else(now_ms);
    let body = key.refresh_body(info["hostId"].as_str().unwrap_or(""), &device_id(st), ts)?;
    let (status, v) = tls::request_json(&h.address, &h.fingerprint, "POST", "/pair/refresh", Some(&body), Some(&h.token)).await?;
    match (status, v["accessToken"].as_str()) {
        (200, Some(t)) => Ok((t.to_string(), v["expiresAtMs"].as_u64().unwrap_or(0))),
        (404, _) => Ok((h.token.clone(), 0)),
        _ => Err(format!("{} — if this device was revoked or reinstalled, forget the host and pair it again", v["error"].as_str().unwrap_or("the host refused this device"))),
    }
}

/// The console page (served by the paired host through the tunnel) asks for a new access token
/// when its own expired: `{token, expiresAtMs}` for the tunnel's host, nothing else.
#[tauri::command]
pub async fn console_access_token<Rt: Runtime>(app: AppHandle<Rt>) -> R<Value> {
    let st = app.state::<AppState>();
    let id = st.tunnel.lock().await.as_ref().map(|t| t.host_id.clone()).ok_or("no paired host is open")?;
    let h = st.hosts().get(&id).ok_or("unknown host")?;
    let (token, exp) = access_token(&st, &h).await?;
    Ok(json!({"token": token, "expiresAtMs": exp}))
}

/// Android "this phone" mode / desktop: the local console (via the boot sequence).
#[tauri::command]
pub fn show_local<Rt: Runtime>(app: AppHandle<Rt>, st: State<'_, AppState>) -> R<()> {
    if st.mode() != Some(Mode::Local) {
        return Err("not running the agent on this device".into());
    }
    boot::start(app);
    Ok(())
}
