//! LAN interconnect CLI and the daemon's PC-to-PC methods (docs/cross-platform.md, 區域網路互聯):
//!
//! - `seagent pair code [--ttl MIN] [--scope write|admin] [--json]` — a pairing offer: QR in the
//!   terminal, the link a phone camera opens (`https://<ip>:<port>/#setup=…`), the
//!   `seagent-pair://` setup code (single use, pins the certificate), the 8-character code for
//!   typing in, and the short fingerprint both screens show.
//! - `seagent devices list|pending|approve CODE|reject CODE|revoke ID|revoke --all --yes|scope ID
//!   read|write|approve [--json]` (docs/SECURITY.md §8: key binding, last address, sign out all).
//! - `seagent tls show|rotate --yes [--json]` — the LAN identity certificate.
//! - `seagent nodes discover [--json] [--timeout SECS]` — SE Agent hosts on the LAN (mDNS).
//! - `seagent lan status|probe ADDRESS|connect ADDRESS (--code CODE | --setup-code CODE)` — pair
//!   this PC with another one as a device and register it as a cluster node (URL `https://`,
//!   pinned fingerprint, the issued token in the vault). ARP: `lan.probe`, `lan.connect`.
//!
//! The device side of pairing lives in `seagent_app::devices`; this module is the PC client.

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;
use seagent_kernel::vault::Vault;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub const COMMANDS: &[&str] = &["devices", "tls", "lan"];
pub const VALUE_FLAGS: &[&str] = &["scope", "code", "setup-code", "fingerprint", "ttl", "timeout", "name"];
pub const BOOL_FLAGS: &[&str] = &["yes", "all"];

/// `pair code` and `nodes discover` are sub-commands of existing commands (`seagent pair …` is
/// also DM pairing, `seagent nodes …` node management).
pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    Some(match (cmd, a.pos(0).unwrap_or("")) {
        ("pair", "code") => pair_code(a),
        ("nodes", "discover") => discover_cmd(a),
        ("devices", _) => devices(a),
        ("tls", _) => tls(a),
        ("lan", _) => lan(a),
        _ => return None,
    })
}

fn daemon(method: &str, params: Value) -> Result<Value, String> {
    seagent_kernel::daemon::call(&Paths::from_env().socket(), method, params).map_err(|e| format!("{e} (is the daemon running? `seagent daemon start`)"))
}

fn json_out(a: &Args, v: &Value) -> bool {
    if a.flag("json") {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    }
    a.flag("json")
}

fn grouped(code: &str) -> String {
    if code.len() == 8 { format!("{}-{}", &code[..4], &code[4..]) } else { code.to_string() }
}

fn pair_code(a: &Args) -> R {
    let ttl = a.num::<u64>("ttl").map_err(|e| e.to_string())?.unwrap_or(10);
    let v = daemon("devices.pair.create", json!({"ttlMin": ttl, "scope": a.val("scope").unwrap_or("write")}))?;
    if json_out(a, &v) {
        return Ok(0);
    }
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    match v["qrText"].as_str() {
        Some(q) => println!("{q}"),
        None => eprintln!("(the link is too long for a terminal QR code; open it or copy the setup code instead)"),
    }
    println!("Scan with the phone's camera (opens this console and pairs it) or with the SE Agent app.");
    println!("\n  link        {}", s("link"));
    println!("  setup code  {}   (single use, {ttl} min)", s("pairUri"));
    println!("\nOr type it in: address {}  code {}", s("address").trim_start_matches("https://").trim_start_matches("http://"), grouped(&s("code")));
    println!("  then approve here: seagent devices approve {}   (or in the console: Devices → Approve)", s("code"));
    if let Some(sas) = v["sas"].as_str() {
        println!("\nFingerprint  {sas}   — the device must show exactly this before you approve it");
    }
    println!("Another PC:  seagent lan connect {} --code {}", s("address").trim_start_matches("https://"), s("code"));
    Ok(0)
}

fn when(ms: &Value) -> String {
    match ms.as_u64().filter(|m| *m > 0) {
        Some(m) => format!("{}s ago", seagent_kernel::event::now_ms().saturating_sub(m) / 1000),
        None => "—".into(),
    }
}

fn devices(a: &Args) -> R {
    let v = match a.pos(0).unwrap_or("list") {
        "list" | "ls" => daemon("devices.list", json!({}))?,
        "pending" => daemon("devices.pending", json!({}))?,
        "approve" => daemon("devices.approve", json!({"code": a.need(1, "code")?}))?,
        "reject" | "deny" => daemon("devices.reject", json!({"code": a.need(1, "code")?}))?,
        // "Sign out all devices": every paired device pairs again (`--all --yes`).
        "revoke" | "rm" | "remove" if a.flag("all") => {
            if !a.flag("yes") {
                return Err("`seagent devices revoke --all` signs out every paired device (they have to pair again); add --yes".to_string().into());
            }
            daemon("devices.revoke_all", json!({}))?
        }
        "revoke" | "rm" | "remove" => daemon("devices.revoke", json!({"id": a.need(1, "device id")?}))?,
        "scope" => daemon("devices.scope", json!({"id": a.need(1, "device id")?, "scope": a.need(2, "scope (read = view only, write = full control, approve)")?}))?,
        o => return Err(format!("unknown `devices {o}` (list, pending, approve CODE, reject CODE, revoke ID|--all --yes, scope ID read|write|approve)").into()),
    };
    if json_out(a, &v) {
        return Ok(0);
    }
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let list = v["devices"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("No paired devices. Pair one with `seagent pair code`.");
            }
            for d in list {
                println!("{:<34} {:<24} {:<9} {:<7} {:<9} paired {} · seen {} from {}", d["id"].as_str().unwrap_or(""), d["name"].as_str().unwrap_or(""), d["platform"].as_str().unwrap_or(""), d["scope"].as_str().unwrap_or(""), if d["keyBound"] == true { "key" } else { "no-key" }, when(&d["pairedAtMs"]), when(&d["lastSeenMs"]), d["lastIp"].as_str().filter(|s| !s.is_empty()).unwrap_or("—"));
            }
            for p in v["pending"].as_array().into_iter().flatten() {
                println!("pending  {}  {} ({}) from {} — seagent devices approve {}", grouped(p["code"].as_str().unwrap_or("")), p["name"].as_str().unwrap_or(""), p["platform"].as_str().unwrap_or(""), p["ip"].as_str().unwrap_or(""), p["code"].as_str().unwrap_or(""));
            }
        }
        "approve" => println!("Approved {} ({}).", v["name"].as_str().unwrap_or(""), v["approved"].as_str().unwrap_or("")),
        "revoke" | "rm" | "remove" if a.flag("all") => println!("Signed out {} device(s): they have to pair again; open connections are closed.", v["revoked"]),
        "revoke" | "rm" | "remove" => println!("{}", if v["revoked"] == true { "Revoked: its token no longer works and open connections are closed." } else { "No such device." }),
        "scope" => println!("{}", if v["updated"] == true { format!("Scope is now {} (from the device's next request).", v["scope"].as_str().unwrap_or("")) } else { "No such device.".to_string() }),
        "reject" | "deny" => println!("{}", if v["rejected"] == true { "Rejected." } else { "No such pairing code." }),
        _ => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
    }
    Ok(0)
}

fn tls(a: &Args) -> R {
    let data = Paths::from_env().data;
    match a.pos(0).unwrap_or("show") {
        "show" | "status" => match seagent_app::lan::load_identity(&data) {
            Some(i) => {
                if !json_out(a, &i.json()) {
                    println!("fingerprint {}\nshort       {}\ncreated     {}\ncertificate {}", i.fingerprint, i.sas(), when(&json!(i.created_ms)), i.cert.display());
                }
            }
            None => println!("No LAN certificate yet; it is created the first time the app server starts with `[app.exposure] lan = true`."),
        },
        "rotate" => {
            if !a.flag("yes") {
                return Err("`seagent tls rotate` gives this host a new identity: every paired phone, app and PC must pair again. Re-run with --yes to do it.".to_string().into());
            }
            let old = seagent_app::lan::load_identity(&data).map(|i| i.fingerprint);
            let i = seagent_app::lan::generate_identity(&data)?;
            seagent_security::audit::record(&data, seagent_security::audit::Event::new("tls.rotate", seagent_security::audit::Actor::local(), "lan", "ok").detail(json!({"old": old, "new": i.fingerprint})));
            if !json_out(a, &i.json()) {
                println!("New identity {} ({}). Restart the daemon (`seagent daemon restart`), then pair devices again.", i.sas(), i.fingerprint);
            }
        }
        o => return Err(format!("unknown `tls {o}` (show, rotate --yes)").into()),
    }
    Ok(0)
}

fn discover_cmd(a: &Args) -> R {
    let t = Duration::from_millis((a.num::<f64>("timeout").map_err(|e| e.to_string())?.unwrap_or(3.0) * 1000.0) as u64);
    let hosts = seagent_app::lan::discover(&Paths::from_env().data, t)?;
    if json_out(a, &json!(hosts)) {
        return Ok(0);
    }
    if hosts.is_empty() {
        println!("No SE Agent hosts found on this network (they advertise only in LAN mode; some networks block multicast).");
    }
    for h in &hosts {
        let me = if h["self"] == true { "  (this machine)" } else { "" };
        println!("{:<24} {:<22} fingerprint {}{me}", h["name"].as_str().unwrap_or(""), h["address"].as_str().unwrap_or(""), h["sas"].as_str().unwrap_or(""));
        let all: Vec<&str> = h["addresses"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if all.len() > 1 {
            println!("    addresses: {}", all.join(", "));
        }
        if h["self"] != true {
            println!("    connect: seagent lan connect {} --code <code shown by `seagent pair code` there>", h["address"].as_str().unwrap_or(""));
        }
    }
    Ok(0)
}

/// `host[:port]` (default port 8640) of an address, URL or discovered host.
fn host_port(address: &str) -> Result<(String, u16), String> {
    let rest = address.trim().split_once("://").map(|(_, r)| r).unwrap_or(address.trim());
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let port = |p: &str| p.parse::<u16>().map_err(|_| format!("bad port in `{address}`"));
    let (host, p) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or("bad IPv6 address")?;
        // `[fe80::1%eth0]` as typed, or `[fe80::1%25eth0]` from a URL (RFC 6874).
        (seagent_net::stream::decode_zone(h), after.strip_prefix(':').map(port).transpose()?)
    } else if authority.matches(':').count() > 1 {
        (authority.to_string(), None)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(port(p)?)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err("enter the other host's address (e.g. 192.168.1.20:8640)".into());
    }
    Ok((host, p.unwrap_or(8640)))
}

/// Connect to `address` once without a pin and report its certificate fingerprint.
pub fn probe(address: &str) -> Result<Value, String> {
    let (host, port) = host_port(address)?;
    let s = seagent_net::Stream::connect_pinned(&host, port, None, Duration::from_secs(6)).map_err(|e| format!("{host}:{port}: {e}"))?;
    let fp = s.peer_fingerprint().ok_or("the host presented no certificate")?;
    s.close();
    Ok(json!({"address": format!("{}:{port}", if host.contains(':') { format!("[{host}]") } else { host }), "fingerprint": fp, "sas": seagent_net::x509::short_fingerprint(&fp)}))
}

/// What to pair with.
#[derive(Debug, Default, Clone)]
pub struct ConnectReq {
    pub address: String,
    pub code: Option<String>,
    pub setup_code: Option<String>,
    /// The full fingerprint the user confirmed (from [`probe`]).
    pub fingerprint: Option<String>,
    /// From discovery TXT `fp`: the certificate must start with it.
    pub fp_prefix: Option<String>,
    /// Cluster node name (default: derived from the host's name).
    pub name: Option<String>,
}

fn node_name(s: &str) -> String {
    let v: String = s.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' }).collect();
    let v = v.trim_matches('-').to_string();
    if v.is_empty() { "lan-peer".into() } else { v.chars().take(48).collect() }
}

/// Pair this PC with another host as a device (`POST /pair/client` over pinned TLS, polling
/// while the other side approves) and register it as a cluster node. `note` reports progress.
pub fn connect(paths: &Paths, vault: &Vault, req: &ConnectReq, note: &dyn Fn(&str)) -> Result<Value, String> {
    let now = seagent_kernel::event::now_ms();
    let (address, bootstrap, mut pin) = match &req.setup_code {
        Some(sc) => {
            let sc = seagent_app::node::SetupCode::decode(sc.trim().split("#setup=").last().unwrap_or(""), now)?;
            let a = sc.url.replacen("wss://", "", 1).split('/').next().unwrap_or("").to_string();
            if !sc.url.starts_with("wss://") {
                return Err("that setup code is not for a TLS (wss://) host; LAN pairing needs one".into());
            }
            (a, Some(sc.bootstrap_token), sc.tls_fingerprint)
        }
        None => (req.address.clone(), None, None),
    };
    if bootstrap.is_none() && req.code.is_none() {
        return Err("give --code (the 8 characters `seagent pair code` shows on the other host) or --setup-code".into());
    }
    let seen = probe(&address)?;
    let fp = seen["fingerprint"].as_str().unwrap_or("").to_string();
    if let Some(want) = req.fingerprint.as_deref().and_then(seagent_app::node::normalize_fingerprint) {
        pin.get_or_insert(want);
    }
    match &pin {
        Some(p) if *p != fp => return Err(format!("the host's certificate ({}) is not the one expected ({}); not pairing", seagent_net::x509::short_fingerprint(&fp), seagent_net::x509::short_fingerprint(p))),
        Some(_) => {}
        None => return Err(format!("confirm the host's fingerprint first: it shows {} — pass --fingerprint {fp} if the other screen shows the same", seen["sas"].as_str().unwrap_or(""))),
    }
    if let Some(prefix) = req.fp_prefix.as_deref().map(|p| p.to_ascii_lowercase()).filter(|p| !p.is_empty()) {
        if !fp.starts_with(&prefix) {
            return Err("the host's certificate does not match what it announced on the network; not pairing".into());
        }
    }
    let (host, port) = host_port(&address)?;
    let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    // A link-local peer keeps its zone in the URL, written `%25<zone>` (RFC 6874).
    let url = format!("https://{}", authority.replacen('%', "%25", 1));
    let device = json!({"id": seagent_app::lan::host_id(&paths.data), "name": seagent_app::lan::display_name(), "platform": format!("seagent-{}", std::env::consts::OS)});
    let mut body = json!({"device": device});
    match (&bootstrap, &req.code) {
        (Some(b), _) => body["bootstrapToken"] = json!(b),
        (None, Some(c)) => body["code"] = json!(seagent_app::devices::normalize_code(c)),
        _ => {}
    }
    let until = Instant::now() + Duration::from_secs(15 * 60);
    let mut told = false;
    let reply = loop {
        let (status, text) = seagent_net::stream::pinned_request(&format!("{url}/pair/client"), &fp, "POST", &[("Content-Type", "application/json"), ("Accept", "application/json")], body.to_string().as_bytes(), Duration::from_secs(25))?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        match status {
            200 => break v,
            202 => {
                if !told {
                    note(&format!("waiting for {authority} to approve this PC (there: seagent devices approve {}); both screens should show {}", req.code.as_deref().unwrap_or(""), seen["sas"].as_str().unwrap_or("")));
                    told = true;
                }
                body["requestId"] = v["requestId"].clone();
                if Instant::now() >= until {
                    return Err("the other host did not approve within 15 minutes".into());
                }
                std::thread::sleep(Duration::from_millis(v["retryAfterMs"].as_u64().unwrap_or(1000).min(5000)));
            }
            404 => return Err(format!("{authority} has no /pair/client: it is not in LAN mode or its SE Agent is too old")),
            s => return Err(v["error"].as_str().map(String::from).unwrap_or_else(|| format!("pairing refused (HTTP {s})"))),
        }
    };
    let token = reply["consoleToken"].as_str().filter(|t| !t.is_empty()).ok_or("the host returned no console token")?;
    let name = node_name(req.name.as_deref().or(reply["name"].as_str()).unwrap_or(&host));
    let secret = format!("LAN_{}_TOKEN", name.to_ascii_uppercase().replace(['-', '.'], "_"));
    vault.set(&secret, token)?;
    let remote = seagent_kernel::cluster::Remote { name: name.clone(), url: url.clone(), token_secret: secret.clone(), admin_secret: String::new(), added_ms: now, fingerprint: fp.clone() };
    seagent_kernel::cluster::remote_add(&paths.data, remote)?;
    seagent_security::audit::record(&paths.data, seagent_security::audit::Event::new("lan.connect", seagent_security::audit::Actor::local(), &name, "ok").detail(json!({"url": url, "fingerprint": fp, "hostId": reply["hostId"], "scope": reply["scope"]})));
    Ok(json!({"node": name, "url": url, "fingerprint": fp, "sas": seen["sas"], "tokenSecret": secret, "hostId": reply["hostId"], "scope": reply["scope"]}))
}

fn lan(a: &Args) -> R {
    let paths = Paths::from_env();
    match a.pos(0).unwrap_or("status") {
        "status" => {
            let v = match daemon("lan.status", json!({})) {
                Ok(v) => v,
                Err(_) => {
                    let ws = crate::workspace(a)?;
                    let cfg = crate::load_config(a, &ws, &paths)?;
                    seagent_app::lan::status(&seagent_app::AppConfig::parse(&cfg.app)?, &paths.data)
                }
            };
            if !json_out(a, &v) {
                println!("LAN mode     {}{}", if v["lan"] == true { "on" } else { "off" }, if v["lan"] == true { format!(" ({})", v["listen"].as_str().unwrap_or("")) } else { " — turn on with `[app.exposure] lan = true` or the setup wizard".into() });
                let ds = &v["discoveryState"];
                let detail = ds["detail"].as_str().filter(|d| !d.is_empty()).map(|d| format!(" — {d}")).unwrap_or_default();
                let on = match ds["state"].as_str() {
                    Some("advertising") => format!("mDNS (_seagent._tcp) on {}{detail}", ds["interfaces"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")),
                    Some("limited") => format!("mDNS (_seagent._tcp), limited{detail}"),
                    _ => "mDNS (_seagent._tcp)".into(),
                };
                println!("discovery    {}", if v["discovery"] == true { on } else { "off".into() });
                println!("address      {}", v["address"].as_str().unwrap_or("—"));
                println!("fingerprint  {}", v["identity"]["sas"].as_str().unwrap_or("— (created on first LAN start)"));
                println!("devices      {} paired", v["devices"]);
            }
            Ok(0)
        }
        "probe" => {
            let v = probe(a.need(1, "address")?)?;
            if !json_out(a, &v) {
                println!("{} presents {} ({})", v["address"].as_str().unwrap_or(""), v["sas"].as_str().unwrap_or(""), v["fingerprint"].as_str().unwrap_or(""));
            }
            Ok(0)
        }
        "connect" => {
            let mut req = ConnectReq { address: a.pos(1).unwrap_or("").to_string(), code: a.val("code").map(String::from), setup_code: a.val("setup-code").map(String::from), fingerprint: a.val("fingerprint").map(String::from), fp_prefix: None, name: a.val("name").map(String::from) };
            // A discovered host can be named by its id or name instead of an address.
            if !req.address.is_empty() && !req.address.contains(['.', ':']) {
                if let Some(h) = seagent_app::lan::discover(&paths.data, Duration::from_secs(3))?.into_iter().find(|h| h["id"] == req.address.as_str() || h["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(&req.address))) {
                    req.address = h["address"].as_str().unwrap_or("").to_string();
                    req.fp_prefix = h["fpPrefix"].as_str().map(String::from);
                }
            }
            if req.address.is_empty() && req.setup_code.is_none() {
                return Err(crate::Fail::Usage("usage: seagent lan connect ADDRESS (--code CODE | --setup-code CODE) [--fingerprint SHA256] [--name NODE]".into()));
            }
            // The code flow pins what the user confirms: show the fingerprint and ask (or take
            // --fingerprint / --yes when there is no terminal).
            if req.setup_code.is_none() && req.fingerprint.is_none() {
                let seen = probe(&req.address)?;
                let sas = seen["sas"].as_str().unwrap_or("");
                let ok = a.flag("yes") || {
                    use std::io::{BufRead, IsTerminal, Write};
                    if !std::io::stdin().is_terminal() {
                        return Err(format!("{} shows fingerprint {sas}; compare it with the other screen and re-run with --fingerprint {} (or --yes)", seen["address"].as_str().unwrap_or(""), seen["fingerprint"].as_str().unwrap_or("")).into());
                    }
                    print!("{} shows fingerprint {sas}. Does the other screen show the same? [y/N] ", seen["address"].as_str().unwrap_or(""));
                    let _ = std::io::stdout().flush();
                    let mut line = String::new();
                    let _ = std::io::stdin().lock().read_line(&mut line);
                    line.trim().eq_ignore_ascii_case("y") || line.trim().eq_ignore_ascii_case("yes")
                };
                if !ok {
                    return Err("not pairing: the fingerprints were not confirmed".to_string().into());
                }
                req.fingerprint = seen["fingerprint"].as_str().map(String::from);
            }
            let vault = Vault::load(&paths.secrets())?;
            let v = connect(&paths, &vault, &req, &|m| eprintln!("{m}"))?;
            if !json_out(a, &v) {
                println!("Paired and registered cluster node `{}` at {} (pinned {}). Its token is in the vault as {}.\nThe daemon picks it up within a few seconds: `seagent cluster status`.", v["node"].as_str().unwrap_or(""), v["url"].as_str().unwrap_or(""), v["sas"].as_str().unwrap_or(""), v["tokenSecret"].as_str().unwrap_or(""));
            }
            Ok(0)
        }
        o => Err(format!("unknown `lan {o}` (status, probe ADDRESS, connect ADDRESS --code CODE)").into()),
    }
}

/// Daemon methods: `devices.*` / `discovery.list` / `lan.status` (from `seagent_app::devices`)
/// plus the PC-to-PC client `lan.probe` and `lan.connect` (admin: unknown prefixes fail closed).
pub fn methods(paths: &Paths, k: seagent_kernel::kernel::Kernel, app: seagent_app::AppConfig) -> seagent_kernel::daemon::MethodExt {
    let public_url = k.cfg.surfaces.get("public_url").and_then(|v| v.as_str()).map(String::from);
    let inner = seagent_app::devices::methods(paths.data.clone(), app, public_url);
    let paths = paths.clone();
    std::sync::Arc::new(move |m: &str, p: &Value| {
        let s = |key: &str| p[key].as_str().map(str::to_string).filter(|v| !v.is_empty());
        match m {
            "lan.probe" => Some(probe(&s("address").unwrap_or_default()).map_err(|e| (-32000, e))),
            "lan.connect" => {
                let req = ConnectReq { address: s("address").unwrap_or_default(), code: s("code"), setup_code: s("setupCode"), fingerprint: s("fingerprint"), fp_prefix: s("fpPrefix"), name: s("name") };
                Some(connect(&paths, &k.vault, &req, &|m| eprintln!("seagentd: {m}")).map_err(|e| (-32000, e)))
            }
            _ => inner(m, p),
        }
    })
}

pub const METHODS: &[&str] = &["lan.probe", "lan.connect"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_names() {
        assert_eq!(host_port("192.168.1.20").unwrap(), ("192.168.1.20".into(), 8640));
        assert_eq!(host_port("192.168.1.20:9000").unwrap(), ("192.168.1.20".into(), 9000));
        assert_eq!(host_port("https://studio.local:8641/x").unwrap(), ("studio.local".into(), 8641));
        assert_eq!(host_port("[fd00::2]:8640").unwrap(), ("fd00::2".into(), 8640));
        assert_eq!(host_port("[fe80::1%eth0]:8640").unwrap(), ("fe80::1%eth0".into(), 8640));
        assert_eq!(host_port("https://[fe80::1%2512]:8641/").unwrap(), ("fe80::1%12".into(), 8641));
        assert_eq!(node_name("Studio PC (Living room)"), "studio-pc--living-room");
        assert_eq!(node_name("!!!"), "lan-peer");
        assert_eq!(grouped("ABCD2345"), "ABCD-2345");
    }
}
