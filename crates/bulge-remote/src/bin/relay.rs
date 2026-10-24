//! `bulge-relay`: the blind meeting point for bulge hosts and their devices.
//! Run it on any machine both can reach (a small VPS); it never holds a key
//! that can read the traffic.

use bulge_remote::cli::{CliError, usage};
use std::collections::HashSet;
use std::time::Duration;

use bulge_remote::relay::{Relay, RelayConfig};

const USAGE: &str = "\
bulge-relay — blind relay for bulge remote sessions

USAGE:
    bulge-relay --allow-host <ID> [--allow-host <ID>...] [OPTIONS]
    bulge-relay --open [OPTIONS]
    bulge-relay --show-key [--key-file <PATH>]
        print the relay key (creating it on first use) and exit; give it to
        `bulge remote init --relay-key` on the bulge computer

OPTIONS:
    --listen <ADDR>              address to listen on (default 0.0.0.0:21117)
    --key-file <PATH>            the relay's key, created on first run
                                 (default ~/.bulge-relay/key.json)
    --allow-host <ID>            serve this host id (printed by `bulge remote init`)
    --open                       serve any host id (anyone can use your relay's bandwidth)
    --max-connections <N>        all connections (default 1024)
    --max-per-address <N>        connections from one IP address (default 32)
    --max-sessions-per-host <N>  live device sessions per host (default 16)
    --idle-secs <N>              close connections silent this long (default 120)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => {}
        Err(error) => {
            error.report(USAGE);
            std::process::exit(2);
        }
    }
}

fn number(value: Option<&String>, flag: &str) -> Result<usize, CliError> {
    value.and_then(|v| v.parse().ok()).filter(|n| *n > 0).ok_or_else(|| usage(format!("{flag} needs a positive number")))
}

fn run(args: &[String]) -> Result<(), CliError> {
    let mut config = RelayConfig::default();
    let mut listen = "0.0.0.0:21117".to_owned();
    let mut allowed = HashSet::new();
    let mut open = false;
    let mut key_file: Option<std::path::PathBuf> = None;
    let mut show_key = false;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1);
        match args[i].as_str() {
            "--listen" => listen = value.ok_or_else(|| usage("--listen needs an address"))?.clone(),
            "--key-file" => key_file = Some(value.ok_or_else(|| usage("--key-file needs a path"))?.into()),
            "--allow-host" => {
                let id = value.ok_or_else(|| usage("--allow-host needs an id"))?;
                bulge_remote::unhex::<32>(id).map_err(|e| format!("--allow-host {id}: {e}"))?;
                allowed.insert(id.to_ascii_lowercase());
            }
            "--open" => {
                open = true;
                i += 1;
                continue;
            }
            "--show-key" => {
                show_key = true;
                i += 1;
                continue;
            }
            "--max-connections" => config.max_connections = number(value, "--max-connections")?,
            "--max-per-address" => config.max_per_address = number(value, "--max-per-address")?,
            "--max-sessions-per-host" => config.max_sessions_per_host = number(value, "--max-sessions-per-host")?,
            "--idle-secs" => config.idle = Duration::from_secs(number(value, "--idle-secs")? as u64),
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(());
            }
            other => return Err(usage(format!("unknown option {other}"))),
        }
        i += 2;
    }
    let key_file = match key_file {
        Some(path) => path,
        None => std::path::PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set; pass --key-file")?).join(".bulge-relay").join("key.json"),
    };
    let keys = bulge_remote::relay::load_or_create_key(&key_file)?;
    if show_key {
        println!("{}", bulge_remote::hex(&keys.public));
        return Ok(());
    }
    config.allow_hosts = match (open, allowed.is_empty()) {
        (true, true) => None,
        (false, false) => Some(allowed),
        (true, false) => return Err(usage("--open and --allow-host contradict each other")),
        (false, true) => return Err(usage("name the hosts to serve with --allow-host, or pass --open")),
    };
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    Ok(runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(&listen).await.map_err(|e| format!("listen on {listen}: {e}"))?;
        // The same port over UDP answers STUN requests (for direct connections).
        let udp = tokio::net::UdpSocket::bind(&listen).await.map_err(|e| format!("listen on udp {listen}: {e}"))?;
        eprintln!("bulge-relay listening on {listen} ({})", match &config.allow_hosts {
            Some(hosts) => format!("{} host(s)", hosts.len()),
            None => "open to any host".into(),
        });
        let relay = Relay::new(config, keys);
        eprintln!("relay key: {}  (give it to `bulge remote init --relay-key`)", relay.public_key());
        tokio::select! {
            result = relay.serve(listener) => result,
            result = bulge_remote::relay::serve_stun(udp) => result,
            _ = tokio::signal::ctrl_c() => Ok(()),
        }
    })?)
}
