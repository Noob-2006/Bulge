//! `bulge remote`: pair your other devices with this bulge.
//!
//! The sessions themselves run inside `bulge channels serve` as the `remote`
//! channel kind; these commands manage the identity, pairing links and the
//! device list (all under `~/.bulge/remote/`).

use std::path::PathBuf;

use bulge_remote::host;
use bulge_remote::link::qr;

const USAGE: &str = "\
USAGE:
    bulge remote init --relay <host:port> --relay-key <key>
                                            create this bulge's keys (or change the relay);
                                            the key comes from `bulge-relay --show-key`
    bulge remote pair                       print a one-time pairing link and QR code (10 min)
    bulge remote devices                    list paired devices
    bulge remote revoke <device-name>       remove a device (a live session ends at its next message)
";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

pub fn dispatch(args: &[String]) -> i32 {
    let Ok(home) = std::env::var("HOME").map(PathBuf::from) else {
        eprintln!("error: HOME is not set");
        return 2;
    };
    let dir = home.join(".bulge/remote");
    let result: Result<(), String> = match args.first().map(String::as_str) {
        Some("init") => match (flag(args, "--relay"), flag(args, "--relay-key")) {
            (Some(relay), Some(relay_key)) => host::init(&dir, relay, relay_key).map(|identity| {
                println!("host id: {}", identity.id());
                println!();
                println!("1. On the relay machine (the one whose key you gave) run:");
                println!("     bulge-relay --listen 0.0.0.0:{} --allow-host {}", relay.rsplit_once(':').map_or("21117", |(_, p)| p), identity.id());
                println!("2. Add this account to ~/.bulge/channels.json and (re)start `bulge channels serve`:");
                println!("     {{ \"kind\": \"remote\" }}");
                println!("3. Pair a device: `bulge remote pair`, then on the device `bulge-remote join <link>`.");
            }),
            _ => Err("init needs --relay <host:port> --relay-key <key> (run `bulge-relay --show-key` on the relay machine)".into()),
        },
        Some("pair") => host::new_pairing(&dir, bulge_remote::now_secs()).and_then(|link| {
            let text = link.encode();
            println!("{}", qr(&text)?);
            println!("{text}");
            println!();
            println!("On the device: bulge-remote join '{text}'");
            println!("Valid once, for {} minutes. It contains a secret: scan or copy it directly; do not send it through chat or email.", host::PAIRING_TTL_SECS / 60);
            println!("`bulge channels serve` (with a remote account) must be running to complete the pairing.");
            Ok(())
        }),
        Some("devices") => host::devices(&dir).map(|devices| {
            if devices.is_empty() {
                println!("no devices are paired");
            }
            for device in devices {
                println!("{}  key {}…", device.name, &device.public[..16]);
            }
        }),
        Some("revoke") => match args.get(1) {
            Some(name) => host::revoke(&dir, name).map(|removed| println!("{}", if removed { "revoked" } else { "no device has that name" })),
            None => Err("revoke needs a device name".into()),
        },
        _ => {
            eprint!("{USAGE}");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    }
}
