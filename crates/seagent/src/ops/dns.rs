//! `seagent dns` (OpenClaw `openclaw dns setup`, `src/infra/widearea-dns.ts`): unicast
//! DNS-SD ("wide-area Bonjour") over Tailscale + CoreDNS, so devices on the tailnet
//! discover this seagent's app server by name.
//!
//! `seagent dns setup [--domain D] [--apply] [--coredns-dir DIR]` prints the domain, zone
//! file (`<config>/dns/<domain>.db`), the tailnet IPs and the Tailscale split-DNS
//! settings; `--apply` writes `<coredns-dir>/conf.d/<domain>.server` (bound to the
//! tailnet IPs, `file <zone> { reload 10s }`), makes the Corefile import `conf.d/*.server`,
//! bootstraps the zone (SOA/NS) when it has none, and restarts CoreDNS (`systemctl
//! restart coredns`; root-owned paths are written through `sudo tee`). Upstream
//! applies via Homebrew on macOS only; seagent applies on Linux (default dir
//! `/etc/coredns`) and macOS (`$(brew --prefix)/etc/coredns`).
//!
//! `seagent dns zone [--domain D] [--port P] [--write]` renders the gateway zone: SOA/NS,
//! host A/AAAA, and `_seagent-gw._tcp` PTR/SRV/TXT records advertising the app server.

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["dns"];
pub const VALUE_FLAGS: &[&str] = &["domain", "coredns-dir", "port"];
pub const BOOL_FLAGS: &[&str] = &["apply", "write"];

const INVALID: &str = "wide-area discovery domain must be a valid DNS name";

fn label_ok(l: &str) -> bool {
    let b = l.as_bytes();
    !b.is_empty() && b.len() <= 63 && b[0].is_ascii_alphanumeric() && b[b.len() - 1].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// Lowercased, with a trailing dot.
pub fn normalize_domain(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    let t = t.strip_suffix('.').unwrap_or(t);
    if t.is_empty() || t.len() > 253 || !t.split('.').all(label_ok) {
        return Err(INVALID.into());
    }
    Ok(format!("{}.", t.to_lowercase()))
}

pub fn zone_path(paths: &Paths, domain: &str) -> PathBuf {
    paths.config_dir.join("dns").join(format!("{}db", domain))
}

pub fn is_tailnet_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

pub fn is_tailnet_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
}

/// (first tailnet IPv4, first tailnet IPv6) of this host's interfaces (`GetAdaptersAddresses`).
#[cfg(windows)]
pub fn tailnet_ips() -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let ips = crate::ops::hostos::local_ips();
    let v4 = ips.iter().find_map(|a| match a {
        std::net::IpAddr::V4(ip) if is_tailnet_v4(*ip) => Some(*ip),
        _ => None,
    });
    let v6 = ips.iter().find_map(|a| match a {
        std::net::IpAddr::V6(ip) if is_tailnet_v6(*ip) => Some(*ip),
        _ => None,
    });
    (v4, v6)
}

/// (first tailnet IPv4, first tailnet IPv6) of this host's interfaces.
#[cfg(unix)]
pub fn tailnet_ips() -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let mut v4 = None;
    let mut v6 = None;
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a linked list we free with freeifaddrs; we only read it.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return (None, None);
        }
        let mut cur = head;
        while !cur.is_null() {
            let a = (*cur).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(a as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        if v4.is_none() && is_tailnet_v4(ip) {
                            v4 = Some(ip);
                        }
                    }
                    libc::AF_INET6 => {
                        let sin = &*(a as *const libc::sockaddr_in6);
                        let ip = Ipv6Addr::from(sin.sin6_addr.s6_addr);
                        if v6.is_none() && is_tailnet_v6(ip) {
                            v6 = Some(ip);
                        }
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    (v4, v6)
}

fn serial() -> String {
    let (y, m, d) = seagent_kernel::util::civil_from_days(seagent_kernel::util::unix_now().div_euclid(86_400));
    format!("{y:04}{m:02}{d:02}01")
}

pub fn bootstrap_zone(domain: &str, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>, serial: &str) -> String {
    let mut l = vec!["; created by seagent dns setup (replaced by `seagent dns zone --write`)".to_string(), format!("$ORIGIN {domain}"), "$TTL 60".into(), format!("@ IN SOA ns1 hostmaster {serial} 7200 3600 1209600 60"), "@ IN NS ns1".into()];
    if let Some(a) = v4 {
        l.push(format!("ns1 IN A {a}"));
    }
    if let Some(a) = v6 {
        l.push(format!("ns1 IN AAAA {a}"));
    }
    l.push(String::new());
    l.join("\n")
}

pub fn server_block(domain: &str, binds: &[String], zone: &Path) -> String {
    format!("{}:53 {{\n  bind {}\n  file {} {{\n    reload 10s\n  }}\n  errors\n  log\n}}\n", domain.trim_end_matches('.'), binds.join(" "), zone.display())
}

fn dns_label(s: &str, fallback: &str) -> String {
    let mut o: String = s.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    o = o.trim_matches('-').chars().take(63).collect::<String>().trim_matches('-').to_string();
    if o.is_empty() { fallback.into() } else { o }
}

fn txt_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn hostname() -> String {
    seagent_core::platform::sysinfo::hostname().split('.').next().unwrap_or("").to_string()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").or_else(|_| std::fs::read_to_string("/etc/hostname")).map(|s| s.trim().split('.').next().unwrap_or("").to_string()).unwrap_or_default()
}

/// The zone advertising this host's seagent app server.
pub fn gateway_zone(domain: &str, host: &str, v4: Ipv4Addr, v6: Option<Ipv6Addr>, port: u16, serial: &str) -> String {
    let h = dns_label(host, "seagent");
    let inst = dns_label(&format!("{host}-gateway"), "seagent-gw");
    let txt = [format!("displayName={}", if host.is_empty() { "seagent" } else { host }), "role=gateway".into(), "transport=gateway".into(), format!("gatewayPort={port}")];
    let mut r = vec![format!("$ORIGIN {domain}"), "$TTL 60".into(), format!("@ IN SOA ns1 hostmaster {serial} 7200 3600 1209600 60"), "@ IN NS ns1".into(), format!("ns1 IN A {v4}"), format!("{h} IN A {v4}")];
    if let Some(a) = v6 {
        r.push(format!("{h} IN AAAA {a}"));
    }
    r.push(format!("_seagent-gw._tcp IN PTR {inst}._seagent-gw._tcp"));
    r.push(format!("{inst}._seagent-gw._tcp IN SRV 0 0 {port} {h}"));
    r.push(format!("{inst}._seagent-gw._tcp IN TXT {}", txt.iter().map(|t| txt_quote(t)).collect::<Vec<_>>().join(" ")));
    format!("{}\n", r.join("\n"))
}

pub fn zone_needs_bootstrap(p: &Path) -> bool {
    match std::fs::read_to_string(p) {
        Ok(t) => !t.split_whitespace().any(|w| w == "SOA") || !t.split_whitespace().any(|w| w == "NS"),
        Err(_) => true,
    }
}

/// Write, falling back to `sudo tee` when the path is root-owned.
fn write_sudo(p: &Path, content: &str, sudo: bool) -> Result<(), String> {
    match std::fs::write(p, content) {
        Ok(()) => Ok(()),
        Err(e) if sudo && e.kind() == std::io::ErrorKind::PermissionDenied => {
            use std::io::Write;
            let mut c = std::process::Command::new("sudo").arg("tee").arg(p).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).spawn().map_err(|e| format!("sudo tee {}: {e}", p.display()))?;
            c.stdin.take().unwrap().write_all(content.as_bytes()).map_err(|e| e.to_string())?;
            let s = c.wait().map_err(|e| e.to_string())?;
            if s.success() { Ok(()) } else { Err(format!("sudo tee {} failed: {s}", p.display())) }
        }
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

fn mkdir_sudo(p: &Path, sudo: bool) -> Result<(), String> {
    match std::fs::create_dir_all(p) {
        Ok(()) => Ok(()),
        Err(e) if sudo && e.kind() == std::io::ErrorKind::PermissionDenied => {
            let s = std::process::Command::new("sudo").args(["mkdir", "-p"]).arg(p).status().map_err(|e| e.to_string())?;
            if s.success() { Ok(()) } else { Err(format!("sudo mkdir -p {} failed", p.display())) }
        }
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// Install the CoreDNS server block / Corefile import / bootstrap zone under `dir`.
pub fn apply(dir: &Path, zone: &Path, domain: &str, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>, sudo: bool) -> Result<Vec<String>, String> {
    let binds: Vec<String> = v4.map(|a| a.to_string()).into_iter().chain(v6.map(|a| a.to_string())).collect();
    if binds.is_empty() {
        return Err("no tailnet IP detected; check that Tailscale is running on this machine".into());
    }
    let mut done = vec![];
    let conf = dir.join("conf.d");
    mkdir_sudo(&conf, sudo)?;
    let corefile = dir.join("Corefile");
    let import = format!("import {}", conf.join("*.server").display());
    match std::fs::read_to_string(&corefile) {
        Err(_) => {
            write_sudo(&corefile, &format!("{import}\n"), sudo)?;
            done.push(format!("wrote {}", corefile.display()));
        }
        Ok(t) if !t.lines().any(|l| l.trim() == import) => {
            write_sudo(&corefile, &format!("{import}\n{t}"), sudo)?;
            done.push(format!("added import to {}", corefile.display()));
        }
        Ok(_) => {}
    }
    let server = conf.join(format!("{}.server", domain.trim_end_matches('.')));
    write_sudo(&server, &server_block(domain, &binds, zone), sudo)?;
    done.push(format!("wrote {}", server.display()));
    if zone_needs_bootstrap(zone) {
        if let Some(p) = zone.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        seagent_kernel::util::atomic_write(zone, bootstrap_zone(domain, v4, v6, &serial()).as_bytes()).map_err(|e| e.to_string())?;
        done.push(format!("bootstrapped {}", zone.display()));
    }
    Ok(done)
}

fn default_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        let prefix = std::process::Command::new("brew").arg("--prefix").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "/opt/homebrew".into());
        PathBuf::from(prefix).join("etc/coredns")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("coredns")
    } else {
        PathBuf::from("/etc/coredns")
    }
}

fn domain_arg(a: &Args) -> Result<String, String> {
    let raw = a.val("domain").map(String::from).or_else(|| std::env::var("SEAGENT_WIDE_AREA_DOMAIN").ok()).ok_or("No wide-area domain configured. Pass --domain (e.g. seagent.internal) or set SEAGENT_WIDE_AREA_DOMAIN.")?;
    normalize_domain(&raw)
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "dns" {
        return None;
    }
    Some((|| -> R {
        let paths = Paths::from_env();
        match a.pos(0).unwrap_or("setup") {
            "setup" => {
                let domain = domain_arg(a)?;
                let zone = zone_path(&paths, &domain);
                let (v4, v6) = tailnet_ips();
                println!("DNS setup\n  Domain      {domain}\n  Zone file   {}\n  Tailnet IP  {}{}", zone.display(), v4.map(|a| a.to_string()).unwrap_or("—".into()), v6.map(|a| format!(" (v6 {a})")).unwrap_or_default());
                println!("\nTailscale admin (DNS → Nameservers):\n  - Add nameserver: {}\n  - Restrict to domain (Split DNS): {}", v4.map(|a| a.to_string()).unwrap_or("<this machine's tailnet IPv4>".into()), domain.trim_end_matches('.'));
                if !a.flag("apply") {
                    println!("\nRun with --apply to configure CoreDNS (needs write access to {}; sudo is used when required).", a.val("coredns-dir").map(PathBuf::from).unwrap_or_else(default_dir).display());
                    return Ok(0);
                }
                let dir = a.val("coredns-dir").map(PathBuf::from).unwrap_or_else(default_dir);
                for l in apply(&dir, &zone, &domain, v4, v6, cfg!(unix))? {
                    println!("{l}");
                }
                if cfg!(windows) {
                    // CoreDNS has no standard service wrapper on Windows (and seagent never elevates).
                    println!("Restart CoreDNS (or its service) so it loads {}. Then publish this host with `seagent dns zone --domain {} --write`.", dir.display(), domain.trim_end_matches('.'));
                    return Ok(0);
                }
                println!("Restarting CoreDNS…");
                let restart = if cfg!(target_os = "macos") { vec!["sudo", "brew", "services", "restart", "coredns"] } else { vec!["sudo", "systemctl", "restart", "coredns"] };
                let ok = std::process::Command::new(restart[0]).args(&restart[1..]).status().is_ok_and(|s| s.success());
                if !ok {
                    eprintln!("could not restart CoreDNS (`{}`); restart it yourself", restart.join(" "));
                    return Ok(1);
                }
                println!("Done. Publish this host with `seagent dns zone --domain {} --write`.", domain.trim_end_matches('.'));
                Ok(0)
            }
            "zone" => {
                let domain = domain_arg(a)?;
                let (v4, v6) = tailnet_ips();
                let v4 = v4.ok_or("no tailnet IPv4 detected; check that Tailscale is running")?;
                let port = a.num::<u16>("port")?.unwrap_or(7272);
                let z = gateway_zone(&domain, &hostname(), v4, v6, port, &serial());
                if a.flag("write") {
                    let p = zone_path(&paths, &domain);
                    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
                    seagent_kernel::util::atomic_write(&p, z.as_bytes()).map_err(|e| e.to_string())?;
                    println!("wrote {}", p.display());
                } else {
                    print!("{z}");
                }
                Ok(0)
            }
            other => crate::usage(format!("unknown `dns {other}` (setup [--domain D] [--apply] [--coredns-dir DIR] | zone [--domain D] [--port P] [--write])")),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_ips_and_zone_text() {
        assert_eq!(normalize_domain(" Seagent.Internal ").unwrap(), "seagent.internal.");
        assert_eq!(normalize_domain("seagent.internal.").unwrap(), "seagent.internal.");
        for bad in ["", "-x.y", "a..b", "a_b.c", &"a".repeat(64)] {
            assert!(normalize_domain(bad).is_err(), "{bad}");
        }
        assert!(is_tailnet_v4("100.101.1.2".parse().unwrap()) && !is_tailnet_v4("100.128.0.1".parse().unwrap()) && !is_tailnet_v4("10.0.0.1".parse().unwrap()));
        assert!(is_tailnet_v6("fd7a:115c:a1e0::1".parse().unwrap()) && !is_tailnet_v6("fe80::1".parse().unwrap()));
        let z = gateway_zone("seagent.internal.", "My Box", "100.64.0.5".parse().unwrap(), None, 7272, "2026110301");
        assert!(z.contains("$ORIGIN seagent.internal.") && z.contains("@ IN SOA ns1 hostmaster 2026110301 7200 3600 1209600 60"));
        assert!(z.contains("my-box IN A 100.64.0.5"));
        assert!(z.contains("_seagent-gw._tcp IN PTR my-box-gateway._seagent-gw._tcp"));
        assert!(z.contains("my-box-gateway._seagent-gw._tcp IN SRV 0 0 7272 my-box"));
        assert!(z.contains("IN TXT \"displayName=My Box\" \"role=gateway\" \"transport=gateway\" \"gatewayPort=7272\""));
    }

    #[test]
    fn apply_writes_coredns_files_idempotently() {
        let kit = crate::testkit::kit();
        let dir = kit.ws.join("coredns");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Corefile"), ". {\n  forward . 1.1.1.1\n}\n").unwrap();
        let zone = zone_path(&kit.paths, "seagent.internal.");
        assert!(apply(&dir, &zone, "seagent.internal.", None, None, false).unwrap_err().contains("no tailnet IP"));
        let v4 = Some("100.64.0.9".parse().unwrap());
        let done = apply(&dir, &zone, "seagent.internal.", v4, None, false).unwrap();
        assert_eq!(done.len(), 3, "{done:?}");
        let core = std::fs::read_to_string(dir.join("Corefile")).unwrap();
        assert!(core.starts_with(&format!("import {}", dir.join("conf.d/*.server").display())) && core.contains("forward . 1.1.1.1"));
        let server = std::fs::read_to_string(dir.join("conf.d/seagent.internal.server")).unwrap();
        assert!(server.starts_with("seagent.internal:53 {\n  bind 100.64.0.9\n") && server.contains("reload 10s"));
        let z = std::fs::read_to_string(&zone).unwrap();
        assert!(z.contains("SOA") && z.contains("ns1 IN A 100.64.0.9"));
        assert!(!zone_needs_bootstrap(&zone));
        let again = apply(&dir, &zone, "seagent.internal.", v4, None, false).unwrap();
        assert_eq!(again.len(), 1, "import and zone are not repeated: {again:?}");
    }

    #[test]
    fn dispatch_is_reachable_and_validates_the_domain() {
        let raw = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // `ops::dispatch` (MODULES order in ops/mod.rs) routes `dns` here, before main.rs.
        let a = Args::parse(&["setup".into(), "--domain".into(), "Seagent.Test".into()]).unwrap();
        match crate::ops::dispatch("dns", &a, &raw(&["dns", "setup"])) {
            Some(Ok(0)) => {}
            Some(Ok(c)) => panic!("`dns setup --domain seagent.test` exited {c}"),
            Some(Err(e)) => panic!("`dns setup --domain seagent.test` failed: {e}"),
            None => panic!("`seagent dns` is not routed to ops::dns"),
        }
        let a = Args::parse(&["setup".into(), "--domain".into(), "bad_domain".into()]).unwrap();
        match crate::ops::dispatch("dns", &a, &raw(&["dns", "setup"])).expect("routed") {
            Err(crate::Fail::Msg(m)) => assert_eq!(m, INVALID),
            Err(e) => panic!("expected the invalid-domain error, got: {e}"),
            Ok(code) => panic!("bad domain accepted (exit {code})"),
        }
        let a = Args::parse(&["nope".into()]).unwrap();
        assert!(matches!(crate::ops::dispatch("dns", &a, &raw(&["dns", "nope"])), Some(Err(crate::Fail::Usage(_)))));
        assert!(dispatch("proxy", &Args::parse(&[]).unwrap(), &[]).is_none());
    }
}
