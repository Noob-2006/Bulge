//! Network policy for every model/auth request. Proxy, NO_PROXY (CIDR, `*.domain`), the
//! custom CA bundle and the offline switch live in `seagent_net::http` — the one client builder
//! every crate uses (ent-036/037/039) — and are re-exported here; this module adds the
//! provider host policy (OpenClaw `provider-network-policy.ts`: cloud metadata endpoints are
//! never a model provider; optional host allowlist; deny list).

use std::net::IpAddr;
use std::time::Duration;

pub use seagent_net::http::{bypass_matches, configure, current, host_port, load_ca, NetConfig};

/// Cloud metadata / link-local targets are never a model provider (SSRF guard). The
/// classification is `seagent_security::url_safety`'s (A14): the model client, the web tools, the
/// browser and the media fetchers share one metadata floor and one address classifier.
/// `metadata` / `instance-data` are the shorthand names provider configs use; they stay here
/// because no HTTP client should ever resolve them either.
pub fn is_metadata_host(host: &str) -> bool {
    let host = seagent_security::url_safety::normalize_host(host);
    if seagent_security::url_safety::BLOCKED_HOSTNAMES.contains(&host.as_str()) || host == "metadata" || host.split('.').any(|l| l == "instance-data") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => seagent_security::url_safety::is_always_blocked_ip(ip) || is_link_local(ip),
        Err(_) => false,
    }
}

/// Link-local (`169.254.0.0/16`, `fe80::/10`) is never a provider, but is not part of the
/// shared *metadata* floor (`is_always_blocked_ip`): a provider on the LAN is legitimate, one
/// on the autoconfiguration range is not.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_link_local(),
        IpAddr::V6(v) => (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn suffix_match(host: &str, pat: &str) -> bool {
    let p = pat
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .to_lowercase();
    !p.is_empty() && (host == p || host.ends_with(&format!(".{p}")))
}

/// Provider host policy for `url`.
pub fn check_host(url: &str) -> Result<(), String> {
    let c = current();
    let (host, _) = host_port(url);
    if is_metadata_host(&host) {
        return Err(format!(
            "{host}: cloud metadata / link-local addresses are not allowed as model providers"
        ));
    }
    if let Some(d) = c.deny_hosts.iter().find(|d| suffix_match(&host, d)) {
        return Err(format!("{host}: blocked by network policy ({d})"));
    }
    if !c.provider_hosts.is_empty()
        && !c.provider_hosts.iter().any(|a| suffix_match(&host, a))
        && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1")
    {
        return Err(format!("{host}: not in network.provider_hosts"));
    }
    Ok(())
}

/// A shared agent for a request to `url` with `global` timeout (proxy chosen per host).
pub fn agent(global: Duration, url: &str) -> ureq::Agent {
    agent_with(global, Duration::from_secs(30), url)
}

pub fn agent_with(global: Duration, connect: Duration, url: &str) -> ureq::Agent {
    seagent_net::http::agent_for(global, connect, url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_and_policy() {
        assert!(is_metadata_host("169.254.169.254"));
        assert!(is_metadata_host("metadata.google.internal"));
        assert!(is_metadata_host("fe80::1"));
        assert!(!is_metadata_host("127.0.0.1"));
        assert!(check_host("http://169.254.169.254/latest").is_err());
        assert!(check_host("https://api.openai.com/v1").is_ok());
    }

    #[test]
    fn ssrf_classification_is_the_shared_one() {
        // A14: the model client's metadata floor is `seagent_security::url_safety`'s, so a range
        // only has to be taught once for the model, web, browser and media fetchers.
        for s in ["169.254.169.254", "169.254.170.2", "100.100.100.200", "::ffff:169.254.169.254", "fd00:ec2::254"] {
            let ip: std::net::IpAddr = s.parse().unwrap();
            assert!(seagent_security::url_safety::is_always_blocked_ip(ip), "{s}: the shared floor");
            assert!(is_metadata_host(s), "{s}: the model client agrees");
        }
        // Metadata names are the shared list (case/suffix handling included).
        for name in ["metadata.google.internal", "metadata.goog", "METADATA.GOOG"] {
            assert!(seagent_security::url_safety::BLOCKED_HOSTNAMES.contains(&seagent_security::url_safety::normalize_host(name).as_str()), "{name}");
            assert!(is_metadata_host(name), "{name}: the model client agrees");
        }
        // A LAN provider (local LLM, llama.cpp on a NAS) stays usable: private is not metadata.
        for host in ["127.0.0.1", "10.0.0.5", "192.168.1.9", "api.anthropic.com"] {
            assert!(!is_metadata_host(host), "{host}");
        }
        // Nothing that is not metadata may be refused by the floor.
        assert!(seagent_security::url_safety::is_blocked_ip("10.0.0.5".parse().unwrap()) && !is_metadata_host("10.0.0.5"));
    }


}
