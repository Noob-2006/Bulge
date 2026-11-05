//! Website blocklist for URL-capable tools (Hermes `tools/website_policy.py`). One
//! implementation serves the whole runtime: `ark_security::url_safety` (rule normalisation,
//! `*.x.com` globs, parent-domain matching, shared files with a re-read TTL). This module only
//! feeds it the two places rules come from: `[security.website_blocklist]` (process-wide,
//! installed by `SecurityConfig::activate`) and the web tools' own `[web.blocklist]`.

use super::config::BlocklistConfig;
use ark_security::url_safety::{self, WebsiteBlocklist};
use std::path::Path;

fn as_security(cfg: &BlocklistConfig) -> WebsiteBlocklist {
    WebsiteBlocklist { enabled: cfg.enabled, domains: cfg.domains.clone(), shared_files: cfg.shared_files.clone() }
}

/// Block message when `url` matches `[web.blocklist]` (relative shared files under `home`)
/// or the process-wide `[security.website_blocklist]`; None when allowed.
pub fn check(cfg: &BlocklistConfig, home: &Path, url: &str) -> Option<String> {
    let local = (cfg.enabled && !(cfg.domains.is_empty() && cfg.shared_files.is_empty())).then(|| url_safety::check_website_access(url, &as_security(cfg), home)).flatten();
    local.or_else(|| url_safety::check_website_global(url))
}

/// Gate for URL-capable tools: `Err(message)` when a website blocklist blocks `url`.
pub fn enforce(cfg: &super::WebConfig, home: &Path, url: &str) -> Result<(), String> {
    check(&cfg.blocklist, home, url).map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforce_gate() {
        let home = crate::testutil::tmpdir("webpolicy-enforce");
        let cfg = super::super::WebConfig::from_value(serde_json::json!({"blocklist":{"domains":["evil.com"]}})).unwrap();
        assert!(enforce(&cfg, &home, "https://a.evil.com/x").unwrap_err().starts_with("Blocked by website policy"));
        assert!(enforce(&cfg, &home, "https://good.com/").is_ok());
    }

    #[test]
    fn rules_and_matching() {
        let home = crate::testutil::tmpdir("webpolicy");
        std::fs::write(home.join("shared.txt"), "# comment\nhttps://www.Evil.com/path\n\n*.ads.net\n").unwrap();
        let cfg = BlocklistConfig { enabled: true, domains: vec!["Bad.org/x".into(), "  ".into()], shared_files: vec!["shared.txt".into(), "missing.txt".into()] };
        assert_eq!(check(&cfg, &home, "https://sub.bad.org/page").unwrap(), "Blocked by website policy: 'sub.bad.org' matched rule 'bad.org' from config");
        assert!(check(&cfg, &home, "https://evil.com/").unwrap().ends_with("shared.txt"), "rule from a relative shared file");
        assert!(check(&cfg, &home, "https://x.ads.net/").is_some() && check(&cfg, &home, "https://ads.net/").is_none(), "*. needs a subdomain");
        assert!(check(&cfg, &home, "example.com/x").is_none() && check(&cfg, &home, "bad.org/schemeless").is_some());
        let off = BlocklistConfig { enabled: false, ..cfg };
        assert!(check(&off, &home, "https://bad.org/").is_none());
    }

    #[test]
    fn security_blocklist_and_policy_reach_web_tools() {
        // `[security]` installs the process-wide policy; web tools honour it without `[web.blocklist]`.
        let bl = WebsiteBlocklist { enabled: true, domains: vec!["global-only.example".into()], shared_files: vec![] };
        let pol = url_safety::UrlPolicy { allow_private_urls: false, fake_ip_ranges: vec!["198.18.0.0/15".into()] };
        url_safety::configure(&pol, &bl, None);
        let home = crate::testutil::tmpdir("webpolicy-global");
        let cfg = super::super::WebConfig::default();
        let blocked = enforce(&cfg, &home, "https://a.global-only.example/").unwrap_err();
        let fake = super::super::ssrf::SsrfPolicy::from_config(&cfg).fake_ip.len();
        url_safety::configure(&url_safety::UrlPolicy::default(), &WebsiteBlocklist::default(), None);
        assert!(blocked.contains("matched rule 'global-only.example'"), "{blocked}");
        assert_eq!(fake, 1, "[security].fake_ip_ranges feed the web SSRF policy");
        assert!(enforce(&cfg, &home, "https://a.global-only.example/").is_ok());
    }
}
