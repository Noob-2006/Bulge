//! `[security]` URL policy → the process-wide policy every fetcher reads.
//!
//! `new_kernel` calls `SecurityConfig::activate_at`, which pushes `allow_private_urls`,
//! `fake_ip_ranges` and the website blocklist into `ark_security::url_safety` (the single
//! SSRF implementation the web tools, the skills hub and the gates all delegate to).
//! One test file so the global state cannot race the crate's unit tests.

use ark_security::url_safety::{self, WebsiteBlocklist};
use ark_security::SecurityConfig;

#[test]
fn security_config_reaches_the_global_url_policy_and_blocklist() {
    // Nothing configured: private targets are refused, no site is blocked.
    SecurityConfig::default().activate_at(None);
    assert!(!url_safety::global_policy().allow_private_urls);
    assert!(url_safety::is_safe_url("http://127.0.0.1:9/x", &url_safety::global_policy()).is_err());
    assert!(url_safety::check_website_global("https://evil.example/x").is_none());

    let cfg: SecurityConfig = toml::from_str(
        r#"
allow_private_urls = true
fake_ip_ranges = ["198.18.0.0/15", "10.0.0.0/8"]

[website_blocklist]
enabled = true
domains = ["evil.example", "*.ads.example"]
"#,
    )
    .expect("security table");
    let dir = std::env::var_os("TMPDIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir).join(format!("ark-policy-wiring-{}", std::process::id()));
    cfg.activate_at(Some(&dir));

    let g = url_safety::global_policy();
    assert!(g.allow_private_urls, "[security] allow_private_urls must reach every fetcher");
    assert_eq!(g.fake_ip_ranges, vec!["198.18.0.0/15".to_string(), "10.0.0.0/8".to_string()], "undeclarable ranges are kept in the config, dropped at use");
    assert!(url_safety::check_website_global("https://sub.evil.example/x").is_some(), "parent-domain rule");
    assert!(url_safety::check_website_global("https://x.ads.example/").is_some(), "glob rule");
    assert!(url_safety::check_website_global("https://ok.example/").is_none());
    // The gates read the same policy: private space is now dialable, metadata never is.
    assert!(url_safety::is_safe_url("http://10.1.2.3:9/x", &url_safety::global_policy()).is_ok());
    assert!(url_safety::is_safe_url("http://169.254.169.254/latest/meta-data", &url_safety::global_policy()).is_err());

    // Relative `shared_files` resolve under the config dir handed to `activate_at`.
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("blocked.txt"), "# one rule per line\nhttps://tracker.example/p\n").unwrap();
    let cfg = SecurityConfig { website_blocklist: WebsiteBlocklist { enabled: true, domains: vec![], shared_files: vec!["blocked.txt".into()] }, ..Default::default() };
    cfg.activate_at(Some(&dir));
    let m = url_safety::check_website_global("https://tracker.example/").expect("shared file rule");
    assert!(m.contains("blocked.txt"), "{m}");

    SecurityConfig::default().activate_at(None);
    let _ = std::fs::remove_dir_all(&dir);
}
