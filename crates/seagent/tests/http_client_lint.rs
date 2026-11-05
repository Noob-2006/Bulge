//! Outbound HTTP client lint (ent-036/037/039).
//!
//! Every outbound client must start from `seagent_net::http::builder()` (or `agent()` /
//! `agent_for()`), so the `[network]` proxy, NO_PROXY (CIDR, `*.domain`), the custom CA bundle,
//! the client certificate and the offline switch apply to *all* traffic — channels, web tools,
//! A2A, telemetry, update, hub — not only the model client. A new `ureq::Agent::config_builder()`
//! somewhere else would silently ignore all of that inside a TLS-intercepting corporate network,
//! so this test fails the build instead.
//!
//! Likewise a raw TLS client must take its roots from `seagent_net::stream` (which honours the CA
//! bundle); `webpki_roots` / `rustls::ClientConfig::builder` outside seagent-net are refused.
//!
//! The test reads files only. Run: `cargo test -p seagent --test http_client_lint`.

use std::path::{Path, PathBuf};

/// Ways to make a ureq agent (or use ureq's implicit global one) without the shared builder.
const FORBIDDEN: &[&str] = &[
    "Agent::config_builder(",
    "Agent::new_with_defaults(",
    "Agent::new_with_config(",
    "ureq::config::Config::builder(",
    "ureq::Config::builder(",
    "ureq::get(",
    "ureq::post(",
    "ureq::put(",
    "ureq::delete(",
    "ureq::head(",
    "ureq::patch(",
    "ureq::options(",
    "ureq::trace(",
    "ureq::agent(",
    "with_default_agent(",
    "webpki_roots::",
    "rustls::ClientConfig::builder",
];

/// The only files allowed to construct clients directly.
const ALLOWED: &[&str] = &["crates/seagent-net/src/http.rs", "crates/seagent-net/src/stream.rs", "crates/seagent/tests/http_client_lint.rs"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == ".git") {
                continue;
            }
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Offending `(file:line, pattern)` pairs under `crates/`.
fn offenders(root: &Path) -> Vec<String> {
    let mut files = vec![];
    walk(&root.join("crates"), &mut files);
    let mut bad = vec![];
    for f in files {
        let rel = f.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for pat in FORBIDDEN {
                if code.contains(pat) {
                    bad.push(format!("{rel}:{}: `{pat}`", i + 1));
                }
            }
        }
    }
    bad
}

#[test]
fn every_outbound_client_goes_through_the_shared_builder() {
    let bad = offenders(&root());
    assert!(
        bad.is_empty(),
        "outbound HTTP/TLS clients built outside `seagent_net::http` — they would ignore [network] proxy, \
         NO_PROXY, ca_file and offline mode.\nfix: replace `ureq::Agent::config_builder()` with \
         `seagent_net::http::builder()` and `ureq::get(url)` with `seagent_net::http::agent().get(url)`; \
         raw TLS goes through `seagent_net::Stream`.\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_lint_catches_a_bypass() {
    let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-lint");
    let d = tmp.path().join("crates/x/src");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("lib.rs"), "fn a() { let _ = ureq::Agent::config_builder().build(); }\n// ureq::get( in a comment is fine\nfn b() { seagent_net::http::builder(); }\n").unwrap();
    let bad = offenders(tmp.path());
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].starts_with("crates/x/src/lib.rs:1:"));
}
