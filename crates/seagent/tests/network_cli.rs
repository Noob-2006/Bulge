//! The enterprise network switches through the real binary (ent-036/037/039): `seagent doctor`
//! shows the proxy / NO_PROXY / CA / offline policy every outbound client is built with, and
//! `[network] offline` (or `SEAGENT_NETWORK_OFFLINE=1`) is one switch.

use std::path::Path;
use std::process::Command;

fn seagent(h: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_seagent"));
    c.args(args).env("SEAGENT_HOME", h).env("HOME", h).env("SEAGENT_OFFLINE", "1").current_dir(h);
    for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SEAGENT_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SEAGENT_NETWORK_OFFLINE"] {
        c.env_remove(k);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().expect("run seagent");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

#[test]
fn doctor_reports_the_network_policy_and_the_offline_switch() {
    let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-netcli");
    let h = tmp.path();
    let (_, out) = seagent(h, &["doctor"], &[]);
    assert!(out.contains("· network proxy: none (direct)"), "{out}");
    assert!(out.contains("· network ca: built-in Mozilla roots"), "{out}");
    assert!(out.contains("· network offline: off"), "{out}");

    let (_, out) = seagent(h, &["doctor", "--set", "network.offline=true", "--set", "network.proxy=\"http://u:pw@proxy.corp:3128\"", "--set", "network.no_proxy=[\"10.0.0.0/8\",\"*.corp\"]"], &[]);
    assert!(out.contains("· network offline: on ([network] offline = true)") && out.contains("web tools are off"), "{out}");
    assert!(out.contains("· network proxy: http://***@proxy.corp:3128") && !out.contains("u:pw"), "{out}");
    assert!(out.contains("· network no_proxy: 10.0.0.0/8,*.corp"), "{out}");

    let (_, out) = seagent(h, &["doctor"], &[("SEAGENT_NETWORK_OFFLINE", "1")]);
    assert!(out.contains("· network offline: on (SEAGENT_NETWORK_OFFLINE)"), "{out}");

    // A CA bundle that does not load is a failed check, not a silent fallback.
    let (code, out) = seagent(h, &["doctor", "--set", "network.ca_file=\"/nonexistent/corp-ca.pem\""], &[]);
    assert!(out.contains("✗ network ca: CA bundle /nonexistent/corp-ca.pem"), "{out}");
    assert_eq!(code, 1);
}

/// ent-023/026: `seagent sandbox explain` names the real isolation level, the kernel features it
/// rests on and every step the fallback took (the decision table itself is unit-tested
/// against fake RHEL 7/8, AL2 and Ubuntu kernels in `seagent_vm::policy`).
#[test]
fn sandbox_explain_shows_the_host_kernel_and_the_fallback() {
    let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-sbx");
    let (code, out) = seagent(tmp.path(), &["sandbox", "explain"], &[]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("host: kernel:") && out.contains("landlock:") && out.contains("user namespaces:") && out.contains("cgroups:"), "{out}");
    assert!(out.contains("without a microVM this host isolates with:"), "{out}");
    let (_, json) = seagent(tmp.path(), &["sandbox", "explain", "--json"], &[]);
    let v: serde_json::Value = serde_json::from_str(json.trim()).unwrap_or_else(|e| panic!("{e}: {json}"));
    assert!(v["isolation"]["host_kernel"]["cgroup"].is_string() && v["isolation"]["namespace_fallback"]["backend"].is_string(), "{v}");
}
