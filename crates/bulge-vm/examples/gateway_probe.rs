//! Live test of the two-key egress gateway: launch a VM whose only way out is
//! the authenticated gateway (allowlist = example.com), then from inside the
//! guest confirm an allowed host works, a non-allowed host is refused, and there
//! is no raw network path.
//!
//! usage: gateway_probe <workspace-dir>

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bulge_vm::vm::{Vm, VmConfig};
use serde_json::json;

async fn sh(vm: &Vm, cmd: &str) -> String {
    let out = vm.invoke("exec", json!({ "command": cmd }), Some(Duration::from_secs(30))).await;
    serde_json::to_string(&out).unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from(std::env::args().nth(1).ok_or("usage: gateway_probe <workspace>")?);
    let home = PathBuf::from(std::env::var("HOME")?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

    let vm = Vm::launch(VmConfig {
        vmm_binary: repo.join("target/debug/bulge-vmm"),
        libkrun_dir: home.join(".local/lib"),
        rootfs: home.join(".bulge/rootfs/current"),
        workspace,
        runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
        cpus: 2,
        ram_mib: 1024,
        network: false,
        egress_allow: vec!["example.com".into(), "example.org".into()],
    })
    .await?;

    let proxy_env = sh(&vm, "echo $HTTPS_PROXY").await;
    println!("[proxy env] {proxy_env}");

    // Allowed host: expect an HTTP status code (reachability), via the proxy.
    let allowed = sh(&vm, "curl -sS -m 20 -o /dev/null -w 'code=%{http_code}' https://example.com; echo").await;
    println!("[allowed example.com] {allowed}");

    // Non-allowed host: the gateway refuses the CONNECT, so curl fails.
    let denied = sh(&vm, "curl -sS -m 20 -o /dev/null -w 'code=%{http_code}' https://github.com 2>&1; echo \" rc=$?\"").await;
    println!("[denied github.com] {denied}");

    // No raw network path: a direct (non-proxied) connection must fail.
    let direct = sh(&vm, "curl -sS -m 10 --noproxy '*' -o /dev/null -w 'code=%{http_code}' https://1.1.1.1 2>&1; echo \" rc=$?\"").await;
    println!("[direct no-proxy 1.1.1.1] {direct}");

    if let Some(stats) = vm.gateway_stats() {
        println!(
            "[gateway stats] allowed={} denied_auth={} denied_policy={} connect_failed={}",
            stats.allowed.load(Ordering::Relaxed),
            stats.denied_auth.load(Ordering::Relaxed),
            stats.denied_policy.load(Ordering::Relaxed),
            stats.connect_failed.load(Ordering::Relaxed),
        );
    }

    vm.shutdown().await;
    Ok(())
}
