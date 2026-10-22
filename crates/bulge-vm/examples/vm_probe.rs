//! P2 integration probe: boot a guest over the real control channel and run
//! commands against a workspace. usage: vm_probe <workspace-dir> "<shell>"...
use std::path::PathBuf;
use std::time::Duration;

use bulge_vm::vm::{Vm, VmConfig};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let workspace = PathBuf::from(args.next().ok_or("usage: vm_probe <workspace> <cmd>...")?);
    let home = PathBuf::from(std::env::var("HOME")?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let config = VmConfig {
        vmm_binary: repo.join("target/debug/bulge-vmm"),
        libkrun_dir: home.join(".local/lib"),
        rootfs: home.join(".bulge/rootfs/current"),
        workspace,
        runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
        cpus: 2,
        ram_mib: 1024,
        network: true,
        egress_allow: Vec::new(),
        egress_approvals: None,
        real_world: std::sync::Arc::new(bulge_guard::RealWorldPolicy::defaults()),
    };
    let started = std::time::Instant::now();
    let vm = Vm::launch(config).await?;
    println!("[boot] {:?}  commands={:?}", started.elapsed(), vm.commands());
    println!("[ping] {:?}", vm.invoke("ping", json!(null), None).await);
    for command in args {
        let outcome = vm.invoke("exec", json!({ "command": command }), Some(Duration::from_secs(120))).await;
        println!("[exec] $ {command}\n{}", serde_json::to_string_pretty(&outcome)?);
    }
    println!("[changes] {}", serde_json::to_string(&vm.invoke("changes", json!(null), None).await)?);
    if let Some(stats) = vm.network_stats() {
        println!("[net] dropped destinations: {:?}", stats.recent_drops());
    }
    vm.shutdown().await;
    Ok(())
}
