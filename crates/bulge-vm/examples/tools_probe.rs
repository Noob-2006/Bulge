//! Exercise the guest file tools end to end. usage: tools_probe <workspace>
use std::path::PathBuf;
use std::time::Duration;

use bulge_vm::vm::{Vm, VmConfig};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from(std::env::args().nth(1).ok_or("usage: tools_probe <workspace>")?);
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
    })
    .await?;
    let calls = [
        ("read", json!({ "path": "app.py", "offset": 2, "limit": 2 })),
        ("edit", json!({ "path": "app.py", "old_string": "print(“hi”)", "new_string": "print('hello')" })),
        ("read", json!({ "path": "app.py" })),
        ("grep", json!({ "pattern": "hello" })),
        ("glob", json!({ "pattern": "*.py" })),
        ("read", json!({ "path": "." })),
        ("exec", json!({ "command": "seq 1 100000" })),
    ];
    for (command, params) in calls {
        let outcome = vm.invoke(command, params.clone(), Some(Duration::from_secs(60))).await;
        let text = serde_json::to_string(&outcome)?;
        println!("[{command}] {params}\n  -> {}", if text.len() > 600 { format!("{}…", &text[..600]) } else { text });
    }
    vm.shutdown().await;
    Ok(())
}
