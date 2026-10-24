//! Print what the in-VM browser shows for each URL (JS-rendered pages).
//! usage: page_text <workspace-dir> <url>...

use std::path::PathBuf;
use std::time::Duration;

use bulge_proto::msg::Outcome;
use bulge_vm::vm::{Vm, VmConfig};
use serde_json::{Value, json};

async fn browser(vm: &Vm, params: Value) -> Result<String, String> {
    match vm.invoke("browser", params, Some(Duration::from_secs(120))).await {
        Outcome::Ok { value } => Ok(value.get("text").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| value.to_string())),
        Outcome::Err { code, message } => Err(format!("{code}: {message}")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from(std::env::args().nth(1).ok_or("usage: page_text <workspace> <url>...")?);
    let home = PathBuf::from(std::env::var("HOME")?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vm = Vm::launch(VmConfig {
        vmm_binary: repo.join("target/debug/bulge-vmm"),
        libkrun_dir: home.join(".local/lib"),
        rootfs: home.join(".bulge/rootfs/current"),
        workspace,
        runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
        cpus: 2,
        ram_mib: 2048,
        network: false,
        egress_allow: vec!["*".into()],
        egress_approvals: None,
        real_world: std::sync::Arc::new(bulge_guard::RealWorldPolicy::defaults()),
    })
    .await?;
    for url in std::env::args().skip(2) {
        let text = browser(&vm, json!({ "action": "navigate", "url": url })).await.unwrap_or_else(|e| e);
        println!("===== {url}\n{text}\n");
    }
    Ok(())
}
