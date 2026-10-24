//! Live probe: can the in-VM browser read search engine result pages?
//! usage: search_probe <workspace-dir>

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
    let workspace = PathBuf::from(std::env::args().nth(1).ok_or("usage: search_probe <workspace>")?);
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
    let query = "黃色小生物 大學 校園";
    let mut failures = 0;
    for (name, url) in [
        ("google", format!("https://www.google.com/search?q={query}&hl=zh-TW")),
        ("duckduckgo", format!("https://duckduckgo.com/?q={query}&kl=tw-tzh")),
        ("bing", format!("https://www.bing.com/search?q={query}&setlang=zh-hant")),
        ("brave", format!("https://search.brave.com/search?q={query}")),
    ] {
        let started = std::time::Instant::now();
        let result = browser(&vm, json!({ "action": "navigate", "url": url })).await;
        let text = result.clone().unwrap_or_else(|e| e);
        let elements = text.lines().filter(|l| l.starts_with("[e")).count();
        let visible = text.split("Visible text:").nth(1).map(|t| t.trim().chars().count()).unwrap_or(0);
        println!("== {name}: {:?}, {elements} elements, {visible} chars of visible text, {:.1}s", result.is_ok(), started.elapsed().as_secs_f32());
        println!("{}", text.lines().take(3).collect::<Vec<_>>().join(" | "));
        if result.is_err() || elements < 5 || visible < 200 {
            failures += 1;
        }
    }
    println!("{failures} engine(s) unreadable");
    Ok(())
}
