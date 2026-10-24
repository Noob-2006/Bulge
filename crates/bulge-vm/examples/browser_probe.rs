//! Live probe of the in-VM browser tool: headless Firefox driven over WebDriver
//! BiDi by sandboxd, reaching the web through the two-key gateway.
//! usage: browser_probe <workspace-dir>

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

fn find_ref<'a>(snapshot: &'a str, role: &str, name_part: &str) -> Option<&'a str> {
    snapshot.lines().find(|l| l.contains(&format!("] {role} ")) && l.to_lowercase().contains(&name_part.to_lowercase()))
        .and_then(|l| l.strip_prefix('[')).and_then(|l| l.split(']').next())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from(std::env::args().nth(1).ok_or("usage: browser_probe <workspace>")?);
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
    let mut failures = 0;
    let mut check = |ok: bool, what: &str| {
        println!("{} {what}", if ok { "PASS" } else { "FAIL" });
        if !ok { failures += 1; }
    };

    let home_page = browser(&vm, json!({ "action": "navigate", "url": "en.wikipedia.org/wiki/Main_Page" })).await;
    let snap = home_page.clone().unwrap_or_else(|e| e);
    println!("--- snapshot head ---\n{}\n---", snap.lines().take(18).collect::<Vec<_>>().join("\n"));
    check(snap.contains("URL: https://en.wikipedia.org/wiki/Main_Page"), "navigate loads an HTTPS page through the gateway");
    let search = find_ref(&snap, "searchbox", "search").or_else(|| find_ref(&snap, "textbox", "search"));
    check(search.is_some(), "snapshot lists the search box with a ref");

    if let Some(search) = search {
        let typed = browser(&vm, json!({ "action": "type", "ref": search, "text": "Rust (programming language)", "submit": true })).await.unwrap_or_else(|e| e);
        check(typed.contains("Rust_(programming_language)") || typed.contains("Title: Rust (programming language)"), "typing + Enter submits the search and lands on the article");
        println!("    now at: {}", typed.lines().next().unwrap_or(""));
        if let Some(link) = find_ref(&typed, "link", "Mozilla") {
            let clicked = browser(&vm, json!({ "action": "click", "ref": link })).await.unwrap_or_else(|e| e);
            println!("    clicked {link} -> {}", clicked.lines().next().unwrap_or(""));
            check(clicked.contains("URL: https://en.wikipedia.org/wiki/Mozilla"), "a real click on a link follows it");
            let back = browser(&vm, json!({ "action": "back" })).await.unwrap_or_else(|e| e);
            check(back.contains("Rust_(programming_language)"), "back returns to the previous page");
        } else {
            check(false, "article lists a Mozilla link");
        }
    }
    let shot = browser(&vm, json!({ "action": "screenshot" })).await.unwrap_or_else(|e| e);
    check(shot.contains("shot-1.png"), "screenshot is saved in the guest");
    let blocked = browser(&vm, json!({ "action": "navigate", "url": "https://api.stripe.com/" })).await;
    println!("    stripe: {}", match &blocked { Ok(s) => s.lines().take(2).collect::<Vec<_>>().join(" | "), Err(e) => e.clone() });
    check(blocked.as_ref().map(|s| !s.contains("URL: https://api.stripe.com")).unwrap_or(true), "a real-world (payment) host stays unreachable from the browser");
    let stale = browser(&vm, json!({ "action": "click", "ref": "e99999" })).await;
    check(stale.is_err(), "an unknown ref is an error, not a misclick");
    let closed = browser(&vm, json!({ "action": "close" })).await;
    check(closed.is_ok(), "close stops the browser");
    vm.shutdown().await;
    println!("{failures} failure(s)");
    std::process::exit(i32::from(failures > 0));
}
