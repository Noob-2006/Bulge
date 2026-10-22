//! Exercise per-agent workspace slots end to end inside a real VM and check the
//! isolation guarantees ORG.md §4.3 relies on. usage: slot_probe <workspace>
//!
//! Every check prints PASS/FAIL; the process exits non-zero if any check fails.
use std::path::PathBuf;
use std::time::Duration;

use bulge_proto::msg::Outcome;
use bulge_vm::vm::{Vm, VmConfig};
use serde_json::{Value, json};

struct Probe {
    vm: Vm,
    failures: usize,
}

impl Probe {
    async fn call(&self, command: &str, params: Value) -> Result<Value, String> {
        match self.vm.invoke(command, params, Some(Duration::from_secs(120))).await {
            Outcome::Ok { value } => Ok(value),
            Outcome::Err { code, message } => Err(format!("{code}: {message}")),
        }
    }

    /// Run a shell command inside `slot` and return its stdout text.
    async fn sh(&self, slot: u8, command: &str) -> Result<(i64, String), String> {
        let value = self.call("slot_run", json!({ "slot": slot, "command": "exec", "params": { "command": command } })).await?;
        let code = value["exit_code"].as_i64().unwrap_or(-1);
        let out = value["stdout"]["text"].as_str().unwrap_or_default().to_string();
        Ok((code, out))
    }

    async fn main_sh(&self, command: &str) -> Result<(i64, String), String> {
        let value = self.call("exec", json!({ "command": command })).await?;
        Ok((value["exit_code"].as_i64().unwrap_or(-1), value["stdout"]["text"].as_str().unwrap_or_default().to_string()))
    }

    fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Display) {
        println!("{} {name} — {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            self.failures += 1;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from(std::env::args().nth(1).ok_or("usage: slot_probe <workspace>")?);
    std::fs::create_dir_all(&workspace)?;
    std::fs::write(workspace.join("shared.txt"), "base\n")?;
    std::fs::write(workspace.join("keep.txt"), "untouched\n")?;
    let home = PathBuf::from(std::env::var("HOME")?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vm = Vm::launch(VmConfig {
        vmm_binary: repo.join("target/debug/bulge-vmm"),
        libkrun_dir: home.join(".local/lib"),
        rootfs: home.join(".bulge/rootfs/current"),
        workspace: workspace.clone(),
        runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
        cpus: 2,
        ram_mib: 1024,
        network: false,
        // Gateway egress (example.com only), so the slot relay is exercised.
        egress_allow: vec!["example.com".into()],
        egress_approvals: None,
        real_world: std::sync::Arc::new(bulge_guard::RealWorldPolicy::defaults()),
    })
    .await?;
    let mut p = Probe { vm, failures: 0 };

    let advertised: Vec<&str> = ["slot_open", "slot_run", "slot_changes", "slot_export", "slot_merge", "slot_close"]
        .into_iter()
        .filter(|c| p.vm.commands().iter().any(|have| have == c))
        .collect();
    let all = advertised.len() == 6;
    p.check("guest advertises all slot commands", all, format!("{advertised:?}"));

    // A change in the main workspace before the slots open must be in their snapshot.
    p.main_sh("printf 'main-before\\n' > main_before.txt").await?;
    for slot in [0u8, 1] {
        let opened = p.call("slot_open", json!({ "slot": slot })).await;
        p.check(&format!("slot {slot} opens"), opened.is_ok(), format!("{opened:?}"));
    }

    let (_, uid0) = p.sh(0, "id -u").await?;
    let (_, main_uid) = p.main_sh("id -u").await?;
    p.check("slots run unprivileged, as the workspace owner", uid0.trim() != "0" && uid0.trim() == main_uid.trim(), format!("slot0={} main={}", uid0.trim(), main_uid.trim()));
    let (_, init) = p.sh(0, "tr '\\0' ' ' < /proc/1/cmdline").await?;
    p.check("slot has its own PID namespace (PID 1 is its slot server)", init.contains("--slot-server"), init.trim());
    p.sh(0, "(sleep 60 >/dev/null 2>&1 &) ; true").await?;
    let (_, seen_by_1) = p.sh(1, "ls /proc | grep -c '^[0-9]'; for d in /proc/[0-9]*; do tr '\\0' ' ' < $d/cmdline 2>/dev/null; echo; done").await?;
    let (_, main_seen) = p.main_sh("ps -o args | grep -c '^sleep 60'").await?;
    p.check("slot 1 cannot see slot 0's processes", !seen_by_1.contains("sleep 60") && main_seen.trim() != "0", format!("slot1 sees: {} | main sees sleep: {}", seen_by_1.replace('\n', " ").trim(), main_seen.trim()));
    p.check("slot cannot see sandboxd or the main agent", !seen_by_1.lines().any(|l| l.trim_start().starts_with("/usr/local/bin/sandboxd") && !l.contains("--slot-server")), "no main sandboxd in the slot's /proc");

    let (_, seen) = p.sh(0, "cat /workspace/main_before.txt").await?;
    p.check("slot sees the main workspace as of open", seen.trim() == "main-before", seen.trim());

    p.sh(0, "printf 'from-slot-0\\n' > a.txt && printf 'slot0\\n' > shared.txt").await?;
    p.sh(1, "printf 'from-slot-1\\n' > b.txt && printf 'slot1\\n' > shared.txt && rm keep.txt").await?;
    let (code, _) = p.sh(1, "test -e /workspace/a.txt").await?;
    p.check("slot 1 cannot see slot 0's new file", code != 0, format!("test -e exit {code}"));
    let (code, _) = p.main_sh("test -e /workspace/a.txt").await?;
    p.check("main workspace is untouched before merge", code != 0, format!("test -e exit {code}"));

    let (_, listing) = p.sh(0, "ls -A /run/bulge 2>&1; echo END").await?;
    p.check("slot cannot see /run/bulge (other slots, main upper, control sockets)", listing.trim() == "END", listing.replace('\n', " "));
    let (code, _) = p.sh(0, "mount -o remount,rw / 2>/dev/null").await?;
    p.check("slot cannot remount the rootfs", code != 0, format!("exit {code}"));
    let (code, out) = p.sh(0, "umount /workspace 2>&1; ls /workspace").await?;
    p.check("slot cannot unmount its workspace view", out.contains("a.txt"), format!("exit {code}: {}", out.replace('\n', " ")));
    let (_, env) = p.sh(0, "tr '\\0' '\\n' < /proc/1/environ").await?;
    let leaked: Vec<&str> = env.lines().filter(|l| { let u = l.to_ascii_uppercase(); u.contains("TOKEN") || u.contains("KEY") || u.contains("SECRET") }).collect();
    p.check("slot server environment carries no secrets", leaked.is_empty() && env.contains("BULGE_SLOT=0"), format!("{} vars, leaked: {leaked:?}", env.lines().count()));

    // Network isolation: each slot has its own network namespace (loopback only).
    let (_, addrs) = p.sh(1, "ip -o -4 addr show | awk '{print $2\"=\"$4}' | tr '\\n' ' '").await?;
    p.check("slot network has no address but loopback", addrs.trim() == "lo=127.0.0.1/8", addrs.trim());
    p.sh(0, "(python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 &) ; sleep 2; true").await?;
    let (_, own) = p.sh(0, "curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/ || true").await?;
    let (_, other) = p.sh(1, "curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/ || true").await?;
    let (_, main_view) = p.main_sh("curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/ || true").await?;
    p.check("CONTROL: a slot reaches its own local service", own.trim() == "200", own.trim());
    p.check("another slot cannot reach it", other.trim() != "200", format!("slot1 got {}", other.trim()));
    p.check("the main agent cannot reach it", main_view.trim() != "200", format!("main got {}", main_view.trim()));
    let (_, egress) = p.sh(1, "curl -s -m 20 -o /dev/null -w '%{http_code}' https://example.com || true").await?;
    p.check("slot egress still works through the relay (allowlisted host)", egress.trim() == "200", egress.trim());
    let (_, blocked) = p.sh(1, "curl -s -m 20 -o /dev/null -w '%{http_code}' https://github.com || true").await?;
    p.check("slot egress is still policy-checked (non-allowlisted host)", blocked.trim() != "200", blocked.trim());

    // An attack the merge must refuse: a symlinked parent pointing outside the workspace.
    p.sh(0, "ln -s /etc evil && true").await?;
    let changes0 = p.call("slot_changes", json!({ "slot": 0 })).await?;
    let paths0: Vec<String> = changes0["changes"].as_array().into_iter().flatten().filter_map(|c| c["path"].as_str().map(str::to_string)).collect();
    p.check("slot 0 changes are listed", paths0.contains(&"a.txt".to_string()) && paths0.contains(&"shared.txt".to_string()), format!("{paths0:?}"));
    let export = p.call("slot_export", json!({ "slot": 0, "paths": ["evil/passwd"] })).await;
    p.check("export refuses a path through a symlinked parent", export.is_err(), format!("{export:?}"));
    let bad = p.call("slot_merge", json!({ "slot": 0, "paths": ["../escape"] })).await;
    p.check("merge rejects path traversal", bad.is_err(), format!("{bad:?}"));

    let merged0 = p.call("slot_merge", json!({ "slot": 0, "paths": ["a.txt", "shared.txt"] })).await?;
    p.check("slot 0 merges cleanly", merged0["conflicts"].as_array().is_some_and(Vec::is_empty) && merged0["merged"].as_array().map_or(0, Vec::len) == 2, &merged0);
    let (_, main_a) = p.main_sh("cat a.txt; stat -c %u a.txt").await?;
    p.check("merged file is in main and owned by the main uid", main_a.contains("from-slot-0") && main_a.contains(main_uid.trim()), main_a.replace('\n', " "));

    let merged1 = p.call("slot_merge", json!({ "slot": 1, "paths": ["b.txt", "shared.txt", "keep.txt"] })).await?;
    let conflicts: Vec<String> = merged1["conflicts"].as_array().into_iter().flatten().filter_map(|c| c["path"].as_str().map(str::to_string)).collect();
    let merged: Vec<String> = merged1["merged"].as_array().into_iter().flatten().filter_map(|c| c.as_str().map(str::to_string)).collect();
    p.check("slot 1: shared.txt conflicts (changed by slot 0 meanwhile)", conflicts == vec!["shared.txt".to_string()], &merged1);
    p.check("slot 1: b.txt and the deletion of keep.txt merge", merged.contains(&"b.txt".to_string()) && merged.contains(&"keep.txt".to_string()), &merged1);
    let (_, shared) = p.main_sh("cat shared.txt; test -e keep.txt && echo KEEP-EXISTS || echo KEEP-GONE").await?;
    p.check("conflicting file kept slot 0's version; deletion applied", shared.contains("slot0") && shared.contains("KEEP-GONE"), shared.replace('\n', " "));

    let (_, suid) = p.sh(0, "printf x > s.bin && chmod 4755 s.bin && stat -c %a s.bin").await?;
    let merged_suid = p.call("slot_merge", json!({ "slot": 0, "paths": ["s.bin"] })).await?;
    let (_, mode) = p.main_sh("stat -c %a s.bin").await?;
    p.check("setuid bit never crosses a merge", mode.trim() == "755", format!("slot mode {} → main mode {} ({merged_suid})", suid.trim(), mode.trim()));

    for slot in [0u8, 1] {
        let closed = p.call("slot_close", json!({ "slot": slot })).await;
        p.check(&format!("slot {slot} closes"), closed.is_ok(), format!("{closed:?}"));
    }
    let after = p.call("slot_run", json!({ "slot": 0, "command": "exec", "params": { "command": "true" } })).await;
    p.check("a closed slot is unavailable", after.is_err(), format!("{after:?}"));

    let failures = p.failures;
    p.vm.shutdown().await;
    println!("{}", if failures == 0 { "ALL PASS".to_string() } else { format!("{failures} FAILED") });
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
