//! Security probe for the VM teardown guarantee: launch a VM with networking
//! (so passt + the relay threads exist), record the child PIDs and runtime dir,
//! then DROP the handle WITHOUT calling shutdown(). `Drop for Vm` must still kill
//! the VMM and passt and remove the runtime directory — nothing may leak.
//!
//! usage: drop_probe <workspace-dir>

use std::path::PathBuf;

use bulge_vm::vm::{Vm, VmConfig};

fn pids_named(pattern: &str) -> std::collections::BTreeSet<u32> {
    let out = std::process::Command::new("pgrep").arg("-f").arg(pattern).output();
    match out {
        Ok(out) => String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.trim().parse().ok()).collect(),
        Err(_) => std::collections::BTreeSet::new(),
    }
}

/// Running means: /proc entry exists AND its state is not `Z` (zombie). A
/// SIGKILL'd child is a zombie until its parent reaps it — effectively dead.
fn running(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false; // already reaped / gone
    };
    // ".../stat" is "pid (comm) STATE ..."; the state char follows ") ".
    match stat.rsplit_once(") ") {
        Some((_, rest)) => rest.split_whitespace().next() != Some("Z"),
        None => false,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from(std::env::args().nth(1).ok_or("usage: drop_probe <workspace>")?);
    let home = PathBuf::from(std::env::var("HOME")?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

    let runtime_root = PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge");
    // Only track processes THIS probe spawns (ignore any pre-existing ones).
    let before = pids_named("bulge-vmm|passt");

    let runtime_dir = {
        let vm = Vm::launch(VmConfig {
            vmm_binary: repo.join("target/debug/bulge-vmm"),
            libkrun_dir: home.join(".local/lib"),
            rootfs: home.join(".bulge/rootfs/current"),
            workspace,
            runtime_root,
            cpus: 2,
            ram_mib: 1024,
            network: true,
        })
        .await?;
        let runtime_dir = vm.runtime_dir().to_path_buf();
        let ours: Vec<u32> = pids_named("bulge-vmm|passt").difference(&before).copied().collect();
        println!("[launched] runtime_dir={}  our new pids={ours:?}", runtime_dir.display());
        println!("[dir exists before drop] {}", runtime_dir.exists());
        // Drop WITHOUT shutdown(): the scope ends here, so only `Drop` cleans up.
        runtime_dir
    };

    // Give the SIGKILLs a moment to take effect.
    std::thread::sleep(std::time::Duration::from_millis(800));

    let after = pids_named("bulge-vmm|passt");
    let ours_now: Vec<u32> = after.difference(&before).copied().collect();
    let still_running: Vec<u32> = ours_now.iter().copied().filter(|p| running(*p)).collect();
    let dir_gone = !runtime_dir.exists();

    println!("[after drop] our pids still present (any state): {ours_now:?}");
    println!("[after drop] our pids still RUNNING (non-zombie): {still_running:?}");
    println!("[after drop] runtime dir removed: {dir_gone}");

    let ok = still_running.is_empty() && dir_gone;
    println!("{}", if ok { "PASS drop-cleanup" } else { "FAIL drop-cleanup" });
    std::process::exit(i32::from(!ok));
}
