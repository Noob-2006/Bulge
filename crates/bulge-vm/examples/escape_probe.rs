//! P2 escape tests: every check actively tries to get out of the guest and
//! must fail; the controls must succeed (so a dead network or broken probe
//! cannot masquerade as "blocked").
//!
//! usage: BULGE_API_KEY=sk-canary-<random> escape_probe <host-ip>... <host-control-port>
//! The caller runs a TCP listener on 0.0.0.0:<port> as the positive control.

use std::path::PathBuf;
use std::time::Duration;

use bulge_proto::msg::Outcome;
use bulge_vm::changes;
use bulge_vm::vm::{Vm, VmConfig};
use serde_json::json;

struct Report {
    failures: usize,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: &str) {
        println!("{} {name}{}", if ok { "PASS" } else { "FAIL" }, if ok { String::new() } else { format!("  -- {detail}") });
        if !ok {
            self.failures += 1;
        }
    }
}

async fn sh(vm: &Vm, command: &str) -> (i64, String) {
    match vm.invoke("exec", json!({ "command": command }), Some(Duration::from_secs(120))).await {
        Outcome::Ok { value } => (
            value["exit_code"].as_i64().unwrap_or(-1),
            format!("{}{}", value["stdout"]["text"].as_str().unwrap_or(""), value["stderr"]["text"].as_str().unwrap_or("")),
        ),
        Outcome::Err { code, message } => (-1, format!("{code}: {message}")),
    }
}

fn token() -> String {
    let mut buf = [0u8; 12];
    getrandom::fill(&mut buf).expect("random");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((port, host_ips)) = args.split_last() else { return Err("usage: escape_probe <host-ip>... <port>".into()) };
    if host_ips.is_empty() {
        return Err("usage: escape_probe <host-ip>... <port>".into());
    }
    let home = PathBuf::from(std::env::var("HOME")?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rootfs = home.join(".bulge/rootfs/current");

    // Canaries that exist only on the host.
    let file_token = token();
    let canary = home.join(format!(".bulge-escape-canary-{file_token}"));
    std::fs::write(&canary, &file_token)?;
    // The caller launches this probe with a canary key in its environment,
    // exactly where the real app would hold a provider key.
    let env_token = std::env::var("BULGE_API_KEY").map_err(|_| "set BULGE_API_KEY=sk-canary-<random> for this probe")?;
    let rootfs_marker = rootfs.join("etc/alpine-release");
    let rootfs_before = std::fs::read(&rootfs_marker)?;

    let workspace = std::env::temp_dir().join(format!("bulge-escape-ws-{}", token()));
    std::fs::create_dir_all(&workspace)?;
    std::fs::write(workspace.join("notes.txt"), "original\n")?;

    let vm = Vm::launch(VmConfig {
        vmm_binary: repo.join("target/debug/bulge-vmm"),
        libkrun_dir: home.join(".local/lib"),
        rootfs: rootfs.clone(),
        workspace: workspace.clone(),
        runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
        cpus: 2,
        ram_mib: 1024,
        network: true,
        egress_allow: Vec::new(),
        egress_approvals: None,
    })
    .await?;
    let mut r = Report { failures: 0 };

    // Filesystem isolation.
    let (_, out) = sh(&vm, &format!("grep -rIl {file_token} / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null | head -3")).await;
    r.check("host file canary not visible anywhere in guest", out.trim().is_empty(), &out);
    let (code, _) = sh(&vm, &format!("test -e {}", home.display())).await;
    r.check("host home directory absent", code != 0, "exists");
    let (code, out) = sh(&vm, "touch /usr/bulge-evil 2>&1; echo x >> /etc/alpine-release 2>&1").await;
    r.check("rootfs not writable from guest", code != 0 && out.contains("Read-only"), &out);
    r.check("host rootfs dir unchanged", std::fs::read(&rootfs_marker)? == rootfs_before && !rootfs.join("usr/bulge-evil").exists(), "modified");
    let (code, _) = sh(&vm, "cat /.bulge-bootstrap").await;
    r.check("bootstrap file is one-shot (already consumed)", code != 0, "readable");

    // Secret isolation.
    let (_, out) = sh(&vm, &format!("env; grep -rIl {env_token} / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null | head -3")).await;
    r.check("host API key not in guest env or files", !out.contains(&env_token), &out);
    let (_, out) = sh(&vm, "cat /proc/1/environ | tr '\\0' '\\n'").await;
    r.check("guest PID 1 env carries no secrets", !out.contains("sk-") && !out.contains(&env_token), &out);

    // Network isolation (with controls).
    let (code, out) = sh(&vm, "curl -sS -o /dev/null -w '%{http_code}' https://example.com").await;
    r.check("CONTROL: public HTTPS reachable", code == 0 && out.trim() == "200", &out);
    // passt gives the guest the host's primary address; connecting to that one
    // only reaches the guest itself, so test every other host address.
    let (_, guest_ip) = sh(&vm, "ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1").await;
    let targets: Vec<&String> = host_ips.iter().filter(|ip| ip.as_str() != guest_ip.trim()).collect();
    r.check("CONTROL: at least one host address differs from the guest's", !targets.is_empty(), &guest_ip);
    for ip in targets {
        let (code, _) = sh(&vm, &format!("nc -z -w3 {ip} {port}")).await;
        r.check(&format!("host address {ip} blocked (listener is live)"), code != 0, "connected");
    }
    let (code, _) = sh(&vm, &format!("nc -z -w3 127.0.0.1 {port}")).await;
    r.check("guest loopback does not reach host", code != 0, "connected");
    let (code, _) = sh(&vm, "nc -z -w3 169.254.169.254 80").await;
    r.check("cloud metadata address blocked", code != 0, "connected");
    let (code, _) = sh(&vm, "GW=$(ip route | awk '/default/{print $3; exit}'); nc -z -w3 $GW 22 || nc -z -w3 $GW 631").await;
    r.check("gateway does not map to host services", code != 0, "connected");
    let vsock = "python3 -c \"import socket,sys\nfor port in (22, 1024, 5000, 8080):\n    s=socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.settimeout(2)\n    try:\n        s.connect((2, port)); print('OPEN', port); sys.exit(0)\n    except OSError: pass\nsys.exit(1)\"";
    let (code, out) = sh(&vm, vsock).await;
    r.check("no vsock path to host services", code != 0, &out);

    // Workspace isolation + review.
    let (code, _) = sh(&vm, "echo changed > notes.txt && ln -s /etc/passwd evil-link && ln -s notes.txt ok-link").await;
    r.check("CONTROL: guest can write its workspace overlay", code == 0, "write failed");
    r.check("host workspace untouched before approval", std::fs::read_to_string(workspace.join("notes.txt"))? == "original\n", "modified");
    let pending = changes::collect(&vm).await?;
    let paths: Vec<String> = pending.iter().map(|c| c.path().to_owned()).collect();
    let report = changes::apply(&workspace, &pending, &paths);
    r.check("absolute symlink to /etc/passwd refused on apply", report.skipped.iter().any(|(p, _)| p == "evil-link") && !workspace.join("evil-link").exists(), &format!("{report:?}"));
    r.check("approved changes applied", std::fs::read_to_string(workspace.join("notes.txt"))? == "changed\n" && workspace.join("ok-link").exists(), &format!("{report:?}"));

    let stats = vm.network_stats();
    vm.shutdown().await;
    let _ = std::fs::remove_file(&canary);
    let _ = std::fs::remove_dir_all(&workspace);
    if let Some(stats) = stats {
        println!("relay dropped destinations: {:?}", stats.recent_drops());
    }
    println!("{} failure(s)", r.failures);
    std::process::exit(i32::from(r.failures > 0));
}

