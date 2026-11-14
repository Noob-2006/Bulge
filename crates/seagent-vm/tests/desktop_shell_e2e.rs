//! The in-VM shell end to end, on a real desktop VM (ignored by default: it needs QEMU, KVM
//! for a reasonable time, network for the Debian image and packages, and ~15 minutes):
//!
//! ```text
//! SEAGENT_DESKTOP_E2E=/tmp/dvm-e2e SEAGENT_DESKTOP_E2E_AGENT=<static seagent-vm-guest> \
//!   cargo test -p seagent-vm --test desktop_shell_e2e -- --ignored --nocapture
//! ```
//!
//! Everything lives under the scratch directory (its own data / cache / runtime dirs), never in
//! the user's seagent home. The agent is a static x86_64 build of this tree's guest
//! (`cargo build --release --target x86_64-unknown-linux-musl -p seagent-vm --bin
//! seagent-vm-guest`, or a `+crt-static` GNU build).

#![cfg(unix)]

use seagent_vm::desktop::{DesktopConfig, DesktopVms};
use std::path::PathBuf;
use std::time::Duration;

#[test]
#[ignore]
fn the_desktop_vm_runs_shell_commands_as_the_desktop_user_on_its_screen() {
    let Some(root) = std::env::var_os("SEAGENT_DESKTOP_E2E").map(PathBuf::from) else {
        eprintln!("SEAGENT_DESKTOP_E2E not set: skipped");
        return;
    };
    let data = root.join("data");
    std::fs::create_dir_all(data.join("vm")).unwrap();
    if let Some(a) = std::env::var_os("SEAGENT_DESKTOP_E2E_AGENT") {
        std::fs::copy(a, data.join("vm").join("seagent-vm-guest")).unwrap();
    }
    // Generous: without KVM (a user outside the `kvm` group) the build runs under TCG.
    let cfg = DesktopConfig { memory_mb: 4096, cpus: 8, build_timeout_secs: 4 * 3600, ..Default::default() };
    let vms = DesktopVms::new(cfg, &data, &root.join("cache"), &root.join("run"));
    let t0 = std::time::Instant::now();
    vms.build(false, &mut |l| eprintln!("[build {:>4}s] {l}", t0.elapsed().as_secs())).expect("desktop image build");
    assert!(vms.image_has_agent(), "{:?}", vms.image_manifest());
    eprintln!("manifest guest_agent: {}", vms.image_manifest().unwrap()["guest_agent"]);
    let st = vms.start("desk").expect("start");
    eprintln!("started: pid {:?} accel {}", st.pid, st.accel);
    let m = vms.channel("desk", Duration::from_secs(1800)).expect("the in-VM agent answers");
    eprintln!("hello: {:?} after {}s", m.hello(), t0.elapsed().as_secs());
    let run = |s: &str| {
        let r = m.run(s, None, &[], None, Duration::from_secs(600)).unwrap();
        let out = String::from_utf8_lossy(&r.output).into_owned();
        eprintln!("$ {s}\n{out}[exit {:?}]", r.code);
        (r.code, out)
    };
    let (code, out) = run("uname -a; id; echo DISPLAY=$DISPLAY; echo HOME=$HOME; pwd");
    assert_eq!(code, Some(0));
    assert!(out.contains("uid=1000(seagent)") && out.contains("DISPLAY=:0") && out.contains("HOME=/home/seagent") && out.contains("/home/seagent/workspace"), "{out}");
    // The X session the person watches: wait until LightDM has logged the user in.
    let (code, out) = run("for i in $(seq 1 500); do xset q >/dev/null 2>&1 && break; sleep 1; done; xset q | head -3; xrandr 2>/dev/null | head -2");
    assert_eq!(code, Some(0), "{out}");
    // Several at once, and stdin.
    let ts: Vec<_> = (0..4).map(|i| { let m = m.clone(); std::thread::spawn(move || m.run(&format!("sleep 1; echo c{i}"), None, &[], None, Duration::from_secs(60)).unwrap()) }).collect();
    for (i, t) in ts.into_iter().enumerate() {
        assert_eq!(String::from_utf8_lossy(&t.join().unwrap().output).trim(), format!("c{i}"));
    }
    let r = m.run("tr a-z A-Z", None, &[], Some(b"piped in"), Duration::from_secs(30)).unwrap();
    assert_eq!(r.output, b"PIPED IN");
    // A dropped connection: the agent takes the next one.
    m.shutdown();
    let m2 = vms.channel("desk", Duration::from_secs(60)).expect("reconnect");
    assert_eq!(m2.run("echo again", None, &[], None, Duration::from_secs(30)).unwrap().output, b"again\n");
    let png = vms.screenshot("desk").unwrap();
    std::fs::write(root.join("screen.png"), png).unwrap();
    assert!(vms.stop("desk").unwrap());
}
