//! seagent-vm-guest — the guest half of seagent's microVM boundary. It is PID 1 of a *Linux*
//! guest (mounts, mknod, AF_VSOCK, setuid, sethostname), whatever OS the host runs: the image
//! in `packaging/vm` is always Linux, and Windows / macOS / Android hosts boot that same image
//! under their own hypervisor. The implementation is [`linux`]; on any other target this
//! binary only says where it belongs, so `cargo check --all-targets` works everywhere.

#[cfg(target_os = "linux")]
#[path = "seagent-vm-guest/linux.rs"]
mod linux;
/// What `tests/boot_vm.rs` imports from the guest (it includes this file as a module).
#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use linux::{guest_abs_path, parse_cmdline, GuestCfg};

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("seagent-vm-guest runs inside the Linux guest only (build it for x86_64/aarch64-unknown-linux-musl and pack it with packaging/vm/build-image.sh)");
    std::process::exit(1);
}
