//! Prove Landlock confinement works on this kernel and with our access flags:
//! after caging the process to a single allowed directory, a file inside it is
//! still readable while a file outside it is refused (EACCES).
//!
//! usage: landlock_probe   (uses temp dirs; no arguments)

use std::io::Write;

use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError};

fn main() {
    let base = std::env::temp_dir().join(format!("bulge-ll-{}", std::process::id()));
    let allowed = base.join("allowed");
    let secret = base.join("secret");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&secret).unwrap();
    let allowed_file = allowed.join("ok.txt");
    let secret_file = secret.join("secret.txt");
    std::fs::File::create(&allowed_file).unwrap().write_all(b"ok").unwrap();
    std::fs::File::create(&secret_file).unwrap().write_all(b"TOP SECRET").unwrap();

    // Both readable before the cage.
    let before_secret = std::fs::read_to_string(&secret_file).is_ok();

    // Cage: allow read+exec on system dirs (so the process keeps working) and
    // read on the allowed dir only. The secret dir is deliberately NOT granted.
    let abi = ABI::V2;
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let read_exec = read | AccessFs::Execute;
    let full = AccessFs::from_all(abi);
    let mut beneath: Vec<Result<PathBeneath<PathFd>, RulesetError>> = Vec::new();
    for dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev"] {
        if let Ok(fd) = PathFd::new(dir) {
            beneath.push(Ok(PathBeneath::new(fd, read_exec)));
        }
    }
    beneath.push(Ok(PathBeneath::new(PathFd::new(&allowed).unwrap(), read)));

    let result = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(full)
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(beneath))
        .and_then(|r| r.restrict_self());
    if let Err(error) = result {
        println!("landlock not supported here: {error}");
        println!("SKIP landlock-confinement");
        let _ = std::fs::remove_dir_all(&base);
        std::process::exit(0);
    }

    // After the cage: allowed readable, secret refused.
    let allowed_ok = std::fs::read_to_string(&allowed_file).is_ok();
    let secret_blocked = std::fs::read_to_string(&secret_file).is_err();

    println!("[before cage] secret readable: {before_secret}");
    println!("[after cage] allowed readable: {allowed_ok}");
    println!("[after cage] secret blocked:  {secret_blocked}");

    let _ = std::fs::remove_dir_all(&base);
    let ok = before_secret && allowed_ok && secret_blocked;
    println!("{}", if ok { "PASS landlock-confinement" } else { "FAIL landlock-confinement" });
    std::process::exit(i32::from(!ok));
}
