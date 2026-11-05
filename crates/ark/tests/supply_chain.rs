//! Supply chain and release tooling (audit row A18), exercised for real.
//!
//! The release scripts are the part of the project that is easiest to rot: nobody runs them
//! between releases, so a broken shebang, a renamed output file or a signature that silently
//! covers the wrong bytes stays invisible until the day a release is cut — or, worse, until a
//! user finds out that the published artifacts do not verify.
//!
//! So this test shells out to the scripts the way the checklist does, in a throw-away sandbox:
//!
//! * `sbom.py` produces an SPDX 2.3 document that is well formed, covers the whole workspace,
//!   carries purls, is byte-identical across two runs, and `--check` rejects a tampered copy;
//! * `gen-key.sh` → `sign.sh` → `verify-release.sh` round-trips, and verification fails after a
//!   single flipped byte, an extra unlisted file, or a tampered `SHA256SUMS`;
//! * `sign.sh` refuses a group-readable private key;
//! * every script is executable and declares the interpreter it needs;
//! * `repro-check.sh` exists and parses — it is *not* run here, because it compiles the workspace
//!   twice (minutes), which does not belong in a unit-test suite.
//!
//! The sandbox has its own `HOME`, `TMPDIR` and `ARK_HOME` (`TempDir` removes it on drop), so
//! nothing here can read or write the developer's real state, and no network is used: the SBOM
//! script falls back to parsing `Cargo.lock` when `cargo metadata --offline` cannot answer.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// `<repo>` from `<repo>/crates/ark`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("crates").parent().expect("repo").to_path_buf()
}

fn release_dir() -> PathBuf {
    repo_root().join("packaging").join("release")
}

fn script(name: &str) -> PathBuf {
    release_dir().join(name)
}

/// Is this external tool usable? Both are present on the machines this project targets; the test
/// skips (with a note) rather than fails on a stripped-down container.
fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok_and(|o| o.status.success())
}

struct Sandbox {
    dir: ark_core::tmp::TempDir,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let dir = ark_core::tmp::TempDir::new(&format!("ark-supply-{tag}"));
        for sub in ["home", "tmp", "ark-home"] {
            std::fs::create_dir_all(dir.path().join(sub)).expect("sandbox subdir");
        }
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.path().join(rel)
    }

    /// Run a program with a *clean* environment: only what a release run legitimately needs.
    /// `PATH` stays (the scripts need `openssl`/`sha256sum`), everything else points at the
    /// sandbox so a stray `$HOME` write cannot escape it.
    fn run(&self, program: &Path, args: &[&str]) -> Output {
        self.run_in(self.path(), program, args)
    }

    /// Same, but with an explicit working directory (`sha256sum` must see the dist files as
    /// bare names, exactly like the checklist's `( cd dist && sha256sum * )`).
    fn run_in(&self, cwd: &Path, program: &Path, args: &[&str]) -> Output {
        Command::new(program)
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()))
            .env("HOME", self.join("home"))
            .env("TMPDIR", self.join("tmp"))
            .env("ARK_HOME", self.join("ark-home"))
            .env("ARK_OFFLINE", "1")
            .env("LC_ALL", "C")
            // Fixed so `creationInfo.created` is predictable and the two runs agree.
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", program.display()))
    }

    /// `python3 <script> ...` — the interpreter is named explicitly so the test still works if a
    /// checkout loses the executable bit; `scripts_are_executable...` checks that bit separately.
    fn python(&self, script_name: &str, args: &[&str]) -> Output {
        let mut argv = vec![script(script_name).to_string_lossy().to_string()];
        argv.extend(args.iter().map(|a| a.to_string()));
        let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        self.run(Path::new("python3"), &refs)
    }

    fn bash(&self, script_name: &str, args: &[&str]) -> Output {
        let mut argv = vec![script(script_name).to_string_lossy().to_string()];
        argv.extend(args.iter().map(|a| a.to_string()));
        let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        self.run(Path::new("bash"), &refs)
    }
}

fn text(out: &Output) -> String {
    format!(
        "status={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_ok(out: &Output, what: &str) {
    assert!(out.status.success(), "{what} failed: {}", text(out));
}

fn assert_failed(out: &Output, what: &str) {
    assert!(!out.status.success(), "{what} unexpectedly succeeded: {}", text(out));
}

fn read_json(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{}: not JSON: {e}", path.display()))
}

fn copy_flat(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("copy dest");
    for entry in std::fs::read_dir(from).expect("copy src").flatten() {
        let path = entry.path();
        if path.is_file() {
            std::fs::copy(&path, to.join(entry.file_name())).expect("copy file");
        }
    }
}

/// A plausible dist directory: the binary (fake), a notice file, the public key and — when
/// `python3` works — a real SBOM.
fn make_dist(sb: &Sandbox, with_sbom: bool) -> PathBuf {
    let dist = sb.join("dist");
    std::fs::create_dir_all(&dist).expect("dist");
    std::fs::write(dist.join("ark"), b"#!/bin/sh\necho ark\n").expect("binary");
    std::fs::write(dist.join("THIRD_PARTY_NOTICES.md"), b"# notices\n").expect("notices");
    std::fs::copy(sb.join("keys/release-key.pub.pem"), dist.join("release-key.pub.pem"))
        .expect("public key");
    if with_sbom {
        let out = dist.join("sbom.spdx.json");
        assert_ok(&sb.python("sbom.py", &["--out", &out.to_string_lossy()]), "sbom.py --out");
    }
    dist
}

/// `(cd dir && sha256sum * | sort -k2 > SHA256SUMS)`, as the checklist does it.
fn write_sums(sb: &Sandbox, dist: &Path) {
    let mut entries: Vec<String> = std::fs::read_dir(dist)
        .expect("dist")
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    entries.sort();
    let mut sums = String::new();
    for name in entries {
        let out = sb.run_in(dist, Path::new("sha256sum"), &[name.as_str()]);
        assert_ok(&out, "sha256sum");
        sums.push_str(String::from_utf8_lossy(&out.stdout).trim_end());
        sums.push('\n');
    }
    std::fs::write(dist.join("SHA256SUMS"), sums).expect("SHA256SUMS");
}

fn gen_key(sb: &Sandbox) {
    let keys = sb.join("keys");
    assert_ok(&sb.bash("gen-key.sh", &["--out-dir", &keys.to_string_lossy()]), "gen-key.sh");
    assert!(keys.join("release-key.pem").is_file(), "private key");
    assert!(keys.join("release-key.pub.pem").is_file(), "public key");
}

// ---------------------------------------------------------------------------------------------
// SBOM
// ---------------------------------------------------------------------------------------------

#[test]
fn sbom_is_deterministic_and_well_formed() {
    if !have("python3") {
        println!("skip: python3 not installed");
        return;
    }
    let sb = Sandbox::new("sbom");
    let first = sb.join("sbom-1.spdx.json");
    let second = sb.join("sbom-2.spdx.json");

    assert_ok(&sb.python("sbom.py", &["--out", &first.to_string_lossy()]), "sbom.py --out");
    let text_one = std::fs::read_to_string(&first).expect("sbom file");

    let doc = read_json(&first);
    assert_eq!(doc["spdxVersion"], "SPDX-2.3", "wrong SPDX version");
    assert_eq!(doc["dataLicense"], "CC0-1.0");
    assert_eq!(doc["SPDXID"], "SPDXRef-DOCUMENT");
    // Fixed by SOURCE_DATE_EPOCH: a release artifact must not change because it was built later.
    assert_eq!(doc["creationInfo"]["created"], "2023-11-14T22:13:20Z");

    let packages = doc["packages"].as_array().expect("packages array");
    assert!(packages.len() >= 10, "only {} packages — the SBOM is not covering the workspace", packages.len());

    let mut ids = std::collections::BTreeSet::new();
    for pkg in packages {
        let id = pkg["SPDXID"].as_str().expect("SPDXID");
        assert!(ids.insert(id.to_string()), "duplicate SPDXID {id}");
        assert!(pkg["versionInfo"].as_str().is_some_and(|v| !v.is_empty()), "{id}: no version");
        assert!(
            pkg["licenseDeclared"].as_str().is_some_and(|l| !l.is_empty()),
            "{id}: no licenseDeclared"
        );
        let refs = pkg["externalRefs"].as_array().expect("externalRefs");
        let purls: Vec<&str> = refs
            .iter()
            .filter(|r| r["referenceType"] == "purl")
            .filter_map(|r| r["referenceLocator"].as_str())
            .collect();
        assert!(
            purls.iter().any(|p| p.starts_with("pkg:cargo/") && p.contains('@')),
            "{id}: missing a pkg:cargo purl ({purls:?})"
        );
    }

    let rels = doc["relationships"].as_array().expect("relationships");
    let describes: Vec<&serde_json::Value> =
        rels.iter().filter(|r| r["relationshipType"] == "DESCRIBES").collect();
    assert_eq!(describes.len(), 1, "expected exactly one DESCRIBES relationship");
    assert_eq!(describes[0]["spdxElementId"], "SPDXRef-DOCUMENT");
    assert!(
        ids.contains(describes[0]["relatedSpdxElement"].as_str().unwrap()),
        "DESCRIBES points at an id that is not a package"
    );
    assert!(
        rels.iter().filter(|r| r["relationshipType"] == "DEPENDS_ON").count() > 5,
        "no dependency edges — the graph would be useless"
    );
    for rel in rels {
        assert!(
            ids.contains(rel["relatedSpdxElement"].as_str().unwrap_or("")),
            "relationship points at unknown package: {rel}"
        );
    }

    // No build-machine identity in a published document.
    assert!(!text_one.contains(sb.path().to_string_lossy().as_ref()), "SBOM leaks a host path");

    assert_ok(&sb.python("sbom.py", &["--out", &second.to_string_lossy()]), "sbom.py --out (2)");
    let text_two = std::fs::read_to_string(&second).expect("sbom file 2");
    assert_eq!(text_one, text_two, "two runs produced different bytes — the SBOM is not deterministic");
}

#[test]
fn sbom_check_rejects_tampered_document() {
    if !have("python3") {
        println!("skip: python3 not installed");
        return;
    }
    let sb = Sandbox::new("sbom-check");
    let good = sb.join("sbom.spdx.json");
    assert_ok(&sb.python("sbom.py", &["--out", &good.to_string_lossy()]), "sbom.py --out");

    // `--check` without a file validates the freshly built document.
    assert_ok(&sb.python("sbom.py", &["--check"]), "sbom.py --check (in memory)");
    assert_ok(
        &sb.python("sbom.py", &["--check", "--out", &good.to_string_lossy()]),
        "sbom.py --check (file)",
    );

    // Remove the package a DEPENDS_ON edge points at: the edge now dangles.
    let mut doc = read_json(&good);
    let target = doc["relationships"]
        .as_array()
        .expect("relationships")
        .iter()
        .find(|r| r["relationshipType"] == "DEPENDS_ON")
        .and_then(|r| r["relatedSpdxElement"].as_str().map(str::to_string))
        .expect("a DEPENDS_ON edge");
    let before = doc["packages"].as_array().expect("packages").len();
    doc["packages"]
        .as_array_mut()
        .expect("packages")
        .retain(|p| p["SPDXID"].as_str() != Some(target.as_str()));
    assert_eq!(doc["packages"].as_array().expect("packages").len(), before - 1);
    let tampered = sb.join("tampered.spdx.json");
    std::fs::write(&tampered, format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()))
        .expect("write tampered");

    let out = sb.python("sbom.py", &["--check", "--out", &tampered.to_string_lossy()]);
    assert_failed(&out, "sbom.py --check on a dangling relationship");
    let all = text(&out);
    assert!(all.contains(target.as_str()), "--check does not name the dangling id {target}:\n{all}");

    // A document that is not JSON at all must also be rejected, not crash.
    let garbage = sb.join("garbage.json");
    std::fs::write(&garbage, b"{not json").expect("write garbage");
    assert_failed(&sb.python("sbom.py", &["--check", "--out", &garbage.to_string_lossy()]), "garbage");
}

// ---------------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------------

#[test]
fn release_signing_roundtrip_and_tamper_detection() {
    if !have("openssl") || !have("sha256sum") || !have("base64") {
        println!("skip: openssl/sha256sum/base64 not installed");
        return;
    }
    let sb = Sandbox::new("sign");
    gen_key(&sb);
    let pubkey = sb.join("keys/release-key.pub.pem");
    let privkey = sb.join("keys/release-key.pem");

    let dist = make_dist(&sb, have("python3"));
    write_sums(&sb, &dist);
    assert_ok(
        &sb.bash("sign.sh", &[dist.join("SHA256SUMS").to_string_lossy().as_ref(), privkey.to_string_lossy().as_ref()]),
        "sign.sh",
    );
    assert!(dist.join("SHA256SUMS.sig").is_file(), "no signature written");

    let good = sb.bash(
        "verify-release.sh",
        &[dist.to_string_lossy().as_ref(), "--key", pubkey.to_string_lossy().as_ref()],
    );
    assert_ok(&good, "verify-release.sh on a good release");
    assert!(text(&good).contains("OK"), "verification is not reporting success:\n{}", text(&good));

    // (1) one flipped byte in an artifact.
    let flipped = sb.join("dist-flipped");
    copy_flat(&dist, &flipped);
    let mut bytes = std::fs::read(flipped.join("ark")).expect("read binary");
    bytes.push(b'X');
    std::fs::write(flipped.join("ark"), &bytes).expect("write binary");
    assert_failed(&verify(&sb, &flipped, &pubkey), "verify after flipping a byte");

    // (2) an extra file that nobody signed.
    let extra = sb.join("dist-extra");
    copy_flat(&dist, &extra);
    std::fs::write(extra.join("bonus.sh"), b"echo hi\n").expect("extra file");
    let out = verify(&sb, &extra, &pubkey);
    assert_failed(&out, "verify with an unlisted file");
    assert!(text(&out).contains("bonus.sh"), "the extra file is not named:\n{}", text(&out));

    // (3) tampering with SHA256SUMS itself — the signature check has to catch this one.
    let sums = sb.join("dist-sums");
    copy_flat(&dist, &sums);
    let original = std::fs::read_to_string(sums.join("SHA256SUMS")).expect("sums");
    let mut lines: Vec<String> = original.lines().map(str::to_string).collect();
    let first = lines[0].clone();
    let flipped_char = if first.starts_with('0') { "f" } else { "0" };
    lines[0] = format!("{flipped_char}{}", &first[1..]);
    std::fs::write(sums.join("SHA256SUMS"), lines.join("\n") + "\n").expect("write sums");
    let out = verify(&sb, &sums, &pubkey);
    assert_failed(&out, "verify after tampering with SHA256SUMS");
    assert!(
        text(&out).contains("signature"),
        "the signature check did not report the tampered sums:\n{}",
        text(&out)
    );
}

fn verify(sb: &Sandbox, dir: &Path, pubkey: &Path) -> Output {
    sb.bash("verify-release.sh", &[dir.to_string_lossy().as_ref(), "--key", pubkey.to_string_lossy().as_ref()])
}

#[test]
fn sign_refuses_group_readable_key() {
    if !have("openssl") {
        println!("skip: openssl not installed");
        return;
    }
    let sb = Sandbox::new("keyperm");
    gen_key(&sb);
    let key = sb.join("keys/release-key.pem");

    // The default is 0600; make it 0640 (a common "share it with my group" mistake) and sign.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    std::fs::write(sb.join("SHA256SUMS"), b"deadbeef  ark\n").expect("sums");
    let sums = sb.join("SHA256SUMS");
    let out = sb.bash("sign.sh", &[sums.to_string_lossy().as_ref(), key.to_string_lossy().as_ref()]);
    assert_failed(&out, "sign.sh with a group-readable key");
    assert!(text(&out).contains("group/world"), "unhelpful refusal message:\n{}", text(&out));
    assert!(!sums.with_extension("sig").exists(), "a signature was written despite the refusal");
}

// ---------------------------------------------------------------------------------------------
// Script hygiene
// ---------------------------------------------------------------------------------------------

#[test]
fn scripts_are_executable_and_declare_their_interpreter() {
    let expected: &[(&str, &str)] = &[
        ("sbom.py", "#!/usr/bin/env python3"),
        ("gen-key.sh", "#!/usr/bin/env bash"),
        ("sign.sh", "#!/usr/bin/env bash"),
        ("verify-release.sh", "#!/usr/bin/env bash"),
        ("repro-check.sh", "#!/usr/bin/env bash"),
    ];
    for (name, shebang) in expected {
        let path = script(name);
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let first = body.lines().next().unwrap_or_default();
        assert_eq!(first, *shebang, "{name}: wrong or missing shebang (got {first:?})");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert!(mode & 0o111 != 0, "{name}: not executable (mode {mode:o}) — `chmod +x` it");
        assert!(
            body.contains("--help"),
            "{name}: no --help; every release script must be runnable by a stranger"
        );
        for banned in ["todo!", "dbg!", "FIXME"] {
            assert!(!body.contains(banned), "{name}: leftover {banned}");
        }
    }
}

#[test]
fn repro_check_parses_but_is_not_run() {
    // Compiling the workspace twice takes minutes, which does not belong in `cargo test`. The
    // script's syntax and its documented default are what this test can hold still.
    let path = script("repro-check.sh");
    let out = Command::new("bash").arg("-n").arg(&path).output().expect("bash -n");
    assert!(
        out.status.success(),
        "bash -n {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(&path).expect("read repro-check.sh");
    assert!(body.contains("ARK_REPRO_FULL"), "repro-check.sh lost its ARK_REPRO_FULL knob");
    assert!(body.contains("--quick"), "repro-check.sh lost its --quick mode");
    assert!(body.contains("SOURCE_DATE_EPOCH"), "repro-check.sh no longer pins SOURCE_DATE_EPOCH");
}
