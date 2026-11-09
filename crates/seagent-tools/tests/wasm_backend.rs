//! The `wasm` exec backend against real `wasm32-wasip1` programs (tests/wasi-fixtures, built
//! here with `cargo build --target wasm32-wasip1`): stdout / stderr / exit codes, pipelines,
//! file I/O confined to the workspace and `/tmp`, symlink and `..` escapes, a read-only
//! workspace, kill on timeout of a busy loop, the memory cap, live stdin, pinned digests and
//! the persistent-shell snapshot epilogue.
//!
//! Needs the `wasm` feature and the `wasm32-wasip1` Rust target (`rustup target add
//! wasm32-wasip1`): `cargo test -p seagent-tools --features wasm --test wasm_backend`.
#![cfg(feature = "wasm")]

use seagent_core::exec::{ExecBackend, ExecRequest, ExitInfo};
use seagent_core::tmp::TempDir;
use seagent_tools::exec::wasm::{WasmBackend, WasmConfig};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const APPLETS: &[&str] = &["say", "cat", "put", "ls", "mkdir", "mv", "rm", "wc", "upper", "env", "fail", "spin", "nap", "hog", "escape", "now"];

/// Build the fixture once per test run; the module path.
fn wbox() -> &'static PathBuf {
    static W: OnceLock<PathBuf> = OnceLock::new();
    W.get_or_init(|| {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasi-fixtures/Cargo.toml");
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("wasi-fixtures");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let out = Command::new(cargo)
            .args(["build", "--release", "--quiet", "--target", "wasm32-wasip1", "--manifest-path"])
            .arg(&manifest)
            .arg("--target-dir")
            .arg(&target)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_TARGET")
            .output()
            .expect("run cargo");
        assert!(out.status.success(), "building the WASI fixtures failed (is the target installed? `rustup target add wasm32-wasip1`):\n{}", String::from_utf8_lossy(&out.stderr));
        target.join("wasm32-wasip1/release/wbox.wasm")
    })
}

fn sha256(p: &Path) -> String {
    seagent_net::crypto::sha256_file_hex(p).unwrap()
}

struct Env {
    _t: TempDir,
    ws: PathBuf,
    tmp: PathBuf,
    home: PathBuf,
    outside: PathBuf,
    tools: PathBuf,
}

/// A workspace, a private /tmp, a home, a file outside all of them, and a tools dir whose
/// `tools.json` maps every applet onto the one pinned module.
fn env(tag: &str) -> Env {
    let t = TempDir::new(&format!("seagent-wasm-{tag}"));
    let root = t.path().canonicalize().unwrap();
    let (ws, tmp, home, tools) = (root.join("ws"), root.join("tmp"), root.join("home"), root.join("tools"));
    for d in [&ws, &tmp, &home, &tools] {
        std::fs::create_dir_all(d).unwrap();
    }
    let outside = root.join("outside.txt");
    std::fs::write(&outside, "TOPSECRET-CONTENT").unwrap();
    std::fs::write(root.join("secret.txt"), "TOPSECRET-CONTENT").unwrap();
    std::fs::copy(wbox(), tools.join("wbox.wasm")).unwrap();
    let mut m = serde_json::json!({"modules": {"wbox.wasm": {"sha256": sha256(&tools.join("wbox.wasm"))}}, "tools": {}});
    for a in APPLETS {
        m["tools"][a] = serde_json::json!({"module": "wbox.wasm", "argv0": a});
    }
    std::fs::write(tools.join("tools.json"), m.to_string()).unwrap();
    Env { _t: t, ws, tmp, home, outside, tools }
}

fn backend(e: &Env, writable: bool, memory_mb: u64) -> WasmBackend {
    let cfg = WasmConfig { tools_dir: e.tools.display().to_string(), memory_mb, ..Default::default() };
    WasmBackend::with_layout(cfg, &e.ws, writable, &e.tmp, &[], &e.home).unwrap()
}

fn run(b: &WasmBackend, script: &str) -> (ExitInfo, String) {
    let (st, out) = seagent_tools::exec::run_capture(b, script, None, Duration::from_secs(60)).unwrap();
    (st, String::from_utf8_lossy(&out).into_owned())
}

#[test]
fn stdio_pipelines_and_exit_codes() {
    let e = env("stdio");
    let b = backend(&e, true, 256);
    assert_eq!(b.id(), "wasm");
    // 16 applets from tools.json plus `wbox` itself (the module file).
    assert!(b.describe().contains("17 WASI tools"), "{}", b.describe());
    let (st, out) = run(&b, "say hello wasm | upper");
    assert_eq!((st, out.as_str()), (ExitInfo::code(0), "HELLO WASM\n"));
    let (st, out) = run(&b, "fail 7; echo \"rc=$?\"; printf 'a\\nb\\nc\\n' | wc");
    assert_eq!(st, ExitInfo::code(0));
    assert_eq!(out, "fail: on purpose\nrc=7\n3\n");
    assert_eq!(run(&b, "fail 9").0, ExitInfo::code(9));
    let (st, out) = run(&b, "no-such-tool x");
    assert_eq!(st, ExitInfo::code(127));
    assert!(out.contains("command not found"), "{out}");
    let (_, out) = run(&b, "now; nap 120");
    assert_eq!(out, "true 4\nslept true\n", "clocks, random_get (HashMap seed) and poll_oneoff sleeps");
    let (_, out) = run(&b, "FOO=bar env");
    for want in ["FOO=bar\n", "HOME=/tmp\n", "TMPDIR=/tmp\n", &format!("PWD={}\n", e.ws.display())] {
        assert!(out.contains(want), "missing {want:?} in\n{out}");
    }
    assert!(!out.contains(&e.home.display().to_string()), "the host home is not leaked: {out}");
}

#[test]
fn files_live_in_the_workspace_and_tmp_only() {
    let e = env("files");
    let b = backend(&e, true, 256);
    let (st, out) = run(&b, "put a.txt hi there; cat a.txt; echo; mkdir sub/deep; cd sub; put b.txt x; ls; cd ..; ls; put /tmp/t.txt q; cat /tmp/t.txt; echo; mv a.txt sub/c.txt; ls sub; rm sub/b.txt; ls sub");
    assert_eq!(st, ExitInfo::code(0), "{out}");
    assert_eq!(out, "hi there\nb.txt\ndeep\na.txt\nsub\nq\nb.txt\nc.txt\ndeep\nc.txt\ndeep\n");
    assert_eq!(std::fs::read_to_string(e.ws.join("sub/c.txt")).unwrap(), "hi there");
    assert_eq!(std::fs::read_to_string(e.tmp.join("t.txt")).unwrap(), "q", "/tmp is the session's private tmp on the host");
    // Shell redirections go through the same policy.
    let (_, out) = run(&b, "echo via-shell > r.txt; cat < r.txt; cat r.txt | upper");
    assert_eq!(out, "via-shell\nVIA-SHELL\n");

    #[cfg(unix)]
    std::os::unix::fs::symlink(e.outside.parent().unwrap(), e.ws.join("link-out")).unwrap();
    let (st, out) = run(&b, "escape");
    assert_eq!(st, ExitInfo::code(0));
    assert!(!out.contains("READ"), "nothing outside the roots is readable:\n{out}");
    assert_eq!(out.matches("denied").count(), 5, "{out}");
    // wasi-libc maps an absolute path no root claims onto the `.` preopen (the cwd): the write
    // lands inside the workspace, never at the host's `/`.
    assert!(out.contains("WROTE /escape.txt") && e.ws.join("escape.txt").is_file(), "{out}");
    assert!(!out.contains("WROTE ../escape.txt"), "{out}");
    let (_, out) = run(&b, "cat ../outside.txt; cat /etc/hostname; cat link-out/secret.txt; echo x > ../w.txt; cd ..; echo \"cd=$?\"");
    assert!(!out.contains("TOPSECRET"), "{out}");
    assert!(out.contains("Capabilities insufficient"), "WASI says ENOTCAPABLE: {out}");
    assert!(out.ends_with("cd=1\n"), "{out}");
    assert!(!e.outside.with_file_name("w.txt").exists());
    assert_eq!(std::fs::read_to_string(&e.outside).unwrap(), "TOPSECRET-CONTENT");
}

#[test]
fn a_read_only_workspace_refuses_writes() {
    let e = env("ro");
    std::fs::write(e.ws.join("keep.txt"), "orig").unwrap();
    let b = backend(&e, false, 256);
    let (_, out) = run(&b, "cat keep.txt; echo; put keep.txt changed; echo \"put=$?\"; echo y > new.txt; echo \"redir=$?\"; rm keep.txt; echo \"rm=$?\"; put /tmp/ok.txt fine; echo \"tmp=$?\"");
    assert!(out.starts_with("orig\n"), "{out}");
    for want in ["put=1", "redir=1", "rm=1", "tmp=0"] {
        assert!(out.contains(want), "{want} in\n{out}");
    }
    assert_eq!(std::fs::read_to_string(e.ws.join("keep.txt")).unwrap(), "orig");
    assert!(!e.ws.join("new.txt").exists());
}

#[test]
fn a_busy_loop_is_killed_and_memory_is_capped() {
    let e = env("kill");
    let b = backend(&e, true, 64);
    let mut child = b.spawn(&ExecRequest { script: "say started; spin".into(), ..Default::default() }).unwrap();
    let mut buf = [0u8; 256];
    let t = Instant::now();
    let mut seen = String::new();
    while t.elapsed() < Duration::from_secs(5) && !seen.contains("started") {
        if let Ok(n) = child.read(&mut buf, Duration::from_millis(50)) {
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    }
    assert!(seen.contains("started"), "{seen}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(child.try_wait().unwrap(), None, "the loop is still running");
    let k = Instant::now();
    child.kill(false);
    let st = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(k.elapsed() < Duration::from_secs(3), "kill takes effect within one fuel slice");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(st, ExitInfo { code: None, signal: Some(9) });
    // A shell `while true` loop and the `sleep` builtin stop the same way.
    let mut c2 = b.spawn(&ExecRequest { script: "while true; do :; done".into(), ..Default::default() }).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    c2.kill(true);
    let k = Instant::now();
    while c2.try_wait().unwrap().is_none() {
        assert!(k.elapsed() < Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(10));
    }
    // 4 GiB of allocations against a 64 MiB cap: the tool fails, the agent does not.
    let (st, out) = run(&b, "hog");
    assert_ne!(st, ExitInfo::code(0), "{out}");
    assert!(!out.contains("allocated"), "{out}");
}

/// The real tool set the iOS app ships (uutils coreutils, `apps/desktop/scripts/build-wasi-tools.sh`)
/// when `SEAGENT_TEST_WASI_TOOLS` names a directory it built; the fixtures above cover the
/// backend itself, this covers the actual commands agents type.
#[test]
fn uutils_coreutils_when_built() {
    let Some(dir) = std::env::var_os("SEAGENT_TEST_WASI_TOOLS").map(PathBuf::from) else {
        eprintln!("SEAGENT_TEST_WASI_TOOLS not set: build the tools with apps/desktop/scripts/build-wasi-tools.sh to run this");
        return;
    };
    let e = env("uutils");
    let cfg = WasmConfig { tools_dir: dir.display().to_string(), ..Default::default() };
    let b = WasmBackend::with_layout(cfg, &e.ws, true, &e.tmp, &[], &e.home).unwrap();
    let (st, out) = run(&b, "echo hello > f.txt; cat f.txt | tr a-z A-Z; printf 'b\\na\\nc\\n' | sort | head -2; mkdir -p a/b && cp f.txt a/b/ && ls a/b; wc -c < f.txt; sha256sum f.txt | cut -c1-16; seq 1 5 | tail -n 2 | paste -sd+; basename /x/y/z.txt .txt; rm -r a; ls; date +%Y | cut -c1-2");
    assert_eq!(st, ExitInfo::code(0), "{out}");
    assert_eq!(out, "HELLO\na\nb\nf.txt\n6\n5891b5b522d5df08\n4+5\nz\nf.txt\n20\n");
    let (_, out) = run(&b, "cat /etc/passwd; ls ..; echo \"rc=$?\"");
    assert!(out.contains("rc=") && !out.contains("root:"), "{out}");
}

/// A tools directory that pins its modules refuses one it does not pin.
#[test]
fn an_unpinned_module_next_to_pinned_ones_is_refused() {
    let e = env("unpinned");
    std::fs::copy(e.tools.join("wbox.wasm"), e.tools.join("say2.wasm")).unwrap();
    let b = backend(&e, true, 256);
    let (st, out) = run(&b, "say2 hi");
    assert_eq!(st, ExitInfo::code(126), "{out}");
    assert!(out.contains("unpinned"), "{out}");
}

fn tool_set() -> Option<(Env, WasmBackend)> {
    let dir = std::env::var_os("SEAGENT_TEST_WASI_TOOLS").map(PathBuf::from)?;
    let e = env("toolset");
    let cfg = WasmConfig { tools_dir: dir.display().to_string(), ..Default::default() };
    let b = WasmBackend::with_layout(cfg, &e.ws, true, &e.tmp, &[], &e.home).unwrap();
    Some((e, b))
}

/// grep (tools/wasi-grep), sed (uutils sed), find (uutils findutils) and the xargs builtin.
#[test]
fn grep_sed_find_xargs_when_built() {
    let Some((e, b)) = tool_set() else {
        eprintln!("SEAGENT_TEST_WASI_TOOLS not set: build the tools with apps/desktop/scripts/build-wasi-tools.sh to run this");
        return;
    };
    let setup = "mkdir -p src/deep; printf 'fn main() {}\\nlet x = 1;\\n// TODO fix\\n' > src/a.rs; printf 'hello\\nTODO: later\\n' > src/deep/b.txt; printf 'x\\n' > notes.md; ";
    let (st, out) = run(&b, &format!("{setup}grep -rn TODO src | sort; grep -c . src/a.rs; grep -E 'fn|let' src/a.rs | wc -l; grep -i -l hello -r .; grep -q nope src/a.rs; echo \"q=$?\"; grep -w 'x' src/a.rs; grep -o '[0-9]' src/a.rs; grep 'm\\(ai\\)n' src/a.rs; echo abc | egrep 'a|z'; echo 'a.b' | fgrep '.'"));
    assert_eq!(st, ExitInfo::code(0), "{out}");
    assert_eq!(out, "src/a.rs:3:// TODO fix\nsrc/deep/b.txt:2:TODO: later\n3\n2\n./src/deep/b.txt\nq=1\nlet x = 1;\n1\nfn main() {}\nabc\na.b\n");
    let (st, out) = run(&b, "printf 'one two\\nthree\\n' | sed 's/o/0/g'; printf 'a\\nb\\nc\\n' | sed -n '2p'; printf 'k=v\\n' > c.ini; sed -i 's/v/w/' c.ini; cat c.ini");
    assert_eq!((st, out.as_str()), (ExitInfo::code(0), "0ne tw0\nthree\nb\nk=w\n"));
    assert_eq!(std::fs::read_to_string(e.ws.join("c.ini")).unwrap(), "k=w\n");
    let (st, out) = run(&b, &format!("{setup}find src -name '*.rs'; find . -type d | sort; find src -type f | sort | xargs grep -l TODO; find src -name '*.txt' | xargs -I{{}} echo got {{}}; echo a b c | xargs -n 1 echo; find /etc -name passwd; echo \"etc=$?\""));
    assert_eq!(st, ExitInfo::code(0), "{out}");
    assert!(out.starts_with("src/a.rs\n.\n./src\n./src/deep\nsrc/a.rs\nsrc/deep/b.txt\ngot src/deep/b.txt\na\nb\nc\n"), "{out}");
    assert!(out.ends_with("etc=1\n") && !out.contains("passwd\n"), "find cannot see outside the roots: {out}");
}

/// CPython for WASI (build-wasi-python.sh): stdlib imports, file I/O in the workspace, exit
/// codes, and the sandbox walls as Python sees them.
#[test]
fn python_when_built() {
    let Some((e, b)) = tool_set() else {
        eprintln!("SEAGENT_TEST_WASI_TOOLS not set: build the tools with apps/desktop/scripts/build-wasi-tools.sh + build-wasi-python.sh to run this");
        return;
    };
    let script = r#"cat > job.py <<'EOF'
import json, os, pathlib, re, sys
p = pathlib.Path("data")
p.mkdir(exist_ok=True)
(p / "out.json").write_text(json.dumps({"n": sum(range(10)), "m": bool(re.match(r"a+b", "aab"))}))
print(open("data/out.json").read())
print(sorted(os.listdir(".")))
for path in ["/etc/passwd", "../outside.txt"]:
    try:
        open(path).read()
        print("READ", path)
    except OSError as e:
        print("denied", path, type(e).__name__)
try:
    open("../escape.txt", "w").write("x")
    print("WROTE")
except OSError:
    print("denied write")
sys.exit(3)
EOF
python3 job.py; echo "rc=$?"; python3 -c 'import sys; print(sys.version_info[:2], sys.platform)'"#;
    let (st, out) = run(&b, script);
    assert_eq!(st, ExitInfo::code(0), "{out}");
    assert!(out.starts_with("{\"n\": 45, \"m\": true}\n['data', 'job.py']\n"), "{out}");
    assert!(out.contains("denied /etc/passwd") && out.contains("denied ../outside.txt") && out.contains("denied write"), "{out}");
    assert!(!out.contains("READ") && !out.contains("WROTE"), "{out}");
    assert!(out.contains("rc=3\n") && out.contains("(3, 14) wasi"), "{out}");
    assert_eq!(std::fs::read_to_string(e.ws.join("data/out.json")).unwrap(), "{\"n\": 45, \"m\": true}");
    assert!(!e.outside.with_file_name("escape.txt").exists());
}

#[test]
fn live_stdin_pinned_digests_and_the_shell_snapshot() {
    let e = env("misc");
    let b = backend(&e, true, 256);
    let mut child = b.spawn(&ExecRequest { script: "cat | upper".into(), stdin: true, ..Default::default() }).unwrap();
    child.write_stdin(b"live input\n").unwrap();
    child.close_stdin();
    let (st, out) = seagent_tools::exec::drain(child, Duration::from_secs(20)).unwrap();
    assert_eq!((st, String::from_utf8_lossy(&out).as_ref()), (ExitInfo::code(0), "LIVE INPUT\n"));

    // The persistent-shell epilogue (`exec::session`) writes into `<home>/shell/<scope>`, a root
    // the shell may use but no tool can see.
    let state = e.home.join("shell/s-1");
    std::fs::create_dir_all(&state).unwrap();
    let st_dir = state.canonicalize().unwrap();
    let script = format!(
        "builtin cd -- '{ws}' 2>/dev/null || {{ printf 'cannot cd to %s\\n' '{ws}' >&2; exit 126; }}\nexport KEEP='one two'\neval 'mkdir d; cd d'\n__seagent_ec=$?\n( umask 077; {{ pwd -P; export -p; }} > '{s}/state.tmp.$$' ) 2>/dev/null && mv -f '{s}/state.tmp.$$' '{s}/state' 2>/dev/null || rm -f '{s}/state.tmp.$$' 2>/dev/null || true\nexit $__seagent_ec\n",
        ws = e.ws.display(),
        s = st_dir.display()
    );
    let (st, out) = run(&b, &script);
    assert_eq!(st, ExitInfo::code(0), "{out}");
    let saved = std::fs::read_to_string(st_dir.join("state")).unwrap();
    assert!(saved.starts_with(&format!("{}/d\n", e.ws.display())), "{saved}");
    assert!(saved.contains("declare -x KEEP=\"one two\""), "{saved}");
    let (_, out) = run(&b, &format!("ls {}", st_dir.display()));
    assert!(out.contains("denied") || out.contains("ls:"), "tools cannot list the snapshot dir: {out}");

    // A module whose bytes do not match the pinned digest is refused.
    let mut bytes = std::fs::read(e.tools.join("wbox.wasm")).unwrap();
    bytes.extend_from_slice(b"\0\0"); // any change to the bytes changes the digest
    std::fs::write(e.tools.join("wbox.wasm"), &bytes).unwrap();
    let b2 = backend(&e, true, 256);
    let (st, out) = run(&b2, "say hi");
    assert_eq!(st, ExitInfo::code(126), "{out}");
    assert!(out.contains("does not match the pinned"), "{out}");
}
