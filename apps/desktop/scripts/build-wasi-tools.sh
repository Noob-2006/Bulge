#!/usr/bin/env bash
# Build the WASI tools the iOS app runs in its `wasm` exec backend (no processes on iOS: every
# command is a wasm32-wasip1 module interpreted in-process by wasmi; docs/cross-platform.md).
#
#   apps/desktop/scripts/build-wasi-tools.sh [OUT_DIR]        default: apps/desktop/src-tauri/wasi-tools
#   apps/desktop/scripts/build-wasi-tools.sh --check [OUT_DIR] verify OUT_DIR against tools.json
#
# What it builds:
#   coreutils.wasm  uutils coreutils $COREUTILS_VERSION, `feat_wasm` (the upstream WASI set: ls,
#                   cat, cp, mv, rm, mkdir, head, tail, sort, uniq, wc, cut, tr, tee, seq, date,
#                   sha256sum, base64, …) as one multi-call module
#   sed.wasm        uutils sed $SED_VERSION (POSIX sed + GNU extensions)
#   find.wasm       uutils findutils $FINDUTILS_VERSION (`find`; its regex engine Oniguruma is C,
#                   compiled with the pinned wasi-sdk from wasi-sdk.sh). `-exec` cannot start a
#                   process under WASI; use `find … | xargs …` (xargs is a shell builtin).
#   grep.wasm       tools/wasi-grep: POSIX grep (-E/-F/-G, -i -v -n -c -l -L -o -q -s -w -x -r,
#                   -e/-f, -A/-B/-C, -m, --include/--exclude), `regex` pinned by its Cargo.lock
#
# Pinning: the crates.io versions are fixed below and `cargo install --locked` / `cargo build
# --locked` builds them with the Cargo.lock their release (or tools/wasi-grep) ships, so every
# dependency is an exact version with its crates.io SHA-256. Each module's digest is written into
# tools.json; the backend refuses to run a module whose bytes do not match it. A rebuild with
# another toolchain may produce other bytes: tools.json is regenerated together with the modules.
# CPython: build-wasi-python.sh, run after this script (it merges python3 into tools.json).
#
# A POSIX shell is not here: dash / busybox ash need fork/exec, which WASI does not have, so the
# backend interprets the shell itself (crates/seagent-tools/src/exec/wasm/shell.rs).
set -euo pipefail
COREUTILS_VERSION=0.12.0
SED_VERSION=0.3.0
FINDUTILS_VERSION=0.11.0

here="$(cd "$(dirname "$0")" && pwd)"
app="$(cd "$here/.." && pwd)"
root="$(cd "$app/../.." && pwd)"
check=0
if [[ "${1:-}" == "--check" ]]; then
  check=1
  shift
fi
out="${1:-$app/src-tauri/wasi-tools}"

verify() {
  python3 - "$1" <<'EOF'
import hashlib, json, os, sys
d = sys.argv[1]
m = json.load(open(os.path.join(d, "tools.json")))
bad = 0
for name, info in m["modules"].items():
    got = hashlib.sha256(open(os.path.join(d, name), "rb").read()).hexdigest()
    if got != info["sha256"]:
        print(f"{name}: sha256 {got} != pinned {info['sha256']}", file=sys.stderr)
        bad = 1
missing = [t for t, i in m["tools"].items() if i["module"] not in m["modules"]]
if missing:
    print(f"tools without a pinned module: {missing}", file=sys.stderr)
    bad = 1
print(f"{d}: {len(m['modules'])} module(s), {len(m['tools'])} command(s){' — MISMATCH' if bad else ', digests ok'}")
sys.exit(bad)
EOF
}

if [[ $check == 1 ]]; then
  verify "$out"
  exit $?
fi

command -v cargo >/dev/null || { echo "cargo is needed" >&2; exit 1; }
rustup target list --installed 2>/dev/null | grep -qx wasm32-wasip1 || rustup target add wasm32-wasip1
# shellcheck source=wasi-sdk.sh
source "$here/wasi-sdk.sh"
sdk="$(wasi_sdk)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
inst() { # crate version [features…]
  local crate=$1 version=$2
  shift 2
  echo "building $crate $version for wasm32-wasip1…"
  CC_wasm32_wasip1="$sdk/bin/clang" AR_wasm32_wasip1="$sdk/bin/llvm-ar" CFLAGS_wasm32_wasip1="--sysroot=$sdk/share/wasi-sysroot" \
    cargo install "$crate" --version "=$version" --locked --target wasm32-wasip1 --root "$work/$crate" --quiet "$@"
}
inst coreutils "$COREUTILS_VERSION" --no-default-features --features feat_wasm
inst sed "$SED_VERSION"
inst findutils "$FINDUTILS_VERSION" --bin find
echo "building tools/wasi-grep…"
cargo build --release --locked --quiet --target wasm32-wasip1 --manifest-path "$root/tools/wasi-grep/Cargo.toml" --target-dir "$work/grep"
install -m 0644 "$work/coreutils/bin/coreutils.wasm" "$out/coreutils.wasm"
install -m 0644 "$work/sed/bin/sed.wasm" "$out/sed.wasm"
install -m 0644 "$work/findutils/bin/find.wasm" "$out/find.wasm"
install -m 0644 "$work/grep/wasm32-wasip1/release/grep.wasm" "$out/grep.wasm"
# Names and debug sections are not needed to run them.
for m in coreutils sed find grep; do "$sdk/bin/llvm-strip" "$out/$m.wasm"; done

# The applets `feat_wasm` enables, read from the released crate's own manifest.
src="$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/coreutils-"$COREUTILS_VERSION" | head -1)"
python3 - "$src/Cargo.toml" "$out" "$COREUTILS_VERSION" "$SED_VERSION" "$FINDUTILS_VERSION" <<'EOF'
import hashlib, json, os, re, sys
toml, out, cu, sed, fu = sys.argv[1:]
text = open(toml).read()
def feature(name):
    m = re.search(r"^%s = \[(.*?)\]" % re.escape(name), text, re.S | re.M)
    return [x.strip().strip('"') for x in m.group(1).split(",") if x.strip()] if m else []
utils, todo, seen = [], ["feat_wasm"], set()
while todo:
    f = todo.pop()
    if f in seen:
        continue
    seen.add(f)
    for item in feature(f):
        if item.startswith("feat_"):
            todo.append(item)
        elif "/" not in item and not item.startswith("dep:"):
            utils.append(item)
utils = sorted(set(utils))
def sha(f):
    return hashlib.sha256(open(os.path.join(out, f), "rb").read()).hexdigest()
path = os.path.join(out, "tools.json")
old = json.load(open(path)) if os.path.exists(path) else {}
# Keep what another script added (python3), replace what this one owns.
mine = {"coreutils.wasm", "sed.wasm", "find.wasm", "grep.wasm"}
modules = {k: v for k, v in old.get("modules", {}).items() if k not in mine}
tools = {k: v for k, v in old.get("tools", {}).items() if v.get("module") not in mine}
modules.update({
    "coreutils.wasm": {"sha256": sha("coreutils.wasm"), "source": f"crates.io coreutils {cu} --locked (feat_wasm)"},
    "sed.wasm": {"sha256": sha("sed.wasm"), "source": f"crates.io sed {sed} --locked (uutils)"},
    "find.wasm": {"sha256": sha("find.wasm"), "source": f"crates.io findutils {fu} --locked (uutils)"},
    "grep.wasm": {"sha256": sha("grep.wasm"), "source": "tools/wasi-grep --locked"},
})
tools.update({u: {"module": "coreutils.wasm", "argv0": u} for u in utils})
tools.update({"sed": {"module": "sed.wasm"}, "find": {"module": "find.wasm"}, "grep": {"module": "grep.wasm"},
              "egrep": {"module": "grep.wasm", "argv0": "grep", "args": ["-E"]}, "fgrep": {"module": "grep.wasm", "argv0": "grep", "args": ["-F"]}})
manifest = {"comment": "WASI tools for the wasm exec backend, built by apps/desktop/scripts/build-wasi-tools.sh (+ build-wasi-python.sh)", "modules": modules, "tools": tools}
json.dump(manifest, open(path, "w"), indent=1, sort_keys=True)
for k in sorted(mine):
    print(f"{k} sha256 {modules[k]['sha256']}")
print(f"{len(tools)} commands")
EOF
verify "$out"
