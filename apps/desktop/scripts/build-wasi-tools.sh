#!/usr/bin/env bash
# Build the WASI tools the iOS app runs in its `wasm` exec backend (no processes on iOS: every
# command is a wasm32-wasip1 module interpreted in-process by wasmi; docs/cross-platform.md).
#
#   apps/desktop/scripts/build-wasi-tools.sh [OUT_DIR]        default: apps/desktop/src-tauri/wasi-tools
#   apps/desktop/scripts/build-wasi-tools.sh --check [OUT_DIR] verify OUT_DIR against tools.json
#
# What it builds — pure Rust, no wasi-sdk / C toolchain needed:
#   coreutils.wasm  uutils coreutils $COREUTILS_VERSION, `feat_wasm` (the upstream WASI set: ls,
#                   cat, cp, mv, rm, mkdir, head, tail, sort, uniq, wc, cut, tr, sed-free text
#                   tools, sha256sum, base64, date, …) as one multi-call module.
#
# Pinning: the crate version is fixed below and `cargo install --locked` builds it with the
# Cargo.lock shipped inside that crate, so every dependency is the exact version (and crates.io
# SHA-256) upstream released. The digest of the resulting module is written into tools.json;
# the backend refuses to run a module whose bytes do not match it. A rebuild with another
# toolchain may produce other bytes: tools.json is regenerated together with the module.
#
# Not here (yet): a POSIX shell — dash / busybox ash need fork/exec, which WASI does not have, so
# the backend interprets the shell itself (crates/seagent-tools/src/exec/wasm/shell.rs); CPython
# for WASI — no pinned python.org release exists, see apps/desktop/MOBILE.md ("Python").
set -euo pipefail
COREUTILS_VERSION=0.12.0

here="$(cd "$(dirname "$0")" && pwd)"
app="$(cd "$here/.." && pwd)"
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

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "building uutils coreutils $COREUTILS_VERSION for wasm32-wasip1 (feat_wasm)…"
cargo install coreutils --version "=$COREUTILS_VERSION" --locked --target wasm32-wasip1 \
  --no-default-features --features feat_wasm --root "$work/root" --quiet

mkdir -p "$out"
install -m 0644 "$work/root/bin/coreutils.wasm" "$out/coreutils.wasm"

# The applets `feat_wasm` enables, read from the released crate's own manifest.
src="$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/coreutils-"$COREUTILS_VERSION" | head -1)"
python3 - "$src/Cargo.toml" "$out" "$COREUTILS_VERSION" <<'EOF'
import hashlib, json, os, re, sys
toml, out, version = sys.argv[1], sys.argv[2], sys.argv[3]
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
digest = hashlib.sha256(open(os.path.join(out, "coreutils.wasm"), "rb").read()).hexdigest()
manifest = {
    "comment": f"uutils coreutils {version} (feat_wasm) for wasm32-wasip1, built by apps/desktop/scripts/build-wasi-tools.sh",
    "modules": {"coreutils.wasm": {"sha256": digest, "source": f"crates.io coreutils {version} --locked"}},
    "tools": {u: {"module": "coreutils.wasm", "argv0": u} for u in utils},
}
json.dump(manifest, open(os.path.join(out, "tools.json"), "w"), indent=1, sort_keys=True)
print(f"coreutils.wasm sha256 {digest}; {len(utils)} commands: {' '.join(utils)}")
EOF
verify "$out"
