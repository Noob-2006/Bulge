#!/usr/bin/env bash
# Build CPython for wasm32-wasip1 and add it to the iOS WASI tool set (python3 / python run in the
# wasm exec backend's interpreter; no processes on iOS — docs/cross-platform.md).
#
#   apps/desktop/scripts/build-wasi-python.sh [OUT_DIR]     default: apps/desktop/src-tauri/wasi-tools
#
# Pinned inputs, both verified by SHA-256 before anything is unpacked:
#   * CPython $PY_VERSION source tarball from python.org
#   * wasi-sdk (wasi-sdk.sh) from the official WebAssembly/wasi-sdk GitHub release
# It runs CPython's own cross build (`python3 Tools/wasm/wasi build`: a native build Python first,
# then the WASI one), copies python.wasm and a trimmed, precompiled standard library into OUT_DIR,
# and merges `python3` / `python` into OUT_DIR/tools.json with the module's SHA-256 pinned.
# Downloads and build trees live in $SEAGENT_WASI_WORK (default ~/.cache/seagent-wasi).
set -euo pipefail
PY_VERSION=3.14.10
PY_SHA256=de414a57119abef52784d8993e341d53aed635fc2b05c2607d9f98a2c5b72032

here="$(cd "$(dirname "$0")" && pwd)"
app="$(cd "$here/.." && pwd)"
mkdir -p "${1:-$app/src-tauri/wasi-tools}"
out="$(cd "${1:-$app/src-tauri/wasi-tools}" && pwd)"
# shellcheck source=wasi-sdk.sh
source "$here/wasi-sdk.sh"
work="$SEAGENT_WASI_WORK"

sdk="$(wasi_sdk)"
fetch_pinned "https://www.python.org/ftp/python/$PY_VERSION/Python-$PY_VERSION.tar.xz" "Python-$PY_VERSION.tar.xz" "$PY_SHA256"
src="$work/Python-$PY_VERSION"
[[ -d "$src" ]] || tar -xJf "$work/dl/Python-$PY_VERSION.tar.xz" -C "$work"

echo "building CPython $PY_VERSION for wasm32-wasip1 with $(basename "$sdk")…"
# `--host-runner true`: CPython's script only uses the runner for a `python.sh --version` smoke
# run; the module is exercised in the agent's own interpreter instead (no wasmtime needed).
(cd "$src" && WASI_SDK_PATH="$sdk" python3 Tools/wasm/wasi build --quiet --host-runner true)

wasm="$src/cross-build/wasm32-wasip1/python.wasm"
[[ -f "$wasm" ]] || { echo "build-wasi-python: no python.wasm produced" >&2; exit 1; }
# The native build Python (cross-build/<build triple>/python, or python.exe on macOS).
buildpy="$(find "$src/cross-build" -mindepth 2 -maxdepth 2 \( -name python -o -name python.exe \) -type f -not -path '*wasm32*' | head -1)"
mm="${PY_VERSION%.*}"
lib="$out/python/lib/python$mm"
rm -rf "$out/python"
mkdir -p "$lib"
install -m 0644 "$wasm" "$out/python.wasm"
# Debug info and names are not needed to run it (about half the module).
"$sdk/bin/llvm-strip" "$out/python.wasm"
# The standard library without what cannot work or is never needed here (GUI, tests, pip
# bootstrap), plus the WASI build's sysconfig data, precompiled by the matching build Python.
(cd "$src/Lib" && tar -cf - --exclude='__pycache__' --exclude='test' --exclude='tests' --exclude='idlelib' --exclude='tkinter' \
  --exclude='turtledemo' --exclude='ensurepip' --exclude='lib2to3' --exclude='venv' .) | tar -xf - -C "$lib"
find "$src/cross-build/wasm32-wasip1/build" -name '_sysconfigdata*.py' -exec cp {} "$lib/" \;
"$buildpy" -m compileall -q -j0 "$lib" >/dev/null || echo "build-wasi-python: precompiling the stdlib failed (it still works, slower)" >&2

python3 - "$out" "$PY_VERSION" "$mm" "$(basename "$sdk")" <<'EOF'
import hashlib, json, os, sys
out, version, mm, sdk = sys.argv[1:]
path = os.path.join(out, "tools.json")
m = json.load(open(path)) if os.path.exists(path) else {"modules": {}, "tools": {}}
digest = hashlib.sha256(open(os.path.join(out, "python.wasm"), "rb").read()).hexdigest()
m["modules"]["python.wasm"] = {"sha256": digest, "source": f"python.org CPython {version} ({sdk})"}
for name in ("python3", "python"):
    m["tools"][name] = {
        "module": "python.wasm",
        "argv0": "python3",
        "dirs": {f"/usr/local/lib/python{mm}": f"python/lib/python{mm}"},
        "env": {"PYTHONHOME": "/usr/local", "PYTHONDONTWRITEBYTECODE": "1"},
    }
json.dump(m, open(path, "w"), indent=1, sort_keys=True)
print(f"python.wasm sha256 {digest}")
EOF
echo "python: $(du -sh "$out/python.wasm" | cut -f1) module, $(du -sh "$out/python" | cut -f1) stdlib in $out"
