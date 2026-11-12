#!/usr/bin/env bash
# Put the built-in VM's runtime back into the AppImage byte-for-byte.
#
# linuxdeploy (Tauri's AppImage step) runs patchelf on every ELF file under usr/lib, including
# the bundled static-pie Firecracker (vm/runtime/firecracker/firecracker); the patched binary
# segfaults at start, so the AppImage had no working microVM (deb/rpm are not affected). This
# copies the staged runtime files (apps/desktop/src-tauri/vm, hashes in its bundle.json) over the
# AppDir copy, checks every hash, and repacks the squashfs behind the original AppImage runtime
# with the same compressor. Idempotent.
#
#   apps/desktop/scripts/appimage-vm-fix.sh [target triple]     # after `cargo tauri build --bundles appimage`
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
desk="$(cd "$here/.." && pwd)"
triple="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
staged="$desk/src-tauri/vm"
[ -f "$staged/bundle.json" ] || { echo "appimage-vm-fix: no staged VM bundle in $staged (packaging/vm/bundle.sh)" >&2; exit 1; }
out="${CARGO_TARGET_DIR:-$desk/target}/$triple/release/bundle/appimage"
appdir="$(find "$out" -maxdepth 1 -name '*.AppDir' -type d | head -1)"
image="$(find "$out" -maxdepth 1 -name '*.AppImage' -type f | head -1)"
[ -n "$appdir" ] && [ -n "$image" ] || { echo "appimage-vm-fix: no AppDir/AppImage under $out" >&2; exit 1; }
vm="$(dirname "$(find "$appdir" -path '*/vm/bundle.json' | head -1)")"
[ -f "$vm/bundle.json" ] || { echo "appimage-vm-fix: the AppDir has no vm/bundle.json" >&2; exit 1; }
py="$(command -v python3 || command -v python)"

# Restore and verify every runtime file listed in bundle.json.
"$py" -I - "$staged" "$vm" <<'PY'
import hashlib, json, os, shutil, sys
staged, vm = sys.argv[1:3]
info = json.load(open(os.path.join(staged, "bundle.json")))
rt = info["runtime"]
changed = 0
for rel, want in rt["files"].items():
    src = os.path.join(staged, rt["dir"], rel)
    dst = os.path.join(vm, rt["dir"], rel)
    if hashlib.sha256(open(dst, "rb").read()).hexdigest() != want:
        shutil.copy2(src, dst)
        changed += 1
    got = hashlib.sha256(open(dst, "rb").read()).hexdigest()
    if got != want:
        sys.exit(f"appimage-vm-fix: {dst} is {got}, bundle.json says {want}")
print(f"appimage-vm-fix: {changed} runtime file(s) restored, all {len(rt['files'])} match bundle.json")
PY

# Repack: original runtime (everything before the squashfs) + a new squashfs of the AppDir.
offset="$("$image" --appimage-offset)"
comp="$(unsquashfs -o "$offset" -s "$image" 2>/dev/null | sed -n 's/^Compression //p' | head -1)"
tmp="$(mktemp -d "$out/.vmfix.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
head -c "$offset" "$image" >"$tmp/new.AppImage"
mksquashfs "$appdir" "$tmp/fs.sqfs" -root-owned -noappend -comp "${comp:-gzip}" -quiet >/dev/null
cat "$tmp/fs.sqfs" >>"$tmp/new.AppImage"
chmod 0755 "$tmp/new.AppImage"
mv -f "$tmp/new.AppImage" "$image"
echo "appimage-vm-fix: repacked $(basename "$image") (${comp:-gzip}, $(stat -c %s "$image") bytes)"
