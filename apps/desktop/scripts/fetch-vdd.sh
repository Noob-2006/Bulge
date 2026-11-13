#!/usr/bin/env bash
# Fetch the virtual display driver bundled into the Windows installers (bundle resource `vdd/`,
# see src-tauri/tauri.windows.conf.json): VirtualDrivers/Virtual-Display-Driver release 25.7.23,
# asset VirtualDisplayDriver-x86.Driver.Only.zip (the x64 driver despite the name: MttVDD.inf
# `NTamd64`, DriverVer 11.30.4.434), MIT, catalog and DLL signed by SignPath Foundation.
# Review notes: packaging/release/DEPENDENCY-REVIEW.md ("Virtual Display Driver").
#
# Every file is checked against its SHA-256 (the same values install-vdd.ps1 pins and checks
# again on the user's machine before installing); nothing is committed to git. Idempotent.
#
#   apps/desktop/scripts/fetch-vdd.sh      # → apps/desktop/src-tauri/windows/vdd/driver/
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="$here/../src-tauri/windows/vdd/driver"
release=25.7.23
zip_url="https://github.com/VirtualDrivers/Virtual-Display-Driver/releases/download/$release/VirtualDisplayDriver-x86.Driver.Only.zip"
zip_sha=e24210692b442b39af763536330ce78b423f19342b7a7792c26de3944e418b3a
lic_url="https://raw.githubusercontent.com/VirtualDrivers/Virtual-Display-Driver/$release/LICENSE"
lic_sha=c2285c867ddc9b88f43b4f8fa2c77a9eec66207166c1217b37353a2ccd62ac03
files="550d211fe481e74dfe3f9d724ed78be48b3a9113405965d683d9373e8d672f5d  MttVDD.inf
c9ca837f57a98fbd43bc416a7f535a95843626e7759eaf85cf0cd7ce334dbb05  MttVDD.dll
08a0093fc9b2e32b287a6f8a77ca4de0a31830d29fc33d2b13a918dc859468f6  mttvdd.cat
$lic_sha  LICENSE.txt"

have() { [[ -d "$dir" ]] && (cd "$dir" && echo "$files" | sha256sum -c --status 2>/dev/null); }
if have; then
  echo "vdd: $dir (cached, sha256 ok)"
  exit 0
fi
mkdir -p "$dir"
tmp="$(mktemp -d "$dir/../.vdd.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/vdd.zip" "$zip_url"
curl -fsSL --retry 3 -o "$tmp/LICENSE.txt" "$lic_url"
echo "$zip_sha  $tmp/vdd.zip" | sha256sum -c --status || { echo "vdd: SHA-256 mismatch for $zip_url" >&2; exit 1; }
# unzip (Git Bash, most distros), else Python's zipfile (the archive is already hash-checked).
members=(VirtualDisplayDriver/MttVDD.inf VirtualDisplayDriver/MttVDD.dll VirtualDisplayDriver/mttvdd.cat)
if command -v unzip >/dev/null; then
  (cd "$tmp" && unzip -q -j vdd.zip "${members[@]}")
else
  py=""; for c in python3 python py; do command -v "$c" >/dev/null && "$c" -c "import sys" >/dev/null 2>&1 && { py="$c"; break; }; done  # not the Store alias
  (cd "$tmp" && "$py" -I -c 'import sys, zipfile, os
z = zipfile.ZipFile("vdd.zip")
for m in sys.argv[1:]:
    open(os.path.basename(m), "wb").write(z.read(m))' "${members[@]}")
fi
(cd "$tmp" && echo "$files" | sha256sum -c --status) || { echo "vdd: a driver file does not match its pinned SHA-256" >&2; exit 1; }
for f in MttVDD.inf MttVDD.dll mttvdd.cat LICENSE.txt; do
  chmod 0644 "$tmp/$f"
  mv "$tmp/$f" "$dir/$f"
done
echo "vdd: $dir (release $release, sha256 ok)"
