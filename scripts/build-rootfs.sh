#!/usr/bin/env bash
# Build the guest rootfs directory: static sandboxd + Alpine userland.
# usage: scripts/build-rootfs.sh [output-dir]   (default ~/.bulge/rootfs/current)
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$HOME/.bulge/rootfs/current}
target=x86_64-unknown-linux-musl
[ "$(uname -m)" = aarch64 ] && target=aarch64-unknown-linux-musl

cargo build --manifest-path "$repo/Cargo.toml" -p sandboxd --release --target "$target"
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
cp "$repo/rootfs/Containerfile" "$repo/rootfs/udhcpc.script" "$ctx/"
cp "$repo/target/$target/release/sandboxd" "$ctx/"
podman build -q -t bulge-rootfs:dev "$ctx" >/dev/null
cid=$(podman create bulge-rootfs:dev)
tmp="$out.new"
rm -rf "$tmp" && mkdir -p "$tmp"
podman export "$cid" | tar -x -C "$tmp" 2>/dev/null || true
podman rm "$cid" >/dev/null
# resolv.conf lives on guest tmpfs (written by udhcpc.script).
rm -f "$tmp/etc/resolv.conf" && ln -s /run/bulge/resolv.conf "$tmp/etc/resolv.conf"
chmod 755 "$tmp/usr/local/share/bulge/udhcpc.script"
test -x "$tmp/usr/local/bin/sandboxd"
rm -rf "$out" && mv "$tmp" "$out"
echo "rootfs: $out ($(du -sh "$out" | cut -f1))"
