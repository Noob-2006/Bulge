#!/usr/bin/env python3
"""Build the Tauri updater manifest (latest.json) from collected release assets.

  latest-json.py <dist-dir> <version> <tag> [repo]   → writes <dist-dir>/latest.json

Uses the installers that have a matching .sig (only produced when TAURI_SIGNING_PRIVATE_KEY was
set): NSIS .exe and .msi (Windows), .app.tar.gz (macOS, universal → both arches), .AppImage
(Linux; .deb/.rpm installs are updated by the package manager instead).
"""
import datetime
import json
import os
import sys


def main():
    dist, version, tag = sys.argv[1], sys.argv[2].lstrip("v"), sys.argv[3]
    repo = sys.argv[4] if len(sys.argv) > 4 else "Noob-2006/System-Engineering-Agent"
    base = f"https://github.com/{repo}/releases/download/{tag}/"
    files = set(os.listdir(dist))
    platforms = {}

    def add(keys, name):
        sig = name + ".sig"
        if name in files and sig in files:
            with open(os.path.join(dist, sig), encoding="utf-8") as f:
                entry = {"signature": f.read().strip(), "url": base + name}
            for k in keys:
                platforms.setdefault(k, entry)

    for n in sorted(files):
        if n.endswith("-setup.exe"):
            add(["windows-x86_64", "windows-x86_64-nsis"], n)
        elif n.endswith(".msi"):
            add(["windows-x86_64-msi"], n)
        elif n.endswith(".app.tar.gz"):
            arches = ["aarch64", "x86_64"] if "universal" in n else (["aarch64"] if "aarch64" in n else ["x86_64"])
            add([f"darwin-{a}" for a in arches] + [f"darwin-{a}-app" for a in arches], n)
        elif n.endswith(".AppImage"):
            arch = "aarch64" if "aarch64" in n else "x86_64"
            add([f"linux-{arch}", f"linux-{arch}-appimage"], n)
    if not platforms:
        print("no signed updater artifacts found; latest.json not written (set TAURI_SIGNING_PRIVATE_KEY)", file=sys.stderr)
        return 0
    manifest = {
        "version": version,
        "notes": f"SE Agent {version} — see https://github.com/{repo}/releases/tag/{tag}",
        "pub_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": platforms,
    }
    with open(os.path.join(dist, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print("latest.json platforms:", ", ".join(sorted(platforms)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
