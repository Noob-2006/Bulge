#!/usr/bin/env python3
"""Write src-tauri/tauri.ci.conf.json (merged with `cargo tauri build --config`) from the
optional CI secrets in the environment. With no secrets the file is `{}` and the build is
unsigned — every signing step is opt-in so forks and PRs still produce installers.

  TAURI_SIGNING_PRIVATE_KEY (+ _PASSWORD)  updater artifacts (.sig) — the CLI reads these itself
  TAURI_UPDATER_PUBKEY                     the matching public key, embedded in the app
  VERSION                                  e.g. 0.2.0 or 0.2.0-alpha from the tag (MSI / Android
                                           get the numeric X.Y.Z part)
  WINDOWS_CERTIFICATE_THUMBPRINT           set by the workflow after importing WINDOWS_CERTIFICATE (pfx)
  AZURE_TRUSTED_SIGNING_ENDPOINT/_ACCOUNT/_PROFILE  Azure Trusted Signing via trusted-signing-cli
                                           (AZURE_CLIENT_ID/_CLIENT_SECRET/_TENANT_ID in env)
  APPLE_SIGNING_IDENTITY, APPLE_CERTIFICATE(+_PASSWORD), APPLE_ID, APPLE_PASSWORD, APPLE_TEAM_ID
                                           read by the Tauri CLI directly (sign + notarize);
                                           without them the .app is ad-hoc signed ("-").
"""
import json
import os
import re
import sys


def env(k):
    v = os.environ.get(k, "").strip()
    return v or None


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "src-tauri", "tauri.ci.conf.json")
    cfg = {}
    win = {}
    v = env("VERSION")
    if v:
        v = v.lstrip("v")
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.]+)?", v)
        if not m:
            print(f"warning: VERSION {v!r} is not X.Y.Z or X.Y.Z-pre; keeping tauri.conf.json's version", file=sys.stderr)
        else:
            cfg["version"] = v
            # MSI and Android take numbers only: 0.2.0-alpha installs as MSI 0.2.0 / versionCode 2000.
            win["wix"] = {"version": "{}.{}.{}".format(*m.groups()[:3])}
            cfg.setdefault("bundle", {})["android"] = {"versionCode": int(m[1]) * 1000000 + int(m[2]) * 1000 + int(m[3])}
    if env("TAURI_SIGNING_PRIVATE_KEY") and env("TAURI_UPDATER_PUBKEY"):
        cfg.setdefault("bundle", {})["createUpdaterArtifacts"] = True
        cfg.setdefault("plugins", {})["updater"] = {"pubkey": env("TAURI_UPDATER_PUBKEY")}
    if env("WINDOWS_CERTIFICATE_THUMBPRINT"):
        win["certificateThumbprint"] = env("WINDOWS_CERTIFICATE_THUMBPRINT")
    elif env("AZURE_TRUSTED_SIGNING_ENDPOINT") and env("AZURE_TRUSTED_SIGNING_ACCOUNT") and env("AZURE_TRUSTED_SIGNING_PROFILE"):
        win["signCommand"] = "trusted-signing-cli -e {} -a {} -c {} -d \"SE Agent\" %1".format(env("AZURE_TRUSTED_SIGNING_ENDPOINT"), env("AZURE_TRUSTED_SIGNING_ACCOUNT"), env("AZURE_TRUSTED_SIGNING_PROFILE"))
    if win:
        cfg.setdefault("bundle", {})["windows"] = win
    with open(out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    shown = json.loads(json.dumps(cfg))
    if "plugins" in shown:
        shown["plugins"]["updater"]["pubkey"] = "<set>"
    print("tauri.ci.conf.json:", json.dumps(shown))
    # RPM forbids '-' in Version: a pre-release goes to Release instead (Fedora's convention,
    # 0.2.0-alpha → Version 0.2.0, Release 0.1.alpha, which sorts before the final 0.2.0-1).
    # Build the rpm with this file in place of tauri.ci.conf.json.
    conf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src-tauri", "tauri.conf.json")
    full = cfg.get("version") or json.load(open(conf, encoding="utf-8"))["version"]
    rpm = json.loads(json.dumps(cfg))
    m = re.fullmatch(r"(\d+\.\d+\.\d+)-([0-9A-Za-z.]+)", full)
    if m:
        rpm["version"] = m[1]
        rpm.setdefault("bundle", {}).setdefault("linux", {})["rpm"] = {"release": "0.1." + m[2]}
    with open(os.path.join(os.path.dirname(out), "tauri.rpm.conf.json"), "w", encoding="utf-8") as f:
        json.dump(rpm, f, indent=2)


if __name__ == "__main__":
    main()
