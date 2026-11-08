#!/usr/bin/env python3
"""Write src-tauri/tauri.ci.conf.json (merged with `cargo tauri build --config`) from the
optional CI secrets in the environment. With no secrets the file is `{}` and the build is
unsigned — every signing step is opt-in so forks and PRs still produce installers.

  TAURI_SIGNING_PRIVATE_KEY (+ _PASSWORD)  updater artifacts (.sig) — the CLI reads these itself
  TAURI_UPDATER_PUBKEY                     the matching public key, embedded in the app
  VERSION                                  e.g. 0.2.0 from the tag (MSI needs plain X.Y.Z)
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
    v = env("VERSION")
    if v:
        v = v.lstrip("v")
        if not re.fullmatch(r"\d+\.\d+\.\d+", v):
            print(f"warning: VERSION {v!r} is not X.Y.Z; keeping tauri.conf.json's version", file=sys.stderr)
        else:
            cfg["version"] = v
    if env("TAURI_SIGNING_PRIVATE_KEY") and env("TAURI_UPDATER_PUBKEY"):
        cfg.setdefault("bundle", {})["createUpdaterArtifacts"] = True
        cfg.setdefault("plugins", {})["updater"] = {"pubkey": env("TAURI_UPDATER_PUBKEY")}
    win = {}
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


if __name__ == "__main__":
    main()
