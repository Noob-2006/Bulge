#!/usr/bin/env python3
"""Fail when a git-tracked file contains something that looks like a real credential.

Usage: python3 -I tools/secret-scan.py [--root DIR] [--all-history]  (CI: .github/workflows/ci.yml)

* Scans `git ls-files` (text files under 2 MiB), or with --all-history every blob reachable from
  HEAD, so a key that was committed and "removed" still fails.
* Patterns are well-known token shapes (private key blocks, cloud and VCS tokens, provider API
  keys, JWTs). Entropy guessing is deliberately left out: it flags test fixtures all day.
* Placeholders are fine: a match is ignored when the surrounding text says it is fake
  (`example`, `dummy`, `fake`, `test`, `xxxx`, `…`), when the exact fingerprint is listed in
  `tools/secret-scan.allow`, or when the file is (`path:crates/x/src/y.rs  # reason`: redaction
  tests that must contain key-shaped strings). One entry per line, reason after `#`.
* Prints file:line and a redacted prefix, never the secret itself.
"""
import hashlib, os, re, subprocess, sys

PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-live-key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}\b")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
]
FAKE = re.compile(r"example|dummy|fake|test|sample|placeholder|xxxx|\.\.\.|…|redact|your[-_ ]|<[a-z_ -]+>|0{8}|1234", re.I)
MAX = 2 << 20


def git(root, *args, text=True):
    return subprocess.run(["git", "-C", root, *args], check=True, capture_output=True, text=text).stdout


def load_allow(root):
    p = os.path.join(root, "tools", "secret-scan.allow")
    out = set()
    if os.path.isfile(p):
        for line in open(p, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(line)
    return out


def fingerprint(s):
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def scan_text(name, text, allow):
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for kind, rx in PATTERNS:
            for m in rx.finditer(line):
                tok = m.group(0)
                ctx = line[max(0, m.start() - 40): m.end() + 40]
                if kind != "private-key" and FAKE.search(ctx):
                    continue
                if fingerprint(tok) in allow or f"path:{name}" in allow:
                    continue
                hits.append((name, n, kind, tok[:6] + "…", fingerprint(tok)))
    return hits


def main(argv):
    root = "."
    history = False
    it = iter(argv)
    for a in it:
        if a == "--root":
            root = next(it)
        elif a == "--all-history":
            history = True
        else:
            print(__doc__)
            return 2
    allow = load_allow(root)
    hits = []
    if history:
        seen = set()
        for line in git(root, "rev-list", "--objects", "HEAD").splitlines():
            sha, _, name = line.partition(" ")
            if not name or sha in seen:
                continue
            seen.add(sha)
            data = subprocess.run(["git", "-C", root, "cat-file", "blob", sha], capture_output=True).stdout
            if len(data) <= MAX and b"\0" not in data[:4096]:
                hits += scan_text(name, data.decode("utf-8", "replace"), allow)
    else:
        for name in git(root, "ls-files", "-z").split("\0"):
            if not name or name == "tools/secret-scan.py":
                continue
            p = os.path.join(root, name)
            try:
                if not os.path.isfile(p) or os.path.getsize(p) > MAX:
                    continue
                data = open(p, "rb").read()
            except OSError:
                continue
            if b"\0" in data[:4096]:
                continue
            hits += scan_text(name, data.decode("utf-8", "replace"), allow)
    for name, n, kind, red, fp in hits:
        print(f"{name}:{n}: possible {kind} ({red}) fingerprint {fp}")
    if hits:
        print(f"secret-scan: {len(hits)} finding(s). Remove the secret and rotate it; if it is a fixture, add its fingerprint to tools/secret-scan.allow.", file=sys.stderr)
        return 1
    print("secret-scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
