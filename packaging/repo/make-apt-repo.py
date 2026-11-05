#!/usr/bin/env python3
"""Signed apt repository from .deb files (ent-028). Stdlib + dpkg-deb + gpg; no reprepro/aptly.

  make-apt-repo.py --debs DIR --out REPO --key-id KEYID [--gnupghome DIR] [--passphrase-file F]
                   [--suite stable] [--component main] [--origin seagent]

Layout (a "classic" repository, works with `deb [signed-by=…] URL stable main`):
  REPO/pool/main/a/seagent/<file>.deb
  REPO/dists/<suite>/main/binary-<arch>/Packages{,.gz}
  REPO/dists/<suite>/{Release,Release.gpg,InRelease}
  REPO/seagent-archive-keyring.gpg (binary, for signed-by=) and seagent-archive-keyring.asc
Deterministic given the same inputs and SOURCE_DATE_EPOCH. Never touches the network.
"""
import argparse, gzip, hashlib, os, shutil, subprocess, sys, time


def run(*a, **k):
    return subprocess.run(a, check=True, capture_output=True, text=k.pop("text", True), **k)


def field_block(deb):
    out = run("dpkg-deb", "--field", deb).stdout
    return out.rstrip("\n")


def digests(path):
    h = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for x in h.values():
                x.update(chunk)
    return {n: x.hexdigest() for n, x in h.items()}


def gpg_base(a):
    c = ["gpg", "--batch", "--yes", "--no-tty"]
    if a.gnupghome:
        c += ["--homedir", a.gnupghome]
    if a.passphrase_file:
        c += ["--pinentry-mode", "loopback", "--passphrase-file", a.passphrase_file]
    return c + ["--local-user", a.key_id]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--debs", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--gnupghome")
    p.add_argument("--passphrase-file")
    p.add_argument("--suite", default="stable")
    p.add_argument("--component", default="main")
    p.add_argument("--origin", default="seagent")
    a = p.parse_args()
    debs = sorted(f for f in os.listdir(a.debs) if f.endswith(".deb"))
    if not debs:
        sys.exit("no .deb files in " + a.debs)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    date = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(epoch))
    out = os.path.abspath(a.out)
    shutil.rmtree(os.path.join(out, "dists"), ignore_errors=True)
    pool = os.path.join(out, "pool", a.component, "a", "seagent")
    os.makedirs(pool, exist_ok=True)
    by_arch = {}
    for d in debs:
        dst = os.path.join(pool, d)
        shutil.copyfile(os.path.join(a.debs, d), dst)
        arch = run("dpkg-deb", "--field", dst, "Architecture").stdout.strip()
        dg = digests(dst)
        block = field_block(dst) + "\nFilename: pool/%s/a/seagent/%s\nSize: %d\nMD5sum: %s\nSHA1: %s\nSHA256: %s\n" % (
            a.component, d, os.path.getsize(dst), dg["md5"], dg["sha1"], dg["sha256"])
        by_arch.setdefault(arch, []).append(block)
    dist = os.path.join(out, "dists", a.suite)
    files = []  # (relative path, bytes)
    for arch, blocks in sorted(by_arch.items()):
        text = "\n".join(blocks).encode()
        rel = "%s/binary-%s/Packages" % (a.component, arch)
        os.makedirs(os.path.dirname(os.path.join(dist, rel)), exist_ok=True)
        open(os.path.join(dist, rel), "wb").write(text)
        gz = gzip.compress(text, 9, mtime=0)
        open(os.path.join(dist, rel + ".gz"), "wb").write(gz)
        files += [(rel, text), (rel + ".gz", gz)]
    rel_lines = ["Origin: " + a.origin, "Label: " + a.origin, "Suite: " + a.suite, "Codename: " + a.suite, "Date: " + date,
                 "Architectures: " + " ".join(sorted(by_arch)), "Components: " + a.component,
                 "Description: seagent agent runtime packages"]
    for name, algo in (("MD5Sum", "md5"), ("SHA1", "sha1"), ("SHA256", "sha256")):
        rel_lines.append(name + ":")
        for rel, data in files:
            rel_lines.append(" %s %d %s" % (hashlib.new(algo, data).hexdigest(), len(data), rel))
    release = os.path.join(dist, "Release")
    open(release, "w").write("\n".join(rel_lines) + "\n")
    g = gpg_base(a)
    run(*g, "--clearsign", "--output", os.path.join(dist, "InRelease"), release)
    run(*g, "--armor", "--detach-sign", "--output", os.path.join(dist, "Release.gpg"), release)
    asc = run(*(["gpg"] + (["--homedir", a.gnupghome] if a.gnupghome else []) + ["--batch", "--armor", "--export", a.key_id])).stdout
    open(os.path.join(out, "seagent-archive-keyring.asc"), "w").write(asc)
    gpgbin = run(*(["gpg"] + (["--homedir", a.gnupghome] if a.gnupghome else []) + ["--batch", "--export", a.key_id]), text=False).stdout
    open(os.path.join(out, "seagent-archive-keyring.gpg"), "wb").write(gpgbin)
    print("apt repository: %s  (%d package(s), arch: %s)" % (out, len(debs), ", ".join(sorted(by_arch))))
    print("client: install -m0644 seagent-archive-keyring.gpg /etc/apt/keyrings/ && echo 'deb [signed-by=/etc/apt/keyrings/seagent-archive-keyring.gpg] <URL> %s %s' > /etc/apt/sources.list.d/seagent.list" % (a.suite, a.component))


main()
