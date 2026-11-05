#!/usr/bin/env python3
"""Distro install matrix (ent-009..017): packages -> install -> --version -> doctor -> one offline chat.

  python3 -I packaging/matrix/matrix.py --dist DIST_DIR [--only al2023,rocky9] [--out report.md] [--json out.json]

DIST_DIR needs seagent_*_amd64.deb, seagent-*.x86_64.rpm, seagent-*-x86_64.pkg.tar.zst, seagent_*_x86_64.apk
and seagent-x86_64-unknown-linux-musl.tar.gz. One
container per distro (named seagent-test-pkg-<id>, removed afterwards, also on Ctrl-C), host networking so
the fake model server of tests/e2e/fake_provider.py (this process starts and stops it) is reachable
on 127.0.0.1. No real model, no real network traffic from seagent. Needs podman or docker and python3.
Exit 0 when every distro passed; rows marked "best_effort" (CentOS 7, openSUSE Leap) are reported but never fail the run.
"""
import argparse, json, os, shutil, signal, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
RT = shutil.which("podman") or shutil.which("docker")
LIVE = set()


def rm(name):
    subprocess.run([RT, "rm", "-f", name], capture_output=True)


def cleanup(*_):
    for n in list(LIVE):
        rm(n)
    sys.exit(130)


def post(url, obj):
    urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST")).read()


def run_one(d, dist, base, timeout):
    name = "seagent-test-pkg-" + d["id"]
    rm(name)
    LIVE.add(name)
    post(base + "/__script", [{"text": "pong from the fake model"}])
    port = base.rsplit(":", 1)[1]
    kind = d["kind"]
    cmd = [RT, "run", "--rm", "--name", name, "--network=host", "-e", "PRE=" + d.get("pre", ""),
           "-v", dist + ":/dist:ro", "-v", os.path.join(HERE, "inner.sh") + ":/inner.sh:ro", d["image"], "sh", "/inner.sh", kind, port]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out, rc = p.stdout + p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        out, rc = "TIMEOUT after %ds\n%s" % (timeout, (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")), 124
    finally:
        rm(name)
        LIVE.discard(name)
    steps = {}
    for line in out.splitlines():
        if line.startswith("RESULT "):
            _, step, status, detail = (line.split(" ", 3) + [""])[:4]
            steps[step] = (status, detail)
    return {"id": d["id"], "label": d["label"], "image": d["image"], "kind": kind, "rc": rc, "secs": round(time.time() - t0),
            "steps": steps, "log_tail": "\n".join(out.splitlines()[-12:])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--out")
    ap.add_argument("--json")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    if not RT:
        sys.exit("need podman or docker")
    dist = os.path.abspath(a.dist)
    distros = json.load(open(os.path.join(HERE, "distros.json")))
    if a.only:
        want = set(a.only.split(","))
        distros = [d for d in distros if d["id"] in want]
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    srv = subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "tests/e2e/fake_provider.py"), "0"], stdout=subprocess.PIPE, text=True)
    try:
        port = int(srv.stdout.readline())
        base = "http://127.0.0.1:%d" % port
        results = []
        for d in distros:
            r = run_one(d, dist, base, a.timeout)
            bad = [s for s, (st, _) in r["steps"].items() if st == "fail"]
            r["ok"] = not bad and r["rc"] == 0 and "install" in r["steps"]
            r["best_effort"] = bool(d.get("best_effort"))
            print("%-11s %-5s %4ds  %s" % (d["id"], "PASS" if r["ok"] else ("WARN" if r["best_effort"] else "FAIL"), r["secs"], ("failed: " + ",".join(bad)) if bad else ""), flush=True)
            results.append(r)
    finally:
        srv.terminate()
        srv.wait()
        for n in list(LIVE):
            rm(n)
    cols = ["install", "version", "doctor", "setup", "chat", "unit-degrade", "service"]
    md = ["| 發行版 | 映像 | 安裝 | --version | doctor | setup | 離線對話 | unit | 服務啟動 | 秒 |", "|---|---|---|---|---|---|---|---|---|---|"]
    sym = {"ok": "通過", "fail": "**失敗**", "skip": "略過"}
    for r in results:
        cells = [sym.get(r["steps"].get(c, ("skip", ""))[0], "?") if c in r["steps"] else "—" for c in cols]
        md.append("| %s | `%s` | %s | %d |" % (r["label"], r["image"].split("/", 1)[-1], " | ".join(cells), r["secs"]))
    text = "\n".join(md) + "\n"
    print(text)
    if a.out:
        open(a.out, "w").write(text)
    if a.json:
        json.dump(results, open(a.json, "w"), indent=1, ensure_ascii=False)
    sys.exit(0 if all(r["ok"] or r["best_effort"] for r in results) else 1)


main()
