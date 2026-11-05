#!/usr/bin/env python3
"""Test seagent plugin for stream hooks (stdlib only).

Declares the four stream observers plus an inline `stream_delta` hook:
  * `seagent/stream` notifications are appended to --log as one JSON line each;
  * `seagent/hook` on `stream_delta` rewrites any delta containing `SECRET` to `<redacted>`
    (tests the synchronous, fail-open rewrite path);
  * `seagent/hook` on `stream_delta` blocks for --slow seconds when the delta is `SLOW`
    (tests that a slow hook cannot hang the reply).
"""
import json, sys, time

args = sys.argv[1:]
def flag(name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default

LOG = flag("--log")
SLOW = float(flag("--slow", "0"))

SEAGENT = {
    "version": 1,
    "hooks": ["stream_delta"],
    "stream_hooks": ["on_stream_start", "on_stream_delta", "on_stream_end", "on_tool_event"],
}

def log(rec):
    if LOG:
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")

def send(m):
    sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()

def handle(method, p):
    if method == "initialize":
        return {"protocolVersion": "2025-06-18", "capabilities": {"experimental": {"seagent": SEAGENT}}, "serverInfo": {"name": "streamtap", "version": "1"}}
    if method == "ping":
        return {}
    if method == "seagent/hook":
        ev, pl = p.get("event"), p.get("payload") or {}
        text = pl.get("input")
        log({"t": "hook", "event": ev, "input": text})
        if ev == "stream_delta" and isinstance(text, str):
            if text == "SLOW":
                time.sleep(SLOW)
                return {"decision": "allow"}
            if "SECRET" in text:
                return {"decision": "modify", "input": text.replace("SECRET", "<redacted>")}
        return {"decision": "allow"}
    raise KeyError(method)

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: m = json.loads(line)
    except ValueError: continue
    if "method" not in m: continue
    if m.get("id") is None:
        if m["method"] == "seagent/stream":
            body = dict(m.get("params") or {})
            body.pop("plugin", None)
            rec = {"t": "stream"}
            rec.update(body)
            log(rec)
        continue
    try: send({"jsonrpc": "2.0", "id": m["id"], "result": handle(m["method"], m.get("params") or {})})
    except KeyError as e: send({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "method not found: " + str(e)}})
