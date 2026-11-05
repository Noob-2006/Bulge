#!/usr/bin/env python3
"""Test ark plugin (stdlib only) exercising every registration kind (docs/plugins.md):
tools, hooks (every event), middleware, commands, CLI commands, HTTP routes, UI panels,
a model provider, a context engine, a memory provider, node commands and a service.

Flags: --log FILE   append one JSON line per hook event / service call
       --sick FILE  service health reports not-ok while FILE exists
"""
import json, sys, os, base64, re

args = sys.argv[1:]
def flag(name):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else None

LOG, SICK = flag("--log"), flag("--sick")
HOOKS = ["session_start", "session_end", "user_prompt", "pre_tool", "post_tool", "turn_end", "pre_model", "post_model",
         "pre_compact", "post_compact", "message_received", "message_sending", "message_sent", "subagent_start",
         "subagent_stop", "notification", "daemon_start", "daemon_stop", "pre_approval_request", "post_approval_response",
         "on_human_input_request", "on_human_input_resolved", "transform_tool_result", "transform_terminal_output",
         "transform_llm_output", "transform_api_error_classification"]
ARK = {
    "version": 1,
    "hooks": HOOKS,
    "commands": [{"name": "ping", "description": "Answer pong", "args": "[text]"}, {"name": "ask", "description": "Turn args into a prompt"}],
    "routes": [{"path": "/echo", "methods": ["GET", "POST"]}, {"path": "/public", "public": True}],
    "providers": [{"id": "plug", "models": ["parrot"], "context_window": 8000}],
    "services": [{"name": "ticker", "health_secs": 1}],
    "middleware": ["tool_request", "tool_execution", "llm_request", "llm_execution"],
    "cli": [{"name": "kinds-echo", "description": "Echo the arguments", "args": "[words…] [--fail]"}],
    "context_engine": {"owns_compaction": True},
    "memory": True,
    "node_commands": [{"command": "kinds.hello", "description": "Greet someone", "dangerous": False,
                       "params": {"type": "object", "properties": {"name": {"type": "string"}}}},
                      {"command": "kinds.wipe", "description": "Pretend to wipe", "dangerous": True}],
    "ui": [{"id": "dash", "title": "Kinds", "surface": "tab"}, {"id": "prefs", "title": "Kinds settings", "surface": "settings"}],
    "backends": [{"kind": "tts", "id": "kinds-voice", "label": "Kinds Voice", "caps": {"voices": ["v1", "v2"]}},
                 {"kind": "web_search", "id": "kinds-search", "label": "Kinds Search"},
                 {"kind": "bogus", "id": "ignored"}],
    "dashboard_auth": {"id": "kinds-auth", "label": "Kinds Auth"},
}
MEMORY = {"memory": [], "user": []}
PANEL = """<!doctype html><html><head><title>kinds</title></head><body><h1>kinds panel</h1>
<script>parent.postMessage({jsonrpc: "2.0", id: 1, method: "count", params: {}}, "*");</script></body></html>"""

def log(**kv):
    if LOG:
        with open(LOG, "a") as f:
            f.write(json.dumps(kv) + "\n")

def send(m):
    sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()

def last_user_text(req):
    for m in reversed(req.get("messages", [])):
        if m.get("role") == "user":
            for b in m.get("content", []):
                if b.get("type") == "text":
                    return b["text"]
    return ""

def last_user(messages):
    # The user's own words: the kernel appends the turn's prefetched recall as a fenced
    # `<recalled-context>` block to the user message (ark_kernel::lifecycle::fence), so strip
    # those blocks before matching — the same thing ark's own `strip_fences` callers do.
    for m in reversed(messages or []):
        if m.get("role") == "user":
            t = "".join(b.get("text", "") for b in m.get("content", []) if b.get("type") == "text")
            return re.sub(r"\n\n<recalled-context.*?</recalled-context>", "", t, flags=re.S).strip()
    return ""

def middleware(kind, phase, pl):
    log(kind="middleware", mw=kind, phase=phase)
    args = pl.get("args") or {}
    if kind == "tool_request" and args.get("text") == "rewrite me":
        return {"args": dict(args, text="rewritten")}
    if kind == "tool_execution" and phase == "call" and args.get("text") == "cached":
        return {"result": {"content": "FROM CACHE", "is_error": False}}
    if kind == "llm_execution" and phase == "call" and last_user((pl.get("request") or {}).get("messages")) == "short-circuit":
        return {"response": {"text": "answered by middleware"}}
    return {}

def handle(mid, method, p):
    if method == "initialize":
        return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "experimental": {"ark": ARK}}, "serverInfo": {"name": "kinds", "version": "1"}}
    if method == "ping": return {}
    if method == "tools/list":
        return {"tools": [{"name": "shout", "description": "Upper-case text.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
    if method == "tools/call":
        return {"content": [{"type": "text", "text": str((p.get("arguments") or {}).get("text", "")).upper()}]}
    if method == "ark/hook":
        ev, pl = p.get("event"), p.get("payload") or {}
        log(kind="hook", event=ev, payload=pl)
        if ev == "message_received" and pl.get("input") == "blocked words":
            return {"decision": "deny", "reason": "kinds plugin drops it"}
        if ev == "message_sending" and isinstance(pl.get("input"), str):
            return {"decision": "modify", "input": pl["input"] + " [via plugin]"}
        if ev == "transform_tool_result" and str(pl.get("tool_name", "")).endswith("shout"):
            return {"decision": "modify", "input": pl.get("input", "") + " [transformed]"}
        if ev == "transform_llm_output" and "TRANSFORM-ME" in str(pl.get("input")):
            return {"decision": "modify", "input": "transformed by plugin"}
        return {"decision": "allow"}
    if method == "ark/command":
        if p.get("name") == "ping":
            return {"text": "pong " + p.get("args", "") + " from " + str((p.get("context") or {}).get("surface"))}
        return {"prompt": "Please answer: " + p.get("args", "")}
    if method == "ark/http":
        body = p.get("body")
        if body is None and p.get("body_base64"): body = base64.b64decode(p["body_base64"]).decode("latin-1")
        out = {"method": p.get("method"), "path": p.get("path"), "query": p.get("query"), "body": body, "has_auth": "authorization" in (p.get("headers") or {})}
        return {"status": 201, "headers": {"content-type": "application/json", "x-plugin": "kinds"}, "body": json.dumps(out)}
    if method == "ark/provider.complete":
        req = p.get("request") or {}
        words = ("parrot says: " + last_user_text(req)).split(" ")
        for i, w in enumerate(words):
            send({"jsonrpc": "2.0", "method": "ark/provider.delta", "params": {"stream_id": p.get("stream_id"), "text": w if i == 0 else " " + w}})
        text = " ".join(words)
        return {"message": {"role": "assistant", "content": [{"type": "text", "text": text}]}, "stop": "end_turn",
                "usage": {"input_tokens": 3, "output_tokens": len(words)}, "model": "plug/" + req.get("model", "")}
    if method == "ark/backend.call":
        kind, bid, op, params = p.get("kind"), p.get("id"), p.get("op"), (p.get("params") or {})
        log(kind="backend", bkind=kind, backend=bid, op=op, params=params)
        if bid == "kinds-voice" and op == "synthesize":
            if params.get("text") == "fail":
                return {"error": "kinds tts failed"}
            return {"audio_base64": base64.b64encode(b"ID3" + (params.get("text") or "").encode()).decode(),
                    "mime": "audio/mpeg", "sample_rate": 24000}
        if bid == "kinds-search" and op == "search":
            return {"results": [{"title": "kinds result", "url": "https://example.test/kinds", "snippet": params.get("query", "")}],
                    "answer": "kinds answer"}
        return {"error": "unsupported " + str(kind) + "/" + str(op)}
    if method == "ark/auth.login_start":
        q = p.get("params") or {}
        log(kind="auth", op="login_start", provider=p.get("id"), redirect_uri=q.get("redirect_uri"))
        return {"url": "https://idp.example.test/authorize?client_id=kinds&state=kinds-state", "state": "kinds-state"}
    if method in ("ark/auth.exchange", "ark/auth.verify"):
        q = p.get("params") or {}
        op = method.split(".", 1)[1]
        log(kind="auth", op=op, provider=p.get("id"))
        if op == "exchange" and q.get("state") != "kinds-state":
            return {"error": "bad state"}
        token = q.get("code") if op == "exchange" else q.get("token")
        if token != "good":
            return {"error": "invalid credentials"}
        return {"subject": "kinds-user", "email": "u@example.test", "name": "Kinds User",
                "expires_at": 1800000000, "admin": False}
    if method == "ark/auth.refresh":
        return {"error": "kinds auth cannot refresh"}
    if method == "ark/middleware":
        return middleware(p.get("kind"), p.get("phase"), p.get("payload") or {})
    if method == "ark/cli":
        argv = p.get("argv") or []
        send({"jsonrpc": "2.0", "method": "ark/cli.output", "params": {"run_id": p.get("run_id"), "stream": "stdout", "text": "streamed\n"}})
        log(kind="cli", argv=argv)
        return {"stdout": "argv=" + json.dumps(argv) + "\n", "stderr": "", "exit": 3 if "--fail" in argv else 0}
    if method == "ark/context.assemble":
        log(kind="assemble", session=p.get("session"), bootstrap=p.get("bootstrap"), n=len(p.get("messages") or []))
        if "ENGINE" in (p.get("prompt") or ""):
            msgs = p.get("messages") or []
            return {"messages": msgs[-1:], "system_prompt_addition": "engine was here"}
        return {}
    if method == "ark/context.compact":
        log(kind="compact", session=p.get("session"), n=len(p.get("messages") or []))
        return {"compacted": True, "summary": "engine summary", "keep_messages": 2}
    if method == "ark/memory.prompt":
        return {"text": "Memory provider: kinds"}
    if method == "ark/memory.call":
        f, a = MEMORY.setdefault(p.get("file", "memory"), []), p.get("action")
        log(kind="memory", action=a)
        if a == "add":
            f.append(p.get("text", "")); return {"text": "added (%d entries)" % len(f)}
        if a == "search":
            q = (p.get("query") or "").lower(); return {"text": "\n".join(e for e in f if q in e.lower()) or "(no match)"}
        if a == "read":
            return {"text": "\n".join(f) or "(no entries)"}
        return {"error": "kinds memory does not support " + str(a)}
    if method == "ark/node.invoke":
        if p.get("command") == "kinds.hello":
            return {"greeting": "hello " + str((p.get("params") or {}).get("name", "you"))}
        return {"error": "nope"}
    if method == "ark/ui.render":
        return {"html": PANEL, "csp": {}} if p.get("id") in ("dash", "prefs") else {"error": "no panel"}
    if method == "ark/ui.call":
        return {"count": 42, "method": p.get("method"), "panel": p.get("id")}
    if method.startswith("ark/service."):
        action = method.split(".", 1)[1]
        log(kind="service", action=action, name=p.get("name"))
        if action == "health":
            sick = SICK and os.path.exists(SICK)
            return {"ok": not sick, "detail": "sick" if sick else "fine"}
        return {"ok": True}
    raise KeyError(method)

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: m = json.loads(line)
    except ValueError: continue
    if "method" not in m: continue
    if m.get("id") is None:
        if m["method"] == "ark/context.ingest":
            log(kind="ingest", session=(m.get("params") or {}).get("session"), role=((m.get("params") or {}).get("message") or {}).get("role"))
        continue
    try: send({"jsonrpc": "2.0", "id": m["id"], "result": handle(m["id"], m["method"], m.get("params") or {})})
    except KeyError as e: send({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "method not found: " + str(e)}})
