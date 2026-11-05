#!/usr/bin/env python3
"""Test MCP server (stdlib only). stdio by default; --http PORT for Streamable HTTP.

Flags: --touch FILE    append "started" to FILE on startup (proves lazy start)
       --proto V       answer initialize with protocol version V
       --plugin        advertise seagent hooks (pre_tool) and channel "loop"
       --token T       (http) require "Authorization: Bearer T"
       --stderr        write noise to stderr on startup
       --instructions S
       --ext           extra tools: outputSchema, MCP Apps (ui://), tasks with input_required,
                       URL elicitation (-32042), sampling with tools
       --modern        2026-07-28 stateless server: no initialize, server/discover, per-request
                       _meta, MRTR input_required results (tool "ask")
"""
import json, sys, time, threading, os, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

args = sys.argv[1:]
def flag(name, default=None):
    if name in args:
        i = args.index(name)
        return args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith("--") else True
    return default

PROTO = flag("--proto", "2025-06-18")
PLUGIN = bool(flag("--plugin"))
TOKEN = flag("--token")
if flag("--touch"):
    with open(flag("--touch"), "a") as f:
        f.write("started\n")
if flag("--stderr"):
    sys.stderr.write("fixture: some debug noise on stderr\n"); sys.stderr.flush()

TOOLS = [
    {"name": "echo", "description": "Echo text back.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}, "annotations": {"readOnlyHint": True}},
    {"name": "add", "description": "Add two numbers.", "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}},
    {"name": "slow", "description": "Sleep ms then reply.", "inputSchema": {"type": "object", "properties": {"ms": {"type": "integer"}}}},
    {"name": "crash", "description": "Exit the server process.", "inputSchema": {"type": "object"}},
    {"name": "garbage", "description": "Print a non-JSON line, then reply.", "inputSchema": {"type": "object"}},
    {"name": "big", "description": "Return n bytes.", "inputSchema": {"type": "object", "properties": {"n": {"type": "integer"}}}},
    {"name": "fail", "description": "Always reports an error.", "inputSchema": {"type": "object"}},
    {"name": "secret_echo", "description": "Echo value (tests secret substitution).", "inputSchema": {"type": "object", "properties": {"value": {"type": "string"}}}},
    {"name": "image", "description": "Return an image block.", "inputSchema": {"type": "object"}},
    {"name": "roots", "description": "Ask the client for roots, report the reply.", "inputSchema": {"type": "object"}},
    {"name": "change", "description": "Announce that the tool list changed.", "inputSchema": {"type": "object"}},
]
EXT = bool(flag("--ext"))
MODERN = bool(flag("--modern"))
if EXT:
    TOOLS += [
        {"name": "typed", "description": "Structured result.", "inputSchema": {"type": "object", "properties": {"good": {"type": "boolean"}}},
         "outputSchema": {"type": "object", "properties": {"n": {"type": "integer", "minimum": 0}}, "required": ["n"], "additionalProperties": False}},
        {"name": "app", "description": "Has an MCP App view.", "inputSchema": {"type": "object"}, "_meta": {"ui": {"resourceUri": "ui://fx/app.html"}}, "annotations": {"readOnlyHint": True}},
        {"name": "app_only", "description": "Called by the view only.", "inputSchema": {"type": "object"}, "_meta": {"ui": {"visibility": ["app"]}}, "annotations": {"readOnlyHint": True}},
        {"name": "job", "description": "Long job (task required).", "inputSchema": {"type": "object"}, "execution": {"taskSupport": "required"}},
        {"name": "needs_url", "description": "Needs a browser sign-in first.", "inputSchema": {"type": "object"}},
        {"name": "sample_tools", "description": "Samples with a tool.", "inputSchema": {"type": "object"}},
    ]
if MODERN:
    TOOLS += [{"name": "ask", "description": "MRTR: asks for a name.", "inputSchema": {"type": "object"}}]
APP_HTML = "<!doctype html><html><head><title>fx</title></head><body><script>parent.postMessage({jsonrpc:'2.0',id:1,method:'ui/initialize',params:{}}, '*')</script></body></html>"
TASKS = {}
STATE = {"authorized": False}
RESOURCES = [{"uri": "mem://a", "name": "Alpha"}, {"uri": "mem://b", "name": "Beta"}]
PROMPTS = [{"name": "review", "description": "Review a file", "arguments": [{"name": "file", "required": True}]}]

out_lock = threading.Lock()
def send(msg):
    with out_lock:
        sys.stdout.write(json.dumps(msg) + "\n"); sys.stdout.flush()

def text(t, err=False):
    return {"content": [{"type": "text", "text": t}], "isError": err}

def ask_client(method, params):
    """stdio only: send a server->client request and read lines until its reply."""
    rid = "srv-%s" % uuid.uuid4().hex[:8]
    send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    while True:
        m = json.loads(sys.stdin.readline())
        if m.get("id") == rid: return m.get("result", m.get("error"))

def task_obj(tid):
    t = TASKS[tid]
    return {"taskId": tid, "status": t["status"], "createdAt": "2026-01-01T00:00:00Z", "lastUpdatedAt": "2026-01-01T00:00:00Z", "ttl": 60000, "pollInterval": 50}

def call_tool(name, a, stdio):
    if EXT and name == "typed": return {"content": [{"type": "text", "text": "typed"}], "structuredContent": {"n": 1} if a.get("good") else {"n": "one"}}
    if EXT and name == "app": return text("app result")
    if EXT and name == "app_only": return text("from the view")
    if EXT and name == "needs_url":
        if not STATE["authorized"]:
            STATE["authorized"] = True
            def done():
                time.sleep(0.2); send({"jsonrpc": "2.0", "method": "notifications/elicitation/complete", "params": {"elicitationId": "el-1"}})
            threading.Thread(target=done).start()
            raise UrlNeeded()
        return text("signed in")
    if EXT and name == "sample_tools" and stdio:
        r = ask_client("sampling/createMessage", {"messages": [{"role": "user", "content": {"type": "text", "text": "weather?"}}], "maxTokens": 50,
                                                  "tools": [{"name": "lookup", "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}}}], "toolChoice": {"mode": "auto"}})
        return text("sampled: " + json.dumps(r))
    if MODERN and name == "ask": return None
    if name == "echo": return text(a.get("text", ""))
    if name == "echo": return text(a.get("text", ""))
    if name == "add": return text(str(a.get("a", 0) + a.get("b", 0)))
    if name == "slow": time.sleep(a.get("ms", 100) / 1000); return text("slept")
    if name == "crash":
        sys.stderr.write("fixture: crashing on purpose\n"); sys.stderr.flush(); os._exit(3)
    if name == "garbage":
        if stdio:
            with out_lock: sys.stdout.write("this is not json\n"); sys.stdout.flush()
        return text("after garbage")
    if name == "big": return text("x" * a.get("n", 1000))
    if name == "fail": return text("it failed", True)
    if name == "secret_echo": return text("got:" + a.get("value", ""))
    if name == "image": return {"content": [{"type": "image", "mimeType": "image/png", "data": "iVBORw0KGgo="}]}
    if name == "roots" and stdio:
        send({"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"})
        while True:
            m = json.loads(sys.stdin.readline())
            if m.get("id") == "srv-1": return text("roots reply: " + json.dumps(m.get("result", m.get("error"))))
    if name == "change" and stdio:
        send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}); return text("changed")
    raise KeyError(name)

class UrlNeeded(Exception): pass

def handle(m, stdio=True):
    """Returns a response dict, or None for notifications."""
    mid, method, p = m.get("id"), m.get("method"), m.get("params") or {}
    if mid is None: return None
    def ok(r): return {"jsonrpc": "2.0", "id": mid, "result": r}
    def err(c, msg, data=None):
        e = {"code": c, "message": msg}
        if data is not None: e["data"] = data
        return {"jsonrpc": "2.0", "id": mid, "error": e}
    if MODERN:
        if method == "initialize": return err(-32022, "Unsupported protocol version", {"supported": ["2026-07-28"], "requested": p.get("protocolVersion")})
        meta = p.get("_meta") or {}
        if meta.get("io.modelcontextprotocol/protocolVersion") != "2026-07-28" or "io.modelcontextprotocol/clientCapabilities" not in meta:
            return err(-32602, "missing per-request _meta protocol fields")
        if method == "server/discover":
            return ok({"resultType": "complete", "supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}, "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "fixture", "version": "1"}}, "instructions": "modern fixture"})
        if method == "tools/call" and p.get("name") == "ask":
            got = (p.get("inputResponses") or {}).get("who")
            if got and p.get("requestState") == "st-1":
                return ok({"resultType": "complete", "content": [{"type": "text", "text": "hello " + got.get("content", {}).get("name", "?")}]})
            return ok({"resultType": "input_required", "requestState": "st-1", "inputRequests": {"who": {"method": "elicitation/create", "params": {"mode": "form", "message": "Name?", "requestedSchema": {"type": "object", "properties": {"name": {"type": "string"}}}}}}})
    if EXT and method == "tools/call" and p.get("name") == "job":
        if "task" not in p: return err(-32601, "job must run as a task")
        tid = str(uuid.uuid4()); TASKS[tid] = {"status": "working", "polls": 0}
        return ok({"task": task_obj(tid)})
    if EXT and method in ("tasks/get", "tasks/result", "tasks/cancel"):
        tid = p.get("taskId")
        if tid not in TASKS: return err(-32602, "Failed to retrieve task: Task not found")
        t = TASKS[tid]
        if method == "tasks/get":
            t["polls"] += 1
            if t["status"] == "working" and t["polls"] >= 2: t["status"] = "input_required"
            return ok(task_obj(tid))
        if method == "tasks/cancel":
            if t["status"] in ("completed", "failed", "cancelled"): return err(-32602, "Cannot cancel task: already terminal")
            t["status"] = "cancelled"; return ok(task_obj(tid))
        rel = {"io.modelcontextprotocol/related-task": {"taskId": tid}}
        if t["status"] == "input_required":
            r = ask_client("elicitation/create", {"mode": "form", "message": "Which env?", "requestedSchema": {"type": "object", "properties": {"env": {"type": "string"}}}, "_meta": rel})
            t["status"] = "completed"; t["result"] = text("job ran in " + str((r or {}).get("content", {}).get("env")))
        r = dict(t.get("result") or text("cancelled", True)); r["_meta"] = rel
        return ok(r)
    if EXT and method == "tasks/list": return ok({"tasks": [task_obj(k) for k in TASKS]})
    if method == "initialize":
        caps = {"tools": {"listChanged": True}, "resources": {}, "prompts": {}}
        if EXT: caps["tasks"] = {"list": {}, "cancel": {}, "requests": {"tools": {"call": {}}}}
        if PLUGIN: caps["experimental"] = {"seagent": {"version": 1, "hooks": ["pre_tool"], "channels": ["loop"]}}
        r = {"protocolVersion": PROTO, "capabilities": caps, "serverInfo": {"name": "fixture", "version": "1"}}
        if flag("--instructions"): r["instructions"] = flag("--instructions")
        return ok(r)
    if method == "ping": return ok({})
    if method == "tools/list":
        # Two pages to exercise pagination.
        if p.get("cursor") == "page2": return ok({"tools": TOOLS[5:]})
        return ok({"tools": TOOLS[:5], "nextCursor": "page2"})
    if method == "tools/call":
        try: return ok(call_tool(p.get("name"), p.get("arguments") or {}, stdio))
        except KeyError: return err(-32602, "unknown tool " + str(p.get("name")))
        except UrlNeeded: return err(-32042, "This request requires more information.", {"elicitations": [{"mode": "url", "elicitationId": "el-1", "url": "https://auth.example/sign-in?x=1", "message": "Sign in to the fixture"}]})
    if method == "resources/list": return ok({"resources": RESOURCES})
    if method == "resources/read":
        u = p.get("uri")
        if u == "mem://a": return ok({"contents": [{"uri": u, "text": "alpha body"}]})
        if u == "mem://b": return ok({"contents": [{"uri": u, "blob": "AAAAAAAA", "mimeType": "application/x-bin"}]})
        if EXT and u == "ui://fx/app.html": return ok({"contents": [{"uri": u, "mimeType": "text/html;profile=mcp-app", "text": APP_HTML, "_meta": {"ui": {"csp": {"connectDomains": ["https://api.example"]}, "prefersBorder": False}}}]})
        return err(-32002, "resource not found")
    if method == "prompts/list": return ok({"prompts": PROMPTS})
    if method == "prompts/get":
        f = (p.get("arguments") or {}).get("file", "?")
        return ok({"messages": [{"role": "user", "content": {"type": "text", "text": "Please review " + f}}]})
    if PLUGIN and method == "seagent/hook":
        s = json.dumps(p.get("payload"))
        if "forbidden" in s: return ok({"decision": "deny", "reason": "fixture forbids it"})
        if "hang" in s: time.sleep(2)
        if "rewrite" in s: return ok({"decision": "modify", "input": {"text": "rewritten"}})
        return ok({"decision": "allow"})
    if PLUGIN and method == "seagent/channel.send":
        msg = p.get("message") or {}
        def later():
            time.sleep(0.05)
            send({"jsonrpc": "2.0", "method": "seagent/channel.inbound", "params": {"channel": p.get("channel"), "message": {"chat": msg.get("chat"), "sender": "echo-bot", "text": "echo: " + str(msg.get("text"))}}})
        threading.Thread(target=later).start()
        return ok({"id": "m1"})
    return err(-32601, "method not found: " + str(method))

def stdio_main():
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try: m = json.loads(line)
        except ValueError: continue
        if "method" not in m: continue  # replies to our own requests handled inline
        r = handle(m)
        if r is not None: send(r)

SESSIONS = set()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        if self.path == "/fail500":
            self.send_response(500); self.end_headers(); self.wfile.write(b"boom"); return
        if TOKEN and self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_response(401); self.end_headers(); self.wfile.write(b"no"); return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        sid = self.headers.get("Mcp-Session-Id")
        if body.get("method") != "initialize" and sid not in SESSIONS:
            self.send_response(404 if sid else 400); self.end_headers(); return
        r = handle(body, stdio=False)
        if r is None:
            self.send_response(202); self.end_headers(); return
        self.send_response(200)
        if body.get("method") == "initialize":
            sid = "s-%d" % len(SESSIONS); SESSIONS.add(sid); self.send_header("Mcp-Session-Id", sid)
        if body.get("method") == "tools/call":
            # Reply as SSE with a notification first, like real servers do.
            self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            note = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}
            self.wfile.write(("event: message\ndata: " + json.dumps(note) + "\n\n").encode())
            self.wfile.write(("data: " + json.dumps(r) + "\n\n").encode())
        else:
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(r).encode())

if flag("--http"):
    srv = ThreadingHTTPServer(("127.0.0.1", int(flag("--http"))), H)
    print("ready", flush=True)
    if flag("--expire"):  # drop sessions after N seconds to test re-initialize
        def expire():
            time.sleep(float(flag("--expire"))); SESSIONS.clear()
        threading.Thread(target=expire, daemon=True).start()
    srv.serve_forever()
else:
    stdio_main()
