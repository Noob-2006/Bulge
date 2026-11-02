"""A scripted ACP agent for tests of ark's ACP client (stdio NDJSON JSON-RPC).

Prompt text decides what it does:
  read:<path>              fs/read_text_file (line 2, limit 1) and echo the content
  write:<path>:<text>      session/request_permission (edit), then fs/write_text_file
  run:<command line>       terminal/create → wait_for_exit → output → release
  slow                     wait until session/cancel, then stop with "cancelled"
  anything else            "echo: <text>" plus a plan
"""
import json, sys, threading, itertools

lock = threading.Lock()
pending = {}
ids = itertools.count(1)
cancelled = threading.Event()
caps = {}


def send(o):
    with lock:
        sys.stdout.write(json.dumps(o) + "\n")
        sys.stdout.flush()


def request(method, params):
    i = next(ids)
    ev = threading.Event()
    pending[i] = [ev, None]
    send({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
    ev.wait(60)
    return pending.pop(i)[1] or {"error": {"message": "timeout"}}


def update(sid, u):
    send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": u}})


def say(sid, text):
    update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text}})


def err(r):
    return r.get("error", {}).get("message") if "error" in r else None


def prompt(mid, p):
    sid = p["sessionId"]
    text = "".join(b.get("text", "") for b in p["prompt"] if b.get("type") == "text")
    stop = "end_turn"
    if text.startswith("read:"):
        path = text[5:]
        update(sid, {"sessionUpdate": "tool_call", "toolCallId": "t1", "title": "Read " + path, "kind": "read", "status": "in_progress", "locations": [{"path": path}]})
        r = request("fs/read_text_file", {"sessionId": sid, "path": path, "line": 2, "limit": 1})
        update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "failed" if err(r) else "completed"})
        say(sid, "error: " + err(r) if err(r) else "content: " + r["result"]["content"])
    elif text.startswith("write:"):
        path, _, body = text[6:].rpartition(":")
        update(sid, {"sessionUpdate": "tool_call", "toolCallId": "t2", "title": "Write " + path, "kind": "edit", "status": "pending"})
        r = request("session/request_permission", {"sessionId": sid, "toolCall": {"toolCallId": "t2", "title": "Write " + path, "kind": "edit"},
                                                    "options": [{"optionId": "yes", "name": "Allow", "kind": "allow_once"}, {"optionId": "no", "name": "Reject", "kind": "reject_once"}]})
        out = r.get("result", {}).get("outcome", {})
        if out.get("outcome") != "selected" or out.get("optionId") != "yes":
            say(sid, "permission rejected")
        else:
            w = request("fs/write_text_file", {"sessionId": sid, "path": path, "content": body})
            say(sid, "error: " + err(w) if err(w) else "wrote " + path)
    elif text.startswith("run:"):
        r = request("terminal/create", {"sessionId": sid, "command": text[4:], "outputByteLimit": 4096})
        if err(r):
            say(sid, "error: " + err(r))
        else:
            tid = r["result"]["terminalId"]
            w = request("terminal/wait_for_exit", {"sessionId": sid, "terminalId": tid})
            o = request("terminal/output", {"sessionId": sid, "terminalId": tid})
            request("terminal/release", {"sessionId": sid, "terminalId": tid})
            say(sid, "output: %s exit %s" % (o["result"]["output"].strip(), w["result"]["exitCode"]))
    elif text == "slow":
        cancelled.clear()
        say(sid, "working…")
        cancelled.wait(30)
        stop = "cancelled"
    else:
        update(sid, {"sessionUpdate": "plan", "entries": [{"content": "answer", "priority": "high", "status": "completed"}]})
        say(sid, "echo: " + text)
    send({"jsonrpc": "2.0", "id": mid, "result": {"stopReason": stop}})


for line in sys.stdin:
    if not line.strip():
        continue
    m = json.loads(line)
    method, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if method is None:
        if mid in pending:
            pending[mid][1] = m
            pending[mid][0].set()
        continue
    if method == "initialize":
        caps = p.get("clientCapabilities", {})
        send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": 1, "agentCapabilities": {"loadSession": True, "sessionCapabilities": {"close": {}}}, "agentInfo": {"name": "fake-acp", "version": "0.1"}, "authMethods": []}})
    elif method == "session/new":
        send({"jsonrpc": "2.0", "id": mid, "result": {"sessionId": "fake-session-1"}})
    elif method == "session/load":
        update(p["sessionId"], {"sessionUpdate": "user_message_chunk", "content": {"type": "text", "text": "old"}})
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "session/prompt":
        threading.Thread(target=prompt, args=(mid, p), daemon=True).start()
    elif method == "session/cancel":
        cancelled.set()
    elif method == "session/close":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no " + method}})
