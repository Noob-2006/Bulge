#!/usr/bin/env python3
"""Fake Telegram Bot API for end-to-end tests (stdlib only).

Usage: fake_telegram.py [port]   → prints "listening <port>" then serves.
  POST /bot<token>/getUpdates   long-poll (honours offset/timeout, max 2s here)
  POST /bot<token>/sendMessage  recorded
  POST /__inject {"chat":1,"sender":2,"text":"hi"[,"name":"amy"]}  queue an update
  GET  /__sent                  JSON list of sendMessage bodies
  POST /__fail {"status":429,"retry_after":1,"count":1}  next N API calls fail
Token "bad" always gets 401.
"""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

lock = threading.Condition()
updates, sent, fail = [], [], {"count": 0}
next_id = [1]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    def do_GET(self):
        if self.path == "/__sent":
            with lock:
                return self.reply(200, sent)
        self.reply(404, {"ok": False})

    def do_POST(self):
        b = self.body()
        if self.path == "/__inject":
            with lock:
                uid = next_id[0]
                next_id[0] += 1
                updates.append({"update_id": uid, "message": {"message_id": uid, "date": int(time.time()), "chat": {"id": b.get("chat", 1)}, "from": {"id": b.get("sender", 1), "username": b.get("name", "tester")}, "text": b.get("text", "")}})
                lock.notify_all()
            return self.reply(200, {"ok": True, "update_id": uid})
        if self.path == "/__fail":
            with lock:
                fail.update(b)
            return self.reply(200, {"ok": True})
        parts = self.path.split("/")
        if len(parts) < 3 or not parts[1].startswith("bot"):
            return self.reply(404, {"ok": False, "description": "Not Found"})
        if parts[1] == "botbad":
            return self.reply(401, {"ok": False, "error_code": 401, "description": "Unauthorized"})
        with lock:
            if fail.get("count", 0) > 0:
                fail["count"] -= 1
                st = fail.get("status", 500)
                return self.reply(st, {"ok": False, "error_code": st, "description": "injected", "parameters": {"retry_after": fail.get("retry_after", 1)}})
        method = parts[2]
        if method == "getUpdates":
            off = int(b.get("offset") or 0)
            deadline = time.time() + min(float(b.get("timeout") or 0), 2.0)
            with lock:
                while True:
                    got = [u for u in updates if u["update_id"] >= off]
                    if got or time.time() >= deadline:
                        return self.reply(200, {"ok": True, "result": got})
                    lock.wait(max(0.01, deadline - time.time()))
        if method == "sendMessage":
            with lock:
                sent.append(b)
            return self.reply(200, {"ok": True, "result": {"message_id": len(sent)}})
        self.reply(404, {"ok": False, "description": "unknown method"})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 0), H)
    print("listening", srv.server_address[1], flush=True)
    srv.serve_forever()
