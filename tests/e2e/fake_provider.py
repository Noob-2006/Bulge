"""Scripted fake LLM provider speaking OpenAI Chat Completions and Anthropic
Messages (streaming SSE). POST /__script with a JSON list to queue replies;
GET /__requests returns what was received; GET /api.json is the models.dev-shaped
metadata for the models below (ark takes context window and capabilities — image
input included — from models.dev, not from /v1/models).

Reply items:
  {"text": "..."}                         assistant text
  {"tool": "name", "args": {...}}         one tool call
  {"tools": [{"tool":..., "args":...}]}   several tool calls in one message
  {"status": 500, "body": "..."}          HTTP error
  {"sleep": 2.0, ...}                     delay before replying
  {"hang": true}                          send headers + one chunk, then stall
"""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
QUEUE = []
SEEN = []
N = [0]

# What this fake advertises for its models, in models.dev's `api.json` shape (the metadata ark
# actually resolves capabilities from). `fake-model` accepts image input, so the send path must
# forward images to it instead of substituting text (`crates/ark-kernel/src/imgprep.rs`).
MODELS_DEV = {
    "fake": {
        "id": "fake",
        "name": "Fake",
        "models": {
            "fake-model": {
                "id": "fake-model",
                "name": "Fake Model",
                "attachment": True,
                "modalities": {"input": ["text", "image"], "output": ["text"]},
                "limit": {"context": 32768, "output": 4096},
                "tool_call": True,
            }
        },
    },
    "fakeanth": {
        "id": "fakeanth",
        "name": "Fake Anthropic",
        "models": {
            "fake-claude": {
                "id": "fake-claude",
                "name": "Fake Claude",
                "attachment": True,
                "modalities": {"input": ["text", "image"], "output": ["text"]},
                "limit": {"context": 200000, "output": 64000},
                "tool_call": True,
            }
        },
    },
}


def next_item():
    with LOCK:
        return QUEUE.pop(0) if QUEUE else {"text": "(fake: script empty)"}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def body(self):
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n)

    def send_json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/__requests":
            with LOCK:
                self.send_json(200, SEEN)
        elif self.path == "/api.json":
            self.send_json(200, MODELS_DEV)
        elif self.path.endswith("/models"):
            if self.headers.get("authorization") == "Bearer bad-key":
                self.send_json(401, {"error": {"message": "invalid api key", "type": "authentication_error"}})
            else:
                self.send_json(200, {"data": [{"id": "fake-model"}, {"id": "fake-embedding"}]})
        else:
            self.send_json(404, {"error": "nope"})

    def do_POST(self):
        raw = self.body()
        if self.path == "/__script":
            with LOCK:
                QUEUE.clear()
                QUEUE.extend(json.loads(raw))
                SEEN.clear()
            return self.send_json(200, {"ok": True})
        try:
            req = json.loads(raw)
        except Exception:
            return self.send_json(400, {"error": {"message": "bad json"}})
        with LOCK:
            SEEN.append({"path": self.path, "body": req, "auth": self.headers.get("authorization") or self.headers.get("x-api-key")})
        item = next_item()
        if "sleep" in item:
            time.sleep(item["sleep"])
        if "status" in item:
            return self.send_json(item["status"], {"error": {"message": item.get("body", "error"), "type": "error"}})
        anthropic = self.path.endswith("/messages")
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        try:
            if anthropic:
                self.anthropic(item)
            else:
                self.openai(item)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def emit(self, data, event=None):
        s = (f"event: {event}\n" if event else "") + f"data: {data if isinstance(data, str) else json.dumps(data)}\n\n"
        self.wfile.write(s.encode())
        self.wfile.flush()

    def calls(self, item):
        if "tool" in item:
            return [{"tool": item["tool"], "args": item.get("args", {})}]
        return item.get("tools", [])

    def openai(self, item):
        base = {"id": "c1", "object": "chat.completion.chunk", "model": "fake-model"}
        if item.get("hang"):
            self.emit({**base, "choices": [{"index": 0, "delta": {"content": "par"}}]})
            time.sleep(3600)
        calls = self.calls(item)
        if calls:
            for i, c in enumerate(calls):
                N[0] += 1
                self.emit({**base, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": i, "id": f"call_{N[0]}", "type": "function", "function": {"name": c["tool"], "arguments": json.dumps(c["args"])}}]}}]})
            finish = "tool_calls"
        else:
            text = item.get("text", "")
            for chunk in [text[i:i + 7] for i in range(0, len(text), 7)] or [""]:
                self.emit({**base, "choices": [{"index": 0, "delta": {"content": chunk}}]})
            finish = item.get("finish", "stop")
        self.emit({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]})
        self.emit({**base, "choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}})
        self.emit("[DONE]")

    def anthropic(self, item):
        self.emit({"type": "message_start", "message": {"id": "m1", "model": "fake-claude", "usage": {"input_tokens": 100, "output_tokens": 0}}}, "message_start")
        calls = self.calls(item)
        idx = 0
        if calls:
            for c in calls:
                N[0] += 1
                self.emit({"type": "content_block_start", "index": idx, "content_block": {"type": "tool_use", "id": f"toolu_{N[0]}", "name": c["tool"], "input": {}}}, "content_block_start")
                self.emit({"type": "content_block_delta", "index": idx, "delta": {"type": "input_json_delta", "partial_json": json.dumps(c["args"])}}, "content_block_delta")
                self.emit({"type": "content_block_stop", "index": idx}, "content_block_stop")
                idx += 1
            stop = "tool_use"
        else:
            self.emit({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}, "content_block_start")
            self.emit({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": item.get("text", "")}}, "content_block_delta")
            self.emit({"type": "content_block_stop", "index": 0}, "content_block_stop")
            stop = "end_turn"
        self.emit({"type": "message_delta", "delta": {"stop_reason": stop}, "usage": {"output_tokens": 20}}, "message_delta")
        self.emit({"type": "message_stop"}, "message_stop")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 0), H)
    srv.daemon_threads = True
    print(srv.server_address[1], flush=True)
    srv.serve_forever()
