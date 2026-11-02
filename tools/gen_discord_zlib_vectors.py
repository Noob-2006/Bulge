#!/usr/bin/env python3
"""Regenerate crates/ark-channel/src/testdata/zlib/discord-stream.json.

Each stream is one zlib context flushed with Z_SYNC_FLUSH per message, the way
Discord's `compress=zlib-stream` gateway transport sends it. `frames` lists the
WebSocket frames (a message may be split over several); `messages` the text the
decoder must produce, one per completed 00 00 FF FF suffix."""
import base64, json, random, sys, zlib

rnd = random.Random(7914)


def stream(msgs, split=(), **kw):
    c = zlib.compressobj(**kw)
    frames = []
    for i, m in enumerate(msgs):
        b = c.compress(m.encode()) + c.flush(zlib.Z_SYNC_FLUSH)
        assert b.endswith(b"\x00\x00\xff\xff")
        if i in split:
            k = len(b) // 2
            frames += [b[:k], b[k:]]
        else:
            frames.append(b)
    return {"frames": [base64.b64encode(f).decode() for f in frames], "messages": msgs}


def j(v):
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


guild = j({"op": 0, "s": 2, "t": "GUILD_CREATE", "d": {"id": "G", "channels": [{"id": str(10**17 + i), "type": i % 6, "name": f"channel-{i}-{rnd.randrange(10**6)}"} for i in range(700)]}})
noise = base64.b64encode(rnd.randbytes(2000)).decode()
msgs = [
    j({"op": 10, "d": {"heartbeat_interval": 41250}, "s": None, "t": None}),
    j({"op": 11}),
    guild,
    guild,  # identical: almost all back-references into the previous frame's window
    j({"op": 0, "s": 3, "t": "MESSAGE_CREATE", "d": {"content": "中文 émoji 🎉 " + noise}}),
    j({"op": 11}),
]
out = {
    "default": stream(msgs, split={2, 4}),
    "stored": stream(msgs[:2] + msgs[4:5], level=0),
    "fixed": stream(msgs, strategy=zlib.Z_FIXED),
    "gateway": stream([
        j({"op": 10, "d": {"heartbeat_interval": 45000}, "s": None, "t": None}),
        j({"op": 0, "s": 1, "t": "READY", "d": {"v": 10, "session_id": "S1", "resume_gateway_url": "ws://unused", "user": {"id": "B", "username": "ark", "bot": True}, "application": {"id": "APP"}, "guilds": []}}),
        j({"op": 0, "s": 2, "t": "MESSAGE_CREATE", "d": {"id": "10", "type": 0, "channel_id": "D1", "author": {"id": "U1", "username": "amy"}, "content": "compressed hello", "mentions": [], "attachments": []}}),
        j({"op": 11}),
    ], split={2}),
}
json.dump(out, open(sys.argv[1], "w"), indent=0)
