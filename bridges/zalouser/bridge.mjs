#!/usr/bin/env node
// seagent zalouser bridge: a Zalo personal-account session (zca-js) behind a small
// bearer-protected loopback HTTP API. See README.md for the protocol.
// The zca-js call shapes follow OpenClaw's extensions/zalouser (MIT).

import { createRequire } from "node:module";
import { createServer } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { promises as fsp, mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync, unlinkSync } from "node:fs";
import path from "node:path";

const TOKEN = process.env.ZALOUSER_BRIDGE_TOKEN || "";
const HOST = process.env.ZALOUSER_BRIDGE_HOST || "127.0.0.1";
const PORT = Number(process.env.ZALOUSER_BRIDGE_PORT || 3920);
const DATA_DIR = process.env.ZALOUSER_DATA_DIR || path.join(process.cwd(), "zalouser-data");
const PROFILE = (process.env.ZALOUSER_PROFILE || "default").replace(/[^A-Za-z0-9_.-]/g, "_");
const MAX_EVENTS = 1000;
const MAX_RECENT = 500;
const MAX_MEDIA = 50 * 1024 * 1024;
const ThreadType = { User: 0, Group: 1 };
const GROUP_INFO_CHUNK_SIZE = 80;

if (TOKEN.length < 16) {
  console.error("ZALOUSER_BRIDGE_TOKEN must be set (16+ chars)");
  process.exit(2);
}

// CommonJS export of zca-js (its ESM entry still imports a removed tough-cookie default).
const require = createRequire(import.meta.url);
const { Zalo } = require("zca-js");

mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
const credPath = path.join(DATA_DIR, `${PROFILE}.credentials.json`);

const EPOCH = randomBytes(8).toString("hex");
let seq = 0;
const events = []; // ring buffer of {seq, kind, type, threadId, isSelf, data}
const recent = new Map(); // msgId → raw zca message (for quotes)
const waiters = new Set();
let api = null;
let ownId = "";
let status = "starting"; // starting | qr_pending | logged_in | reconnecting | logged_out
let qrImage = null;
let reconnectDelay = 1000;

function log(...a) {
  console.error("[zalouser-bridge]", ...a);
}

function loadCreds() {
  try {
    return JSON.parse(readFileSync(credPath, "utf8"));
  } catch {
    return null;
  }
}

function saveCreds(c) {
  const tmp = `${credPath}.tmp${process.pid}`;
  writeFileSync(tmp, JSON.stringify(c), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, credPath);
}

function snapshot(a, prev) {
  try {
    const ctx = a.getContext();
    return { imei: ctx.imei, userAgent: ctx.userAgent, language: ctx.language ?? prev?.language, cookie: a.getCookie().toJSON().cookies };
  } catch {
    return prev;
  }
}

function push(ev) {
  ev.seq = ++seq;
  events.push(ev);
  while (events.length > MAX_EVENTS) events.shift();
  for (const w of waiters) w();
}

function remember(m) {
  const id = m?.data?.msgId;
  if (!id) return;
  recent.set(String(id), m);
  while (recent.size > MAX_RECENT) recent.delete(recent.keys().next().value);
}

function onMessage(m) {
  remember(m);
  if (m.isSelf) return;
  push({ kind: "message", type: m.type, threadId: String(m.threadId ?? ""), isSelf: false, data: m.data });
}

function attachListener(a) {
  a.listener.on("message", onMessage);
  a.listener.on("connected", () => {
    status = "logged_in";
    reconnectDelay = 1000;
    log("listener connected");
  });
  a.listener.on("error", (e) => log("listener error:", String(e?.message ?? e)));
  a.listener.on("closed", (code, reason) => {
    log(`listener closed (${code}) ${reason || ""}`);
    api = null;
    status = "reconnecting";
    setTimeout(start, reconnectDelay).unref();
    reconnectDelay = Math.min(reconnectDelay * 2, 60_000);
  });
  a.listener.start({ retryOnClose: false });
}

async function loginQr(zalo) {
  status = "qr_pending";
  return zalo.loginQR({ qrPath: path.join(DATA_DIR, `${PROFILE}.qr.png`) }, (ev) => {
    switch (ev.type) {
      case 0: // QRCodeGenerated
        qrImage = ev.data.image.startsWith("data:") ? ev.data.image : `data:image/png;base64,${ev.data.image}`;
        log(`QR ready: GET http://${HOST}:${PORT}/qr`);
        break;
      case 1: // QRCodeExpired
        ev.actions?.retry();
        break;
      case 2: // QRCodeScanned
        log(`QR scanned by ${ev.data?.display_name ?? "?"}; confirm on the phone`);
        break;
      case 3: // QRCodeDeclined
        status = "logged_out";
        qrImage = null;
        break;
      case 4: // GotLoginInfo
        saveCreds({ imei: ev.data.imei, cookie: ev.data.cookie, userAgent: ev.data.userAgent });
        qrImage = null;
        break;
    }
  });
}

async function start() {
  if (api) return;
  // selfListen: our own sends come back with their cliMsgId, which `undo` needs.
  // onMessage remembers them but never queues them as events.
  const zalo = new Zalo({ logging: false, selfListen: true });
  const creds = loadCreds();
  try {
    let a;
    if (creds) {
      try {
        a = await zalo.login(creds);
      } catch (e) {
        log("saved session rejected, starting QR login:", String(e?.message ?? e));
        a = await loginQr(zalo);
      }
    } else {
      a = await loginQr(zalo);
    }
    const snap = snapshot(a, loadCreds());
    if (snap) saveCreds(snap);
    api = a;
    ownId = String(a.getOwnId() ?? "");
    status = "logged_in";
    attachListener(a);
  } catch (e) {
    log("login failed:", String(e?.message ?? e));
    status = status === "logged_out" ? "logged_out" : "reconnecting";
    if (status !== "logged_out") {
      setTimeout(start, reconnectDelay).unref();
      reconnectDelay = Math.min(reconnectDelay * 2, 60_000);
    }
  }
}

function authorized(req) {
  const h = String(req.headers.authorization || "");
  const got = Buffer.from(h.startsWith("Bearer ") ? h.slice(7).trim() : "");
  const want = Buffer.from(TOKEN);
  return got.length === want.length && timingSafeEqual(got, want);
}

function send(res, code, body) {
  const b = JSON.stringify(body);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) });
  res.end(b);
}

async function readJson(req) {
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > 1024 * 1024) throw Object.assign(new Error("body too large"), { status: 413 });
    chunks.push(c);
  }
  try {
    return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
  } catch {
    throw Object.assign(new Error("bad json"), { status: 400 });
  }
}

function need(a, ...keys) {
  for (const k of keys) {
    if (a[k] === undefined || a[k] === null || a[k] === "") throw Object.assign(new Error(`${k} required`), { status: 400 });
  }
}

function msgIdOf(r) {
  const id = r?.msgId ?? r?.message?.msgId ?? r?.attachment?.[0]?.msgId;
  return id == null ? "" : String(id);
}

function styleList(s) {
  if (!Array.isArray(s)) return undefined;
  const out = s
    .filter((x) => x && Number.isInteger(x.start) && Number.isInteger(x.len) && x.len > 0 && typeof x.st === "string")
    .map((x) => (x.st === "ind_$" ? { start: x.start, len: x.len, st: x.st, indentSize: Number(x.indentSize) || 1 } : { start: x.start, len: x.len, st: x.st }));
  return out.length ? out : undefined;
}

function matches(q, ...fields) {
  const needle = String(q || "").trim().toLowerCase();
  if (!needle) return { hit: true, exact: false };
  const hay = fields.map((f) => String(f ?? "").toLowerCase());
  return { hit: hay.some((h) => h.includes(needle)), exact: hay.some((h) => h === needle) };
}

// Wait briefly for our own send to echo through the listener (selfListen).
async function recentMessage(id, waitMs) {
  const until = Date.now() + waitMs;
  for (;;) {
    const m = recent.get(String(id));
    if (m || Date.now() >= until) return m;
    await new Promise((r) => setTimeout(r, 100));
  }
}

function requireApi() {
  if (!api) throw Object.assign(new Error(status === "qr_pending" ? "not_logged_in: scan the QR code (GET /qr)" : "not_logged_in"), { status: 409 });
  return api;
}

async function loadMedia(b) {
  let data;
  let name = b.filename;
  if (b.path) {
    data = await fsp.readFile(b.path);
    name ||= path.basename(b.path);
  } else {
    const r = await fetch(b.url, { signal: AbortSignal.timeout(60_000) });
    if (!r.ok) throw Object.assign(new Error(`media download HTTP ${r.status}`), { status: 502 });
    data = Buffer.from(await r.arrayBuffer());
    name ||= path.basename(new URL(b.url).pathname) || "";
  }
  if (data.length > MAX_MEDIA) throw Object.assign(new Error("attachment too large"), { status: 413 });
  if (!name || !name.includes(".")) {
    name = `${name || "upload"}.${{ image: "jpg", video: "mp4", audio: "mp3" }[b.kind] || "bin"}`;
  }
  return { data, filename: name, metadata: { totalSize: data.length } };
}

const routes = {
  "GET /health": async () => ({ status, ownId, epoch: EPOCH, profile: PROFILE, queued: events.length }),
  "GET /qr": async () => ({ status, qr: qrImage }),
  "GET /messages": async (_b, url) => {
    let after = Number(url.searchParams.get("after") || 0);
    if (url.searchParams.get("epoch") !== EPOCH) after = 0; // bridge restarted: replay the buffer
    const wait = Math.min(Math.max(Number(url.searchParams.get("wait") || 0), 0), 60) * 1000;
    const pick = () => events.filter((e) => e.seq > after);
    let got = pick();
    if (!got.length && wait > 0 && status !== "logged_out") {
      await new Promise((resolve) => {
        const done = () => {
          waiters.delete(done);
          clearTimeout(t);
          resolve();
        };
        const t = setTimeout(done, wait);
        waiters.add(done);
      });
      got = pick();
    }
    return { epoch: EPOCH, ownId, status, events: got };
  },
  "POST /send": async (b) => {
    need(b, "threadId", "text");
    const a = requireApi();
    const type = b.isGroup ? ThreadType.Group : ThreadType.User;
    const quote = b.replyTo ? recent.get(String(b.replyTo))?.data : undefined;
    const styles = styleList(b.styles);
    const r = await a.sendMessage({ msg: b.text, ...(styles ? { styles } : {}), ...(quote ? { quote } : {}) }, String(b.threadId), type);
    return { msgId: msgIdOf(r) };
  },
  "POST /send-media": async (b) => {
    need(b, "threadId");
    if (!b.path && !b.url) throw Object.assign(new Error("path or url required"), { status: 400 });
    const a = requireApi();
    const type = b.isGroup ? ThreadType.Group : ThreadType.User;
    const att = await loadMedia(b);
    const caption = String(b.caption || "");
    if (b.kind === "audio") {
      // Upstream: upload, then send the uploaded URL as a voice message.
      let textId = "";
      if (caption) textId = msgIdOf(await a.sendMessage(caption, String(b.threadId), type));
      const up = await a.uploadAttachment([att], String(b.threadId), type);
      const voiceUrl = up.find((u) => u?.fileUrl && (u.fileType === "others" || u.fileType === "video"))?.fileUrl;
      if (!voiceUrl) throw Object.assign(new Error("could not resolve uploaded audio URL"), { status: 502 });
      const r = await a.sendVoice({ voiceUrl }, String(b.threadId), type);
      return { msgId: msgIdOf(r) || textId };
    }
    const quote = b.replyTo ? recent.get(String(b.replyTo))?.data : undefined;
    const styles = caption ? styleList(b.styles) : undefined;
    const r = await a.sendMessage({ msg: caption, attachments: [att], ...(styles ? { styles } : {}), ...(quote ? { quote } : {}) }, String(b.threadId), type);
    return { msgId: msgIdOf(r) };
  },
  "POST /react": async (b) => {
    need(b, "threadId", "msgId", "cliMsgId");
    const a = requireApi();
    const type = b.isGroup ? ThreadType.Group : ThreadType.User;
    const icon = b.remove ? { rType: -1, source: 6, icon: "" } : String(b.icon || "/-strong");
    await a.addReaction(icon, { data: { msgId: String(b.msgId), cliMsgId: String(b.cliMsgId) }, threadId: String(b.threadId), type });
    return { ok: true };
  },
  // Own messages: recall for everyone (`undo`). Others': delete for everyone, which
  // Zalo allows only to group admins; never in a DM.
  "POST /delete": async (b) => {
    need(b, "threadId", "msgId");
    const a = requireApi();
    const type = b.isGroup ? ThreadType.Group : ThreadType.User;
    const m = await recentMessage(b.msgId, 3000);
    const d = m?.data;
    if (!d?.cliMsgId) throw Object.assign(new Error("message not found (only recent messages can be deleted)"), { status: 404 });
    if (m.isSelf || String(d.uidFrom) === ownId || String(d.uidFrom) === "0") {
      await a.undo({ msgId: String(d.msgId), cliMsgId: String(d.cliMsgId) }, String(b.threadId), type);
    } else if (b.isGroup) {
      await a.deleteMessage({ data: { cliMsgId: String(d.cliMsgId), msgId: String(d.msgId), uidFrom: String(d.uidFrom) }, threadId: String(b.threadId), type }, false);
    } else {
      throw Object.assign(new Error("cannot delete another user's message in a direct chat"), { status: 400 });
    }
    recent.delete(String(b.msgId));
    return { ok: true };
  },
  // Lookups behind seagent's `zalouser` tool (upstream listZaloFriendsMatching / listZaloGroupsMatching / getZaloUserInfo).
  "GET /friends": async (_b, url) => {
    const a = requireApi();
    const q = url.searchParams.get("query");
    const rows = (await a.getAllFriends()).map((f) => ({ userId: String(f.userId), displayName: f.displayName || f.zaloName || f.username || String(f.userId), avatar: f.avatar || undefined }));
    return rows
      .map((f) => ({ f, ...matches(q, f.userId, f.displayName) }))
      .filter((x) => x.hit)
      .sort((x, y) => Number(y.exact) - Number(x.exact))
      .map((x) => x.f);
  },
  "GET /groups": async (_b, url) => {
    const a = requireApi();
    const ids = Object.keys((await a.getAllGroups())?.gridVerMap ?? {});
    const info = new Map();
    for (let i = 0; i < ids.length; i += GROUP_INFO_CHUNK_SIZE) {
      const r = await a.getGroupInfo(ids.slice(i, i + GROUP_INFO_CHUNK_SIZE));
      for (const [id, g] of Object.entries(r?.gridInfoMap ?? {})) info.set(id, g);
    }
    const q = url.searchParams.get("query");
    return ids
      .map((id) => {
        const g = info.get(id);
        return { groupId: id, name: g?.name?.trim() || id, memberCount: Number.isFinite(g?.totalMember) ? g.totalMember : undefined };
      })
      .filter((g) => matches(q, g.groupId, g.name).hit);
  },
  "GET /me": async () => {
    const a = requireApi();
    const info = await a.fetchAccountInfo();
    const u = info && typeof info === "object" && "profile" in info ? info.profile : info;
    if (!u?.userId) throw Object.assign(new Error("not_logged_in"), { status: 409 });
    return { userId: String(u.userId), displayName: u.displayName || u.zaloName || String(u.userId), avatar: u.avatar || undefined };
  },
  "POST /typing": async (b) => {
    need(b, "threadId");
    const a = requireApi();
    await a.sendTypingEvent(String(b.threadId), b.isGroup ? ThreadType.Group : ThreadType.User);
    return { ok: true };
  },
  "POST /logout": async () => {
    try {
      api?.listener.stop();
    } catch {}
    api = null;
    try {
      unlinkSync(credPath);
    } catch {}
    status = "logged_out";
    return { ok: true };
  },
  "POST /login": async () => {
    if (!api) {
      status = "starting";
      start();
    }
    return { status };
  },
};

const server = createServer(async (req, res) => {
  try {
    if (!authorized(req)) return send(res, 401, { error: "unauthorized" });
    const url = new URL(req.url || "/", "http://localhost");
    const route = routes[`${req.method} ${url.pathname}`];
    if (!route) return send(res, 404, { error: "no such route" });
    const body = req.method === "POST" ? await readJson(req) : {};
    send(res, 200, await route(body, url));
  } catch (e) {
    send(res, e?.status || 502, { error: String(e?.message ?? e) });
  }
});
server.requestTimeout = 90_000;
server.listen(PORT, HOST, () => log(`listening on http://${HOST}:${PORT} (profile ${PROFILE})`));
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    try {
      api?.listener.stop();
    } catch {}
    server.close();
    process.exit(0);
  });
}
start();
