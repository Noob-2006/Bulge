// Interop harness for seagent's Matrix E2EE (run by the ignored Rust test
// `matrix::tests::interop_with_matrix_sdk_crypto`): a tiny fake homeserver for
// the seagent device plus "bob" and "carol", matrix-rust-sdk crypto (vodozemac)
// OlmMachines — the crypto Element uses — driven in-process against the same
// state. Bob talks first (seagent answers on Bob's Olm session); Carol never sends
// to-device messages, so seagent must claim her one-time key and open the session.
//
//   MATRIX_SDK_CRYPTO_WASM=/path/to/@matrix-org/matrix-sdk-crypto-wasm/node.mjs node matrix_interop.mjs
//
// Prints `PORT <n>` once listening. Control endpoints: POST /_test/send?who=bob
// {body, file_b64?, hold_seagent?, backup_to_seagent?}, /_test/read?who=bob|carol, /_test/olm,
// /_test/xsign?who=bob (bootstrap cross-signing), /_test/verify?who=bob {action:
// request|step} (SAS driven by vodozemac), /_test/trust?who=bob, /_test/backup_decrypt
// {key} (seagent's key backup opened with vodozemac), /_test/state.
import http from "node:http";

const sdk = await import(process.env.MATRIX_SDK_CRYPTO_WASM);
// Optional: matrix-js-sdk (MATRIX_JS_SDK=…/node_modules/matrix-js-sdk) to check secret storage and recovery keys.
const js = process.env.MATRIX_JS_SDK ? {
  rk: await import(`${process.env.MATRIX_JS_SDK}/lib/crypto-api/recovery-key.js`),
  dec: (await import(`${process.env.MATRIX_JS_SDK}/lib/utils/decryptAESSecretStorageItem.js`)).default,
  ss: await import(`${process.env.MATRIX_JS_SDK}/lib/secret-storage.js`),
} : null;
const SEAGENT = "@seagent:hs.test", BOB = "@bob:hs.test", CAROL = "@carol:hs.test", SEAGENTDEV = "SEAGENTDEV", ROOM = "!e2e:hs.test";
const MEMBERS = [SEAGENT, BOB, CAROL];
const S = { keys: {}, otks: {}, fallback: {}, todev: {}, timeline: [], media: [], olm: [], cross: {}, ad: {}, backup: {}, restores: 0, uia: 0 };
const ENC = { algorithm: "m.megolm.v1.aes-sha2", rotation_period_msgs: 4 };
const q = (u, d) => `${u}|${d}`;

function upload(user, dev, b) {
  if (b.device_keys) (S.keys[user] ??= {})[dev] = b.device_keys;
  Object.assign((S.otks[q(user, dev)] ??= {}), b.one_time_keys ?? {});
  if (b.fallback_keys && Object.keys(b.fallback_keys).length) S.fallback[q(user, dev)] = b.fallback_keys;
  return { one_time_key_counts: { signed_curve25519: Object.keys(S.otks[q(user, dev)]).length } };
}
function query(b, who) {
  const r = { failures: {}, device_keys: {}, master_keys: {}, self_signing_keys: {}, user_signing_keys: {} };
  for (const u of Object.keys(b.device_keys)) {
    r.device_keys[u] = S.keys[u] ?? {};
    const c = S.cross[u];
    if (c) { r.master_keys[u] = c.master_key; r.self_signing_keys[u] = c.self_signing_key; if (u === who) r.user_signing_keys[u] = c.user_signing_key; }
  }
  return r;
}
function signatures(b) {
  for (const [u, objs] of Object.entries(b)) for (const [id, obj] of Object.entries(objs)) {
    const target = S.keys[u]?.[id] ?? (S.cross[u]?.master_key?.keys?.[`ed25519:${id}`] ? S.cross[u].master_key : null);
    if (!target) continue;
    for (const [su, sigs] of Object.entries(obj.signatures ?? {})) Object.assign(((target.signatures ??= {})[su] ??= {}), sigs);
  }
  return { failures: {} };
}
function backupPut(user, rooms) {
  const v = S.backup[user]?.at(-1);
  if (!v) return;
  for (const [room, r] of Object.entries(rooms)) for (const [sid, d] of Object.entries(r.sessions)) (v.rooms[room] ??= {})[sid] = d;
}
function claim(b) {
  const out = {};
  for (const [u, devs] of Object.entries(b.one_time_keys)) for (const d of Object.keys(devs)) {
    const pool = S.otks[q(u, d)] ?? {};
    const kid = Object.keys(pool)[0];
    let got;
    if (kid) { got = { [kid]: pool[kid] }; delete pool[kid]; } else got = S.fallback[q(u, d)];
    if (got) (out[u] ??= {})[d] = got;
  }
  return { failures: {}, one_time_keys: out };
}
function toDevice(sender, type, b) {
  for (const [u, devs] of Object.entries(b.messages)) for (const [d, content] of Object.entries(devs)) {
    (S.todev[q(u, d)] ??= []).push({ type, sender, content });
    for (const c of Object.values(content.ciphertext ?? {})) S.olm.push(`${sender}:${c.type}`);
  }
  return {};
}
const event = (sender, type, content) => { const ev = { type, sender, content, event_id: `$ev${S.timeline.length}`, origin_server_ts: Date.now(), room_id: ROOM }; S.timeline.push(ev); return ev; };

// ---- bob / carol (vodozemac via matrix-sdk-crypto)
const P = {};
for (const [u, d] of [[BOB, "BOBDEV"], [CAROL, "CAROLDEV"]]) P[u] = { user: u, dev: d, read: 0, m: await sdk.OlmMachine.initialize(new sdk.UserId(u), new sdk.DeviceId(d)) };
const uids = (l) => l.map((u) => new sdk.UserId(u));
async function flush(p) {
  for (let i = 0; i < 5; i++) {
    const reqs = await p.m.outgoingRequests();
    if (!reqs.length) return;
    for (const r of reqs) {
      const b = JSON.parse(r.body);
      let resp = {};
      if (r.type === sdk.RequestType.KeysUpload) resp = upload(p.user, p.dev, b);
      else if (r.type === sdk.RequestType.KeysQuery) resp = query(b, p.user);
      else if (r.type === sdk.RequestType.SignatureUpload) resp = signatures(b);
      else if (r.type === sdk.RequestType.KeysBackup) { backupPut(SEAGENT, b.rooms); resp = { etag: "1", count: 1 }; }
      else if (r.type === sdk.RequestType.KeysClaim) resp = claim(b);
      else if (r.type === sdk.RequestType.ToDevice) resp = toDevice(p.user, r.event_type, b);
      await p.m.markRequestAsSent(r.id, r.type, JSON.stringify(resp));
    }
  }
}
async function sendOut(p, r) {
  if (!r) return;
  if (r.event_type) toDevice(p.user, r.event_type, JSON.parse(r.body));
  if (r.id) await p.m.markRequestAsSent(r.id, sdk.RequestType.ToDevice, "{}");
}
async function deliver(p) {
  const evs = S.todev[q(p.user, p.dev)] ?? [];
  S.todev[q(p.user, p.dev)] = [];
  await p.m.receiveSyncChanges(JSON.stringify(evs), new sdk.DeviceLists(), new Map([["signed_curve25519", Object.keys(S.otks[q(p.user, p.dev)] ?? {}).length]]), new Set(["signed_curve25519"]));
  await flush(p);
}
async function verify(p, action) {
  if (action === "request") {
    await p.m.updateTrackedUsers(uids([SEAGENT]));
    await flush(p);
    const d = await p.m.getDevice(new sdk.UserId(SEAGENT), new sdk.DeviceId(SEAGENTDEV));
    const [req, out] = d.requestVerification();
    p.req = req;
    p.codes = {};
    await sendOut(p, out);
    return { flow: req.flowId };
  }
  await deliver(p);
  if (!p.req || p.req.isDone() || p.req.isCancelled()) {
    const fresh = p.m.getVerificationRequests(new sdk.UserId(SEAGENT)).find((r) => !r.isDone() && !r.isCancelled());
    if (fresh) { p.req = fresh; p.codes = {}; }
  }
  const req = p.req;
  if (!req) return { none: true };
  if (req.phase() === sdk.VerificationRequestPhase.Requested && !req.weStarted()) await sendOut(p, req.accept());
  let sas = req.getVerification();
  if (req.phase() === sdk.VerificationRequestPhase.Ready && req.weStarted() && !sas) {
    const r = await req.startSas();
    sas = r[0];
    await sendOut(p, r[1]);
  }
  const out = { flow: req.flowId, phase: req.phase(), done: req.isDone(), cancelled: req.isCancelled(), cancel: req.cancelInfo?.reason };
  if (sas instanceof sdk.Sas) {
    if (!sas.weStarted() && !sas.hasBeenAccepted()) await sendOut(p, sas.accept());
    if (sas.canBePresented()) {
      out.emoji = Array.from(sas.emojiIndex());
      out.decimals = Array.from(sas.decimals());
      out.symbols = sas.emoji().map((e) => e.symbol);
      p.codes = { emoji: out.emoji, decimals: out.decimals, symbols: out.symbols };
      if (!sas.haveWeConfirmed()) for (const r of await sas.confirm()) await sendOut(p, r);
    }
    out.sas_done = sas.isDone();
  }
  Object.assign(out, { ...p.codes, ...out });
  await flush(p);
  return out;
}
async function trust(p) {
  await p.m.updateTrackedUsers(uids([SEAGENT]));
  // Re-query seagent: signatures uploaded since (ours on seagent's master key) only count once fetched.
  await p.m.receiveSyncChanges("[]", new sdk.DeviceLists(uids([SEAGENT])), new Map(), new Set(["signed_curve25519"]));
  await flush(p);
  const d = await p.m.getDevice(new sdk.UserId(SEAGENT), new sdk.DeviceId(SEAGENTDEV));
  const id = await p.m.getIdentity(new sdk.UserId(SEAGENT));
  return { device_verified: d.isVerified(), cross_signed_by_owner: d.isCrossSignedByOwner(), locally_trusted: d.isLocallyTrusted(), identity_verified: id ? id.isVerified() : null };
}
async function xsign(p) {
  const r = await p.m.bootstrapCrossSigning(true);
  const keys = JSON.parse(r.uploadSigningKeysRequest.body);
  S.cross[p.user] = { master_key: keys.master_key, self_signing_key: keys.self_signing_key, user_signing_key: keys.user_signing_key };
  signatures(JSON.parse(r.uploadSignaturesRequest.body));
  await flush(p);
  return { master: Object.values(keys.master_key.keys)[0] };
}
function backupDecrypt(keyB64) {
  const key = sdk.BackupDecryptionKey.fromBase64(keyB64);
  const v = S.backup[SEAGENT].at(-1);
  const out = { public_ok: key.megolmV1PublicKey.publicKeyBase64 === v.info.auth_data.public_key, sessions: [] };
  for (const [room, sessions] of Object.entries(v.rooms)) for (const [sid, d] of Object.entries(sessions)) {
    const sd = d.session_data;
    out.sessions.push({ room, session_id: sid, first_message_index: d.first_message_index, ...JSON.parse(key.decryptV1(sd.ephemeral, sd.mac, sd.ciphertext)) });
  }
  return out;
}
async function ssss(recoveryKey) {
  if (!js) return { skipped: true };
  const key = js.rk.decodeRecoveryKey(recoveryKey);
  const id = S.ad["m.secret_storage.default_key"].key;
  const desc = S.ad[`m.secret_storage.key.${id}`];
  const check = await js.ss.calculateKeyCheck(key, desc.iv);
  const secrets = {};
  for (const name of ["m.cross_signing.master", "m.cross_signing.self_signing", "m.cross_signing.user_signing", "m.megolm_backup.v1"]) secrets[name] = await js.dec(S.ad[name].encrypted[id], key, name);
  return { mac_ok: check.mac.replace(/=+$/, "") === desc.mac.replace(/=+$/, ""), reencoded: js.rk.encodeRecoveryKey(key), secrets };
}
async function peerSend(p, text, fileB64) {
  await p.m.updateTrackedUsers(uids(MEMBERS));
  await flush(p);
  const c = await p.m.getMissingSessions(uids(MEMBERS));
  if (c) await p.m.markRequestAsSent(c.id, c.type, JSON.stringify(claim(JSON.parse(c.body))));
  const settings = new sdk.EncryptionSettings();
  settings.rotationPeriodMessages = 2n; // round 2 needs a new room key (more Olm traffic)
  for (const r of await p.m.shareRoomKey(new sdk.RoomId(ROOM), uids(MEMBERS), settings)) {
    toDevice(p.user, r.event_type, JSON.parse(r.body));
    await p.m.markRequestAsSent(r.id, r.type, "{}");
  }
  const out = [];
  const send = async (content) => out.push(event(p.user, "m.room.encrypted", JSON.parse(await p.m.encryptRoomEvent(new sdk.RoomId(ROOM), "m.room.message", JSON.stringify(content)))).event_id);
  await send({ msgtype: "m.text", body: text });
  if (fileB64) {
    const att = sdk.Attachment.encrypt(new Uint8Array(Buffer.from(fileB64, "base64")));
    const info = JSON.parse(att.mediaEncryptionInfo);
    S.media.push(Buffer.from(att.encryptedData));
    await send({ msgtype: "m.file", body: "from-bob.bin", file: { ...info, url: `mxc://hs.test/${S.media.length - 1}` }, info: { mimetype: "application/octet-stream" } });
  }
  return { event_ids: out };
}
async function peerRead(p) {
  await deliver(p);
  const out = [];
  for (; p.read < S.timeline.length; p.read++) {
    const ev = S.timeline[p.read];
    if (ev.sender !== SEAGENT) continue;
    if (ev.type !== "m.room.encrypted") { out.push({ plain: true, type: ev.type, content: ev.content }); continue; }
    try {
      const d = await p.m.decryptRoomEvent(JSON.stringify(ev), new sdk.RoomId(ROOM), new sdk.DecryptionSettings(sdk.TrustRequirement.Untrusted));
      const e = JSON.parse(d.event);
      const r = { type: e.type, content: e.content };
      if (e.content.file) {
        const bytes = S.media[Number(e.content.file.url.split("/").pop())];
        r.file_b64 = Buffer.from(sdk.Attachment.decrypt(new sdk.EncryptedAttachment(new Uint8Array(bytes), JSON.stringify(e.content.file)))).toString("base64");
      }
      out.push(r);
    } catch (err) { out.push({ error: String(err) }); }
  }
  return out;
}

// ---- homeserver for seagent
let sinceTimeline = 0;
function sync(url) {
  const since = url.searchParams.get("since");
  const evs = S.todev[q(SEAGENT, SEAGENTDEV)] ?? [];
  S.todev[q(SEAGENT, SEAGENTDEV)] = [];
  const from = since ? Number(since) : 0;
  const room = { timeline: { events: S.timeline.slice(from) } };
  if (!since) room.state = { events: [{ type: "m.room.encryption", state_key: "", content: ENC }] };
  sinceTimeline = S.timeline.length;
  return { next_batch: String(sinceTimeline), to_device: { events: evs }, device_lists: { changed: [], left: [] }, device_one_time_keys_count: { signed_curve25519: Object.keys(S.otks[q(SEAGENT, SEAGENTDEV)] ?? {}).length }, device_unused_fallback_key_types: ["signed_curve25519"], rooms: { join: { [ROOM]: { summary: { "m.joined_member_count": 3 }, ...room } } } };
}
async function route(m, url, raw) {
  const p = url.pathname, b = () => JSON.parse(raw.toString() || "{}");
  const who = P[`@${url.searchParams.get("who")}:hs.test`];
  if (p === "/_test/send") {
    const x = b();
    if (x.backup_to_seagent) {
      // vodozemac encrypts its sessions to seagent's backup key (as if another seagent device had).
      const v = S.backup[SEAGENT].at(-1);
      await who.m.enableBackupV1(v.info.auth_data.public_key, String(S.backup[SEAGENT].length));
      await who.m.invalidateGroupSession(new sdk.RoomId(ROOM));
    }
    const held = (S.todev[q(SEAGENT, SEAGENTDEV)] ?? []).length;
    const r = await peerSend(who, x.body, x.file_b64);
    if (x.hold_seagent) S.todev[q(SEAGENT, SEAGENTDEV)] = (S.todev[q(SEAGENT, SEAGENTDEV)] ?? []).slice(0, held);
    if (x.backup_to_seagent) {
      const req = await who.m.backupRoomKeys();
      if (req) { backupPut(SEAGENT, JSON.parse(req.body).rooms); await who.m.markRequestAsSent(req.id, req.type, JSON.stringify({ etag: "1", count: 1 })); }
    }
    return [200, r];
  }
  if (p === "/_test/xsign") return [200, await xsign(who)];
  if (p === "/_test/verify") return [200, await verify(who, b().action)];
  if (p === "/_test/trust") return [200, await trust(who)];
  if (p === "/_test/backup_decrypt") return [200, backupDecrypt(b().key)];
  if (p === "/_test/ssss") return [200, await ssss(b().recovery_key)];
  if (p === "/_test/state") return [200, { cross: S.cross, restores: S.restores, uia: S.uia, backup_versions: (S.backup[SEAGENT] ?? []).length }];
  if (p === "/_test/read") return [200, await peerRead(who)];
  if (p === "/_test/olm") return [200, S.olm];
  if (p === "/_matrix/client/v3/account/whoami") return [200, { user_id: SEAGENT, device_id: SEAGENTDEV }];
  if (p === "/_matrix/client/v3/keys/upload") return [200, upload(SEAGENT, SEAGENTDEV, b())];
  if (p === "/_matrix/client/v3/keys/query") return [200, query(b(), SEAGENT)];
  if (p === "/_matrix/client/v3/keys/device_signing/upload") {
    const x = b();
    if (!x.auth) { S.uia++; return [401, { session: "uia1", flows: [{ stages: ["m.login.dummy"] }], params: {} }]; }
    S.cross[SEAGENT] = { master_key: x.master_key, self_signing_key: x.self_signing_key, user_signing_key: x.user_signing_key };
    return [200, {}];
  }
  if (p === "/_matrix/client/v3/keys/signatures/upload") return [200, signatures(b())];
  const ad = p.match(/^\/_matrix\/client\/v3\/user\/([^/]+)\/account_data\/([^/]+)$/);
  if (ad) {
    const k = decodeURIComponent(ad[2]);
    if (m === "PUT") { S.ad[k] = b(); return [200, {}]; }
    return S.ad[k] ? [200, S.ad[k]] : [404, { errcode: "M_NOT_FOUND", error: "no" }];
  }
  if (p === "/_matrix/client/v3/room_keys/version") {
    const all = (S.backup[SEAGENT] ??= []);
    if (m === "POST") { all.push({ info: b(), rooms: {} }); return [200, { version: String(all.length) }]; }
    return all.length ? [200, { ...all.at(-1).info, version: String(all.length) }] : [404, { errcode: "M_NOT_FOUND", error: "no backup" }];
  }
  if (p === "/_matrix/client/v3/room_keys/keys") { backupPut(SEAGENT, b().rooms); return [200, { etag: "1", count: 1 }]; }
  if (p.startsWith("/_matrix/client/v3/room_keys/keys/")) {
    const [room, sid] = p.split("/").slice(6).map(decodeURIComponent);
    S.restores++;
    const d = S.backup[SEAGENT]?.at(-1)?.rooms[room]?.[sid];
    return d ? [200, d] : [404, { errcode: "M_NOT_FOUND", error: "no" }];
  }
  if (p === "/_matrix/client/v3/keys/claim") return [200, claim(b())];
  if (p.startsWith("/_matrix/client/v3/sendToDevice/")) return [200, toDevice(SEAGENT, decodeURIComponent(p.split("/")[5]), b())];
  if (p === "/_matrix/client/v3/sync") return [200, sync(url)];
  if (p.endsWith("/state/m.room.encryption/")) return [200, ENC];
  if (p.endsWith("/joined_members")) return [200, { joined: Object.fromEntries(MEMBERS.map((u) => [u, {}])) }];
  if (p.includes("/send/")) { const typ = decodeURIComponent(p.split("/")[7]); return [200, { event_id: event(SEAGENT, typ, b()).event_id }]; }
  if (p === "/_matrix/media/v3/upload") { S.media.push(raw); return [200, { content_uri: `mxc://hs.test/${S.media.length - 1}` }]; }
  if (p.startsWith("/_matrix/client/v1/media/download/hs.test/")) return [200, S.media[Number(p.split("/").pop())], true];
  if (p.includes("/profile/")) return [200, { displayname: "Seagent" }];
  return [200, {}];
}
const srv = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    try {
      const [status, body, binary] = await route(req.method, new URL(req.url, "http://x"), Buffer.concat(chunks));
      res.writeHead(status, { "content-type": binary ? "application/octet-stream" : "application/json" });
      res.end(binary ? body : JSON.stringify(body));
    } catch (e) { res.writeHead(500); res.end(JSON.stringify({ errcode: "M_UNKNOWN", error: String(e.stack) })); }
  });
});
srv.listen(0, "127.0.0.1", () => console.log(`PORT ${srv.address().port}`));
