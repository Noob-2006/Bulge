// Generates tests/fixtures/matrix_vodozemac_vectors.json (vodozemac → Olm/Megolm/attachment vectors for
// `matrix_e2ee::tests::decrypts_vodozemac_vectors`); ark's side uses fixed keys (Ed25519 seed 01…, Curve25519 02…, one-time key 03…):
//   MATRIX_SDK_CRYPTO_WASM=…/matrix-sdk-crypto-wasm/node.mjs node matrix_vectors_gen.mjs > fixtures/matrix_vodozemac_vectors.json
import crypto from "node:crypto";
const sdk = await import(process.env.MATRIX_SDK_CRYPTO_WASM);
const ARK = "@ark:hs.test", DEV = "ARKDEV", ROOM = "!vec:hs.test";
const b64 = (b) => Buffer.from(b).toString("base64").replace(/=+$/, "");
const pk8 = (prefix, s) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from(prefix, "hex"), s]), format: "der", type: "pkcs8" });
const edPriv = pk8("302e020100300506032b657004220420", Buffer.alloc(32, 0x01));
const edPub = crypto.createPublicKey(edPriv).export({ format: "der", type: "spki" }).subarray(-32);
const xPub = (s) => crypto.createPublicKey(pk8("302e020100300506032b656e04220420", s)).export({ format: "der", type: "spki" }).subarray(-32);
const canon = (v) => Array.isArray(v) ? `[${v.map(canon).join(",")}]` : v && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",")}}` : JSON.stringify(v);
const sign = (o) => { const { signatures, unsigned, ...rest } = o; o.signatures = { [ARK]: { [`ed25519:${DEV}`]: b64(crypto.sign(null, Buffer.from(canon(rest)), edPriv)) } }; return o; };
const device = sign({ user_id: ARK, device_id: DEV, algorithms: ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"], keys: { [`curve25519:${DEV}`]: b64(xPub(Buffer.alloc(32, 0x02))), [`ed25519:${DEV}`]: b64(edPub) } });
const otk = sign({ key: b64(xPub(Buffer.alloc(32, 0x03))) });
const alice = await sdk.OlmMachine.initialize(new sdk.UserId("@alice:hs.test"), new sdk.DeviceId("ALICEDEV"));
let aliceKeys;
async function flush() {
  for (const r of await alice.outgoingRequests()) {
    let resp = {};
    if (r.type === sdk.RequestType.KeysUpload) { aliceKeys = JSON.parse(r.body).device_keys; resp = { one_time_key_counts: { signed_curve25519: 50 } }; }
    if (r.type === sdk.RequestType.KeysQuery) resp = { device_keys: { [ARK]: { [DEV]: device } }, failures: {} };
    await alice.markRequestAsSent(r.id, r.type, JSON.stringify(resp));
  }
}
await flush();
await alice.updateTrackedUsers([new sdk.UserId(ARK)]);
await flush();
const c = await alice.getMissingSessions([new sdk.UserId(ARK)]);
await alice.markRequestAsSent(c.id, c.type, JSON.stringify({ one_time_keys: { [ARK]: { [DEV]: { "signed_curve25519:AAAAAQ": otk } } }, failures: {} }));
const td = await alice.shareRoomKey(new sdk.RoomId(ROOM), [new sdk.UserId(ARK)], new sdk.EncryptionSettings());
const toDevice = JSON.parse(td[0].body).messages[ARK][DEV];
const events = [];
for (const body of ["first", "second", "third"]) events.push(JSON.parse(await alice.encryptRoomEvent(new sdk.RoomId(ROOM), "m.room.message", JSON.stringify({ msgtype: "m.text", body }))));
const att = sdk.Attachment.encrypt(new Uint8Array(Buffer.from("vodozemac attachment vector")));
console.log(JSON.stringify({ alice_device_keys: aliceKeys, to_device: toDevice, events, attachment: { ciphertext: b64(att.encryptedData), info: JSON.parse(att.mediaEncryptionInfo) }, ark_ed25519: b64(edPub), ark_curve25519: device.keys[`curve25519:${DEV}`], otk: otk.key }, null, 1));
