// Device keys for this browser / app WebView (docs/SECURITY.md §8; server side:
// crates/seagent-app/src/device_auth.rs). Loaded before app.js; exposes `window.DevAuth`.
//
// - Pairing sends `device.publicKey`: an ECDSA P-256 key made here with WebCrypto, private half
//   non-extractable and kept in IndexedDB (script on this origin can use it, nobody can copy it).
// - The stored console token (`sed1_…`) is then only good for `POST /pair/refresh` together with
//   a fresh signature; what the console really uses is a short-lived access token (`sea1_…`),
//   refreshed here silently.
// - A device paired before keys existed binds a key on its next start (migration).
// - Inside the SE Agent app the page gets an access token in `#token=`; the app mints new ones
//   through its `console_access_token` command (its Rust side holds the key).
// - No WebCrypto / IndexedDB, or an older host without /pair/refresh: the token is used as before.
'use strict';

(function () {
  const DB = 'seagent-devkey';
  let cached = null; // { token, exp, from }

  const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const nonce = () => { const b = new Uint8Array(18); crypto.getRandomValues(b); return b64url(b); };

  function idb(mode, fn) {
    return new Promise((ok, fail) => {
      const open = indexedDB.open(DB, 1);
      open.onupgradeneeded = () => open.result.createObjectStore('keys');
      open.onerror = () => fail(open.error);
      open.onsuccess = () => {
        const tx = open.result.transaction('keys', mode);
        const r = fn(tx.objectStore('keys'));
        tx.oncomplete = () => ok(r && r.result);
        tx.onerror = () => fail(tx.error);
      };
    });
  }

  let pair = null;
  async function keyPair() {
    if (pair) return pair;
    if (!window.isSecureContext || !window.crypto || !crypto.subtle || !window.indexedDB) return null;
    try {
      let kp = await idb('readonly', (s) => s.get('device'));
      if (!kp) {
        kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
        await idb('readwrite', (s) => s.put(kp, 'device'));
      }
      pair = kp;
      return kp;
    } catch { return null; }
  }

  async function publicKey() {
    if (window.__TAURI__) return undefined; // the app pairs with its own key
    const kp = await keyPair();
    if (!kp) return undefined;
    try { return b64url(await crypto.subtle.exportKey('raw', kp.publicKey)); } catch { return undefined; }
  }

  // The host id and clock the signature is made for (both public: the id is in mDNS too).
  async function hostInfo() {
    const t0 = Date.now();
    const r = await fetch('/pair/info', { cache: 'no-store' });
    if (!r.ok) return null;
    const v = await r.json();
    return { hostId: v.hostId, skew: (v.nowMs || t0) - Math.round((t0 + Date.now()) / 2) };
  }

  // Console token → access token. Returns the token to use, or the console token itself when
  // this browser or the host cannot do device keys.
  async function refresh(consoleToken, deviceId) {
    const kp = await keyPair();
    if (!kp) return consoleToken;
    const info = await hostInfo().catch(() => null);
    if (!info || !info.hostId) return consoleToken; // an older host
    const ts = Date.now() + info.skew;
    const n = nonce();
    const msg = `seagent-device-refresh|v1|${info.hostId}|${deviceId}|${ts}|${n}`;
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new TextEncoder().encode(msg));
    const body = { deviceId, ts, nonce: n, sig: b64url(sig), publicKey: await publicKey() };
    const r = await fetch('/pair/refresh', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${consoleToken}` }, body: JSON.stringify(body) });
    if (r.status === 404) return consoleToken;
    const v = await r.json().catch(() => ({}));
    if (r.ok && v.accessToken) {
      cached = { token: v.accessToken, exp: v.expiresAtMs || 0, from: consoleToken };
      return v.accessToken;
    }
    // 409 / 401 "send publicKey" means an unbound device on a host that could not bind it:
    // keep using the token; anything else the console reports as a sign-in problem.
    return consoleToken;
  }

  // {token, expiresAtMs} from the SE Agent app (its Rust side signs with the device key).
  async function fromApp() {
    const tauri = window.__TAURI__ && window.__TAURI__.core;
    if (!tauri) return null;
    try { return await tauri.invoke('console_access_token'); } catch { return null; }
  }

  let stale = false;
  window.DevAuth = {
    publicKey,
    // A fresh pairing answered with an access token already.
    seed(token, exp, from) { if (token) cached = { token, exp: exp || 0, from }; },
    // The last token did not work (expired, daemon restarted): mint a new one next time.
    forget() { cached = null; stale = true; },
    async access(token, deviceId) {
      const fresh = cached && cached.exp - Date.now() > 60000;
      if (typeof token !== 'string') return token;
      if (token.startsWith('sea1_')) {
        if (fresh && cached.from === token) return cached.token;
        // Handed over by the app: use it until it fails, then ask the app for a new one.
        if (!cached && !stale) { cached = { token, exp: Date.now() + 5 * 60000, from: token }; return token; }
        stale = false;
        const t = await fromApp();
        if (t && t.token) { cached = { token: t.token, exp: t.expiresAtMs || Date.now() + 10 * 60000, from: token }; return t.token; }
        return token;
      }
      if (!token.startsWith('sed1_')) return token; // the app token / a scoped token
      // Inside the SE Agent app the key belongs to the app (its Rust side): an older app that
      // still hands over the console token must not get the WebView's key bound instead.
      if (window.__TAURI__) return token;
      if (fresh && cached.from === token) return cached.token;
      stale = false;
      try { return await refresh(token, deviceId); } catch { return token; }
    },
  };
})();
