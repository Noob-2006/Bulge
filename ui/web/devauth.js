// Device keys for this browser / app WebView (docs/SECURITY.md §8; server side:
// crates/seagent-app/src/device_auth.rs). Loaded before app.js; exposes `window.DevAuth`.
//
// - Pairing sends `device.publicKey`: an ECDSA P-256 key made here with WebCrypto, private half
//   non-extractable and kept in IndexedDB (script on this origin can use it, nobody can copy it).
// - The stored console token (`sed1_…`) is then only good for `POST /pair/refresh` together with
//   a fresh signature; what the console really uses is a short-lived access token (`sea1_…`).
// - Renewal is silent and endless: a timer renews at ~80 % of the token's life, a failed renewal
//   is retried with backoff (2 s … 60 s, forever: network down, host restarting, laptop asleep),
//   and a connection refused with an expired token makes app.js call `forget()` and reconnect,
//   which renews first. The open WebSocket is never torn down for renewal (the host keeps it up
//   past the token's expiry).
// - A device paired before keys existed binds a key on its next start (migration).
// - Inside the SE Agent app the page gets an access token in `#token=`; the app mints new ones
//   through its `console_access_token` command (its Rust side holds the key).
// - No WebCrypto / IndexedDB, or an older host without /pair/refresh: the token is used as before.
'use strict';

(function () {
  const DB = 'seagent-devkey';
  let cached = null; // { token, exp, from }
  let last = null; // { token, deviceId } of the last access(): what the timer renews
  let timer = null;
  let stale = false;

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
    if (r.status >= 500) throw new Error(`HTTP ${r.status}`);
    if (!r.ok) return null;
    const v = await r.json();
    return { hostId: v.hostId, skew: (v.nowMs || t0) - Math.round((t0 + Date.now()) / 2) };
  }

  // Console token → access token (also sets `cached`). Throws on a transient failure (network,
  // 5xx, lockout, a signature made before the host restarted) so the caller retries; returns
  // the console token itself when keys cannot be used here or the host refused the device.
  async function refresh(consoleToken, deviceId) {
    const kp = await keyPair();
    if (!kp) return consoleToken;
    const info = await hostInfo();
    if (!info || !info.hostId) return consoleToken; // an older host
    const ts = Date.now() + info.skew;
    const n = nonce();
    const msg = `seagent-device-refresh|v1|${info.hostId}|${deviceId}|${ts}|${n}`;
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new TextEncoder().encode(msg));
    const body = { deviceId, ts, nonce: n, sig: b64url(sig), publicKey: await publicKey(), keyStore: 'webcrypto' };
    const r = await fetch('/pair/refresh', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${consoleToken}` }, body: JSON.stringify(body) });
    if (r.status === 404) return consoleToken;
    const v = await r.json().catch(() => ({}));
    if (r.ok && v.accessToken) {
      cached = { token: v.accessToken, exp: v.expiresAtMs || 0, from: consoleToken };
      return v.accessToken;
    }
    if (r.status >= 500 || r.status === 429 || /before this host started|replay window/.test(v.error || '')) throw new Error(v.error || `HTTP ${r.status}`);
    if (/revoked|another key/.test(v.error || '')) window.DevAuth.revoked = true; // pair again
    return consoleToken;
  }

  // {token, expiresAtMs} from the SE Agent app (its Rust side signs with the device key).
  async function fromApp() {
    const tauri = window.__TAURI__ && window.__TAURI__.core;
    if (!tauri) return null;
    try { return await tauri.invoke('console_access_token'); } catch { return null; }
  }

  // One renewal of whatever `last` names; throws when it did not produce a new token.
  async function renewNow() {
    const { token, deviceId } = last;
    if (token.startsWith('sea1_')) {
      const t = await fromApp();
      if (!t || !t.token) throw new Error('the app could not renew the token');
      cached = { token: t.token, exp: t.expiresAtMs || Date.now() + 10 * 60000, from: token };
      return;
    }
    if ((await refresh(token, deviceId)) === token) throw new Error('no access token');
  }

  // Renew at ~80 % of the token's life; after a failure retry in 2, 4, 8 … 60 s, forever.
  function schedule(retryMs) {
    if (timer) clearTimeout(timer);
    timer = null;
    if (!last || !/^se[ad]1_/.test(last.token)) return;
    let wait = retryMs;
    if (wait === undefined) {
      if (!cached || !cached.exp) return;
      wait = Math.max(500, Math.round((cached.exp - Date.now()) * 0.8));
    }
    timer = setTimeout(async () => {
      timer = null;
      try {
        await renewNow();
        window.DevAuth.renewals++;
        schedule();
      } catch {
        schedule(Math.min(60000, Math.max(2000, (retryMs || 1000) * 2)));
      }
    }, wait);
  }

  window.DevAuth = {
    publicKey,
    // How many timer renewals happened (tests and diagnostics).
    renewals: 0,
    // The host refused this device for good (revoked / another key): the console asks to pair.
    revoked: false,
    // A fresh pairing answered with an access token already.
    seed(token, exp, from) { if (token) { cached = { token, exp: exp || 0, from }; if (from) last = { token: from, deviceId: last && last.deviceId }; schedule(); } },
    // The last token did not work (expired, daemon restarted): mint a new one next time.
    forget() { cached = null; stale = true; },
    // The token the console should use right now.
    current() { return cached && cached.token; },
    async access(token, deviceId) {
      if (typeof token !== 'string') return token;
      last = { token, deviceId };
      const fresh = cached && cached.from === token && cached.exp - Date.now() > 1000;
      if (token.startsWith('sea1_')) {
        if (fresh) return cached.token;
        // Handed over by the app: use it until it fails, then ask the app for a new one.
        if (!cached && !stale) { cached = { token, exp: 0, from: token }; return token; }
        stale = false;
        try { await renewNow(); schedule(); return cached.token; } catch { return token; }
      }
      if (!token.startsWith('sed1_')) return token; // the app token / a scoped token
      // Inside the SE Agent app the key belongs to the app (its Rust side): an older app that
      // still hands over the console token must not get the WebView's key bound instead.
      if (window.__TAURI__) return token;
      if (fresh) return cached.token;
      stale = false;
      for (let i = 0; i < 3; i++) {
        try {
          const t = await refresh(token, deviceId);
          schedule();
          return t;
        } catch {
          await new Promise((r) => setTimeout(r, 500 * 3 ** i));
        }
      }
      schedule(2000); // keep trying in the background; app.js retries the connection too
      return token;
    },
  };
})();
