// seagent web UI: real-time live view for the workspace pane (work.js). Instead of polling
// view.*.frame, the pane opens one WebSocket to /view/live per thing it shows:
//   kind=browser  — the tab's CDP screencast (JPEG frames, ack-paced on the server),
//   kind=desktop  — the Bot Desktop / desktop VM framebuffer (JPEG, only when it changed),
//   kind=terminal — the agent's commands as they run (every exec backend, the microVM too).
// Protocol and auth: crates/seagent-app/src/live_view.rs. Falls back to work.js's polling when
// the stream cannot open. Nothing streams while the pane is closed or the page is hidden.
// Uses app.js / work.js globals: S, W, $, esc, LANG, toast, workRenderTabs.
'use strict';

const LV = { ws: null, key: '', url: null, meta: null, fails: 0, live: false, stats: null, term: null, termOpen: false, termSession: null, cmds: new Map(), nodisplay: false, size: null };
// The viewer's choice (quality, fps). Crisp by default; the server lowers quality, then fps,
// only while the link cannot keep up, and climbs back to this choice.
const LV_LEVELS = [
  { id: 'sharp30', q: 85, fps: 30, zh: '清晰 · 30 fps', en: 'Sharp · 30 fps' },
  { id: 'sharp60', q: 85, fps: 60, zh: '清晰 · 60 fps', en: 'Sharp · 60 fps' },
  { id: 'max30', q: 95, fps: 30, zh: '最高畫質 · 30 fps', en: 'Best · 30 fps' },
  { id: 'max60', q: 95, fps: 60, zh: '最高畫質 · 60 fps', en: 'Best · 60 fps' },
  { id: 'saver', q: 60, fps: 15, zh: '省流量 · 15 fps', en: 'Data saver · 15 fps' },
];
let lvLevel = LV_LEVELS[0];
try { lvLevel = LV_LEVELS.find((l) => l.id === localStorage.getItem('seagent.live.level')) || lvLevel; } catch {}
const LVL = (zh, en) => (LANG === 'en' ? en : zh);
const lvPollFrame = workFrame; // work.js polling, kept as the fallback

function lvKey(cur) { return !cur ? '' : cur.kind === 'tab' ? `browser:${cur.key}:${cur.targetId}` : `desktop:${cur.id}`; }

// Full device-pixel resolution: the stage's real size × devicePixelRatio, so text is crisp.
function lvStageSize() {
  const dpr = devicePixelRatio || 1;
  const st = $('workStage');
  return { w: Math.max(320, Math.round(st.clientWidth * dpr)), h: Math.max(240, Math.round(st.clientHeight * dpr)) };
}

function lvUrl(cur) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const sz = lvStageSize();
  LV.size = sz;
  const lv = { maxWidth: sz.w, maxHeight: sz.h, quality: lvLevel.q, fps: lvLevel.fps };
  const p = new URLSearchParams(cur.kind === 'tab'
    ? { kind: 'browser', key: cur.key, targetId: cur.targetId, ...lv }
    : { kind: 'desktop', target: cur.id, ...lv });
  return `${proto}://${location.host}/view/live?${p}`;
}

function lvSocket(url) {
  // The token rides in a subprotocol, never in the URL (history, logs, Referer).
  const ws = new WebSocket(url, ['seagent.live', `seagent.token.${S.arp.token}`]);
  ws.binaryType = 'blob';
  return ws;
}

function lvClose() {
  if (LV.ws) { LV.ws.onclose = null; try { LV.ws.close(); } catch {} }
  LV.ws = null; LV.key = ''; LV.live = false; LV.meta = null; LV.base = null;
  lvPatchMode(false);
  lvBadge();
}

function lvBadge() {
  const b = $('workLive');
  if (!b) return;
  b.hidden = !LV.live;
  const st = LV.stats;
  b.textContent = st && st.fps != null ? `LIVE ${Math.round(st.fps)} fps` : 'LIVE';
  const a = st && st.adapt;
  const lowered = a && (a.quality < a.chosen.quality || a.fpsTarget < a.chosen.fps);
  b.classList.toggle('low', !!lowered);
  b.title = st ? `${st.kbps} kbit/s${st.latencyMs != null ? ` · ${st.latencyMs} ms` : ''}${a ? ` · JPEG ${a.quality} · ${a.fpsTarget} fps${lowered ? LVL('（連線跟不上，暫時降低）', ' (lowered: the link cannot keep up)') : ''}` : ''}` : '';
}

function lvOpen(cur) {
  lvClose();
  if (!cur || !S.arp || (cur.kind === 'desktop' && !cur.running)) return;
  const key = lvKey(cur);
  const ws = lvSocket(lvUrl(cur));
  LV.ws = ws; LV.key = key; LV.nodisplay = false;
  ws.onmessage = (e) => {
    if (LV.ws !== ws) return;
    if (typeof e.data !== 'string') return lvShow(cur, e.data);
    let m; try { m = JSON.parse(e.data); } catch { return; }
    if (m.t === 'hello') {
      LV.live = true; LV.fails = 0; lvBadge();
      // Windows Bot Desktop without the virtual display: say once why native apps stream slower.
      if (m.display && m.display.reason && !LV.vddTold) { LV.vddTold = true; toast(m.display.message + LVL('（設定 → 虛擬顯示器）', ' (Settings → Virtual display)')); }
    }
    else if (m.t === 'frame' || m.t === 'patch') LV.meta = m;
    else if (m.t === 'stats') { LV.stats = m; lvBadge(); }
    else if (m.t === 'nodisplay') { LV.nodisplay = true; $('workEmpty').textContent = LVL('這個桌面沒有畫面可顯示，下方是代理正在執行的指令。', 'This desktop has no display to show; the agent\'s commands are below.'); lvTerm(true); }
    else if (m.t === 'input' && !m.ok) toast(m.error, true);
    else if (m.t === 'error' || m.t === 'end') { $('workEmpty').textContent = m.message || m.reason || ''; LV.fails++; }
    else if (m.t === 'revoked') toast(LVL('憑證已失效，串流已中斷。', 'Credential revoked; the stream stopped.'), true);
  };
  ws.onclose = () => {
    if (LV.ws !== ws) return;
    LV.ws = null; LV.live = false; LV.fails++; lvBadge();
    // Retry a few times (agent switched tabs, daemon restart), then fall back to polling.
    if (W.open && !document.hidden && LV.fails < 4) setTimeout(() => { if (W.open && lvKey(W.cur) === key && !LV.ws) lvOpen(W.cur); }, 600 * LV.fails);
  };
}

// Patch mode (the Bot Desktop with the agent's browser on it): a base picture of the desktop
// plus the browser page as its own screencast frames, `{t:'patch', x, y, w, h}` in screen
// pixels. They are composed on a canvas over the picture; the picture underneath stays the
// <img> work.js maps clicks with (invisible while the canvas shows).
function lvCanvas() {
  let c = $('workCanvas');
  if (!c) {
    c = document.createElement('canvas');
    c.id = 'workCanvas'; c.className = 'work-canvas';
    $('workFrame').after(c);
  }
  return c;
}
function lvPatchMode(on) {
  $('workStage').classList.toggle('canvas-on', on);
  if (!on && $('workCanvas')) $('workCanvas').hidden = true;
}
async function lvPatch(m, blob) {
  const c = lvCanvas();
  if (!c.width || !LV.base) return; // a patch before any base picture: wait for one
  try {
    const bmp = await createImageBitmap(blob);
    const s = c.width / LV.base.w;
    c.getContext('2d').drawImage(bmp, m.x * s, m.y * s, m.w * s, m.h * s);
    bmp.close();
    LV.patches = (LV.patches || 0) + 1;
  } catch {}
}
async function lvBase(m, blob) {
  const c = lvCanvas();
  try {
    const bmp = await createImageBitmap(blob);
    if (c.width !== bmp.width || c.height !== bmp.height) { c.width = bmp.width; c.height = bmp.height; }
    c.getContext('2d').drawImage(bmp, 0, 0);
    bmp.close();
    LV.base = { w: m.width || c.width, h: m.height || c.height };
    c.hidden = false;
    lvPatchMode(true);
  } catch {}
}

function lvShow(from, blob) {
  // work.js rebuilds its target objects on every refresh: follow the current one.
  const cur = W.cur;
  if (lvKey(cur) !== lvKey(from)) return;
  const m = LV.meta || {};
  if (m.t === 'patch') return lvPatch(m, blob);
  if (m.mode === 'patch') lvBase(m, blob);
  else if ($('workStage').classList.contains('canvas-on')) { lvPatchMode(false); LV.base = null; }
  const img = $('workFrame');
  const url = URL.createObjectURL(blob);
  const old = LV.url;
  LV.url = url;
  img.onload = () => { if (old) URL.revokeObjectURL(old); };
  img.src = url;
  $('workEmpty').textContent = '';
  if (cur.kind === 'tab') {
    if (m.cssWidth) W.nat = { w: m.cssWidth, h: m.cssHeight };
    if (m.url != null && document.activeElement !== $('workUrl')) $('workUrl').value = m.url;
    if (m.title && m.title !== cur.title) { cur.title = m.title; workRenderTabs(); }
  }
}

// work.js calls workFrame on every tick and after each input: with a live stream open for the
// current target there is nothing to fetch; otherwise open one (or poll if streaming failed).
workFrame = async function (force) {
  if (!W.open || !W.cur || document.hidden) return;
  if (W.cur.kind === 'desktop' && !W.cur.running) { lvClose(); return; }
  const key = lvKey(W.cur);
  if (LV.ws && LV.key === key) return;
  if (LV.fails >= 4 && LV.key === key) return lvPollFrame(force);
  if (LV.key !== key) LV.fails = 0;
  lvOpen(W.cur);
};

const lvWorkShow = workShow;
workShow = async function (on) {
  if (!on) { lvClose(); lvTerm(false); }
  await lvWorkShow(on);
  if (on && !W.cur) lvTerm(true); // nothing to look at yet: show what the agent runs
};

const lvWorkSession = workSession;
workSession = function () { lvClose(); if (LV.termOpen) lvTermConnect(); lvWorkSession(); };

document.addEventListener('visibilitychange', () => {
  if (document.hidden) { lvClose(); if (LV.term) { LV.term.onclose = null; LV.term.close(); LV.term = null; } }
  else if (W.open) { workFrame(true); if (LV.termOpen) lvTermConnect(); }
});

// ── live terminal ──

function lvTermEls() {
  if ($('workTerm')) return;
  const pre = document.createElement('pre');
  pre.id = 'workTerm'; pre.className = 'work-term'; pre.hidden = true;
  pre.setAttribute('aria-live', 'polite');
  $('workStage').after(pre);
  const btn = document.createElement('button');
  btn.id = 'workTermBtn'; btn.type = 'button'; btn.className = 'btn ghost small';
  btn.textContent = LVL('終端機', 'Terminal');
  btn.title = LVL('代理正在執行的指令（即時）', 'The agent\'s commands, live');
  btn.onclick = () => lvTerm(!LV.termOpen);
  const live = document.createElement('span');
  live.id = 'workLive'; live.className = 'work-live'; live.hidden = true; live.textContent = 'LIVE';
  const sel = document.createElement('select');
  sel.id = 'workLevel'; sel.className = 'work-level';
  sel.title = LVL('即時畫面的畫質與畫面更新率', 'Live stream quality and frame rate');
  sel.setAttribute('aria-label', sel.title);
  for (const l of LV_LEVELS) { const o = document.createElement('option'); o.value = l.id; o.textContent = LVL(l.zh, l.en); sel.append(o); }
  sel.value = lvLevel.id;
  sel.onchange = () => lvChoose(sel.value);
  const foot = $('workTake').parentElement;
  foot.insertBefore(btn, $('workTake'));
  foot.insertBefore(sel, btn);
  foot.insertBefore(live, foot.firstChild);
}

function lvChoose(id) {
  lvLevel = LV_LEVELS.find((l) => l.id === id) || LV_LEVELS[0];
  try { localStorage.setItem('seagent.live.level', lvLevel.id); } catch {}
  // The open stream switches in place (no reconnect).
  if (LV.ws && LV.ws.readyState === 1) LV.ws.send(JSON.stringify({ t: 'tune', quality: lvLevel.q, fps: lvLevel.fps }));
}

// The stage changed size (pane widened, window resized, moved to a HiDPI screen): ask for
// frames at the new device-pixel size.
let lvResizeTimer = null;
new ResizeObserver(() => {
  clearTimeout(lvResizeTimer);
  lvResizeTimer = setTimeout(() => {
    if (!LV.ws || !LV.size || !W.cur) return;
    const sz = lvStageSize();
    if (Math.abs(sz.w - LV.size.w) / LV.size.w > 0.2 || Math.abs(sz.h - LV.size.h) / LV.size.h > 0.2) lvOpen(W.cur);
  }, 500);
}).observe($('workStage'));

function lvTerm(on) {
  lvTermEls();
  LV.termOpen = on;
  $('workTerm').hidden = !on;
  $('workTermBtn').classList.toggle('on', on);
  if (on) lvTermConnect();
  else if (LV.term) { LV.term.onclose = null; LV.term.close(); LV.term = null; }
}

function lvTermConnect() {
  if (!S.arp || document.hidden) return;
  if (LV.term) { LV.term.onclose = null; LV.term.close(); }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const q = new URLSearchParams({ kind: 'terminal' });
  if (S.current) q.set('session', S.current);
  const ws = lvSocket(`${proto}://${location.host}/view/live?${q}`);
  LV.term = ws; LV.termSession = S.current;
  ws.onmessage = (e) => {
    if (LV.term !== ws || typeof e.data !== 'string') return;
    let m; try { m = JSON.parse(e.data); } catch { return; }
    if (m.t === 'term') for (const ev of m.events) lvTermEvent(ev);
  };
  ws.onclose = () => { if (LV.term === ws) { LV.term = null; if (LV.termOpen && W.open) setTimeout(() => { if (LV.termOpen && !LV.term) lvTermConnect(); }, 1500); } };
}

const LV_TERM_MAX = 200_000; // characters kept on screen
function lvTermEvent(ev) {
  const pre = $('workTerm');
  const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 8;
  if (ev.e === 'start') {
    if (LV.cmds.has(ev.cmd)) return; // re-announced to a newcomer
    LV.cmds.set(ev.cmd, true);
    const h = document.createElement('div');
    h.className = 'cmd';
    h.textContent = `$ ${ev.script}`;
    const b = document.createElement('span');
    b.className = 'faint';
    b.textContent = `  [${ev.backend}]`;
    h.append(b);
    pre.append(h);
  } else if (ev.e === 'out') {
    pre.append(document.createTextNode(lvStripAnsi(ev.data)));
  } else if (ev.e === 'exit') {
    const x = document.createElement('div');
    x.className = ev.code === 0 ? 'faint' : 'err';
    x.textContent = ev.signal != null ? `[signal ${ev.signal}]` : `[exit ${ev.code}]`;
    pre.append(x);
  } else if (ev.e === 'gap') {
    const g = document.createElement('div');
    g.className = 'err';
    g.textContent = LVL(`…略過 ${ev.bytes} 位元組（輸出太快）`, `… ${ev.bytes} bytes skipped (output too fast)`);
    pre.append(g);
  }
  while (pre.textContent.length > LV_TERM_MAX && pre.firstChild) pre.firstChild.remove();
  if (stick) pre.scrollTop = pre.scrollHeight;
}

// Colour and cursor escapes would show as noise in a <pre>.
function lvStripAnsi(s) { return s.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, '').replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, '').replace(/\r(?!\n)/g, ''); }

lvTermEls();
