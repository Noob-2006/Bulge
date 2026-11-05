// seagent web UI: the workspace pane beside the transcript — the agent's browser tabs and
// desktops (the host Bot Desktop, desktop VMs), live, with take-over / hand-back.
// Data: crates/seagent-app/src/browser_view.rs — view.browser.list|frame|input,
// view.desktop.list|state|frame|input|takeover|handback. The agent and a human never act at
// once: input is accepted only from the viewer holding the desktop lease, and while a human
// holds it the agent's screen actions are refused.
// Uses app.js globals: S, $, esc, t, LANG, toast, store.
'use strict';

const W = { open: false, targets: [], cur: null, timer: null, busy: false, lease: null, holds: false, nat: null, dismissed: new Set(), wheel: 0 };
const WL = (zh, en) => (LANG === 'en' ? en : zh);
// A random id for this tab: the lease remembers which viewer took control.
const VIEWER = (() => {
  let v = null;
  try { v = sessionStorage.getItem('seagent.viewer'); } catch {}
  if (!v) {
    const a = new Uint8Array(12);
    crypto.getRandomValues(a);
    v = 'web-' + Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
    try { sessionStorage.setItem('seagent.viewer', v); } catch {}
  }
  return v;
})();

const tabKey = (x) => (x.kind === 'tab' ? `tab:${x.key}:${x.targetId}` : `desk:${x.id}`);

async function workTargets() {
  const out = [];
  let list = null;
  try { list = await S.arp.call('view.browser.list', S.current ? { session: S.current } : {}); } catch {}
  const mine = list && list.session ? list.session.targetId : null;
  // A desktop VM's Chromium is the agent's browser there: show it as that desktop (the screen
  // a person sees, panel and all), not as a separate tab.
  const skey = list && list.session ? String(list.session.key || '') : '';
  const agentDesk = skey.startsWith('vm:') ? skey : null;
  for (const b of (list && list.browsers) || []) {
    if (String(b.key || '').startsWith('vm:')) continue;
    for (const tb of b.tabs || []) out.push({ kind: 'tab', key: b.key, targetId: tb.targetId, title: tb.title || tb.url || 'tab', url: tb.url || '', agent: tb.targetId === mine, novnc: b.novnc });
  }
  // Desktops: every running target the daemon knows (host Bot Desktop, desktop VMs).
  let desks = null;
  try { desks = await S.arp.call('view.desktop.list', {}); } catch {}
  // Stopped desktop VMs stay listed so they can be started from here.
  for (const d of Array.isArray(desks) ? desks : []) if (d.running || (d.kind === 'vm' && d.imageBuilt)) out.push({ kind: 'desktop', id: d.id, title: d.label || d.id, width: d.width, height: d.height, vm: d.kind === 'vm', running: !!d.running, controller: d.controller, agent: d.id === agentDesk });
  return { targets: out, mine };
}

function workRenderTabs() {
  const nav = $('workTabs');
  nav.innerHTML = W.targets.map((x, i) => `<button type="button" class="wtab${W.cur && tabKey(W.cur) === tabKey(x) ? ' on' : ''}${x.agent ? ' agent' : ''}" data-i="${i}" title="${esc(x.url || x.title)}"><span class="k">${x.kind === 'tab' ? 'web' : x.vm ? 'vm' : 'desk'}</span>${x.kind === 'desktop' && !x.running ? '<span class="light"></span>' : ''}<span class="t">${esc(x.title)}</span></button>`).join('');
  for (const b of nav.querySelectorAll('[data-i]')) b.onclick = () => { W.cur = W.targets[+b.dataset.i]; W.pinned = true; workRenderTabs(); workFrame(true); };
  const n = W.targets.length;
  $('workBadge').hidden = !n;
  $('workBadge').textContent = n;
}

async function workRefresh() {
  if (!S.arp) return;
  const { targets, mine } = await workTargets();
  W.targets = targets;
  // Follow the agent's current tab unless the person picked one; keep the pick while it lives.
  const still = W.cur && targets.find((x) => tabKey(x) === tabKey(W.cur));
  if (!still || (!W.pinned && mine && !still.agent && targets.some((x) => x.agent))) W.cur = targets.find((x) => x.agent) || still || targets[0] || null;
  else W.cur = still;
  workRenderTabs();
  $('workBar').hidden = !(W.cur && W.cur.kind === 'tab');
  $('workEmpty').textContent = W.cur ? '' : WL('這個對話還沒有開瀏覽器或桌面。代理用 browser 或 computer_use 工具時，畫面會出現在這裡。', 'No browser or desktop yet. When the agent uses the browser or computer-use tools, it shows up here.');
  if (!W.cur) $('workFrame').removeAttribute('src');
  if (W.cur && W.cur.kind === 'desktop' && !W.cur.running) {
    $('workFrame').removeAttribute('src');
    $('workEmpty').innerHTML = `<div><p>${esc(W.cur.title)} · ${esc(WL('已停止', 'stopped'))}</p><button class="btn" id="workStart" data-write>${esc(WL('啟動桌面 VM', 'Start desktop VM'))}</button><p class="faint">${esc(WL('開機約需 20–40 秒。', 'Boot takes about 20–40 s.'))}</p></div>`;
    $('workStart').onclick = async () => {
      $('workStart').disabled = true;
      $('workStart').textContent = WL('開機中…', 'Booting…');
      try { await S.arp.call('view.vm.start', { name: W.cur.id.replace(/^vm:/, '') }); } catch (e) { toast(e.message, true); }
      await workRefresh();
      workLoop();
    };
  }
  await workLease();
}

async function workLease() {
  try {
    const st = await S.arp.call('view.desktop.state', W.cur && W.cur.kind === 'desktop' ? { viewer: VIEWER, target: W.cur.id } : { viewer: VIEWER });
    W.lease = st.lease || {};
    W.holds = !!st.viewerHolds;
  } catch { W.lease = null; W.holds = false; }
  const human = W.lease && W.lease.holder === 'human';
  $('work').classList.toggle('human', W.holds);
  $('workUrl').readOnly = !W.holds;
  $('workWho').innerHTML = W.holds
    ? `<span class="star pulse" style="--size:10px"></span> ${esc(WL('你正在控制 · 代理暫停', 'You have control · agent paused'))}`
    : human
      ? `<span class="light warn"></span> ${esc(WL('另一位使用者正在控制', 'Another person has control'))}`
      : `<span class="star" style="--size:10px"></span> ${esc(WL('代理控制中', 'Agent in control'))}`;
  $('workTake').textContent = W.holds ? WL('交還給代理', 'Hand back') : WL('接手控制', 'Take control');
  $('workTake').classList.toggle('ghost', W.holds);
  $('workTake').disabled = human && !W.holds;
}

async function workFrame(force) {
  if (!W.open || !W.cur || (W.busy && !force) || document.hidden) return;
  if (W.cur.kind === 'desktop' && !W.cur.running) return;
  W.busy = true;
  const cur = W.cur;
  try {
    let r;
    if (cur.kind === 'tab') {
      const w = Math.min(1600, Math.round($('workStage').clientWidth * (devicePixelRatio || 1)));
      r = await S.arp.call('view.browser.frame', { key: cur.key, targetId: cur.targetId, maxWidth: Math.max(320, w), quality: 62 });
      if (document.activeElement !== $('workUrl')) $('workUrl').value = r.url || '';
      if (r.title && r.title !== cur.title) { cur.title = r.title; workRenderTabs(); }
      W.nat = { w: r.cssWidth, h: r.cssHeight };
    } else {
      r = await S.arp.call('view.desktop.frame', { target: cur.id });
    }
    if (W.cur === cur) $('workFrame').src = `data:${r.mime || 'image/png'};base64,${r.data}`;
    $('workEmpty').textContent = '';
  } catch (e) {
    if (W.cur === cur) $('workEmpty').textContent = e.message;
  } finally { W.busy = false; }
}

function workLoop() {
  clearInterval(W.timer);
  if (!W.open) return;
  let n = 0;
  W.timer = setInterval(() => {
    n++;
    workFrame(false);
    if (n % 6 === 0) workRefresh();
  }, W.cur && W.cur.kind === 'desktop' ? 1200 : 700);
}

async function workShow(on) {
  W.open = on;
  $('work').hidden = !on;
  $('workBtn').classList.toggle('on', on);
  if (on) { await workRefresh(); workFrame(true); workLoop(); } else clearInterval(W.timer);
}

// Where on the target a point of the shown image is: fractions for a browser tab (view.browser
// .input), pixels of the screen for a desktop (view.desktop.input).
function workPoint(e) {
  const img = $('workFrame');
  const b = img.getBoundingClientRect();
  // The picture inside the element (object-fit: contain leaves bars on two sides).
  const s = Math.min(b.width / (img.naturalWidth || 1), b.height / (img.naturalHeight || 1));
  const r = { width: img.naturalWidth * s, height: img.naturalHeight * s };
  r.left = b.left + (b.width - r.width) / 2;
  r.top = b.top + (b.height - r.height) / 2;
  const fx = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
  const fy = Math.min(1, Math.max(0, (e.clientY - r.top) / r.height));
  const ping = $('workPing');
  const sr = $('workStage').getBoundingClientRect();
  ping.style.left = e.clientX - sr.left + 'px';
  ping.style.top = e.clientY - sr.top + 'px';
  ping.hidden = true; void ping.offsetWidth; ping.hidden = false;
  return W.cur.kind === 'tab' ? { x: fx, y: fy } : { x: Math.round(fx * img.naturalWidth), y: Math.round(fy * img.naturalHeight) };
}
async function workInput(ev) {
  if (!W.holds || !W.cur) return;
  try {
    if (W.cur.kind === 'tab') await S.arp.call('view.browser.input', { viewer: VIEWER, key: W.cur.key, targetId: W.cur.targetId, event: ev });
    else await S.arp.call('view.desktop.input', { viewer: VIEWER, target: W.cur.id, event: ev.type === 'text' ? { type: 'type', text: ev.text } : ev });
  } catch (e) { toast(e.message, true); }
  setTimeout(() => workFrame(true), 150);
}

$('workFrame').addEventListener('click', (e) => { if (W.holds) workInput({ type: 'click', button: 'left', ...workPoint(e) }); else toast(WL('先按「接手控制」才能操作畫面。', 'Take control first to use the screen.')); });
$('workFrame').addEventListener('dblclick', (e) => { if (W.holds) workInput({ type: 'dblclick', button: 'left', ...workPoint(e) }); });
$('workFrame').addEventListener('contextmenu', (e) => { if (!W.holds) return; e.preventDefault(); workInput({ type: 'click', button: 'right', ...workPoint(e) }); });
$('workStage').addEventListener('wheel', (e) => {
  if (!W.holds) return;
  e.preventDefault();
  const now = Date.now();
  if (now - W.wheel < 120) return;
  W.wheel = now;
  workInput({ type: 'scroll', ...workPoint(e), dx: Math.round(e.deltaX), dy: Math.round(e.deltaY) });
}, { passive: false });
// Keyboard: a hidden textarea takes the focus while a person has control, so an input method
// (注音、倉頡、拼音…) can compose into it; committed text goes to the target as `text`, special
// keys and shortcuts as `key`. A plain focusable div would never receive IME text.
const KEYS = new Set(['Enter', 'Backspace', 'Tab', 'Escape', 'Delete', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown']);
const KB = $('workKeys');
function workFocusKeys() { if (W.holds) KB.focus({ preventScroll: true }); }
KB.addEventListener('keydown', (e) => {
  if (!W.holds || e.isComposing || e.keyCode === 229) return;
  if (e.ctrlKey || e.metaKey || e.altKey) {
    if (e.key.length === 1 && !(e.ctrlKey && e.key.toLowerCase() === 'v')) { e.preventDefault(); workInput({ type: 'key', key: (e.metaKey ? 'Meta+' : e.altKey && !e.ctrlKey ? 'Alt+' : 'Control+') + e.key }); }
    return;
  }
  if (KEYS.has(e.key)) { e.preventDefault(); workInput({ type: 'key', key: e.key }); }
});
KB.addEventListener('compositionend', (e) => { if (W.holds && e.data) workInput({ type: 'text', text: e.data }); KB.value = ''; });
KB.addEventListener('input', (e) => {
  if (!W.holds || e.isComposing) return;
  // Plain typing (no IME) and anything inserted outside a composition.
  if (e.inputType === 'insertText' && e.data) workInput({ type: 'text', text: e.data });
  KB.value = '';
});
KB.addEventListener('paste', (e) => { if (!W.holds) return; const tx = e.clipboardData && e.clipboardData.getData('text'); e.preventDefault(); if (tx) workInput({ type: 'text', text: tx }); });
$('workFrame').addEventListener('mouseup', () => setTimeout(workFocusKeys, 0));
$('workStage').addEventListener('focus', workFocusKeys);
$('workUrl').addEventListener('keydown', (e) => { if (e.key === 'Enter' && W.holds) { e.preventDefault(); workInput({ type: 'navigate', url: $('workUrl').value.trim() }); workFocusKeys(); } });
for (const b of document.querySelectorAll('[data-nav]')) b.onclick = () => { if (W.holds) workInput({ type: b.dataset.nav }); else toast(WL('先按「接手控制」才能操作畫面。', 'Take control first to use the screen.')); };
$('workTake').onclick = async () => {
  try {
    const target = W.cur && W.cur.kind === 'desktop' ? W.cur.id : undefined;
    if (W.holds) await S.arp.call('view.desktop.handback', { viewer: VIEWER, target });
    else await S.arp.call('view.desktop.takeover', { viewer: VIEWER, target, reason: WL('使用者從主控台接手', 'taken over from the web console') });
  } catch (e) { toast(e.message, true); }
  await workLease();
  if (W.holds) workFocusKeys();
};
$('workBtn').onclick = () => { if (W.open) { W.dismissed.add(S.current); workShow(false); } else { if (S.view !== 'chat' && S.current) openSession(S.current); W.dismissed.delete(S.current); workShow(true); } };
$('workClose').onclick = () => { W.dismissed.add(S.current); workShow(false); };
$('workWide').onclick = () => $('work').classList.toggle('wide');

// app.js calls this for every tool call it draws: browser / computer-use calls open the pane
// (unless the person closed it for this conversation) and show what the agent just did.
function workNote(b) {
  if (!/^(browser|computer|screen)/.test(b.name || '')) return;
  const arg = typeof toolArg === 'function' ? toolArg(b.name, b.input) : '';
  $('workLast').textContent = `${b.name} ${arg}`.trim();
  if (!W.open && !W.dismissed.has(S.current) && S.view === 'chat') workShow(true);
  else if (W.open) setTimeout(workRefresh, 400);
}
// Switching conversations: refresh what the pane shows for the new one.
function workSession() { W.pinned = false; W.cur = null; if (W.open) workRefresh().then(() => workFrame(true)); }
// Keep the lease on a closed tab from blocking the agent: hand back when leaving.
addEventListener('pagehide', () => { if (W.holds && S.arp) S.arp.call('view.desktop.handback', { viewer: VIEWER }).catch(() => {}); });
