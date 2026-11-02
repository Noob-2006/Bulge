// ark web / desktop UI: an ARP (JSON-RPC 2.0 over WebSocket) client.
// Same methods and events as the terminal UI and the unix-socket daemon protocol.
'use strict';

const $ = (id) => document.getElementById(id);
// Per-page CSP nonce (ui.rs); MCP App views inherit the page policy, so their scripts need it.
const NONCE = (document.currentScript && document.currentScript.nonce) || '';
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};

// ── starfield ──
(function stars() {
  const f = $('starfield');
  const n = Math.round(Math.min(40, (innerWidth * innerHeight) / 40000));
  for (let i = 0; i < n; i++) {
    const s = document.createElement('span');
    s.className = 'star';
    s.style.left = Math.random() * 100 + '%';
    s.style.top = Math.random() * 100 + '%';
    s.style.setProperty('--size', 4 + Math.random() * 10 + 'px');
    s.style.animationDelay = -Math.random() * 6 + 's';
    s.style.animationDuration = 4 + Math.random() * 6 + 's';
    f.appendChild(s);
  }
})();

// ── tiny markdown (escape first, then a safe subset) ──
function esc(s) { return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function md(src) {
  const parts = String(src).split(/```(\w*)\n?([\s\S]*?)```/g);
  let out = '';
  for (let i = 0; i < parts.length; i++) {
    if (i % 3 === 0) {
      let t = esc(parts[i]);
      t = t.replace(/`([^`\n]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
        .replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,!?]|$)/g, '$1<em>$2</em>')
        .replace(/~~([^~\n]+)~~/g, '<del>$1</del>')
        .replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
        .replace(/^#{1,6} (.+)$/gm, '<strong>$1</strong>')
        .replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')
        .replace(/^[-*] (.+)$/gm, '• $1')
        .replace(/\n/g, '<br>');
      out += t;
    } else if (i % 3 === 2) {
      out += `<pre><code>${esc(parts[i])}</code></pre>`;
    }
  }
  return out;
}

// ── ARP client ──
class Arp {
  constructor(token) {
    this.token = token; this.next = 1; this.waiting = new Map(); this.handlers = new Map(); this.ws = null; this.ready = null;
  }
  connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    this.ws = new WebSocket(`${proto}://${location.host}/arp`, ['arp', `ark.token.${this.token}`]);
    this.ready = new Promise((ok, fail) => {
      this.ws.onopen = () => ok();
      this.ws.onerror = () => fail(new Error('連線失敗'));
    });
    this.ws.onmessage = (e) => this.onMessage(JSON.parse(e.data));
    this.ws.onclose = () => { for (const [, w] of this.waiting) w.fail(new Error('連線中斷')); this.waiting.clear(); this.emit('close', {}); };
    return this.ready;
  }
  call(method, params = {}) {
    const id = this.next++;
    this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    return new Promise((ok, fail) => this.waiting.set(id, { ok, fail }));
  }
  on(m, f) { this.handlers.set(m, f); }
  emit(m, p) { const f = this.handlers.get(m); if (f) f(p); }
  onMessage(v) {
    if (v.method) return this.emit(v.method, v.params || {});
    const w = this.waiting.get(v.id);
    if (!w) return;
    this.waiting.delete(v.id);
    v.error ? w.fail(new Error(v.error.message)) : w.ok(v.result);
  }
}

// ── app state ──
const S = { arp: null, sessions: [], current: null, sub: null, streaming: null, running: false, pending: new Map() };

function setConn(text) { $('conn').textContent = text; }
function setStatus(running) {
  S.running = running;
  $('stop').hidden = !running;
  $('status').innerHTML = running ? '<span class="star pulse" style="--size:12px"></span> 工作中' : '';
}

function addMsg(kind, who, html) {
  const el = $('tpl-msg').content.firstElementChild.cloneNode(true);
  el.classList.add(...kind.split(' '));
  el.querySelector('.who').innerHTML = who;
  el.querySelector('.body').innerHTML = html;
  $('log').appendChild(el);
  $('log').scrollTop = $('log').scrollHeight;
  return el;
}

function textOf(m) {
  return (m.content || []).map((b) => (b.type === 'text' ? b.text : '')).join('');
}

function renderEvent(ev) {
  const k = ev.type;
  if (k === 'message') {
    const m = ev.message;
    if (m.role === 'user') {
      const t = (m.content || []).map((b) => b.type === 'text' ? b.text : b.type === 'tool_result' ? `↳ ${String(b.content).slice(0, 600)}` : '').join('');
      const tool = (m.content || []).some((b) => b.type === 'tool_result');
      if (t.trim()) addMsg(tool ? 'tool' : 'user', tool ? '工具結果' : '你', tool ? esc(t) : md(t));
    } else {
      const t = textOf(m);
      if (S.streaming) {
        // The final message replaces what was streamed so far.
        if (t.trim()) {
          S.streaming.el.querySelector('.who').innerHTML = '<span class="star" style="--size:11px"></span> ark';
          S.streaming.el.querySelector('.body').innerHTML = md(t);
        } else S.streaming.el.remove();
        S.streaming = null;
      } else if (t.trim()) addMsg('assistant', '<span class="star" style="--size:11px"></span> ark', md(t));
      for (const b of m.content || []) if (b.type === 'tool_use') addMsg('tool', `呼叫 ${esc(b.name)}`, esc(JSON.stringify(b.input, null, 1)).slice(0, 2000));
    }
  } else if (k === 'turn_start') setStatus(true);
  else if (k === 'turn_end') { setStatus(false); S.streaming = null; }
  else if (k === 'notice') addMsg('notice', '', esc(ev.text));
  else if (k === 'error') addMsg('notice', '', '⚠ ' + esc(ev.message));
  else if (k === 'gate') addMsg('notice', '', `閘門 ${esc(ev.gate)}：${esc(ev.verdict)} — ${esc(ev.reason)}`);
  else if (k === 'tool_settled' && ev.ui_resource) renderApp(ev.ui_resource);
}

// ── MCP Apps (io.modelcontextprotocol/ui): ui:// views in sandboxed iframes ──
// The view talks JSON-RPC over postMessage: ui/initialize → ui/notifications/initialized
// → we push tool-input / tool-result; tools/call is proxied through ARP (mcp.app_call,
// which gates anything not read-only); ui/notifications/size-changed resizes the frame.
const APPS = new Map(); // contentWindow → view state
function appCsp(csp) {
  const list = (a) => (Array.isArray(a) ? a : []).filter((d) => typeof d === 'string' && /^https:\/\/[A-Za-z0-9.*-]+(:\d+)?$/.test(d)).join(' ');
  const res = list(csp && csp.resourceDomains), con = list(csp && csp.connectDomains);
  return `default-src 'none'; script-src 'nonce-${NONCE}' ${res}; style-src 'unsafe-inline' ${res}; img-src data: blob: ${res}; font-src data: ${res}; media-src data: ${res}; connect-src ${con || "'none'"}; frame-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'`;
}
function appDoc(ui) {
  const meta = `<meta http-equiv="Content-Security-Policy" content="${esc(appCsp(ui.csp))}">`;
  let html = String(ui.html || '').replace(/<script\b(?![^>]*\bnonce=)/gi, `<script nonce="${NONCE}"`);
  // The policy must sit in <head>, after any doctype (a meta before it would force quirks mode).
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, (h) => h + meta);
  if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, (h) => h + '<head>' + meta + '</head>');
  if (/^\s*<!doctype[^>]*>/i.test(html)) return html.replace(/^\s*<!doctype[^>]*>/i, (d) => d + '<head>' + meta + '</head>');
  return '<head>' + meta + '</head>' + html;
}
function renderApp(ui) {
  const el = addMsg('tool app', `介面 ${esc(ui.server)} · ${esc(ui.tool)}`, '');
  const frame = document.createElement('iframe');
  frame.className = 'mcp-app';
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.title = `${ui.server} ${ui.tool}`;
  if (ui.prefersBorder === false) frame.classList.add('borderless');
  frame.srcdoc = appDoc(ui);
  el.querySelector('.body').appendChild(frame);
  const st = { ui, frame, session: S.current, ready: false, initialized: false };
  // The WindowProxy is stable across the srcdoc navigation, so register before the view's scripts run.
  APPS.set(frame.contentWindow, st);
}
// ── plugin UI panels: same sandbox and CSP as MCP App views; the panel's JSON-RPC
// requests go to the plugin through ARP (plugins.ui_call). ──
async function openPluginPanel(plugin, ui) {
  $('panelTitle').textContent = `${ui.title || ui.id} · ${plugin}`;
  $('panelBody').innerHTML = '<span class="star spin"></span>';
  $('panelDialog').showModal();
  try {
    const r = await S.arp.call('plugins.ui', { plugin, id: ui.id });
    const frame = document.createElement('iframe');
    frame.className = 'mcp-app plugin-panel';
    frame.setAttribute('sandbox', 'allow-scripts');
    frame.setAttribute('referrerpolicy', 'no-referrer');
    frame.title = `${plugin} ${ui.id}`;
    frame.srcdoc = appDoc({ html: r.html, csp: r.csp });
    $('panelBody').innerHTML = '';
    $('panelBody').appendChild(frame);
    APPS.set(frame.contentWindow, { plugin, panel: ui.id, frame, ui: {}, ready: true, initialized: true });
  } catch (e) { $('panelBody').textContent = e.message; }
}
async function loadPluginPanels() {
  const nav = $('pluginPanels');
  nav.innerHTML = '';
  let list = [];
  try { list = await S.arp.call('plugins.list'); } catch { return; }
  for (const p of list) for (const ui of p.ui || []) {
    if ((ui.surface || 'tab') !== 'tab') continue;
    const b = document.createElement('button');
    b.className = 'btn ghost small';
    b.textContent = ui.title || ui.id;
    b.title = `${p.name} 外掛面板`;
    b.onclick = () => openPluginPanel(p.name, ui);
    nav.appendChild(b);
  }
  S.settingsPanels = list.flatMap((p) => (p.ui || []).filter((u) => u.surface === 'settings').map((u) => [p.name, u]));
}
async function pluginFrameMessage(st, m) {
  const reply = (result) => m.id !== undefined && appPost(st, { jsonrpc: '2.0', id: m.id, result });
  const fail = (code, message) => m.id !== undefined && appPost(st, { jsonrpc: '2.0', id: m.id, error: { code, message } });
  if (m.method === 'ui/notifications/size-changed') {
    const h = m.params && m.params.height;
    if (typeof h === 'number' && isFinite(h)) st.frame.style.height = Math.min(1200, Math.max(80, Math.round(h))) + 'px';
    return;
  }
  if (m.method === 'ping') return reply({});
  try { reply(await S.arp.call('plugins.ui_call', { plugin: st.plugin, id: st.panel, method: m.method, params: m.params || {} })); }
  catch (err) { fail(-32000, err.message); }
}

function appPost(st, msg) { st.frame.contentWindow && st.frame.contentWindow.postMessage(msg, '*'); }
window.addEventListener('message', async (e) => {
  const st = APPS.get(e.source);
  const m = e.data;
  // Only our own views, only JSON-RPC 2.0 (opaque-origin frames report origin "null").
  if (!st || !m || typeof m !== 'object' || m.jsonrpc !== '2.0' || typeof m.method !== 'string') return;
  if (st.plugin) return pluginFrameMessage(st, m);
  const reply = (result) => m.id !== undefined && appPost(st, { jsonrpc: '2.0', id: m.id, result });
  const fail = (code, message) => m.id !== undefined && appPost(st, { jsonrpc: '2.0', id: m.id, error: { code, message } });
  switch (m.method) {
    case 'ui/initialize':
      st.ready = true;
      return reply({
        protocolVersion: (m.params && m.params.protocolVersion) || '2026-01-26',
        hostInfo: { name: 'ark', version: '1' },
        hostCapabilities: { serverTools: {}, openLinks: {} },
        hostContext: { theme: matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light', displayMode: 'inline', availableDisplayModes: ['inline'], containerDimensions: { width: st.frame.clientWidth, maxHeight: 1200 }, locale: navigator.language, timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone, platform: 'web' },
      });
    case 'ui/notifications/initialized':
      if (!st.ready || st.initialized) return;
      st.initialized = true;
      appPost(st, { jsonrpc: '2.0', method: 'ui/notifications/tool-input', params: { arguments: st.ui.toolInput || {} } });
      appPost(st, { jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: st.ui.toolResult || {} });
      return;
    case 'ui/notifications/size-changed': {
      const h = m.params && m.params.height;
      if (typeof h === 'number' && isFinite(h)) st.frame.style.height = Math.min(1200, Math.max(80, Math.round(h))) + 'px';
      return;
    }
    case 'ping': return reply({});
    case 'tools/call':
      if (!st.initialized) return fail(-32002, 'MCP App initialization is incomplete');
      try {
        const p = m.params || {};
        reply(await S.arp.call('mcp.app_call', { server: st.ui.server, name: p.name, arguments: p.arguments || {}, session: st.session }));
      } catch (err) { fail(-32000, err.message); }
      return;
    case 'ui/open-link': {
      const url = m.params && m.params.url;
      if (typeof url !== 'string' || !/^https:\/\//.test(url)) return fail(-32602, 'only https links');
      if (confirm(`${st.ui.server} 想開啟連結：\n${url}`)) { window.open(url, '_blank', 'noopener,noreferrer'); return reply({}); }
      return fail(-32001, 'declined');
    }
    default:
      return fail(-32601, `method ${m.method} not supported by ark`);
  }
});

function onDelta(p) {
  if (p.session !== S.current) return;
  if (!S.streaming) S.streaming = { el: addMsg('assistant', '<span class="star spin" style="--size:11px"></span> ark', ''), text: '', think: '' };
  if (p.thinking) S.streaming.think += p.text; else S.streaming.text += p.text;
  const th = S.streaming.think ? `<div class="thinking">${esc(S.streaming.think.slice(-400))}</div>` : '';
  S.streaming.el.querySelector('.body').innerHTML = th + md(S.streaming.text);
  $('log').scrollTop = $('log').scrollHeight;
}

function onPending(p) {
  if (p.session && S.current && p.session !== S.current) return;
  if (S.pending.has(p.id)) return;
  const box = document.createElement('div');
  box.className = 'ask panel cornered';
  box.innerHTML = '<span class="star corner tl"></span><span class="star corner br"></span>';
  if (p.kind === 'approval') {
    box.innerHTML += `<div class="q"><span class="star pulse" style="--size:18px"></span><div><strong>需要核准：${esc(p.gate)}</strong><div class="dim">${esc(p.tool)} — ${esc(p.reason)}</div><pre>${esc(p.summary || '')}</pre></div></div>
      <div class="acts"><button class="btn danger small" data-a="deny">拒絕</button><button class="btn ghost small" data-a="always">本次對話都允許</button><button class="btn small" data-a="once">允許一次</button></div>`;
  } else {
    box.innerHTML += `<div class="q"><span class="star pulse" style="--size:18px"></span><div><strong>ark 想問你</strong><div>${md(p.question)}</div></div></div>
      <input type="text" placeholder="你的回答"><div class="acts"><button class="btn small" data-a="answer">回答</button></div>`;
  }
  box.addEventListener('click', async (e) => {
    const a = e.target.dataset.a;
    if (!a) return;
    const answer = a === 'answer' ? box.querySelector('input').value : a;
    try { await S.arp.call('gate.answer', { id: p.id, answer }); } catch (err) { addMsg('notice', '', esc(err.message)); }
    box.remove(); S.pending.delete(p.id);
  });
  S.pending.set(p.id, box);
  $('pending').appendChild(box);
}

async function loadSessions() {
  S.sessions = await S.arp.call('session.list', { limit: 100 });
  const nav = $('sessions');
  nav.innerHTML = '';
  for (const s of S.sessions) {
    const b = document.createElement('button');
    b.className = 'sess' + (s.id === S.current ? ' active' : '');
    b.innerHTML = `${s.running ? '<span class="star pulse" style="--size:10px"></span>' : ''}<span class="t">${esc(s.title || s.id)}</span><span class="m">${s.messages}</span>`;
    b.onclick = () => openSession(s.id);
    nav.appendChild(b);
  }
  if (!S.sessions.length) nav.innerHTML = '<div class="dim" style="padding:8px">還沒有對話</div>';
}

async function openSession(id) {
  S.current = id; S.streaming = null;
  $('log').innerHTML = '';
  $('side').classList.remove('open');
  const s = S.sessions.find((x) => x.id === id);
  $('title').textContent = s ? (s.title || s.id) : id;
  setStatus(!!(s && s.running));
  if (S.sub) { S.arp.call('unsubscribe', { subscription: S.sub }).catch(() => {}); }
  S.sub = S.arp.next;
  S.arp.call('subscribe', { id, from_seq: 0 }).catch((e) => addMsg('notice', '', esc(e.message)));
  for (const b of $('sessions').children) b.classList.toggle('active', b.textContent.includes(s ? (s.title || s.id) : id));
}

async function newSession() {
  const ws = store.get('ark.workspace') || '';
  // No workspace chosen: the server uses [app] workspace (or its own directory), never "/".
  const { id } = await S.arp.call('session.create', ws ? { workspace: ws, title: '網頁對話' } : { title: '網頁對話' }).catch((e) => (addMsg('notice', '', esc(e.message)), {}));
  if (!id) return;
  await loadSessions();
  openSession(id);
}

async function send(text) {
  if (!text.trim()) return;
  if (!S.current) await newSession();
  if (!S.current) return;
  try { await S.arp.call('session.submit', { id: S.current, text, source: 'web' }); setStatus(true); }
  catch (e) { addMsg('notice', '', '⚠ ' + esc(e.message)); }
}

async function showPanel(title, fn, after) {
  $('panelTitle').textContent = title;
  $('panelBody').innerHTML = '<span class="star spin"></span>';
  $('panelDialog').showModal();
  try { $('panelBody').innerHTML = await fn(); if (after) after(); } catch (e) { $('panelBody').textContent = e.message; }
}

function row(cells) { return '<tr>' + cells.map((c) => `<td>${c}</td>`).join('') + '</tr>'; }

async function start(token) {
  S.arp = new Arp(token);
  setConn('連線中…');
  try { await S.arp.connect(); } catch (e) { setConn('連線失敗'); store.del('ark.token'); return askToken(); }
  S.arp.on('ready', (p) => setConn(`已連線 · ${p.server.version}`));
  // Two subscriptions share the socket: the global one feeds the sidebar and approvals,
  // the session one feeds the transcript. Route by subscription id so nothing renders twice.
  S.arp.on('event', (p) => {
    if (p.subscription === S.globalSub) { if (p.event && (p.event.type === 'turn_end' || p.event.type === 'header')) loadSessions(); return; }
    if (p.session === S.current) renderEvent(p.event);
  });
  S.arp.on('delta', (p) => { if (p.subscription !== S.globalSub) onDelta(p); });
  S.arp.on('pending', (p) => { if (p.subscription === S.globalSub) onPending(p); });
  S.arp.on('close', () => { setConn('連線中斷，3 秒後重試'); setTimeout(() => start(token), 3000); });
  // A second subscription follows every session for approvals and the sidebar.
  S.globalSub = S.arp.next;
  S.arp.call('subscribe', {}).catch(() => {});
  await loadSessions();
  loadPluginPanels();
  for (const p of await S.arp.call('gate.pending')) onPending(p);
  if (!S.current && S.sessions[0]) openSession(S.sessions[0].id);
  else if (!S.sessions.length) $('log').innerHTML = '<div class="empty"><span class="star twinkle"></span><div>開始一段新對話吧</div></div>';
}

function askToken() {
  $('login').showModal();
  $('loginForm').onsubmit = () => {
    const t = $('token').value.trim();
    if ($('remember').checked) store.set('ark.token', t);
    start(t);
  };
}

// ── wiring ──
$('composer').onsubmit = (e) => { e.preventDefault(); const t = $('input').value; $('input').value = ''; autosize(); send(t); };
$('input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); $('composer').requestSubmit(); } });
function autosize() { const t = $('input'); t.style.height = 'auto'; t.style.height = Math.min(t.scrollHeight, innerHeight * 0.4) + 'px'; }
$('input').addEventListener('input', autosize);
$('newSession').onclick = newSession;
$('stop').onclick = () => S.current && S.arp.call('session.interrupt', { id: S.current });
$('menu').onclick = () => $('side').classList.toggle('open');
$('panelClose').onclick = () => $('panelDialog').close();
$('showNodes').onclick = () => showPanel('裝置（nodes）', async () => {
  const r = await S.arp.call('node.list');
  const pend = await S.arp.call('node.pair.list');
  let h = '<table class="kv"><tr><th>裝置</th><th>平台</th><th>指令</th></tr>';
  for (const n of r.connected) h += row([esc(n.name), esc(n.platform), esc(n.commands.join(', '))]);
  h += '</table>';
  if (pend.length) h += '<h3>等待配對</h3><table class="kv">' + pend.map((p) => row([esc(p.name), esc(p.platform), `<code>${esc(p.code)}</code>`])).join('') + '</table><p class="dim">在主機上執行 <code>ark nodes approve &lt;code&gt;</code> 核准。</p>';
  return h;
});
$('showSettings').onclick = () => showPanel('設定', async () => {
  const m = await S.arp.call('models.list');
  const tools = await S.arp.call('tools.list');
  return `<table class="kv">${row(['預設模型', esc(m.default)])}${row(['備援', esc((m.fallback || []).join(', ') || '—')])}${row(['輔助模型', esc(m.aux)])}${row(['工具', String(tools.length)])}</table>
    <p><label class="dim">新對話的工作目錄</label><input type="text" id="wsInput" value="${esc(store.get('ark.workspace') || '')}" placeholder="/home/you/project"></p>
    ${(S.settingsPanels || []).map(([p, u], i) => `<p><button class="btn ghost small" data-panel="${i}">${esc(u.title || u.id)}（${esc(p)}）</button></p>`).join('')}
    <p><button class="btn ghost small" id="logout">登出這台裝置</button></p>`;
}, () => {
  for (const b of $('panelBody').querySelectorAll('[data-panel]')) { const [p, u] = S.settingsPanels[+b.dataset.panel]; b.onclick = () => openPluginPanel(p, u); }
  // CSP forbids inline handlers: bind after rendering.
  $('wsInput').onchange = (e) => store.set('ark.workspace', e.target.value);
  $('logout').onclick = () => { store.del('ark.token'); location.reload(); };
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

// Token: #token=… (from `ark app open`), saved token, or ask.
const fromHash = new URLSearchParams(location.hash.slice(1)).get('token');
if (fromHash) { store.set('ark.token', fromHash); history.replaceState(null, '', location.pathname); }
const saved = fromHash || store.get('ark.token');
saved ? start(saved) : askToken();
// A link with #token=… opened on an already-loaded page.
addEventListener('hashchange', () => { if (new URLSearchParams(location.hash.slice(1)).get('token')) location.reload(); });
