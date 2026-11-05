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

// ── i18n: zh-Hant (default) and en, switchable per device ─────────────────────────────
// Every shell string goes through `t()`; page bodies in pages.js stay in the configured
// language of their own module (the Control UI is translated through `ui.pages` titles).
const I18N = {
  'zh-Hant': {
    'conn.idle': '尚未連線', 'conn.connecting': '連線中…', 'conn.failed': '連線失敗', 'conn.ready': '已連線 · {v}', 'conn.down': '連線中斷，3 秒後重試',
    'new': '＋ 新對話', 'boards': '儀表板', 'boards_all': '總覽', 'devices': '裝置', 'control': '控制台', 'settings': '設定',
    'pick': '選擇或建立一個對話', 'input': '輸入訊息…  / 顯示指令', 'stop': '停止', 'send': '送出', 'working': '工作中',
    'you': '你', 'tool_result': '工具結果', 'tool_call': '呼叫 {n}', 'tool_error': '工具失敗',
    'approval': '需要核准：{gate}', 'deny': '拒絕', 'always': '本次對話都允許', 'once': '允許一次',
    'ask': 'ark 想問你', 'answer': '回答', 'close': '關閉',
    'no_sessions': '還沒有對話', 'start': '開始一段新對話吧', 'login': '連線到 ark',
    'login_hint': '輸入 App Server 的 token（<code>ark app token</code> 會顯示）。', 'connect': '連線', 'remember': '記住這台裝置',
    'slash_hint': '指令 · ↑↓ 選擇、Tab 補齊、Esc 關閉', 'attach': '附加', 'attached': '已附加 {n} 個檔案',
    'too_big': '檔案太大（上限 8 MiB）', 'lang': 'EN', 'lang.name': 'English',
    'theme': '主題', 'theme.crimson': '深緋紅', 'theme.midnight': '極夜', 'theme.daylight': '日光',
    'not_a_command': '未知指令：{line}（/help 看清單）', 'local_only': '/{name} 只在終端機有效；這裡改用對應的頁面。',
    'quit_web': '/quit 只關閉終端機；關掉這個分頁即可離開。', 'copied': '已複製最後一則回覆。',
  },
  en: {
    'conn.idle': 'Not connected', 'conn.connecting': 'Connecting…', 'conn.failed': 'Connection failed', 'conn.ready': 'Connected · {v}', 'conn.down': 'Disconnected, retrying in 3s',
    'new': '+ New chat', 'boards': 'Dashboards', 'boards_all': 'Overview', 'devices': 'Devices', 'control': 'Control', 'settings': 'Settings',
    'pick': 'Pick or start a conversation', 'input': 'Message…  / for commands', 'stop': 'Stop', 'send': 'Send', 'working': 'Working',
    'you': 'You', 'tool_result': 'Tool result', 'tool_call': 'Calling {n}', 'tool_error': 'Tool failed',
    'approval': 'Approval needed: {gate}', 'deny': 'Deny', 'always': 'Always in this chat', 'once': 'Allow once',
    'ask': 'ark asks', 'answer': 'Answer', 'close': 'Close',
    'no_sessions': 'No conversations yet', 'start': 'Start a new conversation', 'login': 'Connect to ark',
    'login_hint': 'Enter the App Server token (shown by <code>ark app token</code>).', 'connect': 'Connect', 'remember': 'Remember this device',
    'slash_hint': 'Commands · ↑↓ pick, Tab complete, Esc close', 'attach': 'Attach', 'attached': '{n} file(s) attached',
    'too_big': 'File too large (8 MiB max)', 'lang': '中文', 'lang.name': '繁體中文',
    'theme': 'Theme', 'theme.crimson': 'Crimson', 'theme.midnight': 'Midnight', 'theme.daylight': 'Daylight',
    'not_a_command': 'Unknown command: {line} (see /help)', 'local_only': '/{name} only works in a terminal; use the matching page here.',
    'quit_web': '/quit closes the terminal UI; just close this tab to leave.', 'copied': 'Copied the last reply.',
  },
};
let LANG = store.get('ark.lang') || 'zh-Hant';
function t(key, vars) {
  let s = (I18N[LANG] && I18N[LANG][key]) || I18N['zh-Hant'][key] || key;
  for (const k in vars || {}) s = s.split('{' + k + '}').join(String(vars[k]));
  return s;
}
function setLang(l, save) {
  LANG = I18N[l] ? l : 'zh-Hant';
  if (save !== false) store.set('ark.lang', LANG);
  document.documentElement.lang = LANG === 'en' ? 'en' : 'zh-Hant';
  applyI18n();
}
// Static strings: text (`data-i18n`), placeholder (`data-i18n-ph`), title (`data-i18n-title`).
function applyI18n() {
  for (const el of document.querySelectorAll('[data-i18n]')) el.textContent = t(el.dataset.i18n);
  for (const el of document.querySelectorAll('[data-i18n-ph]')) el.placeholder = t(el.dataset.i18nPh);
  for (const el of document.querySelectorAll('[data-i18n-title]')) el.title = t(el.dataset.i18nTitle);
  const hint = document.getElementById('loginHint');
  if (hint) hint.innerHTML = t('login_hint');
  if ($('conn') && !S.arp) setConn(t('conn.idle'));
  if ($('title') && !S.current) $('title').textContent = t('pick');
  document.title = 'ark';
}
// ── themes: the shell's palette is theme.css; these variables re-tint it ──
const THEMES = ['crimson', 'midnight', 'daylight'];
function setTheme(name, save) {
  const n = THEMES.includes(name) ? name : 'crimson';
  if (n === 'crimson') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', n);
  if (save !== false) store.set('ark.theme', n);
  const sel = $('theme');
  if (sel) sel.value = n;
  const meta = document.querySelector('meta[name=theme-color]');
  if (meta) meta.content = n === 'daylight' ? '#f6ecdf' : n === 'midnight' ? '#0a1020' : '#330716';
}
// ── attachments: paste / drop / pick a file, upload it over ARP, attach to the next message ──
const ATT = []; // {path, name, bytes}
const ATT_MAX = 8 * 1024 * 1024;
function readAsDataURL(f) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(String(r.result));
    r.onerror = () => rej(new Error('read failed'));
    r.readAsDataURL(f);
  });
}
function renderAtt() {
  const box = $('attachments');
  if (!box) return;
  box.innerHTML = ATT.map((a, i) => `<span class="att" title="${esc(a.path)}">${esc(a.name)} <span class="dim">${a.bytes ? '<span class="att-bytes">' + Math.ceil(a.bytes / 1024) + 'K</span>' : ''}</span><button class="btn ghost small" data-rm="${i}" aria-label="remove">✕</button></span>`).join('');
  box.hidden = !ATT.length;
  for (const b of box.querySelectorAll('[data-rm]')) {
    b.onclick = async () => {
      const [a] = ATT.splice(Number(b.dataset.rm), 1);
      if (a) { try { await S.arp.call('ui.upload.delete', { path: a.path }); } catch {} }
      renderAtt();
    };
  }
}
async function addFiles(files) {
  if (!files || !files.length || !S.arp) return;
  for (const f of Array.from(files).slice(0, 8)) {
    if (f.size > ATT_MAX) { addMsg('notice', '', esc(t('too_big'))); continue; }
    try {
      const data = await readAsDataURL(f);
      const r = await S.arp.call('ui.upload', { name: f.name || 'paste.png', data });
      ATT.push({ path: r.path, name: r.name || f.name, bytes: r.bytes || f.size });
    } catch (e) { addMsg('notice', '', '⚠ ' + esc(e.message)); }
  }
  renderAtt();
}

// ── slash commands: complete from `command.list` and run through `command.run` ──
const CMDS = { list: [], loaded: false };
async function loadCommands() {
  if (CMDS.loaded || !S.arp) return CMDS.list;
  try { CMDS.list = (await S.arp.call('command.list')) || []; CMDS.loaded = true; } catch {}
  return CMDS.list;
}
const SLASH = { open: false, items: [], idx: 0 };
function slashWord() {
  const v = $('input').value;
  return v.startsWith('/') && !v.includes('\n') && !/\s/.test(v.slice(1)) ? v.slice(1).toLowerCase() : null;
}
async function updateSlashMenu() {
  const q = slashWord();
  if (q === null) return closeSlash();
  const list = await loadCommands();
  const pool = list.filter((c) => c && c.name);
  const rank = (c) => (c.name.toLowerCase().startsWith(q) ? 0 : (c.aliases || []).some((a) => a.toLowerCase().startsWith(q)) ? 1 : c.name.toLowerCase().includes(q) ? 2 : 9);
  SLASH.items = pool.map((c) => [rank(c), c]).filter(([r]) => r < 9).sort((a, b) => a[0] - b[0] || a[1].name.localeCompare(b[1].name)).slice(0, 12).map(([, c]) => c);
  if (!SLASH.items.length) return closeSlash();
  SLASH.open = true;
  SLASH.idx = Math.min(SLASH.idx, SLASH.items.length - 1);
  const menu = $('slashMenu');
  menu.innerHTML = '<div class="slash-hint dim">' + esc(t('slash_hint')) + '</div>' + SLASH.items.map((c, i) =>
    `<button type="button" class="slash-item${i === SLASH.idx ? ' on' : ''}" data-slash="${esc(c.name)}"><b>/${esc(c.name)}</b> <span class="dim">${esc((c.aliases || []).map((a) => '/' + a).join(' ') || '')}</span> <span class="slash-args dim">${esc(c.args || '')}</span> <span class="slash-desc">${esc(c.description || '')}</span></button>`).join('');
  menu.hidden = false;
  for (const b of menu.querySelectorAll('[data-slash]')) b.onclick = () => pickSlash(b.dataset.slash);
}
function closeSlash() { SLASH.open = false; SLASH.items = []; const m = $('slashMenu'); if (m) { m.hidden = true; m.innerHTML = ''; } }
function pickSlash(name) {
  $('input').value = '/' + name + ' ';
  closeSlash();
  $('input').focus();
  autosize();
}
function moveSlash(d) {
  if (!SLASH.open) return false;
  SLASH.idx = (SLASH.idx + d + SLASH.items.length) % SLASH.items.length;
  for (const [i, b] of [...$('slashMenu').querySelectorAll('[data-slash]')].entries()) b.classList.toggle('on', i === SLASH.idx);
  return true;
}
// `command.run` reply: text (shown as a notice) + optional prompt (sent as a turn) + the
// host action (`new_session`, `quit`, `local`) which the web UI performs itself.
async function runSlash(line) {
  if (!S.current) await newSession();
  if (!S.current) return;
  let r;
  try { r = await S.arp.call('command.run', { line, session: S.current, surface: 'web' }); }
  catch (e) { addMsg('notice', '', '⚠ ' + esc(e.message)); return; }
  if (!r || r.handled === false) { addMsg('notice', '', esc(t('not_a_command', { line }))); return; }
  if (r.text) addMsg('notice', '', md(String(r.text)));
  if (r.action) await runAction(r.action);
  if (r.prompt) await send(r.prompt, { raw: true });
}
async function runAction(a) {
  if (a.kind === 'new_session') { await newSession(); if (a.clear) $('log').innerHTML = ''; return; }
  if (a.kind === 'quit') { addMsg('notice', '', esc(t('quit_web'))); return; }
  if (a.kind === 'local') {
    const n = a.name || '';
    if (n === 'clear' || n === 'redraw') { $('log').innerHTML = ''; if (S.current) openSession(S.current); return; }
    if (n === 'copy') {
      const msgs = [...$('log').querySelectorAll('.msg.assistant .body')];
      const last = msgs[msgs.length - 1];
      if (last) { try { await navigator.clipboard.writeText(last.innerText); addMsg('notice', '', esc(t('copied'))); } catch {} }
      return;
    }
    if (n === 'statusbar' || n === 'palette' || n === 'compose' || n === 'paste') { addMsg('notice', '', esc(t('local_only', { name: n }))); return; }
    if (a.arg) addMsg('notice', '', esc(a.arg));
    return;
  }
}

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
  $('status').innerHTML = running ? '<span class="star pulse" style="--size:12px"></span> ' + esc(t('working')) : '';
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

// A tool call/result as a collapsible card (`<details>`), so a long transcript stays scannable.
function addToolCard(title, body, collapsible, badge) {
  const el = addMsg('tool toolcard', badge ? `<span class="bad">${esc(badge)}</span> ${esc(title)}` : esc(title), '');
  const pre = `<pre>${esc(String(body).slice(0, 20000))}</pre>`;
  el.querySelector('.body').innerHTML = collapsible
    ? `<details><summary>${esc(title)}</summary>${pre}</details>`
    : pre;
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
      const txt = (m.content || []).map((b) => b.type === 'text' ? b.text : '').join('');
      const results = (m.content || []).filter((b) => b.type === 'tool_result');
      if (results.length) {
        // One card per result: the head shows the status, the body the (truncated) output.
        for (const b of results) {
          const body = typeof b.content === 'string' ? b.content : JSON.stringify(b.content, null, 1);
          const collapsible = String(body).length > 400 || String(body).includes('\n');
          addToolCard(txt && !results.length ? txt : t('tool_result'), String(body), collapsible, b.is_error ? t('tool_error') : '');
        }
        if (txt.trim()) addMsg('user', esc(t('you')), md(txt));
      } else if (txt.trim()) addMsg('user', esc(t('you')), md(txt));
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
      for (const b of m.content || []) if (b.type === 'tool_use') addToolCard(t('tool_call', { n: '' }) + b.name, JSON.stringify(b.input, null, 1), true, '');
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
    box.innerHTML += `<div class="q"><span class="star pulse" style="--size:18px"></span><div><strong>${esc(t('approval', { gate: p.gate }))}</strong><div class="dim">${esc(p.tool)} — ${esc(p.reason)}</div><pre>${esc(p.summary || '')}</pre></div></div>
      <div class="acts"><button class="btn danger small" data-a="deny">${esc(t('deny'))}</button><button class="btn ghost small" data-a="always">${esc(t('always'))}</button><button class="btn small" data-a="once">${esc(t('once'))}</button></div>`;
  } else {
    // `clarify` questions carry pickable choices (`choices`, `multi_select`); a plain
    // question (ask_user) has none and stays a free-text box.
    const choices = Array.isArray(p.choices) ? p.choices : [];
    const multi = !!p.multi_select;
    box._choices = choices;
    box._multi = multi;
    box._picked = new Set();
    const acts = choices.length
      ? `<div class="acts">${choices.map((c, i) => `<button class="btn ghost small" data-c="${esc(c)}" data-i="${i}">${esc(c)}</button>`).join('')}${multi ? '<button class="btn small" data-a="answer">送出</button>' : ''}</div>`
      : `<input type="text" placeholder="${esc(t('answer'))}"><div class="acts"><button class="btn small" data-a="answer">${esc(t('answer'))}</button></div>`;
    box.innerHTML += `<div class="q"><span class="star pulse" style="--size:18px"></span><div><strong>${esc(t('ask'))}</strong><div>${md(p.question)}</div>${multi ? '<div class="dim">可多選</div>' : ''}</div></div>${acts}`;
  }
  box.addEventListener('click', async (e) => {
    const d = e.target.dataset;
    if (d.c !== undefined && d.i !== undefined) {
      // A choice was clicked: single-select answers at once, multi-select toggles.
      if (box._multi) {
        const i = Number(d.i);
        if (box._picked.has(i)) { box._picked.delete(i); e.target.classList.remove('on'); }
        else { box._picked.add(i); e.target.classList.add('on'); }
        return;
      }
      try { await S.arp.call('gate.answer', { id: p.id, answer: d.c }); } catch (err) { addMsg('notice', '', esc(err.message)); }
      box.remove(); S.pending.delete(p.id);
      return;
    }
    const a = d.a;
    if (!a) return;
    let answer = a;
    if (a === 'answer') {
      const input = box.querySelector('input');
      answer = input ? input.value : [...box._picked].sort((x, y) => x - y).map((i) => box._choices[i]).join(', ');
    }
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
  if (!S.sessions.length) nav.innerHTML = '<div class="dim" style="padding:8px">' + esc(t('no_sessions')) + '</div>';
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

async function send(text, opts) {
  if (!text.trim() && !ATT.length) return;
  if (!S.current) await newSession();
  if (!S.current) return;
  // `/…` lines are commands: the shared table in the kernel decides what they do, and the
  // action they return (new_session / quit / local) is performed by this client.
  if (text.trim().startsWith('/') && !(opts && opts.raw)) { closeSlash(); return runSlash(text.trim()); }
  const uploads = ATT.map((a) => a.path);
  try {
    if (uploads.length) {
      await S.arp.call('ui.submit', { id: S.current, text, uploads });
      ATT.length = 0;
      renderAtt();
    } else await S.arp.call('session.submit', { id: S.current, text, source: 'web' });
    setStatus(true);
  } catch (e) { addMsg('notice', '', '⚠ ' + esc(e.message)); }
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
  setConn(t('conn.connecting'));
  try { await S.arp.connect(); } catch (e) { setConn(t('conn.failed')); store.del('ark.token'); return askToken(); }
  S.arp.on('ready', (p) => setConn(t('conn.ready', { v: p.server.version })));
  // Two subscriptions share the socket: the global one feeds the sidebar and approvals,
  // the session one feeds the transcript. Route by subscription id so nothing renders twice.
  S.arp.on('event', (p) => {
    if (p.subscription === S.globalSub) { if (p.event && (p.event.type === 'turn_end' || p.event.type === 'header')) loadSessions(); return; }
    if (p.session === S.current) renderEvent(p.event);
  });
  S.arp.on('delta', (p) => { if (p.subscription !== S.globalSub) onDelta(p); });
  S.arp.on('pending', (p) => { if (p.subscription === S.globalSub) onPending(p); });
  S.arp.on('close', () => { setConn(t('conn.down')); setTimeout(() => start(token), 3000); });
  // A second subscription follows every session for approvals and the sidebar.
  S.globalSub = S.arp.next;
  S.arp.call('subscribe', {}).catch(() => {});
  await loadSessions();
  loadPluginPanels();
  for (const p of await S.arp.call('gate.pending')) onPending(p);
  if (!S.current && S.sessions[0]) openSession(S.sessions[0].id);
  else if (!S.sessions.length) $('log').innerHTML = '<div class="empty"><span class="star twinkle"></span><div>' + esc(t('start')) + '</div></div>';
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
$('composer').onsubmit = (e) => { e.preventDefault(); const text = $('input').value; $('input').value = ''; autosize(); closeSlash(); send(text); };
$('input').addEventListener('keydown', (e) => {
  if (SLASH.open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) { e.preventDefault(); moveSlash(e.key === 'ArrowDown' ? 1 : -1); return; }
  if (SLASH.open && (e.key === 'Tab' || (e.key === 'Enter' && !e.shiftKey))) { e.preventDefault(); pickSlash(SLASH.items[SLASH.idx].name); return; }
  if (SLASH.open && e.key === 'Escape') { e.preventDefault(); closeSlash(); return; }
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); $('composer').requestSubmit(); }
});
$('input').addEventListener('input', () => { autosize(); updateSlashMenu(); });
// Paste / drop files (images stay images: ui.upload + ui.submit build the content blocks).
$('input').addEventListener('paste', (e) => { const f = e.clipboardData && e.clipboardData.files; if (f && f.length) { e.preventDefault(); addFiles(f); } });
$('composer').addEventListener('dragover', (e) => { e.preventDefault(); $('composer').classList.add('drop'); });
$('composer').addEventListener('dragleave', () => $('composer').classList.remove('drop'));
$('composer').addEventListener('drop', (e) => { e.preventDefault(); $('composer').classList.remove('drop'); if (e.dataTransfer && e.dataTransfer.files.length) addFiles(e.dataTransfer.files); });
$('attach').onclick = () => $('file').click();
$('file').onchange = (e) => { addFiles(e.target.files); e.target.value = ''; };
$('lang').onclick = () => { setLang(LANG === 'en' ? 'zh-Hant' : 'en'); $('lang').textContent = t('lang'); };
$('theme').onchange = (e) => setTheme(e.target.value);
setLang(LANG, false);
setTheme(store.get('ark.theme') || 'crimson', false);
$('lang').textContent = t('lang');
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

applyI18n();
// Token: #token=… (from `ark app open`), saved token, or ask.
const fromHash = new URLSearchParams(location.hash.slice(1)).get('token');
if (fromHash) { store.set('ark.token', fromHash); history.replaceState(null, '', location.pathname); }
const saved = fromHash || store.get('ark.token');
saved ? start(saved) : askToken();
// A link with #token=… opened on an already-loaded page.
addEventListener('hashchange', () => { if (new URLSearchParams(location.hash.slice(1)).get('token')) location.reload(); });
