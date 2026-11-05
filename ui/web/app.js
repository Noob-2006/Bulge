// ark web / desktop UI: an ARP (JSON-RPC 2.0 over WebSocket) client.
// Same methods and events as the terminal UI and the unix-socket daemon protocol.
// Layout: a rail (navigation + conversations) and one view at a time — the operations views
// (ops.js), the chat transcript, or a Control UI page (pages.js / surfaces.js).
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
    'conn.idle': '尚未連線', 'conn.connecting': '連線中…', 'conn.failed': '連線失敗', 'conn.ready': '已連線 · v{v}', 'conn.down': '連線中斷，3 秒後重試',
    'new': '新對話', 'boards': '儀表板', 'boards_all': '所有儀表板', 'devices': '裝置', 'control': '控制台', 'settings': '設定',
    'nav.ops': '總覽', 'nav.chat': '對話', 'nav.agents': '代理', 'nav.approvals': '核准', 'nav.audit': '稽核', 'nav.sessions': '對話紀錄',
    'filter': '搜尋對話', 'back': '← 返回', 'palette': '指令', 'palette_ph': '跳到頁面、對話或指令…', 'jump': '↓ 最新', 'send_hint': 'Enter 送出 · Shift+Enter 換行',
    'pick': '選擇或建立一個對話', 'input': '交代 ark 要做的事…  輸入 / 顯示指令', 'stop': '停止', 'send': '送出', 'working': '工作中',
    'you': '你', 'tool_result': '工具結果', 'tool_call': '呼叫 {n}', 'tool_error': '失敗', 'tool_ok': '完成', 'tool_run': '執行中', 'gate.egress': '連網', 'gate.exec': '執行', 'gate.fs': '檔案', 'gate.privilege': '權限',
    'approval': '需要核准 · {gate}', 'deny': '拒絕', 'always': '本次對話都允許', 'once': '允許一次',
    'ask': 'ark 想問你', 'answer': '回答', 'close': '關閉',
    'no_sessions': '還沒有對話', 'start': '開始一段新對話', 'start_sub': '交代任務、貼上檔案，或輸入 / 看所有指令。ark 會在需要時請你核准。', 'login': '連線到 ark',
    'login_hint': '輸入 App Server 的 token（<code>ark app token</code> 會顯示）。', 'connect': '連線', 'remember': '記住這台裝置',
    'slash_hint': '指令 · ↑↓ 選擇、Tab 補齊、Esc 關閉', 'attach': '附加', 'attached': '已附加 {n} 個檔案',
    'too_big': '檔案太大（上限 8 MiB）', 'lang': 'EN', 'lang.name': 'English',
    'theme': '主題', 'theme.crimson': '深緋紅', 'theme.midnight': '極夜', 'theme.daylight': '日光',
    'not_a_command': '未知指令：{line}（/help 看清單）', 'local_only': '/{name} 只在終端機有效；這裡改用對應的頁面。',
    'quit_web': '/quit 只關閉終端機；關掉這個分頁即可離開。', 'copied': '已複製。', 'copy': '複製',
    'today': '今天', 'yesterday': '昨天', 'earlier': '更早', 'thinking': '思考中…',
    'work': '工作區', 'dual': '雙人覆核', 'requester': '申請者', 'dual_wait': '已記下你的核准（{n}/{m}），還需要其他核准者。',
    'review': '覆核', 'reviewed': '標記已覆核', 'flagged': '標記可疑', 'review_note': '覆核註記（選填）', 'review_done': '已記錄覆核：{s}',
  },
  en: {
    'conn.idle': 'Not connected', 'conn.connecting': 'Connecting…', 'conn.failed': 'Connection failed', 'conn.ready': 'Connected · v{v}', 'conn.down': 'Disconnected, retrying in 3s',
    'new': 'New chat', 'boards': 'Dashboards', 'boards_all': 'All dashboards', 'devices': 'Devices', 'control': 'Control', 'settings': 'Settings',
    'nav.ops': 'Overview', 'nav.chat': 'Chat', 'nav.agents': 'Agents', 'nav.approvals': 'Approvals', 'nav.audit': 'Audit', 'nav.sessions': 'Conversations',
    'filter': 'Search conversations', 'back': '← Back', 'palette': 'Commands', 'palette_ph': 'Jump to a page, conversation or command…', 'jump': '↓ Latest', 'send_hint': 'Enter to send · Shift+Enter for newline',
    'pick': 'Pick or start a conversation', 'input': 'Tell ark what to do…  / for commands', 'stop': 'Stop', 'send': 'Send', 'working': 'Working',
    'you': 'You', 'tool_result': 'Tool result', 'tool_call': 'Calling {n}', 'tool_error': 'failed', 'tool_ok': 'done', 'tool_run': 'running', 'gate.egress': 'network', 'gate.exec': 'exec', 'gate.fs': 'files', 'gate.privilege': 'privilege',
    'approval': 'Approval needed · {gate}', 'deny': 'Deny', 'always': 'Always in this chat', 'once': 'Allow once',
    'ask': 'ark asks', 'answer': 'Answer', 'close': 'Close',
    'no_sessions': 'No conversations yet', 'start': 'Start a conversation', 'start_sub': 'Describe a task, paste files, or type / for every command. ark asks before anything risky.', 'login': 'Connect to ark',
    'login_hint': 'Enter the App Server token (shown by <code>ark app token</code>).', 'connect': 'Connect', 'remember': 'Remember this device',
    'slash_hint': 'Commands · ↑↓ pick, Tab complete, Esc close', 'attach': 'Attach', 'attached': '{n} file(s) attached',
    'too_big': 'File too large (8 MiB max)', 'lang': '中文', 'lang.name': '繁體中文',
    'theme': 'Theme', 'theme.crimson': 'Crimson', 'theme.midnight': 'Midnight', 'theme.daylight': 'Daylight',
    'not_a_command': 'Unknown command: {line} (see /help)', 'local_only': '/{name} only works in a terminal; use the matching page here.',
    'quit_web': '/quit closes the terminal UI; just close this tab to leave.', 'copied': 'Copied.', 'copy': 'Copy',
    'today': 'Today', 'yesterday': 'Yesterday', 'earlier': 'Earlier', 'thinking': 'Thinking…',
    'work': 'Workspace', 'dual': 'Dual control', 'requester': 'requested by', 'dual_wait': 'Your approval is recorded ({n}/{m}); more approvers are needed.',
    'review': 'Review', 'reviewed': 'Mark reviewed', 'flagged': 'Flag', 'review_note': 'Review note (optional)', 'review_done': 'Review recorded: {s}',
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
  // The connection line is live state, not a static string: re-render it in the new language.
  if ($('conn')) setConn(...(S.conn || ['conn.idle']));
  if ($('title') && !S.current && S.view === 'chat') $('title').textContent = t('pick');
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
  if (meta) meta.content = n === 'daylight' ? '#f6f2ec' : n === 'midnight' ? '#04070f' : '#0b0105';
}

// ── toasts ──
function toast(text, bad) {
  const el = document.createElement('div');
  el.className = 'toast' + (bad ? ' bad' : '');
  el.textContent = text;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), bad ? 6000 : 3200);
}

// ── views: one main view at a time ──
// `ops`, `agents`, `devices`, `approvals`, `audit` are drawn by ops.js (VIEWS registry);
// `chat` is the transcript; `page` is a Control UI page / dashboard (#panelDialog).
const VIEWS = {}; // name → {title, render(el), leave()} (ops.js)
const VIEW_SEC = { ops: 'nav.ops', chat: 'nav.chat', agents: 'nav.agents', devices: 'devices', approvals: 'nav.approvals', audit: 'nav.audit', page: 'control' };
function showView(name, opts) {
  const prev = S.view;
  if (prev && prev !== name && VIEWS[prev] && VIEWS[prev].leave) VIEWS[prev].leave();
  if (name !== 'chat' && typeof W === 'object' && W.open) workShow(false);
  S.view = name;
  for (const el of document.querySelectorAll('.view')) el.hidden = true;
  const el = name === 'page' ? $('panelDialog') : $('view-' + name);
  if (el) el.hidden = false;
  for (const b of document.querySelectorAll('.nav-item')) b.classList.toggle('on', b.dataset.view === name || (name === 'page' && b.id === (S.pageNav || 'showControl')));
  $('crumbSec').textContent = t(VIEW_SEC[name] || 'nav.ops');
  if (name !== 'chat' && name !== 'page') $('title').textContent = (VIEWS[name] && VIEWS[name].title()) || '';
  if (name === 'chat') $('title').textContent = S.current ? sessTitle(S.current) : t('pick');
  $('reviewBtn').hidden = !(name === 'chat' && S.current);
  $('side').classList.remove('open');
  if (!(opts && opts.keepHash)) history.replaceState(null, '', name === 'page' ? location.pathname : '#view=' + name);
  if (VIEWS[name] && S.arp) VIEWS[name].render($('view-' + name));
  if (name !== 'page') store.set('ark.view', name);
}
// pages.js / surfaces.js still talk to the page view as the old dialog: `.open`, `.close()`,
// `.showModal()`.
(function shimPageView() {
  const pv = $('panelDialog');
  Object.defineProperty(pv, 'open', { get: () => S.view === 'page' });
  pv.close = () => { if (S.view === 'page') showView(S.back || 'ops'); };
  pv.showModal = () => { if (S.view !== 'page') S.back = S.view; showView('page'); };
})();

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
  box.innerHTML = ATT.map((a, i) => `<span class="att" title="${esc(a.path)}">${esc(a.name)} <span class="dim">${a.bytes ? '<span class="att-bytes">' + Math.ceil(a.bytes / 1024) + 'K</span>' : ''}</span><button class="btn ghost small icon" data-rm="${i}" aria-label="remove">✕</button></span>`).join('');
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
    if (f.size > ATT_MAX) { toast(t('too_big'), true); continue; }
    try {
      const data = await readAsDataURL(f);
      const r = await S.arp.call('ui.upload', { name: f.name || 'paste.png', data });
      ATT.push({ path: r.path, name: r.name || f.name, bytes: r.bytes || f.size });
    } catch (e) { toast(e.message, true); }
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
  catch (e) { addMsg('notice err', '', esc(e.message)); return; }
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
      if (last) { try { await navigator.clipboard.writeText(last.innerText); toast(t('copied')); } catch {} }
      return;
    }
    if (n === 'palette') { openPalette(); return; }
    if (n === 'statusbar' || n === 'compose' || n === 'paste') { addMsg('notice', '', esc(t('local_only', { name: n }))); return; }
    if (a.arg) addMsg('notice', '', esc(a.arg));
    return;
  }
}

// ── starfield (sparse, only visible behind empty space) ──
(function stars() {
  const f = $('starfield');
  const n = Math.round(Math.min(18, (innerWidth * innerHeight) / 90000));
  for (let i = 0; i < n; i++) {
    const s = document.createElement('span');
    s.className = 'star';
    s.style.left = Math.random() * 100 + '%';
    s.style.top = Math.random() * 100 + '%';
    s.style.setProperty('--size', 4 + Math.random() * 8 + 'px');
    s.style.animationDelay = -Math.random() * 6 + 's';
    f.appendChild(s);
  }
})();

// ── markdown (escape first, then a safe subset: headings, lists, tables, quotes, code) ──
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function inline(s) {
  return esc(s)
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,!?:;]|$)/g, '$1<em>$2</em>')
    .replace(/~~([^~\n]+)~~/g, '<del>$1</del>')
    .replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
}
function codeBlock(lang, src) {
  return `<div class="code"><div class="code-head"><span>${esc(lang || 'text')}</span><button type="button" data-copy>${esc(t('copy'))}</button></div><pre><code>${esc(src.replace(/\n$/, ''))}</code></pre></div>`;
}
function mdBlocks(text) {
  const lines = text.split('\n');
  let out = '';
  let i = 0;
  const para = [];
  const flush = () => { if (para.length) { out += '<p>' + para.map(inline).join('<br>') + '</p>'; para.length = 0; } };
  while (i < lines.length) {
    const l = lines[i];
    if (!l.trim()) { flush(); i++; continue; }
    let m;
    if ((m = l.match(/^(#{1,6})\s+(.+)$/))) { flush(); out += `<h4>${inline(m[2])}</h4>`; i++; continue; }
    if (/^\s*([-*+]|\d+[.)])\s+/.test(l)) {
      flush();
      const ordered = /^\s*\d+[.)]/.test(l);
      let items = '';
      while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
        const it = lines[i].replace(/^\s*([-*+]|\d+[.)])\s+/, '').replace(/^\[( |x)\]\s+/i, (x) => (/x/i.test(x) ? '☑ ' : '☐ '));
        items += `<li>${inline(it)}</li>`;
        i++;
      }
      out += ordered ? `<ol>${items}</ol>` : `<ul>${items}</ul>`;
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(l) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      flush();
      const cells = (r) => r.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      let h = '<table><tr>' + cells(l).map((c) => `<th>${inline(c)}</th>`).join('') + '</tr>';
      i += 2;
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { h += '<tr>' + cells(lines[i]).map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>'; i++; }
      out += h + '</table>';
      continue;
    }
    if (/^>\s?/.test(l)) {
      flush();
      const q = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { q.push(lines[i].replace(/^>\s?/, '')); i++; }
      out += `<blockquote>${q.map(inline).join('<br>')}</blockquote>`;
      continue;
    }
    if (/^(-{3,}|\*{3,})$/.test(l.trim())) { flush(); out += '<hr>'; i++; continue; }
    para.push(l);
    i++;
  }
  flush();
  return out;
}
function md(src) {
  const parts = String(src).split(/```([\w+-]*)\n?([\s\S]*?)```/g);
  let out = '';
  for (let i = 0; i < parts.length; i++) {
    if (i % 3 === 0) out += mdBlocks(parts[i]);
    else if (i % 3 === 2) out += codeBlock(parts[i - 1], parts[i]);
  }
  return out;
}
document.addEventListener('click', async (e) => {
  const mc = e.target.closest('[data-msgcopy]');
  if (mc) { try { await navigator.clipboard.writeText(mc.closest('.msg').querySelector('.body').innerText); toast(t('copied')); } catch {} return; }
  const b = e.target.closest('[data-copy]');
  if (!b) return;
  const code = b.closest('.code');
  try { await navigator.clipboard.writeText(code.querySelector('pre').innerText); b.textContent = t('copied'); setTimeout(() => (b.textContent = t('copy')), 1400); } catch {}
});

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
    if (!this.ws || this.ws.readyState !== 1) return Promise.reject(new Error('連線中斷'));
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
const S = { arp: null, sessions: [], current: null, sub: null, streaming: null, running: false, pending: new Map(), tools: new Map(), view: null, back: null, usage: null };

function setConn(key, vars, state) {
  S.conn = [key, vars, state];
  const c = $('conn');
  c.textContent = key === 'conn.ready' && !vars ? t(key, { v: '' }).replace(' · v', '') : t(key, vars);
  c.classList.toggle('live', state === 'live');
  c.classList.toggle('down', state === 'down');
}
// While a turn runs the topbar shows how long it has been going (Claude Code's spinner line).
function setStatus(running) {
  if (running && !S.running) S.turnStart = Date.now();
  S.running = running;
  $('stop').hidden = !running;
  clearInterval(S.turnTimer);
  const draw = () => {
    const s = Math.floor((Date.now() - (S.turnStart || Date.now())) / 1000);
    $('status').innerHTML = S.running && S.view === 'chat' ? `<span class="star pulse" style="--size:11px"></span> ${esc(t('working'))} <span class="faint mono">${s >= 60 ? Math.floor(s / 60) + 'm ' : ''}${s % 60}s · Esc ${esc(t('stop'))}</span>` : '';
  };
  draw();
  if (running) S.turnTimer = setInterval(draw, 1000);
}

const chatScroll = () => $('chatScroll');
function nearBottom() { const c = chatScroll(); return c.scrollHeight - c.scrollTop - c.clientHeight < 120; }
// Follow the transcript unless the person scrolled up; our own scrolling never counts as that.
function stick(force) {
  const c = chatScroll();
  if (force || S.stick !== false) { c.scrollTop = c.scrollHeight; S.autoTop = c.scrollTop; }
}

function addMsg(kind, who, html) {
  const el = $('tpl-msg').content.firstElementChild.cloneNode(true);
  el.classList.add(...kind.split(' '));
  el.querySelector('.who').innerHTML = who;
  el.querySelector('.body').innerHTML = html;
  $('log').appendChild(el);
  stick();
  return el;
}

// One line per tool call (Claude Code style): name, the most telling argument, status; the
// input and the result expand underneath. Results find their call through `tool_use_id`.
function toolArg(name, input) {
  if (!input || typeof input !== 'object') return '';
  if (Array.isArray(input.items)) return `${input.action || ''} · ${input.items.length} ${LANG === 'en' ? 'items' : '項'}`;
  // Action tools (browser, computer_use, vm…): the action, then what it acts on.
  if (typeof input.action === 'string' && input.action) {
    const on = ['url', 'targetUrl', 'text', 'ref', 'selector', 'key', 'name'].map((k) => input[k]).find((v) => typeof v === 'string' && v);
    const at = Array.isArray(input.coordinate) ? `(${input.coordinate.join(', ')})` : '';
    return [input.action, on ? on.split('\n')[0].slice(0, 160) : at].filter(Boolean).join(' ');
  }
  for (const k of ['command', 'cmd', 'path', 'file_path', 'file', 'url', 'query', 'pattern', 'task', 'name', 'prompt']) {
    if (typeof input[k] === 'string' && input[k]) return input[k].split('\n')[0].slice(0, 200);
  }
  const s = JSON.stringify(input);
  return s.length > 2 ? s.slice(0, 160) : '';
}
function diffHtml(text) {
  return String(text).split('\n').map((l) => {
    const c = /^@@/.test(l) ? 'diff-hunk' : /^\+(?!\+\+)/.test(l) ? 'diff-add' : /^-(?!--)/.test(l) ? 'diff-del' : '';
    return c ? `<span class="${c}">${esc(l)}</span>` : esc(l);
  }).join('\n');
}
// The call's input, shown the way a person reads it: an edit as a diff, a shell command as a
// prompt line, a todo list as checkboxes; anything else as JSON.
function toolInput(name, input) {
  const i = input || {};
  if ((name === 'edit' || name === 'str_replace') && typeof i.old_string === 'string') {
    const lines = [`--- ${i.path || i.file_path || ''}`, `+++ ${i.path || i.file_path || ''}`, '@@'].concat(i.old_string.split('\n').map((l) => '-' + l), String(i.new_string || '').split('\n').map((l) => '+' + l));
    return `<pre class="in">${diffHtml(lines.join('\n').slice(0, 20000))}</pre>`;
  }
  if ((name === 'shell' || name === 'job' || name === 'bash') && typeof i.command === 'string') return `<pre class="in"><span class="faint">$</span> ${esc(i.command.slice(0, 20000))}</pre>`;
  if (name === 'write' && typeof i.content === 'string') return `<pre class="in"><span class="faint">${esc(i.path || i.file_path || '')} · ${i.content.split('\n').length} lines</span>\n${esc(i.content.slice(0, 4000))}</pre>`;
  if (name === 'todo' && Array.isArray(i.items)) {
    return `<ul class="todo">${i.items.map((it) => { const st = (it && it.status) || ''; const txt = (it && (it.content || it.text || it.step || it.title)) || String(it); return `<li class="${esc(st)}">${st === 'completed' || st === 'done' ? '☑' : st === 'in_progress' ? '◐' : '☐'} ${esc(txt)}</li>`; }).join('')}</ul>`;
  }
  return `<pre class="in">${esc(JSON.stringify(i, null, 2).slice(0, 20000))}</pre>`;
}
// A gate record as one readable line: what was checked, the verdict, and why (the rule's own
// "[tier N: …]" detail stays in the session log and the audit view).
function gateLine(ev) {
  const names = { egress: t('gate.egress'), exec: t('gate.exec'), fs: t('gate.fs'), privilege: t('gate.privilege') };
  const reason = String(ev.reason || '').replace(/\s*\[tier \d+: [^\]]*\]$/, '');
  return `<span class="gate-k">${esc(names[ev.gate] || ev.gate)}</span> · ${esc(ev.verdict)} — ${esc(reason)}`;
}
function addToolCall(b) {
  // `tool_call` is the wrapper for tools outside the pinned set: show the tool it calls.
  if (b.name === 'tool_call' && b.input && typeof b.input.name === 'string') b = { ...b, name: b.input.name, input: b.input.input || {} };
  const el = addMsg('tool', '', '');
  const det = document.createElement('details');
  det.className = 'tl run';
  det.innerHTML = `<summary><span class="star spin" style="--size:9px"></span><span class="nm">${esc(b.name)}</span><span class="arg">${esc(toolArg(b.name, b.input))}</span><span class="st">${esc(t('tool_run'))}</span></summary>${toolInput(b.name, b.input)}`;
  if (b.name === 'todo') det.open = true;
  if (typeof workNote === 'function') workNote(b);
  el.querySelector('.body').appendChild(det);
  if (b.id) S.tools.set(b.id, det);
  return det;
}
function settleTool(b) {
  const body = typeof b.content === 'string' ? b.content : (Array.isArray(b.content) ? b.content.map((x) => (x && x.type === 'text' ? x.text : JSON.stringify(x))).join('\n') : JSON.stringify(b.content, null, 1));
  let det = b.tool_use_id && S.tools.get(b.tool_use_id);
  if (!det) det = addToolCall({ name: t('tool_result'), input: {} });
  det.classList.remove('run');
  det.classList.add(b.is_error ? 'err' : 'ok');
  const star = det.querySelector('summary .star');
  if (star) { star.classList.remove('spin'); star.classList.add(b.is_error ? 'crit' : 'ok'); }
  det.querySelector('.st').textContent = b.is_error ? t('tool_error') : t('tool_ok');
  const looksDiff = /^(---|\+\+\+|@@) /m.test(body);
  det.insertAdjacentHTML('beforeend', `<pre class="out">${looksDiff ? diffHtml(body.slice(0, 20000)) : esc(String(body).slice(0, 20000))}</pre>`);
  if (b.is_error) det.open = true;
}

function textOf(m) {
  return (m.content || []).map((b) => (b.type === 'text' ? b.text : '')).join('');
}
const ARK = '<span class="star" style="--size:9px"></span> ark<button type="button" class="msg-copy" data-msgcopy>' + '⧉' + '</button>';

function renderEvent(ev) {
  const k = ev.type;
  if (k === 'message') {
    const m = ev.message;
    if (m.role === 'user') {
      const txt = (m.content || []).map((b) => b.type === 'text' ? b.text : '').join('');
      for (const b of (m.content || []).filter((x) => x.type === 'tool_result')) settleTool(b);
      // The kernel tags where a message came from (`[from web] …`); show it as a label.
      const src = txt.match(/^\[from ([\w.-]+)\]\s*/);
      if (txt.trim()) addMsg('user', esc(t('you')) + (src && src[1] !== 'web' ? ` <span class="faint">· ${esc(src[1])}</span>` : ''), md(src ? txt.slice(src[0].length) : txt));
    } else {
      const tx = textOf(m);
      if (S.streaming) {
        // The final message replaces what was streamed so far.
        if (tx.trim()) {
          S.streaming.el.querySelector('.who').innerHTML = ARK;
          S.streaming.el.querySelector('.body').innerHTML = md(tx);
        } else S.streaming.el.remove();
        S.streaming = null;
      } else if (tx.trim()) addMsg('assistant', ARK, md(tx));
      for (const b of m.content || []) if (b.type === 'tool_use') addToolCall(b);
    }
  } else if (k === 'turn_start') setStatus(true);
  else if (k === 'turn_end') { setStatus(false); S.streaming = null; }
  else if (k === 'notice') addMsg('notice', '', esc(ev.text));
  else if (k === 'error') addMsg('notice err', '', esc(ev.message));
  else if (k === 'gate') addMsg('notice', '', gateLine(ev));
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
  const el = addMsg('tool app', '', '');
  el.querySelector('.who').style.display = 'flex';
  el.querySelector('.who').textContent = `${ui.server} · ${ui.tool}`;
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
        hostContext: { theme: document.documentElement.dataset.theme === 'daylight' ? 'light' : 'dark', displayMode: 'inline', availableDisplayModes: ['inline'], containerDimensions: { width: st.frame.clientWidth, maxHeight: 1200 }, locale: navigator.language, timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone, platform: 'web' },
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
  if (!S.streaming) S.streaming = { el: addMsg('assistant', '<span class="star spin" style="--size:9px"></span> ark', ''), text: '', think: '' };
  if (p.thinking) S.streaming.think += p.text; else S.streaming.text += p.text;
  const th = S.streaming.think && !S.streaming.text ? `<div class="thinking">${esc(S.streaming.think.slice(-600))}</div>` : '';
  S.streaming.el.querySelector('.body').innerHTML = th + md(S.streaming.text);
  stick();
}

// ── pending approvals / questions (the chat dock shows the current session's; the approvals
// view lists all of them — ops.js reads S.pending) ──
function pendingChanged() {
  const n = [...S.pending.values()].length;
  const b = $('badgeApprovals');
  b.hidden = !n;
  b.textContent = n;
  if (S.view === 'approvals' && VIEWS.approvals) VIEWS.approvals.render($('view-approvals'));
  if (typeof opsStrip === 'function') opsStrip();
}
async function answerPending(id, answer) {
  let r;
  try { r = await S.arp.call('gate.answer', { id, answer }); }
  catch (err) { toast(err.message, true); return false; }
  const e = S.pending.get(id);
  // Dual control (four-eyes): a vote is recorded but the call waits for more approvers.
  if (r && r.final === false) {
    toast(t('dual_wait', { n: r.approvals, m: r.required }));
    if (e) { e.p.dual_control = Object.assign({}, e.p.dual_control || {}, { approvals: Array(r.approvals).fill({}), required: r.required, voted: true }); if (e.box) { const nb = pendingBox(e.p); e.box.replaceWith(nb); e.box = nb; } }
    pendingChanged();
    return true;
  }
  if (e && e.box) e.box.remove();
  S.pending.delete(id);
  pendingChanged();
  return true;
}
function pendingBox(p) {
  const box = document.createElement('div');
  box.className = 'ask' + (p.kind === 'approval' ? '' : ' question');
  if (p.kind === 'approval') {
    const dc = p.dual_control;
    const dual = dc ? `<div class="dual"><div><span class="label">${esc(t('dual'))}</span> ${Array.from({ length: dc.required || 2 }, (_, i) => `<span class="slot${i < (dc.approvals || []).length ? ' on' : ''}"></span>`).join('')} <span class="faint">${(dc.approvals || []).length}/${dc.required || 2}${dc.requester ? ' · ' + esc(t('requester')) + ' ' + esc(dc.requester) : ''}${(dc.approver_roles || []).length ? ' · ' + esc(dc.approver_roles.join('/')) : ''}${dc.change_ticket ? ' · ' + esc(dc.change_ticket.number || dc.change_ticket) : ''}</span></div>${(dc.votes || []).map((v) => `<div class="faint mono">${v.approve ? '✓' : '✕'} ${esc(v.by || '')}${v.role ? ' (' + esc(v.role) + ')' : ''}</div>`).join('')}</div>` : '';
    box.innerHTML = `<div class="q"><span class="star pulse warn" style="--size:14px"></span><div><strong>${esc(t('approval', { gate: p.gate }))}</strong>${p.tier !== undefined ? ` <span class="chip">tier ${esc(p.tier)}</span>` : ''}<div class="dim">${esc(p.tool)} — ${esc(p.reason)}</div>${p.summary ? `<pre>${esc(p.summary)}</pre>` : ''}${dual}</div></div>
      <div class="acts" data-approve-ui><button class="btn danger small" data-a="deny">${esc(t('deny'))}</button><button class="btn ghost small" data-a="always">${esc(t('always'))}</button><button class="btn small" data-a="once">${esc(t('once'))}</button></div>`;
  } else {
    // `clarify` questions carry pickable choices (`choices`, `multi_select`); a plain
    // question (ask_user) has none and stays a free-text box.
    const choices = Array.isArray(p.choices) ? p.choices : [];
    const multi = !!p.multi_select;
    box._choices = choices;
    box._multi = multi;
    box._picked = new Set();
    const acts = choices.length
      ? `<div class="acts">${choices.map((c, i) => `<button class="btn ghost small" data-c="${esc(c)}" data-i="${i}">${esc(c)}</button>`).join('')}${multi ? `<button class="btn small" data-a="answer">${esc(t('send'))}</button>` : ''}</div>`
      : `<input type="text" placeholder="${esc(t('answer'))}"><div class="acts" data-approve-ui><button class="btn small" data-a="answer">${esc(t('answer'))}</button></div>`;
    box.innerHTML = `<div class="q"><span class="star pulse" style="--size:14px"></span><div><strong>${esc(t('ask'))}</strong><div>${md(p.question)}</div>${multi ? '<div class="dim">可多選</div>' : ''}</div></div>${acts}`;
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
      await answerPending(p.id, d.c);
      return;
    }
    const a = d.a;
    if (!a) return;
    let answer = a;
    if (a === 'answer') {
      const input = box.querySelector('input');
      answer = input ? input.value : [...box._picked].sort((x, y) => x - y).map((i) => box._choices[i]).join(', ');
    }
    await answerPending(p.id, answer);
  });
  box.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); box.querySelector('[data-a=answer]').click(); } });
  return box;
}
function onPending(p) {
  if (S.pending.has(p.id)) return;
  const entry = { p, box: null };
  S.pending.set(p.id, entry);
  if (!p.session || p.session === S.current) { entry.box = pendingBox(p); $('pending').appendChild(entry.box); stick(); }
  else toast(`${p.kind === 'approval' ? t('approval', { gate: p.gate }) : t('ask')} · ${sessTitle(p.session)}`);
  pendingChanged();
}
// After switching sessions: show that session's open items in the dock.
function redrawDock() {
  $('pending').innerHTML = '';
  for (const e of S.pending.values()) {
    e.box = null;
    if (!e.p.session || e.p.session === S.current) { e.box = pendingBox(e.p); $('pending').appendChild(e.box); }
  }
}

// ── conversations (rail) ──
function sessTitle(id) { const s = S.sessions.find((x) => x.id === id); return s ? (s.title || s.id) : id; }
function ago(ms) {
  if (!ms) return '';
  const d = (Date.now() - ms) / 1000;
  if (d < 60) return LANG === 'en' ? 'now' : '剛剛';
  if (d < 3600) return Math.floor(d / 60) + (LANG === 'en' ? 'm' : ' 分');
  if (d < 86400) return Math.floor(d / 3600) + (LANG === 'en' ? 'h' : ' 時');
  return Math.floor(d / 86400) + (LANG === 'en' ? 'd' : ' 天');
}
function renderSessions() {
  const nav = $('sessions');
  const q = ($('sessFilter').value || '').trim().toLowerCase();
  nav.innerHTML = '';
  const list = S.sessions.filter((s) => !q || (s.title || s.id).toLowerCase().includes(q) || s.id.includes(q));
  // Children follow their parent (one level of indentation is enough to read the tree).
  const ids = new Set(list.map((s) => s.id));
  const roots = list.filter((s) => !s.parent || !ids.has(s.parent));
  const kids = (id) => list.filter((s) => s.parent === id);
  const day = 86400000;
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const group = (s) => (s.updated_ms >= start.getTime() ? 'today' : s.updated_ms >= start.getTime() - day ? 'yesterday' : 'earlier');
  let last = '';
  const add = (s, child) => {
    const b = document.createElement('button');
    b.className = 'sess' + (s.id === S.current ? ' active' : '') + (child ? ' child' : '');
    b.dataset.id = s.id;
    b.title = s.id;
    b.innerHTML = `${s.running ? '<span class="star pulse" style="--size:10px"></span>' : '<span class="dot"></span>'}<span class="t">${esc(s.title || s.id)}</span><span class="m">${ago(s.updated_ms)}</span>`;
    b.onclick = () => openSession(s.id);
    nav.appendChild(b);
  };
  for (const s of roots) {
    const g = group(s);
    if (g !== last) { nav.insertAdjacentHTML('beforeend', `<div class="sess-group label">${esc(t(g))}</div>`); last = g; }
    add(s, false);
    for (const c of kids(s.id)) add(c, true);
  }
  if (!list.length) nav.innerHTML = '<div class="none" style="padding:8px 10px">' + esc(t('no_sessions')) + '</div>';
  const running = S.sessions.filter((s) => s.running).length;
  const ba = $('badgeAgents');
  ba.hidden = !running;
  ba.textContent = running;
}
async function loadSessions() {
  try { S.sessions = await S.arp.call('session.list', { limit: 200 }); } catch { return; }
  renderSessions();
  if (S.current && S.view === 'chat') $('title').textContent = sessTitle(S.current);
}

function emptyChat() {
  $('log').innerHTML = `<div class="empty"><span class="star glow twinkle"></span><h3>${esc(t('start'))}</h3><p>${esc(t('start_sub'))}</p><div class="tips">${['/help', '/status', '/model'].map((c) => `<button type="button" data-tip="${c}">${c}</button>`).join('')}</div></div>`;
  for (const b of $('log').querySelectorAll('[data-tip]')) b.onclick = () => { $('input').value = b.dataset.tip; autosize(); $('input').focus(); updateSlashMenu(); };
}

async function openSession(id) {
  S.current = id; S.streaming = null; S.tools = new Map(); S.stick = true;
  store.set('ark.session', id);
  $('log').innerHTML = '';
  showView('chat');
  const s = S.sessions.find((x) => x.id === id);
  setStatus(!!(s && s.running));
  $('modelChip').textContent = (s && s.model) || (S.models && S.models.default) || '';
  if (S.sub) { S.arp.call('unsubscribe', { subscription: S.sub }).catch(() => {}); }
  S.sub = S.arp.next;
  S.arp.call('subscribe', { id, from_seq: 0 }).catch((e) => addMsg('notice err', '', esc(e.message)));
  renderSessions();
  redrawDock();
  $('reviewBtn').hidden = false;
  loadReview();
  if (typeof workSession === 'function') workSession();
  $('input').focus();
}
// ── session review (reviewer marks a conversation reviewed / flagged; audited server-side) ──
async function loadReview() {
  const id = S.current;
  let r = null;
  try { r = await S.arp.call('session.review.get', { id }); } catch {}
  if (id !== S.current) return;
  S.review = r && r.current;
  $('reviewMark').textContent = S.review ? (S.review.status === 'flagged' ? ' ⚑' : ' ✓') : '';
  $('reviewMark').className = 'review-mark ' + (S.review ? S.review.status : '');
}
$('reviewBtn').onclick = () => {
  const c = S.review;
  $('reviewCur').textContent = c ? `${c.status} · ${c.by || ''} · ${new Date(c.at_ms).toLocaleString()}${c.note ? ' — ' + c.note : ''}` : '';
  $('reviewNote').value = '';
  $('reviewDlg').showModal();
};
$('reviewDlg').addEventListener('close', async () => {
  const v = $('reviewDlg').returnValue;
  if (v !== 'reviewed' && v !== 'flagged') return;
  try { await S.arp.call('session.review.set', { id: S.current, status: v, note: $('reviewNote').value }); toast(t('review_done', { s: t(v) })); }
  catch (e) { toast(e.message, true); }
  loadReview();
});

// The switch happens at once (a message typed while the server creates the session must not
// land in the previous one): `send` waits on `S.creating`.
function newSession() {
  if (S.creating) return S.creating;
  const prev = S.current;
  S.current = null;
  $('log').innerHTML = '';
  S.creating = (async () => {
    const ws = store.get('ark.workspace') || '';
    // No workspace chosen: the server uses [app] workspace (or its own directory), never "/".
    const { id } = await S.arp.call('session.create', ws ? { workspace: ws, title: '網頁對話' } : { title: '網頁對話' }).catch((e) => (toast(e.message, true), {}));
    if (!id) { if (prev && !S.current) await openSession(prev); return; }
    await loadSessions();
    await openSession(id);
  })().finally(() => { S.creating = null; });
  return S.creating;
}

async function send(text, opts) {
  if (!text.trim() && !ATT.length) return;
  if (S.creating) await S.creating;
  if (!S.current) await newSession();
  if (!S.current) return;
  // `/…` lines are commands: the shared table in the kernel decides what they do, and the
  // action they return (new_session / quit / local) is performed by this client.
  if (text.trim().startsWith('/') && !(opts && opts.raw)) { closeSlash(); return runSlash(text.trim()); }
  const uploads = ATT.map((a) => a.path);
  if ($('log').querySelector('.empty')) $('log').innerHTML = '';
  S.stick = true;
  try {
    if (uploads.length) {
      await S.arp.call('ui.submit', { id: S.current, text, uploads });
      ATT.length = 0;
      renderAtt();
    } else await S.arp.call('session.submit', { id: S.current, text, source: 'web' });
    setStatus(true);
  } catch (e) { addMsg('notice err', '', esc(e.message)); }
}

async function showPanel(title, fn, after) {
  $('panelTitle').textContent = title;
  $('title').textContent = title;
  $('panelBody').innerHTML = '<span class="star spin"></span>';
  $('panelDialog').showModal();
  $('title').textContent = title;
  try { $('panelBody').innerHTML = await fn(); if (after) after(); } catch (e) { $('panelBody').innerHTML = `<p class="bad">${esc(e.message)}</p>`; }
  guardPanel($('panelBody'));
  $('panelDialog').scrollTop = 0;
}

// ── RBAC in the UI (gen2-518): the server enforces every method; the UI mirrors what the
// caller may do (`whoami.can`) so a read-only role never sees a control that would only fail.
function applyAccess(me) {
  const can = (me && me.can) || { write: true, approve: true };
  document.body.classList.toggle('ro', !can.write);
  document.body.classList.toggle('no-approve', !can.approve);
  if (!can.write) document.body.dataset.access = (me && me.access) || 'read';
  const who = me && (me.name || me.kind);
  $('whoami').innerHTML = who ? `<span class="star" style="--size:9px"></span><span>${esc(who)}</span>${me.access ? `<span class="role">${esc(me.access)}</span>` : ''}` : '';
}
// Read-only callers: every control in a Control UI page is hidden / disabled unless it is a
// pure read (navigation, refresh, export, filters), which pages.js marks with `data-read`.
function guardPanel(root) {
  if (!document.body.classList.contains('ro') || !root) return;
  for (const b of root.querySelectorAll('button:not([data-read]):not([data-page])')) b.hidden = true;
  for (const el of root.querySelectorAll('input:not([data-read]), select:not([data-read]), textarea:not([data-read])')) el.disabled = true;
  if (!root.querySelector('.ro-note')) root.insertAdjacentHTML('afterbegin', '<p class="ro-note dim">唯讀角色：寫入操作已隱藏。</p>');
}

function row(cells) { return '<tr>' + cells.map((c) => `<td>${c}</td>`).join('') + '</tr>'; }

// ── command palette (Ctrl/⌘+K): views, Control pages, conversations, slash commands ──
const PAL = { items: [], idx: 0 };
function paletteItems(q) {
  const items = [];
  for (const [v, key] of Object.entries(VIEW_SEC)) if (v !== 'page') items.push({ kind: 'view', label: t(key), sub: '#' + v, run: () => (v === 'chat' && S.current ? openSession(S.current) : showView(v)) });
  if (typeof PAGES === 'object') for (const [id, p] of Object.entries(PAGES)) items.push({ kind: 'page', label: p.title, sub: id, run: () => { S.pageNav = 'showControl'; openPage(id); } });
  for (const s of S.sessions.slice(0, 80)) items.push({ kind: 'chat', label: s.title || s.id, sub: ago(s.updated_ms), run: () => openSession(s.id) });
  for (const c of CMDS.list.slice(0, 120)) items.push({ kind: 'cmd', label: '/' + c.name, sub: c.description || '', run: () => { if (!S.current) return; showView('chat'); $('input').value = '/' + c.name + ' '; autosize(); $('input').focus(); } });
  const n = q.trim().toLowerCase();
  if (!n) return items.slice(0, 40);
  return items.map((it) => [it.label.toLowerCase().startsWith(n) ? 0 : it.label.toLowerCase().includes(n) ? 1 : String(it.sub).toLowerCase().includes(n) ? 2 : 9, it]).filter(([r]) => r < 9).sort((a, b) => a[0] - b[0]).slice(0, 40).map(([, it]) => it);
}
function renderPalette() {
  PAL.items = paletteItems($('paletteInput').value);
  PAL.idx = Math.min(PAL.idx, Math.max(0, PAL.items.length - 1));
  $('paletteList').innerHTML = PAL.items.map((it, i) => `<button type="button" class="pal${i === PAL.idx ? ' on' : ''}" data-i="${i}"><span class="kind">${esc(it.kind)}</span><span>${esc(it.label)}</span><span class="sub">${esc(String(it.sub).slice(0, 60))}</span></button>`).join('');
  for (const b of $('paletteList').querySelectorAll('[data-i]')) b.onclick = () => runPalette(+b.dataset.i);
}
function runPalette(i) { const it = PAL.items[i]; $('palette').close(); if (it) it.run(); }
async function openPalette() {
  $('paletteInput').value = '';
  PAL.idx = 0;
  renderPalette();
  $('palette').showModal();
  $('paletteInput').focus();
  // Commands arrive after the first paint; whatever was typed meanwhile still filters them.
  if (!CMDS.loaded) { await loadCommands(); renderPalette(); }
}
$('paletteInput').addEventListener('input', () => { PAL.idx = 0; renderPalette(); });
$('paletteInput').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); PAL.idx = (PAL.idx + (e.key === 'ArrowDown' ? 1 : -1) + PAL.items.length) % Math.max(1, PAL.items.length); renderPalette(); }
  else if (e.key === 'Enter') { e.preventDefault(); runPalette(PAL.idx); }
});
$('palette').addEventListener('click', (e) => { if (e.target === $('palette')) $('palette').close(); });
$('paletteBtn').onclick = openPalette;
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); }
  else if (e.key === 'Escape' && S.view === 'page' && !document.querySelector('dialog[open]')) $('panelDialog').close();
});

async function start(token) {
  S.arp = new Arp(token);
  setConn('conn.connecting');
  // A failed connect is usually the daemon restarting: keep the saved token and retry. Only
  // when it has never worked in this page (likely a wrong token) ask for one, pre-filled.
  try { await S.arp.connect(); } catch (e) {
    setConn('conn.failed', null, 'down');
    S.fails = (S.fails || 0) + 1;
    if (S.connected || S.fails < 3) { setTimeout(() => start(token), Math.min(10000, 1500 * S.fails)); return; }
    $('token').value = token;
    return askToken();
  }
  S.connected = true;
  S.fails = 0;
  S.arp.on('ready', (p) => setConn('conn.ready', { v: p.server.version }, 'live'));
  // Two subscriptions share the socket: the global one feeds the rail and approvals,
  // the session one feeds the transcript. Route by subscription id so nothing renders twice.
  S.arp.on('event', (p) => {
    if (p.subscription === S.globalSub) {
      if (p.event && (p.event.type === 'turn_end' || p.event.type === 'turn_start' || p.event.type === 'header')) loadSessions();
      if (typeof opsEvent === 'function') opsEvent(p);
      return;
    }
    if (p.session === S.current) renderEvent(p.event);
  });
  S.arp.on('delta', (p) => { if (p.subscription !== S.globalSub) onDelta(p); });
  S.arp.on('pending', (p) => { if (p.subscription === S.globalSub) onPending(p); });
  S.arp.on('close', () => { if (S.arp && S.arp.token !== token) return; setConn('conn.down', null, 'down'); setTimeout(() => start(token), 3000); });
  // After the handlers: the server's `ready` notification must not arrive unobserved.
  try { S.me = await S.arp.call('whoami'); } catch { S.me = null; }
  applyAccess(S.me);
  if (S.conn && S.conn[0] === 'conn.connecting') setConn('conn.ready', null, 'live');
  // A second subscription follows every session for approvals and the rail.
  S.globalSub = S.arp.next;
  S.arp.call('subscribe', {}).catch(() => {});
  try { S.models = await S.arp.call('models.list'); } catch { S.models = null; }
  await loadSessions();
  loadPluginPanels();
  S.pending.clear();
  try { for (const p of await S.arp.call('gate.pending')) onPending(p); } catch {}
  // Start where the person left off: a deep link, the last view, or the overview.
  const h = new URLSearchParams(location.hash.slice(1));
  const want = h.get('view') || store.get('ark.view') || 'ops';
  const last = store.get('ark.session');
  if (want === 'chat') {
    const id = (last && S.sessions.some((s) => s.id === last)) ? last : (S.sessions[0] && S.sessions[0].id);
    if (id) openSession(id); else { showView('chat'); emptyChat(); }
  } else if (!h.get('page')) showView(VIEWS[want] ? want : 'ops', { keepHash: true });
  if (typeof opsStart === 'function') opsStart();
}

function askToken() {
  $('login').showModal();
  $('loginForm').onsubmit = () => {
    const tk = $('token').value.trim();
    if ($('remember').checked) store.set('ark.token', tk);
    start(tk);
  };
}

// ── wiring ──
$('composer').onsubmit = (e) => { e.preventDefault(); const text = $('input').value; $('input').value = ''; autosize(); closeSlash(); send(text); };
$('input').addEventListener('keydown', (e) => {
  if (SLASH.open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) { e.preventDefault(); moveSlash(e.key === 'ArrowDown' ? 1 : -1); return; }
  if (SLASH.open && (e.key === 'Tab' || (e.key === 'Enter' && !e.shiftKey))) { e.preventDefault(); pickSlash(SLASH.items[SLASH.idx].name); return; }
  if (SLASH.open && e.key === 'Escape') { e.preventDefault(); closeSlash(); return; }
  if (e.key === 'Escape' && S.running) { e.preventDefault(); $('stop').click(); return; }
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
$('lang').onclick = () => { setLang(LANG === 'en' ? 'zh-Hant' : 'en'); $('lang').textContent = t('lang'); renderSessions(); if (S.view && S.view !== 'page') showView(S.view, { keepHash: true }); };
$('theme').onchange = (e) => setTheme(e.target.value);
setLang(LANG, false);
setTheme(store.get('ark.theme') || 'crimson', false);
$('lang').textContent = t('lang');
function autosize() { const ta = $('input'); ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, innerHeight * 0.4) + 'px'; }
$('newSession').onclick = newSession;
$('sessFilter').addEventListener('input', renderSessions);
$('stop').onclick = () => S.current && S.arp.call('session.interrupt', { id: S.current });
$('menu').onclick = () => $('side').classList.toggle('open');
$('panelClose').onclick = () => $('panelDialog').close();
chatScroll().addEventListener('scroll', () => {
  const c = chatScroll();
  if (Math.abs(c.scrollTop - (S.autoTop || 0)) < 4) return;
  S.stick = nearBottom();
  if (S.stick) S.autoTop = c.scrollTop;
  $('jump').hidden = S.stick;
});
$('jump').onclick = () => { S.stick = true; stick(true); $('jump').hidden = true; };
for (const b of document.querySelectorAll('.nav-item[data-view]')) {
  b.addEventListener('click', () => {
    const v = b.dataset.view;
    if (v === 'chat') { const id = S.current || store.get('ark.session') || (S.sessions[0] && S.sessions[0].id); if (id && S.sessions.some((s) => s.id === id)) openSession(id); else { showView('chat'); emptyChat(); } }
    else showView(v);
  });
}
// Control pages and dashboards light up their own nav entry.
for (const id of ['showControl', 'showBoards', 'showSettings']) $(id).addEventListener('click', () => { S.pageNav = id; }, true);
$('showSettings').onclick = () => showPanel(t('settings'), async () => {
  const m = await S.arp.call('models.list');
  const tools = await S.arp.call('tools.list');
  return `<h3>模型</h3><table class="kv">${row(['預設模型', `<code>${esc(m.default)}</code>`])}${row(['備援', esc((m.fallback || []).join(', ') || '—')])}${row(['輔助模型', `<code>${esc(m.aux || '—')}</code>`])}${row(['工具', String(tools.length)])}</table>
    <h3>這台裝置</h3>
    <p><label class="dim">新對話的工作目錄</label><input type="text" id="wsInput" value="${esc(store.get('ark.workspace') || '')}" placeholder="（伺服器預設）"></p>
    ${(S.settingsPanels || []).length ? '<h3>外掛設定</h3>' : ''}${(S.settingsPanels || []).map(([p, u], i) => `<p><button class="btn ghost small" data-panel="${i}">${esc(u.title || u.id)}（${esc(p)}）</button></p>`).join('')}
    <p><button class="btn ghost small" id="logout" data-read>登出這台裝置</button></p>`;
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
