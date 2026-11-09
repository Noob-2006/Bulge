// seagent web UI: split view — a second conversation beside the main one ("⋯ › Open in ›
// Split view"). The pane shows that conversation's transcript (session.view), follows it through
// the global event stream, and has its own composer; ⇄ swaps it with the main pane, ✕ closes it.
// Below 900px the two panes stack. Uses app.js globals: S, $, esc, md, t, toolArg, toast,
// openSession, sessTitle; chat_menu.js: tt. Hooks ops.js `opsEvent` (global events).
'use strict';

const SPLIT = { id: null, el: null, timer: null, running: false };

function splitPane() {
  if (SPLIT.el) return SPLIT.el;
  const el = document.createElement('aside');
  el.className = 'split-pane';
  el.id = 'splitPane';
  el.setAttribute('aria-label', tt('分割檢視', 'Split view'));
  el.innerHTML = `<header class="split-head"><span class="star" style="--size:9px"></span><span class="split-title"></span><span class="split-st faint"></span><span class="spacer"></span>
      <button type="button" class="btn ghost small icon" data-split="swap" title="${esc(tt('與主畫面交換', 'Swap with the main pane'))}">⇄</button>
      <button type="button" class="btn ghost small icon" data-split="close" title="${esc(tt('關閉分割檢視', 'Close split view'))}">✕</button></header>
    <div class="split-scroll"><section class="log split-log" aria-live="polite"></section></div>
    <form class="composer split-composer" data-write><textarea rows="1" placeholder="${esc(tt('傳訊息到這個對話…', 'Message this conversation…'))}" autocomplete="off"></textarea>
      <div class="composer-bar"><span class="chip split-model"></span><span class="spacer"></span><button type="submit" class="btn small">${esc(t('send'))}</button></div></form>`;
  const main = document.querySelector('#view-chat .chat-main');
  main.parentNode.insertBefore(el, main.nextSibling);
  el.querySelector('[data-split=close]').onclick = splitClose;
  el.querySelector('[data-split=swap]').onclick = splitSwap;
  const ta = el.querySelector('textarea');
  const form = el.querySelector('form');
  ta.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); form.requestSubmit(); } });
  ta.addEventListener('input', () => { ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, 160) + 'px'; });
  form.onsubmit = async (e) => {
    e.preventDefault();
    const text = ta.value.trim();
    if (!text || !SPLIT.id) return;
    ta.value = '';
    try { await S.arp.call('session.submit', { id: SPLIT.id, text, source: 'web' }); SPLIT.running = true; splitRender(); } catch (err) { toast(err.message, true); }
  };
  SPLIT.el = el;
  return el;
}

function splitOpen(id) {
  if (!id) return;
  if (!S.current) { openSession(id); return; }
  if (id === S.current) return;
  if (S.view !== 'chat') openSession(S.current);
  SPLIT.id = id;
  const el = splitPane();
  el.hidden = false;
  document.getElementById('view-chat').classList.add('split');
  splitRender();
}
function splitClose() {
  SPLIT.id = null;
  if (SPLIT.el) SPLIT.el.hidden = true;
  document.getElementById('view-chat').classList.remove('split');
}
function splitSwap() {
  const other = SPLIT.id, cur = S.current;
  if (!other || !cur) return;
  SPLIT.id = cur;
  openSession(other);
  splitRender();
}

// The transcript as the model sees it: user and assistant text, one line per tool call.
async function splitRender() {
  const id = SPLIT.id;
  if (!id || !SPLIT.el) return;
  let v;
  try { v = await S.arp.call('session.view', { id }); } catch (e) { SPLIT.el.querySelector('.split-log').innerHTML = `<p class="bad">${esc(e.message)}</p>`; return; }
  if (id !== SPLIT.id) return;
  const s = (S.sessions || []).find((x) => x.id === id) || {};
  SPLIT.running = !!v.running;
  SPLIT.el.querySelector('.split-title').textContent = sessTitle(id);
  SPLIT.el.querySelector('.split-st').textContent = v.running ? tt('工作中…', 'working…') : '';
  SPLIT.el.querySelector('.split-model').textContent = s.model || '';
  const log = SPLIT.el.querySelector('.split-log');
  const box = SPLIT.el.querySelector('.split-scroll');
  const atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  let html = '';
  for (const m of v.messages || []) {
    const blocks = m.content || [];
    const text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('');
    if (m.role === 'user') {
      const src = text.match(/^\[from ([\w.-]+)\]\s*/);
      if (text.trim()) html += `<article class="msg user"><div class="who">${esc(t('you'))}</div><div class="body">${md(src ? text.slice(src[0].length) : text)}</div></article>`;
    } else {
      if (text.trim()) html += `<article class="msg assistant"><div class="who"><span class="star" style="--size:9px"></span> SE Agent</div><div class="body">${md(text)}</div></article>`;
      for (const b of blocks.filter((x) => x.type === 'tool_use')) html += `<article class="msg tool"><div class="body"><div class="split-tool"><span class="nm">${esc(b.name)}</span> <span class="faint">${esc(toolArg(b.name, b.input))}</span></div></div></article>`;
    }
  }
  log.innerHTML = html || `<div class="empty"><p class="faint">${esc(tt('這個對話還沒有訊息', 'No messages yet'))}</p></div>`;
  if (atEnd) box.scrollTop = box.scrollHeight;
}

// Follow the split conversation through the global subscription (debounced re-render).
function splitEvent(p) {
  if (!SPLIT.id || !p || p.session !== SPLIT.id) return;
  const k = p.event && p.event.type;
  if (!['message', 'turn_start', 'turn_end', 'notice', 'error', 'title'].includes(k)) return;
  clearTimeout(SPLIT.timer);
  SPLIT.timer = setTimeout(splitRender, 150);
}
if (typeof opsEvent === 'function') {
  const prevOpsEvent = opsEvent;
  // eslint-disable-next-line no-global-assign
  opsEvent = function (p) { prevOpsEvent(p); splitEvent(p); };
}
