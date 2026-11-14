// seagent web UI: agent work surfaces — session dashboards (show_widget / dashboard),
// progress cards, the dashboards gallery and paused lobster workflows.
// Uses app.js globals: S, $, esc, appDoc, showPanel, row.
'use strict';

const SURF = { tab: null, expanded: false, timer: null };
const SL = (zh, en) => (typeof LANG !== 'undefined' && LANG === 'en' ? en : zh);
// What a dashboard is, in one sentence (top of both views), and how to get one.
const BOARD_WHAT = () => SL('儀表板是 agent 為這個對話釘上的小工具與進度卡（圖表、清單、狀態），會隨對話更新；在對話裡請它「建立儀表板」就會出現。', 'A dashboard holds the widgets and progress card the agent pins for a conversation (charts, lists, status); it updates as the conversation goes on. Ask the agent to "make a dashboard" in the chat and it appears here.');
const BOARD_ASK = () => SL('幫我為這個對話建立一個儀表板，把目前的進度和重點釘上去。', 'Make a dashboard for this conversation and pin the current progress and key points.');
function boardIntro() { return `<p class="dim board-intro">${esc(BOARD_WHAT())}</p>`; }
// Put the example request in the composer of `session` (the user still presses send).
function boardTry(session) {
  $('panelDialog').close();
  const go = () => { const i = $('input'); if (!i) return; i.value = BOARD_ASK(); i.dispatchEvent(new Event('input')); i.focus(); };
  if (session && S.current !== session && typeof openSession === 'function') Promise.resolve(openSession(session)).then(go);
  else go();
}
function boardEmpty(session) {
  return `<div class="none board-empty"><p><strong>${esc(session ? SL('這個對話還沒有儀表板。', 'This conversation has no dashboard yet.') : SL('還沒有任何對話有儀表板。', 'No conversation has a dashboard yet.'))}</strong></p><p class="dim">${esc(SL('在對話裡對 agent 說，例如：', 'Ask the agent in the chat, for example:'))}「${esc(BOARD_ASK())}」</p>${session || S.current ? `<button class="btn small" data-board-try="${esc(session || S.current)}" data-write>${esc(SL('把這句放進對話輸入框', 'Put this in the message box'))}</button>` : `<p class="dim">${esc(SL('先開一個對話，再請 agent 建立。', 'Open a conversation first, then ask the agent.'))}</p>`}</div>`;
}
function bindBoardTry(root) { for (const b of root.querySelectorAll('[data-board-try]')) b.onclick = () => boardTry(b.dataset.boardTry); }
const CDN = ['https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net', 'https://esm.sh', 'https://unpkg.com', 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'];

function widgetFrame(w) {
  const f = document.createElement('iframe');
  f.className = 'mcp-app widget';
  f.setAttribute('referrerpolicy', 'no-referrer');
  f.title = w.title || w.name;
  if (w.url) {
    // session:website: a live HTTPS site, isolated from seagent (no token, no tools).
    f.setAttribute('sandbox', 'allow-scripts allow-forms allow-popups allow-same-origin');
    f.src = w.url;
  } else {
    f.setAttribute('sandbox', 'allow-scripts');
    const connect = w.grantState === 'granted' && w.declared ? w.declared.netOrigins || [] : [];
    f.srcdoc = appDoc({ html: w.document || '', csp: { resourceDomains: CDN, connectDomains: connect } });
  }
  f.style.height = (w.sizeH || 4) * 70 + 'px';
  f.dataset.widget = w.name;
  return f;
}

function cardHtml(c) {
  if (!c) return '';
  const steps = (c.steps || []).map((s) => `<li>${s.status === 'completed' ? '✓' : s.status === 'in_progress' ? '▶' : '○'} ${esc(s.step)}</li>`).join('');
  const bar = /<progress[^>]*value="([\d.]+)"[^>]*max="([\d.]+)"/.exec(c.markdown || '');
  const label = /aria-label="([^"]*)"/.exec(c.markdown || '');
  const note = (c.markdown || '').replace(/<[^>]*>/g, '').trim();
  return `<section class="card-progress"><h3>進度卡 <span class="dim">rev ${c.revision}</span></h3>${bar ? `<progress value="${bar[1]}" max="${bar[2]}"></progress> <span class="dim">${esc(label ? label[1] : '')}</span>` : ''}${note ? `<p>${esc(note)}</p>` : ''}${steps ? `<ul class="steps">${steps}</ul>` : ''}</section>`;
}

async function openBoard(session, tab) {
  if (!session) return showBoards();
  const sname = (() => { const s = (S.sessions || []).find((x) => x.id === session); return s && s.title ? s.title : ''; })();
  await showPanel(sname ? SL(`儀表板 · ${sname}`, `Dashboard · ${sname}`) : SL('儀表板', 'Dashboard'), async () => '<div id="boardView"></div>');
  const view = $('boardView');
  let b;
  try { b = await S.arp.call('surfaces.board', { session }); } catch (e) { view.textContent = e.message; return; }
  SURF.tab = tab || SURF.tab || (b.tabs[0] && b.tabs[0].tabId);
  if (!b.tabs.some((t) => t.tabId === SURF.tab)) SURF.tab = b.tabs[0] && b.tabs[0].tabId;
  const empty = !b.widgets.length && !b.progressCard;
  view.innerHTML = boardIntro() + cardHtml(b.progressCard) + (empty ? '' : `<nav class="board-tabs">${b.tabs.map((t) => `<button class="btn ghost small${t.tabId === SURF.tab ? ' on' : ''}" data-tab="${esc(t.tabId)}">${esc(t.title)}</button>`).join('')}</nav>`) + `<div class="board-grid"></div><p class="dim"><a href="#" data-boards-all>${esc(SL('看所有對話的儀表板 →', 'All dashboards →'))}</a></p>`;
  if (empty) view.querySelector('.board-grid').insertAdjacentHTML('beforebegin', boardEmpty(session));
  bindBoardTry(view);
  for (const a of view.querySelectorAll('[data-boards-all]')) a.onclick = (e) => { e.preventDefault(); showBoards(); };
  for (const btn of view.querySelectorAll('[data-tab]')) btn.onclick = () => openBoard(session, btn.dataset.tab);
  const grid = view.querySelector('.board-grid');
  grid.classList.toggle('expanded', SURF.expanded || b.defaultPresentation === 'expanded');
  for (const w of b.widgets.filter((x) => x.tabId === SURF.tab)) {
    const cell = document.createElement('div');
    cell.className = 'board-cell' + (w.presentation === 'frameless' ? ' frameless' : '');
    cell.style.gridColumn = `span ${Math.min(12, w.sizeW || 6)}`;
    cell.innerHTML = `<div class="board-head">${esc(w.title || w.name)}</div>`;
    if (w.grantState === 'pending') {
      const d = w.declared || {};
      const ask = document.createElement('div');
      ask.className = 'grant';
      ask.innerHTML = `<p>這個小工具要求：${esc([...(d.netOrigins || []), ...(d.tools || [])].join(', '))}</p><button class="btn small" data-g="grant">允許</button> <button class="btn ghost small" data-g="reject">拒絕</button>`;
      for (const g of ask.querySelectorAll('[data-g]')) g.onclick = async () => { await S.arp.call('surfaces.board.update', { session, op: { kind: g.dataset.g, name: w.name } }); openBoard(session, SURF.tab); };
      cell.appendChild(ask);
    }
    cell.appendChild(widgetFrame(w));
    grid.appendChild(cell);
  }
}

async function showBoards() {
  await showPanel(SL('儀表板總覽', 'All dashboards'), async () => {
    const [boards, runs] = await Promise.all([S.arp.call('surfaces.boards'), S.arp.call('lobster.runs').catch(() => [])]);
    const name = (id) => { const s = (S.sessions || []).find((x) => x.id === id); return s && s.title ? s.title : id; };
    let h = boardIntro() + `<p class="dim">${esc(SL('每個對話各有自己的儀表板；點對話名稱打開。', 'Each conversation has its own dashboard; click a conversation to open it.'))}</p>`;
    h += `<table class="kv"><tr><th>${esc(SL('對話', 'Conversation'))}</th><th>${esc(SL('小工具', 'Widgets'))}</th><th>${esc(SL('內容', 'Contents'))}</th></tr>`;
    for (const b of boards) h += `<tr><td><a href="#" data-board="${esc(b.session)}">${esc(name(b.session))}</a></td><td>${b.widgets}</td><td class="dim">${esc((b.titles || []).join('、'))}</td></tr>`;
    h += '</table>';
    if (!boards.length) h = boardIntro() + boardEmpty('');
    if (runs.length) {
      h += '<h3>等待中的工作流程（lobster）</h3><table class="kv"><tr><th>關卡</th><th>提示</th><th>ID</th></tr>' + runs.map((r) => row([esc(r.gate), esc(r.prompt), `<code>${esc(r.approvalId)}</code>`])).join('') + '</table><p class="dim">在對話中回覆 agent 以核准或取消。</p>';
    }
    return h;
  }, () => { bindBoardTry($('panelBody')); for (const a of $('panelBody').querySelectorAll('[data-board]')) a.onclick = (e) => { e.preventDefault(); openBoard(a.dataset.board); }; });
}

// Widgets talk to the host with postMessage: size reports and user-initiated prompts.
window.addEventListener('message', (e) => {
  const m = e.data;
  if (!m || typeof m !== 'object' || typeof m.type !== 'string' || !m.type.startsWith('seagent:widget-')) return;
  const frame = [...document.querySelectorAll('iframe')].find((f) => f.contentWindow === e.source);
  if (!frame) return;
  if (m.type === 'seagent:widget-size' && Number.isFinite(m.height)) frame.style.height = Math.min(2000, Math.max(60, m.height + 4)) + 'px';
  if (m.type === 'seagent:widget-prompt' && typeof m.prompt === 'string' && S.current) {
    S.arp.call('session.submit', { id: S.current, text: m.prompt.slice(0, 4000), source: 'widget' }).catch(() => {});
  }
});

// Dashboard commands (focus_tab / set_presentation) arrive by polling while a session is open.
// Not while the window is hidden (minimised, another tab, the app in the tray): nobody sees the
// board then, and every poll is a request; it catches up as soon as the window shows again.
async function pollBoard() {
  if (!S.arp || !S.current || document.hidden) return;
  try {
    const r = await S.arp.call('surfaces.poll', { session: S.current });
    for (const c of r.commands || []) {
      if (c.kind === 'focus_tab') openBoard(S.current, c.tabId);
      if (c.kind === 'set_chat_dock') { SURF.expanded = c.dock === 'hidden'; openBoard(S.current); }
    }
  } catch {}
}
SURF.timer = setInterval(pollBoard, 5000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) pollBoard(); });

$('showBoards').onclick = () => (S.current ? openBoard(S.current) : showBoards());
$('showBoardsAll').onclick = showBoards;
