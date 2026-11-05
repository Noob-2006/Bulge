// seagent web UI: agent work surfaces — session dashboards (show_widget / dashboard),
// progress cards, the dashboards gallery and paused lobster workflows.
// Uses app.js globals: S, $, esc, appDoc, showPanel, row.
'use strict';

const SURF = { tab: null, expanded: false, timer: null };
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
  await showPanel('儀表板', async () => '<div id="boardView"></div>');
  const view = $('boardView');
  let b;
  try { b = await S.arp.call('surfaces.board', { session }); } catch (e) { view.textContent = e.message; return; }
  SURF.tab = tab || SURF.tab || (b.tabs[0] && b.tabs[0].tabId);
  if (!b.tabs.some((t) => t.tabId === SURF.tab)) SURF.tab = b.tabs[0] && b.tabs[0].tabId;
  view.innerHTML = cardHtml(b.progressCard) + `<nav class="board-tabs">${b.tabs.map((t) => `<button class="btn ghost small${t.tabId === SURF.tab ? ' on' : ''}" data-tab="${esc(t.tabId)}">${esc(t.title)}</button>`).join('')}</nav><div class="board-grid"></div>`;
  if (!b.widgets.length && !b.progressCard) view.innerHTML += '<p class="dim">這個對話還沒有儀表板。請 agent 用 show_widget（pin=true）或 dashboard 建立。</p>';
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
  await showPanel('儀表板總覽', async () => {
    const [boards, runs] = await Promise.all([S.arp.call('surfaces.boards'), S.arp.call('lobster.runs').catch(() => [])]);
    const name = (id) => { const s = (S.sessions || []).find((x) => x.id === id); return s && s.title ? s.title : id; };
    let h = '<table class="kv"><tr><th>對話</th><th>小工具</th><th>內容</th></tr>';
    for (const b of boards) h += `<tr><td><a href="#" data-board="${esc(b.session)}">${esc(name(b.session))}</a></td><td>${b.widgets}</td><td class="dim">${esc((b.titles || []).join('、'))}</td></tr>`;
    h += '</table>';
    if (!boards.length) h = '<p class="dim">還沒有 agent 建立的儀表板。</p>';
    if (runs.length) {
      h += '<h3>等待中的工作流程（lobster）</h3><table class="kv"><tr><th>關卡</th><th>提示</th><th>ID</th></tr>' + runs.map((r) => row([esc(r.gate), esc(r.prompt), `<code>${esc(r.approvalId)}</code>`])).join('') + '</table><p class="dim">在對話中回覆 agent 以核准或取消。</p>';
    }
    return h;
  }, () => { for (const a of $('panelBody').querySelectorAll('[data-board]')) a.onclick = (e) => { e.preventDefault(); openBoard(a.dataset.board); }; });
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
async function pollBoard() {
  if (!S.arp || !S.current) return;
  try {
    const r = await S.arp.call('surfaces.poll', { session: S.current });
    for (const c of r.commands || []) {
      if (c.kind === 'focus_tab') openBoard(S.current, c.tabId);
      if (c.kind === 'set_chat_dock') { SURF.expanded = c.dock === 'hidden'; openBoard(S.current); }
    }
  } catch {}
}
SURF.timer = setInterval(pollBoard, 5000);

$('showBoards').onclick = () => (S.current ? openBoard(S.current) : showBoards());
$('showBoardsAll').onclick = showBoards;
