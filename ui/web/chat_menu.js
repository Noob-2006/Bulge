// seagent web UI: conversation management in the chat rail and per-conversation settings.
// - Every conversation row has a "⋯" menu (also right-click): open in a new tab / window,
//   settings, pin (P), mark unread (U), rename (R), fork (F), hide nested sessions (H), move to
//   section (M), export (E), archive (A), delete (D, with confirmation and undo).
// - The rail groups conversations: pinned, user sections (collapsible, renamable), by day,
//   archived, recently deleted (restorable). Sub-agent / child sessions nest under their parent.
// - The chat header's ⚙ opens the conversation's own settings (model, reasoning effort, fast
//   mode, exec route, approval mode, tools, persona); the composer's model chip switches the
//   model from each provider's live list (ui.chat.models.list).
// Backed by `ui.chat.*` (crates/seagent/src/ops/chat_ux.rs) and `ui.chat.models.list`
// (ops/model_keys.rs). Uses app.js globals: S, $, esc, t, LANG, toast, store, ago, openSession,
// loadSessions, renderSessions, newSession, showView, emptyChat. Hooks called from app.js:
// chatRail() (renderSessions), chatRailLoad() (loadSessions), chatOpened(id) (openSession).
'use strict';

const tt = (zh, en) => (LANG === 'en' ? en : zh);
const CM = {
  state: { sections: [], read_ms: {}, unread: [], folded: [], trash: [] },
  menu: null, // {levels: [{el, items, idx}], row, focus}
  renaming: null,
  open: { archived: false, trash: false },
  models: null, modelsAt: 0,
};
const cmCall = (m, p) => S.arp.call(m, p || {});
const cmErr = (e) => toast((e && e.message) || String(e), true);

// "Open in › new tab / window": #view=chat&chat=<id> opens that conversation (app.js start()
// reads the last session from storage once connected, so set it now).
(function chatDeepLink() {
  const id = new URLSearchParams(location.hash.slice(1)).get('chat');
  if (id && /^[A-Za-z0-9_-]{1,64}$/.test(id)) { store.set('seagent.session', id); store.set('seagent.view', 'chat'); }
})();

// ── rail state ──
function isUnread(s) {
  if (!s) return false;
  if ((CM.state.unread || []).includes(s.id)) return true;
  const r = (CM.state.read_ms || {})[s.id];
  return !!r && s.updated_ms > r + 1500;
}
async function chatRailLoad() {
  if (!S.arp) return;
  try { Object.assign(CM.state, await cmCall('ui.chat.list')); } catch { return; }
  // The conversation on screen is being read: new turns there do not make it unread.
  const cur = S.current && (S.sessions || []).find((s) => s.id === S.current);
  if (cur && S.view === 'chat' && document.visibilityState === 'visible' && isUnread(cur)) markRead(cur.id);
}
function markRead(id) {
  CM.state.unread = (CM.state.unread || []).filter((x) => x !== id);
  CM.state.read_ms = Object.assign({}, CM.state.read_ms, { [id]: Date.now() });
  cmCall('ui.chat.read', { id }).catch(() => {});
}
function chatOpened(id) {
  if (!document.body.classList.contains('ro')) markRead(id);
  const s = (S.sessions || []).find((x) => x.id === id);
  setModelChip((s && s.model) || (S.models && S.models.default) || '');
  renderSessions();
}

// ── rail rendering (replaces the body of app.js renderSessions) ──
function chatRail() {
  const nav = $('sessions');
  const q = ($('sessFilter').value || '').trim().toLowerCase();
  const all = S.sessions || [];
  const list = all.filter((s) => !q || (s.title || s.id).toLowerCase().includes(q) || s.id.includes(q));
  const ids = new Set(list.map((s) => s.id));
  const kids = new Map();
  for (const s of list) if (s.parent && ids.has(s.parent)) { if (!kids.has(s.parent)) kids.set(s.parent, []); kids.get(s.parent).push(s); }
  const roots = list.filter((s) => !s.parent || !ids.has(s.parent));
  const live = roots.filter((s) => !s.archived);
  const f = document.createDocumentFragment();
  const pinned = live.filter((s) => s.pinned);
  if (pinned.length) railGroup(f, tt('已釘選', 'Pinned'), pinned, kids);
  const sections = (CM.state.sections || []).slice();
  // A group set from the CLI (`seagent session group`) shows up as a section too.
  for (const g of new Set(live.filter((s) => s.group && !sections.some((x) => x.name === s.group)).map((s) => s.group))) sections.push({ name: g, collapsed: false });
  for (const sec of sections) railSection(f, sec, live.filter((s) => !s.pinned && s.group === sec.name), kids);
  const day = 86400000;
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const when = (s) => (s.updated_ms >= start.getTime() ? 'today' : s.updated_ms >= start.getTime() - day ? 'yesterday' : 'earlier');
  let last = '';
  let bucket = [];
  const flush = () => { if (bucket.length) railGroup(f, t(last), bucket, kids); bucket = []; };
  for (const s of live.filter((x) => !x.pinned && !x.group)) { const g = when(s); if (g !== last) { flush(); last = g; } bucket.push(s); }
  flush();
  const arch = roots.filter((s) => s.archived);
  if (arch.length) railFold(f, 'archived', tt('已封存', 'Archived'), arch.length, () => { for (const s of arch) railRows(f, s, kids); });
  const trash = (CM.state.trash || []).filter((x) => !q || String(x.title || x.id).toLowerCase().includes(q));
  if (trash.length) railFold(f, 'trash', tt('最近刪除', 'Recently deleted'), trash.length, () => { for (const x of trash) f.appendChild(trashRow(x)); });
  if (!list.length && !trash.length) f.appendChild(Object.assign(document.createElement('div'), { className: 'none', textContent: t('no_sessions') }));
  const ns = document.createElement('button');
  ns.type = 'button';
  ns.className = 'btn ghost small sess-new-sec';
  ns.dataset.write = '';
  ns.textContent = tt('＋ 新增分區', '+ New section');
  ns.onclick = () => newSection();
  f.appendChild(ns);
  nav.innerHTML = '';
  nav.appendChild(f);
  if (CM.renaming) { const inp = nav.querySelector('.sess-rename'); if (inp) { inp.focus(); inp.select(); } }
  const running = all.filter((s) => s.running).length;
  const ba = $('badgeAgents');
  ba.hidden = !running;
  ba.textContent = running;
}
function railGroup(f, label, members, kids) {
  f.appendChild(Object.assign(document.createElement('div'), { className: 'sess-group label', textContent: label }));
  for (const s of members) railRows(f, s, kids);
}
function railFold(f, key, label, n, body) {
  const h = document.createElement('div');
  h.className = 'sess-sec' + (CM.open[key] ? '' : ' collapsed');
  h.dataset.fold = key;
  h.innerHTML = `<span class="caret">›</span><span class="label">${esc(label)}</span><span class="count">${n}</span>`;
  h.onclick = () => { CM.open[key] = !CM.open[key]; chatRail(); };
  f.appendChild(h);
  if (CM.open[key]) body();
}
function railSection(f, sec, members, kids) {
  const h = document.createElement('div');
  h.className = 'sess-sec' + (sec.collapsed ? ' collapsed' : '');
  h.dataset.section = sec.name;
  h.innerHTML = `<span class="caret">›</span><span class="label">${esc(sec.name)}</span><span class="count">${members.length}</span><button type="button" class="sess-more" data-write aria-haspopup="menu" aria-label="${esc(tt('分區選項', 'Section options'))}">⋯</button>`;
  h.onclick = (e) => {
    if (e.target.closest('.sess-more')) return;
    sec.collapsed = !sec.collapsed;
    const known = (CM.state.sections || []).find((x) => x.name === sec.name);
    if (known) known.collapsed = sec.collapsed;
    chatRail();
    cmCall('ui.chat.section', { op: 'collapse', name: sec.name, collapsed: sec.collapsed }).then((r) => { CM.state.sections = r.sections; }).catch(cmErr);
  };
  const more = h.querySelector('.sess-more');
  more.onclick = (e) => { e.stopPropagation(); cmMenu(sectionItems(sec), more.getBoundingClientRect(), { focus: more }); };
  f.appendChild(h);
  if (sec.collapsed) return;
  if (!members.length) {
    const hint = document.createElement('div');
    hint.className = 'none faint';
    hint.setAttribute('style', 'padding:2px 10px 6px 24px;font-size:11.5px');
    hint.textContent = tt('（空）用「⋯ › 移到分區」把對話放進來', '(empty) use ⋯ › Move to section');
    f.appendChild(hint);
  }
  for (const s of members) railRows(f, s, kids);
}
function railRows(f, s, kids) {
  const children = kids.get(s.id) || [];
  f.appendChild(railRow(s, false, children.length));
  if (children.length && !(CM.state.folded || []).includes(s.id)) for (const c of children) f.appendChild(railRow(c, true, 0));
}
function moreButton(label, onOpen) {
  const more = document.createElement('button');
  more.type = 'button';
  more.className = 'sess-more';
  more.dataset.write = '';
  more.setAttribute('aria-haspopup', 'menu');
  more.setAttribute('aria-label', label);
  more.title = label;
  more.textContent = '⋯';
  more.onclick = (e) => { e.stopPropagation(); if (CM.menu && CM.menu.focus === more) { cmClose(); return; } onOpen(more); };
  return more;
}
function railRow(s, child, nkids) {
  const row = document.createElement('div');
  row.className = 'sess-row' + (isUnread(s) && s.id !== S.current ? ' unread' : '');
  row.dataset.id = s.id;
  if (CM.renaming === s.id) {
    const inp = document.createElement('input');
    inp.className = 'sess-rename';
    inp.value = s.title || '';
    inp.maxLength = 80;
    inp.setAttribute('aria-label', tt('對話名稱', 'Conversation name'));
    let done = false;
    const finish = async (save) => {
      if (done) return;
      done = true;
      CM.renaming = null;
      const v = inp.value.trim();
      if (save && v && v !== s.title) {
        s.title = v;
        try { await cmCall('ui.chat.settings.set', { id: s.id, title: v }); } catch (e) { cmErr(e); }
        if (s.id === S.current) $('title').textContent = v;
      }
      chatRail();
    };
    inp.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); finish(true); } else if (e.key === 'Escape') { e.preventDefault(); finish(false); } };
    inp.onblur = () => finish(true);
    row.appendChild(inp);
    return row;
  }
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'sess' + (s.id === S.current ? ' active' : '') + (child ? ' child' : '');
  b.title = s.id;
  b.innerHTML = `${s.running ? '<span class="star pulse" style="--size:10px"></span>' : '<span class="dot"></span>'}<span class="t">${esc(s.title || s.id)}</span><span class="m">${ago(s.updated_ms)}</span>`;
  b.onclick = () => openSession(s.id);
  b.oncontextmenu = (e) => { if (document.body.classList.contains('ro')) return; e.preventDefault(); cmMenu(chatItems(s), { x: e.clientX, y: e.clientY }, { row, focus: b }); };
  row.appendChild(b);
  if (nkids) {
    const folded = (CM.state.folded || []).includes(s.id);
    const fb = document.createElement('button');
    fb.type = 'button';
    fb.className = 'sess-fold';
    fb.textContent = "›"; fb.classList.toggle("open", !folded);
    fb.title = folded ? tt(`顯示 ${nkids} 個子對話`, `Show ${nkids} nested`) : tt('隱藏子對話', 'Hide nested sessions');
    fb.onclick = (e) => { e.stopPropagation(); setMeta(s, { folded: !folded }); };
    row.appendChild(fb);
  }
  row.appendChild(moreButton(tt('對話選項', 'Conversation options'), (more) => cmMenu(chatItems(s), more.getBoundingClientRect(), { row, focus: more })));
  return row;
}
function trashRow(x) {
  const row = document.createElement('div');
  row.className = 'sess-row';
  row.dataset.trash = x.id;
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'sess';
  b.title = x.id;
  b.innerHTML = `<span class="dot"></span><span class="t faint">${esc(x.title || x.id)}</span><span class="m">${ago(x.deleted_ms)}</span>`;
  const items = () => [
    { head: x.title || x.id },
    { label: tt('還原', 'Restore'), icon: '↺', key: 'R', run: () => restoreChat(x.id) },
    { sep: true },
    { label: tt('永久刪除…', 'Delete forever…'), icon: '✕', key: 'D', danger: true, run: () => purgeChat(x) },
  ];
  b.onclick = () => cmMenu(items(), b.getBoundingClientRect(), { row, focus: b });
  row.appendChild(b);
  row.appendChild(moreButton(tt('選項', 'Options'), (more) => cmMenu(items(), more.getBoundingClientRect(), { row, focus: more })));
  return row;
}

// ── menu engine: one element per level, keyboard + shortcut letters, bottom sheet on phones ──
const isPhone = () => matchMedia('(max-width: 600px)').matches;
function cmClose() {
  const m = CM.menu;
  if (!m) return;
  CM.menu = null;
  for (const l of m.levels) l.el.remove();
  if (m.row) m.row.classList.remove('menu-open');
  document.removeEventListener('keydown', cmKey, true);
  document.removeEventListener('pointerdown', cmOutside, true);
  window.removeEventListener('resize', cmClose);
  if (m.focus && document.contains(m.focus)) m.focus.focus();
}
function cmOutside(e) {
  const m = CM.menu;
  if (!m || m.levels.some((l) => l.el.contains(e.target))) return;
  // A press on the button that opened the menu is that button's toggle, not "outside".
  if (m.focus && m.focus.contains(e.target)) return;
  cmClose();
}
// `at` is the opener's DOMRect, or a point {x, y} (right-click). Phones: CSS makes a sheet.
function cmPlace(el, at, beside) {
  if (isPhone() || !at) return;
  const w = el.offsetWidth, h = el.offsetHeight;
  const rect = at.left !== undefined;
  let x = rect ? (beside ? at.right - 2 : at.left) : at.x;
  let y = rect ? (beside ? at.top - 5 : at.bottom + 2) : at.y;
  if (x + w > innerWidth - 8) x = rect && beside ? at.left - w + 2 : innerWidth - w - 8;
  if (y + h > innerHeight - 8) y = rect ? (beside ? at.bottom - h + 5 : at.top - h - 2) : at.y - h;
  el.style.left = Math.max(8, x) + 'px';
  el.style.top = Math.max(8, y) + 'px';
}
function cmLevel(items, at, beside) {
  const el = document.createElement('div');
  el.className = 'cm-menu';
  el.setAttribute('role', 'menu');
  const lvl = { el, items, idx: -1 };
  items.forEach((it, i) => {
    if (it.sep) { el.appendChild(Object.assign(document.createElement('div'), { className: 'cm-sep' })); return; }
    if (it.head) { el.appendChild(Object.assign(document.createElement('div'), { className: 'cm-head', textContent: it.head })); return; }
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'cm-item' + (it.danger ? ' danger' : '');
    b.setAttribute('role', 'menuitem');
    if (it.disabled) b.disabled = true;
    b.innerHTML = `<span class="ic">${esc(it.icon || '')}</span><span class="lb">${esc(it.label)}</span>${it.sub ? '<span class="sub">›</span>' : it.key ? `<kbd>${esc(it.key)}</kbd>` : ''}`;
    b.onclick = (e) => { e.stopPropagation(); cmActivate(lvl, i); };
    b.onmouseenter = () => { cmHighlight(lvl, i); if (it.sub && !isPhone()) cmOpenSub(lvl, i); else cmCloseSubs(lvl); };
    it.btn = b;
    el.appendChild(b);
  });
  document.body.appendChild(el);
  cmPlace(el, at, beside);
  return lvl;
}
function cmMenu(items, at, opts) {
  cmClose();
  const o = opts || {};
  CM.menu = { levels: [cmLevel(items.filter(Boolean), at, false)], row: o.row || null, focus: o.focus || null };
  if (o.row) o.row.classList.add('menu-open');
  document.addEventListener('keydown', cmKey, true);
  setTimeout(() => document.addEventListener('pointerdown', cmOutside, true), 0);
  window.addEventListener('resize', cmClose);
  const top = CM.menu.levels[0];
  cmHighlight(top, cmNext(top, -1, 1));
}
function cmHighlight(lvl, i) {
  lvl.idx = i;
  lvl.items.forEach((it, j) => it.btn && it.btn.classList.toggle('on', j === i));
  const it = lvl.items[i];
  if (it && it.btn) it.btn.focus();
}
function cmNext(lvl, from, d) {
  const n = lvl.items.length;
  for (let k = 1; k <= n; k++) {
    const j = (((from + d * k) % n) + n) % n;
    const it = lvl.items[j];
    if (it && it.btn && !it.disabled) return j;
  }
  return from;
}
function cmCloseSubs(lvl) {
  const m = CM.menu;
  if (!m) return;
  const at = m.levels.indexOf(lvl);
  if (at < 0) return;
  while (m.levels.length > at + 1) m.levels.pop().el.remove();
}
function cmOpenSub(lvl, i) {
  const m = CM.menu;
  const it = lvl.items[i];
  if (m.levels[m.levels.indexOf(lvl) + 1] && m.levels[m.levels.indexOf(lvl) + 1].from === i) return m.levels[m.levels.indexOf(lvl) + 1];
  cmCloseSubs(lvl);
  const sub = (typeof it.sub === 'function' ? it.sub() : it.sub).filter(Boolean);
  if (isPhone()) {
    // A bottom sheet has no room beside it: the sub-menu replaces it, with a way back.
    const parent = lvl.items, row = m.row, focus = m.focus;
    const back = { label: tt('返回', 'Back'), icon: '‹', run: () => cmMenu(parent, {}, { row, focus }) };
    cmMenu([back, { head: it.label }].concat(sub), {}, { row, focus });
    return null;
  }
  const nl = cmLevel(sub, it.btn.getBoundingClientRect(), true);
  nl.from = i;
  m.levels.push(nl);
  return nl;
}
function cmActivate(lvl, i) {
  const it = lvl.items[i];
  if (!it || it.disabled) return;
  if (it.sub) { const nl = cmOpenSub(lvl, i); if (nl) cmHighlight(nl, cmNext(nl, -1, 1)); return; }
  cmClose();
  if (it.run) Promise.resolve(it.run()).catch(cmErr);
}
function cmKey(e) {
  const m = CM.menu;
  if (!m) return;
  const lvl = m.levels[m.levels.length - 1];
  if (e.target && e.target.tagName === 'INPUT') { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); cmClose(); } return; }
  const k = e.key;
  if (k === 'Escape' || (k === 'ArrowLeft' && m.levels.length > 1)) {
    e.preventDefault(); e.stopPropagation();
    if (m.levels.length > 1) { m.levels.pop().el.remove(); const p = m.levels[m.levels.length - 1]; cmHighlight(p, p.idx); } else cmClose();
    return;
  }
  if (k === 'ArrowDown' || k === 'ArrowUp') { e.preventDefault(); cmHighlight(lvl, cmNext(lvl, lvl.idx, k === 'ArrowDown' ? 1 : -1)); return; }
  if (k === 'ArrowRight') { const it = lvl.items[lvl.idx]; if (it && it.sub) { e.preventDefault(); cmActivate(lvl, lvl.idx); } return; }
  if (k === 'Enter' || k === ' ') { e.preventDefault(); cmActivate(lvl, lvl.idx); return; }
  if (k === 'Tab') { e.preventDefault(); cmHighlight(lvl, cmNext(lvl, lvl.idx, e.shiftKey ? -1 : 1)); return; }
  if (k.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
    const j = lvl.items.findIndex((it) => it.btn && !it.disabled && it.key && it.key.toLowerCase() === k.toLowerCase());
    if (j >= 0) { e.preventDefault(); cmActivate(lvl, j); }
  }
}

// ── the conversation menu ──
function chatItems(s) {
  const unread = (isUnread(s) && s.id !== S.current) || (CM.state.unread || []).includes(s.id);
  const nkids = (S.sessions || []).filter((x) => x.parent === s.id).length;
  const folded = (CM.state.folded || []).includes(s.id);
  const sections = () => {
    const names = [...new Set((CM.state.sections || []).map((x) => x.name).concat((S.sessions || []).map((x) => x.group).filter(Boolean)))];
    return names.map((n) => ({ label: n, icon: s.group === n ? '✓' : '', run: () => setMeta(s, { group: n }) }))
      .concat([
        names.length ? { sep: true } : null,
        { label: tt('新增分區…', 'New section…'), icon: '＋', run: async () => { const n = await cmPrompt(tt('新增分區', 'New section'), '', tt('分區名稱', 'Section name')); if (n) await setMeta(s, { group: n }); } },
        s.group ? { label: tt('移出分區', 'Remove from section'), icon: '↤', run: () => setMeta(s, { group: '' }) } : null,
      ]);
  };
  return [
    { head: s.title || s.id },
    { label: tt('開啟於', 'Open in'), icon: '↗', sub: [{ label: tt('新分頁', 'New tab'), icon: '⧉', run: () => openIn(s, 'tab') }, { label: tt('新視窗', 'New window'), icon: '▢', run: () => openIn(s, 'window') }] },
    { label: tt('對話設定…', 'Settings…'), icon: '⚙', key: 'S', run: () => openChatSettings(s.id) },
    { sep: true },
    { label: s.pinned ? tt('取消釘選', 'Unpin') : tt('釘選', 'Pin'), icon: '⊼', key: 'P', run: () => setMeta(s, { pinned: !s.pinned }) },
    { label: unread ? tt('標為已讀', 'Mark as read') : tt('標為未讀', 'Mark as unread'), icon: '●', key: 'U', run: () => { if (unread) { markRead(s.id); chatRail(); } else return setMeta(s, { unread: true }); } },
    { label: tt('重新命名', 'Rename'), icon: '✎', key: 'R', run: () => { CM.renaming = s.id; chatRail(); } },
    { label: tt('分支對話', 'Fork conversation'), icon: '⑂', key: 'F', run: () => forkChat(s) },
    nkids ? { label: folded ? tt(`顯示子對話（${nkids}）`, `Show nested sessions (${nkids})`) : tt(`隱藏子對話（${nkids}）`, `Hide nested sessions (${nkids})`), icon: '⋮', key: 'H', run: () => setMeta(s, { folded: !folded }) } : null,
    { label: tt('移到分區', 'Move to section'), icon: '▤', key: 'M', sub: sections },
    { label: tt('匯出', 'Export'), icon: '⤓', key: 'E', sub: [{ label: 'Markdown (.md)', icon: '⤓', run: () => exportChat(s.id, 'md') }, { label: 'JSON (.json)', icon: '⤓', run: () => exportChat(s.id, 'json') }] },
    { sep: true },
    { label: s.archived ? tt('取消封存', 'Unarchive') : tt('封存', 'Archive'), icon: '▣', key: 'A', run: () => setMeta(s, { archived: !s.archived }) },
    { label: tt('刪除…', 'Delete…'), icon: '✕', key: 'D', danger: true, run: () => deleteChat(s) },
  ];
}
function sectionItems(sec) {
  const names = (CM.state.sections || []).map((x) => x.name);
  const i = names.indexOf(sec.name);
  return [
    { head: sec.name },
    { label: tt('重新命名分區…', 'Rename section…'), icon: '✎', key: 'R', run: async () => {
      const n = await cmPrompt(tt('重新命名分區', 'Rename section'), sec.name, tt('分區名稱', 'Section name'));
      if (!n || n === sec.name) return;
      const r = await cmCall('ui.chat.section', { op: 'rename', name: sec.name, to: n });
      CM.state.sections = r.sections;
      await loadSessions();
    } },
    i > 0 ? { label: tt('上移', 'Move up'), icon: '↑', run: () => moveSection(sec, i - 1) } : null,
    i >= 0 && i < names.length - 1 ? { label: tt('下移', 'Move down'), icon: '↓', run: () => moveSection(sec, i + 1) } : null,
    { sep: true },
    { label: tt('刪除分區…', 'Delete section…'), icon: '✕', danger: true, key: 'D', run: async () => {
      if (!(await cmConfirm(tt('刪除分區', 'Delete section'), tt(`刪除「${sec.name}」？裡面的對話會留下，只是不再分區。`, `Delete "${sec.name}"? Its conversations stay; they just leave the section.`), tt('刪除分區', 'Delete section'), true))) return;
      const r = await cmCall('ui.chat.section', { op: 'delete', name: sec.name });
      CM.state.sections = r.sections;
      await loadSessions();
    } },
  ];
}
async function moveSection(sec, index) {
  const r = await cmCall('ui.chat.section', { op: 'move', name: sec.name, index });
  CM.state.sections = r.sections;
  chatRail();
}
async function newSection() {
  const n = await cmPrompt(tt('新增分區', 'New section'), '', tt('分區名稱', 'Section name'));
  if (!n) return;
  try { const r = await cmCall('ui.chat.section', { op: 'add', name: n }); CM.state.sections = r.sections; chatRail(); } catch (e) { cmErr(e); }
}

// ── actions ──
async function setMeta(s, patch) {
  // Optimistic: the rail answers at once; a refusal puts the server's state back.
  if ('pinned' in patch) s.pinned = patch.pinned;
  if ('archived' in patch) s.archived = patch.archived;
  if ('group' in patch) {
    s.group = patch.group || null;
    if (patch.group && !(CM.state.sections || []).some((x) => x.name === patch.group)) CM.state.sections = (CM.state.sections || []).concat([{ name: patch.group, collapsed: false }]);
  }
  if ('unread' in patch) CM.state.unread = patch.unread ? [...new Set((CM.state.unread || []).concat([s.id]))] : (CM.state.unread || []).filter((x) => x !== s.id);
  if ('folded' in patch) CM.state.folded = patch.folded ? [...new Set((CM.state.folded || []).concat([s.id]))] : (CM.state.folded || []).filter((x) => x !== s.id);
  chatRail();
  try { await cmCall('ui.chat.meta.set', Object.assign({ id: s.id }, patch)); } catch (e) { cmErr(e); await loadSessions(); }
}
function openIn(s, how) {
  const url = `${location.pathname}#view=chat&chat=${encodeURIComponent(s.id)}`;
  window.open(url, '_blank', how === 'window' ? 'popup=yes,width=1180,height=820' : 'noopener');
}
async function forkChat(s) {
  const r = await cmCall('ui.chat.fork', { id: s.id });
  await loadSessions();
  await openSession(r.id);
  toast(tt('已分支成新對話。', 'Forked into a new conversation.'));
}
async function deleteChat(s) {
  const ok = await cmConfirm(tt('刪除對話', 'Delete conversation'), tt(`刪除「${s.title || s.id}」？它會移到「最近刪除」，30 天內可以還原。`, `Delete "${s.title || s.id}"? It moves to Recently deleted and can be restored for 30 days.`), tt('刪除', 'Delete'), true);
  if (!ok) return;
  await cmCall('ui.chat.delete', { id: s.id });
  const wasCurrent = S.current === s.id;
  await loadSessions();
  if (wasCurrent) {
    S.current = null;
    const next = (S.sessions || []).find((x) => !x.archived);
    if (next) openSession(next.id); else { showView('chat'); emptyChat(); }
  }
  undoToast(tt(`已刪除「${s.title || s.id}」`, `Deleted "${s.title || s.id}"`), () => restoreChat(s.id));
}
async function restoreChat(id) {
  await cmCall('ui.chat.restore', { id });
  await loadSessions();
  toast(tt('已還原。', 'Restored.'));
}
async function purgeChat(x) {
  if (!(await cmConfirm(tt('永久刪除', 'Delete forever'), tt(`永久刪除「${x.title || x.id}」？這無法復原。`, `Delete "${x.title || x.id}" forever? This cannot be undone.`), tt('永久刪除', 'Delete forever'), true))) return;
  await cmCall('ui.chat.purge', { id: x.id });
  await loadSessions();
}
async function exportChat(id, format) {
  const r = await cmCall('ui.chat.export', { id, format });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([r.text], { type: r.mime || 'text/plain' }));
  a.download = r.name || `${id}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1500);
}
function undoToast(text, undo) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = `<span>${esc(text)}</span> <button type="button" class="btn ghost small">${esc(tt('復原', 'Undo'))}</button>`;
  el.querySelector('button').onclick = () => { el.remove(); Promise.resolve(undo()).catch(cmErr); };
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 9000);
}

// ── small dialogs (no window.prompt / confirm: the desktop app's webview may not show them) ──
function cmDialog(cls) {
  const d = document.createElement('dialog');
  d.className = 'modal ' + cls;
  document.body.appendChild(d);
  d.addEventListener('close', () => setTimeout(() => d.remove(), 0));
  return d;
}
function cmConfirm(title, text, okLabel, danger) {
  return new Promise((res) => {
    const d = cmDialog('cm-confirm');
    d.innerHTML = `<form method="dialog"><div class="modal-head"><h2>${esc(title)}</h2></div><p class="dim">${esc(text)}</p><menu style="gap:8px"><button class="btn ghost" value="no">${esc(tt('取消', 'Cancel'))}</button><button class="btn${danger ? ' danger' : ''}" value="yes">${esc(okLabel)}</button></menu></form>`;
    d.addEventListener('close', () => res(d.returnValue === 'yes'));
    d.showModal();
    d.querySelector('[value=yes]').focus();
  });
}
function cmPrompt(title, value, placeholder) {
  return new Promise((res) => {
    const d = cmDialog('cm-confirm');
    d.innerHTML = `<form method="dialog"><div class="modal-head"><h2>${esc(title)}</h2></div><p><input type="text" maxlength="60" autocomplete="off" placeholder="${esc(placeholder || '')}" value="${esc(value || '')}"></p><menu style="gap:8px"><button class="btn ghost" value="no">${esc(tt('取消', 'Cancel'))}</button><button class="btn" value="yes">${esc(tt('確定', 'OK'))}</button></menu></form>`;
    const inp = d.querySelector('input');
    inp.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); d.close('yes'); } };
    d.addEventListener('close', () => res(d.returnValue === 'yes' ? inp.value.trim() : null));
    d.showModal();
    inp.focus();
    inp.select();
  });
}

// ── live model list (shared by the composer switch and the settings dialog) ──
async function cmModels(refresh) {
  if (!refresh && CM.models && Date.now() - CM.modelsAt < 60000) return CM.models;
  CM.models = await cmCall('ui.chat.models.list', refresh ? { refresh: true } : {});
  CM.modelsAt = Date.now();
  return CM.models;
}
const srcLabel = (p) => ({ live: tt('即時', 'live'), cache: tt('快取', 'cached'), builtin: tt('內建', 'built-in') }[p.source] || p.source);
function setModelChip(ref) {
  const c = $('modelChip');
  if (!c) return;
  c.textContent = ref || tt('選擇模型', 'Choose model');
  c.title = tt('切換這個對話的模型', 'Switch this conversation’s model') + (ref ? ` · ${ref}` : '');
}
async function applyModel(ref) {
  if (!S.current) await newSession();
  if (!S.current) return;
  const id = S.current;
  try { await cmCall('ui.chat.settings.set', { id, model: ref }); } catch (e) { cmErr(e); return; }
  const s = (S.sessions || []).find((x) => x.id === id);
  if (s) s.model = ref;
  if (id === S.current) setModelChip(ref);
  toast(tt(`模型已切換為 ${ref}（下一則訊息起生效）`, `Model switched to ${ref} (from the next message)`));
}
function openModelPicker(anchor) {
  cmClose();
  const el = document.createElement('div');
  el.className = 'cm-menu cm-picker';
  el.setAttribute('role', 'dialog');
  el.setAttribute('aria-label', tt('切換模型', 'Switch model'));
  el.innerHTML = `<div class="cm-picker-head"><input type="search" placeholder="${esc(tt('搜尋或輸入 provider/model…', 'Search or type provider/model…'))}" autocomplete="off" aria-label="${esc(tt('搜尋模型', 'Search models'))}"><button type="button" class="btn ghost small" data-refresh title="${esc(tt('從供應商重新抓取清單', 'Fetch the lists again from the providers'))}">↻</button></div><div class="cm-picker-list" role="listbox"><div class="cm-head"><span class="star spin" style="--size:10px"></span> ${esc(tt('載入模型清單…', 'Loading models…'))}</div></div><div class="cm-picker-foot"><span class="faint" data-status></span><button type="button" class="btn ghost small" data-keys>${esc(tt('管理 API 金鑰', 'Manage API keys'))}</button></div>`;
  document.body.appendChild(el);
  const lvl = { el, items: [], idx: -1 };
  CM.menu = { levels: [lvl], row: null, focus: anchor };
  const r = anchor.getBoundingClientRect();
  const place = () => { if (isPhone()) return; el.style.left = Math.max(8, Math.min(r.left, innerWidth - el.offsetWidth - 8)) + 'px'; el.style.top = Math.max(8, r.top - el.offsetHeight - 6) + 'px'; };
  place();
  const input = el.querySelector('input');
  const listEl = el.querySelector('.cm-picker-list');
  const cur = () => { const s = (S.sessions || []).find((x) => x.id === S.current); return (s && s.model) || (S.models && S.models.default) || ''; };
  let data = null;
  const draw = () => {
    if (!data) return;
    const q = input.value.trim().toLowerCase();
    let html = '';
    let shown = 0;
    lvl.items = [];
    lvl.idx = -1;
    for (const p of data.providers || []) {
      const ms = (p.models || []).filter((m) => !q || m.ref.toLowerCase().includes(q) || String(p.label).toLowerCase().includes(q));
      if (!ms.length) continue;
      html += `<div class="cm-picker-prov"><span>${esc(p.label || p.id)}</span><span class="src ${esc(p.source)}">${esc(srcLabel(p))}</span>${p.error ? `<span class="err" title="${esc(p.error)}">${esc(p.error)}</span>` : ''}</div>`;
      for (const m of ms.slice(0, q ? 200 : 40)) {
        const i = lvl.items.length;
        lvl.items.push({ ref: m.ref });
        html += `<button type="button" class="cm-item" role="option" data-i="${i}"><span class="ic">${m.ref === cur() ? '✓' : ''}</span><span class="lb">${esc(m.id)}</span>${m.context ? `<span class="sub">${Math.round(m.context / 1000)}k</span>` : ''}</button>`;
        shown++;
      }
      if (!q && ms.length > 40) html += `<div class="cm-head">${esc(tt(`還有 ${ms.length - 40} 個，輸入以搜尋`, `${ms.length - 40} more, type to search`))}</div>`;
    }
    const typed = input.value.trim();
    if (/^[\w.-]+\/\S+$/.test(typed) && !lvl.items.some((x) => x.ref.toLowerCase() === typed.toLowerCase())) {
      lvl.items.push({ ref: typed });
      html += `<button type="button" class="cm-item" data-i="${lvl.items.length - 1}"><span class="ic">↵</span><span class="lb">${esc(tt('使用', 'Use'))} ${esc(typed)}</span></button>`;
    }
    listEl.innerHTML = html || `<div class="cm-head">${esc(tt('沒有符合的模型。到「API 金鑰」加入供應商的金鑰。', 'No matching model. Add a provider key under API keys.'))}</div>`;
    for (const b of listEl.querySelectorAll('[data-i]')) {
      const it = lvl.items[+b.dataset.i];
      it.btn = b;
      b.onclick = () => { cmClose(); applyModel(it.ref); };
    }
    const live = (data.providers || []).filter((p) => p.source === 'live' || p.source === 'cache').length;
    el.querySelector('[data-status]').textContent = data.offline ? tt('離線：顯示內建清單', 'Offline: built-in lists') : tt(`${live}/${(data.providers || []).length} 個供應商有即時清單 · ${shown} 個模型`, `${live}/${(data.providers || []).length} providers live · ${shown} models`);
    place();
  };
  const load = async (refresh) => {
    try { data = await cmModels(refresh); draw(); } catch (e) { listEl.innerHTML = `<div class="cm-head bad">${esc(e.message)}</div>`; }
  };
  input.oninput = draw;
  input.onkeydown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); cmHighlight(lvl, cmNext(lvl, lvl.idx, 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); const it = lvl.items[Math.max(0, lvl.idx)]; if (it) { cmClose(); applyModel(it.ref); } }
  };
  el.querySelector('[data-refresh]').onclick = () => { listEl.innerHTML = `<div class="cm-head"><span class="star spin" style="--size:10px"></span> ${esc(tt('重新抓取…', 'Refreshing…'))}</div>`; load(true); };
  el.querySelector('[data-keys]').onclick = () => { cmClose(); if (typeof openPage === 'function') { S.pageNav = 'showSettings'; openPage('apikeys'); } };
  document.addEventListener('keydown', cmKey, true);
  setTimeout(() => document.addEventListener('pointerdown', cmOutside, true), 0);
  window.addEventListener('resize', cmClose);
  input.focus();
  load(false);
}

// ── per-conversation settings dialog ──
const EXEC = [['auto', '自動', 'Auto', '依設定檔', 'as configured'], ['sandbox', '沙箱', 'Sandbox', '指令在隔離環境執行', 'commands run isolated'], ['host', '主機', 'Host', '直接在這台機器執行', 'directly on this machine'], ['node', '節點', 'Node', '配對的遠端節點', 'a paired remote node']];
const APPROVAL = [['ask', '詢問', 'Ask', '有風險的動作先問你', 'risky actions ask first'], ['yolo', 'YOLO', 'YOLO', '略過核准提示（硬底線與拒絕規則仍有效）', 'skip approval prompts (hard floors and deny rules still apply)'], ['elevated', '提升權限', 'Elevated', '主機指令不提示，但每次都記錄', 'host commands run without a prompt, each one recorded']];
async function openChatSettings(id) {
  id = id || S.current;
  if (!id) return;
  let st;
  try { st = await cmCall('ui.chat.settings.get', { id }); } catch (e) { cmErr(e); return; }
  const d = cmDialog('cm-settings');
  const seg = (name, rows, val, dis) => `<div class="seg" role="radiogroup">${rows.map(([v, zh, en, hz, he]) => `<label class="${dis && dis(v) ? 'dis' : ''}" title="${esc(tt(hz, he))}"><input type="radio" name="${name}" value="${v}"${v === val ? ' checked' : ''}${dis && dis(v) ? ' disabled' : ''}> ${esc(tt(zh, en))}</label>`).join('')}</div>`;
  const efforts = [''].concat(st.efforts || []);
  if (st.thinking && !efforts.includes(st.thinking)) efforts.push(st.thinking);
  const fasts = ['', 'normal', 'fast', 'flex', 'auto'];
  if (st.fast && !fasts.includes(st.fast)) fasts.push(st.fast);
  const tools = st.tools || [];
  d.innerHTML = `<form method="dialog">
    <div class="modal-head"><h2>${esc(tt('對話設定', 'Conversation settings'))}</h2></div>
    <div class="row"><label for="csTitle">${esc(tt('名稱', 'Name'))}</label><input type="text" id="csTitle" maxlength="80" value="${esc(st.title || '')}"></div>
    <div class="row"><label for="csModel">${esc(tt('模型', 'Model'))}</label><div class="model-row"><select id="csModel"><option value="${esc(st.model)}">${esc(st.model)}</option></select><button type="button" class="btn ghost small" id="csModelRefresh" title="${esc(tt('從供應商重新抓取', 'Fetch again from the providers'))}">↻</button></div><div class="hint faint" id="csModelHint"></div></div>
    <div class="row"><label for="csThinking">${esc(tt('推理強度', 'Reasoning effort'))}</label><select id="csThinking">${efforts.map((e) => `<option value="${esc(e)}"${e === (st.thinking || '') ? ' selected' : ''}>${esc(e || tt('供應商預設', 'provider default'))}</option>`).join('')}</select></div>
    <div class="row"><label for="csFast">${esc(tt('快速模式', 'Fast mode'))}</label><select id="csFast">${fasts.map((e) => `<option value="${esc(e)}"${e === (st.fast || '') ? ' selected' : ''}>${esc(e || tt('設定預設', 'config default'))}</option>`).join('')}</select></div>
    <div class="row"><label>${esc(tt('執行環境', 'Exec backend'))}</label>${seg('csExec', EXEC, st.exec_host || 'auto')}<div class="hint faint">${esc(tt('shell / job / process 工具在哪裡執行（同 /exec host=）', 'Where shell / job / process tools run (same as /exec host=)'))}</div></div>
    <div class="row"><label>${esc(tt('核准模式', 'Approval mode'))}</label>${seg('csApproval', APPROVAL, st.approval || 'ask', (v) => v === 'elevated' && !st.elevated_enabled)}<div class="hint faint" id="csApprovalHint"></div></div>
    <div class="row top"><label>${esc(tt("工具", "Tools"))} <span class="faint" id="csToolCount"></span></label><div><div class="cm-tools-bar"><input type="search" id="csToolFilter" placeholder="${esc(tt('篩選工具…', 'Filter tools…'))}" autocomplete="off"><button type="button" class="btn ghost small" data-tools="all">${esc(tt('全選', 'All'))}</button><button type="button" class="btn ghost small" data-tools="none">${esc(tt('全不選', 'None'))}</button></div><div class="cm-tools" id="csTools">${tools.map((x) => `<label data-name="${esc(x.name)}"><input type="checkbox" value="${esc(x.name)}"${x.enabled ? ' checked' : ''}><code>${esc(x.name)}</code><span class="d" title="${esc(x.description)}">${esc(x.description)}</span></label>`).join('')}</div></div></div>
    <div class="row top"><label for="csPersona">${esc(tt('角色／系統提示', 'Persona / system prompt'))}</label><textarea id="csPersona" rows="4" maxlength="20000" placeholder="${esc(tt('這個對話專用的額外指示（附加在系統提示之後）', 'Extra instructions for this conversation only (added after the system prompt)'))}">${esc(st.persona || '')}</textarea></div>
    <menu><span class="left"><button type="button" class="btn ghost small" data-export="md">${esc(tt('匯出 .md', 'Export .md'))}</button><button type="button" class="btn ghost small" data-export="json">${esc(tt('匯出 .json', 'Export .json'))}</button></span><button class="btn ghost" value="cancel">${esc(tt('取消', 'Cancel'))}</button><button class="btn" value="save" id="csSave">${esc(tt('儲存', 'Save'))}</button></menu>
  </form>`;
  const q = (s) => d.querySelector(s);
  const approvalHint = () => {
    const v = (q('input[name=csApproval]:checked') || {}).value;
    const row = APPROVAL.find((x) => x[0] === v);
    const h = q('#csApprovalHint');
    h.textContent = (row ? tt(row[3], row[4]) : '') + (!st.elevated_enabled ? ' · ' + tt('提升權限未啟用（approvals.elevated.enabled）', 'elevated is not enabled (approvals.elevated.enabled)') : '') + (st.process_yolo ? ' · ' + tt('整個程序已是 YOLO', 'the whole process runs YOLO') : '');
    h.classList.toggle('warn', v === 'yolo');
  };
  approvalHint();
  for (const r of d.querySelectorAll('input[name=csApproval]')) r.onchange = approvalHint;
  const countTools = () => { const all = d.querySelectorAll('#csTools input'); q('#csToolCount').textContent = `${[...all].filter((x) => x.checked).length}/${all.length}`; };
  countTools();
  q('#csTools').onchange = countTools;
  q('#csToolFilter').oninput = (e) => { const f = e.target.value.trim().toLowerCase(); for (const l of d.querySelectorAll('#csTools label')) l.hidden = !!f && !l.textContent.toLowerCase().includes(f); };
  for (const b of d.querySelectorAll('[data-tools]')) b.onclick = () => { for (const l of d.querySelectorAll('#csTools label')) if (!l.hidden) l.querySelector('input').checked = b.dataset.tools === 'all'; countTools(); };
  for (const b of d.querySelectorAll('[data-export]')) b.onclick = () => exportChat(id, b.dataset.export).catch(cmErr);
  const fillModels = async (refresh) => {
    const sel = q('#csModel');
    q('#csModelHint').textContent = tt('載入模型清單…', 'Loading models…');
    try {
      const r = await cmModels(refresh);
      const keep = sel.value;
      sel.innerHTML = '';
      let found = false;
      for (const p of r.providers || []) {
        if (!(p.models || []).length) continue;
        const g = document.createElement('optgroup');
        g.label = `${p.label || p.id} · ${srcLabel(p)}`;
        for (const m of p.models) { g.appendChild(new Option(m.id, m.ref, false, m.ref === keep)); found = found || m.ref === keep; }
        sel.appendChild(g);
      }
      if (!found) sel.insertBefore(new Option(keep, keep, true, true), sel.firstChild);
      sel.value = keep;
      const bad = (r.providers || []).filter((p) => p.error).map((p) => `${p.id}: ${p.error}`);
      const hint = q('#csModelHint');
      hint.textContent = bad.length ? tt(`${bad.length} 個供應商改用內建／快取清單（滑過看原因）`, `${bad.length} provider list(s) fell back to built-in / cached (hover for why)`) : tt('清單來自各供應商的 API', 'Lists come from each provider’s API');
      hint.title = bad.join('\n');
    } catch (e) { q('#csModelHint').textContent = e.message; }
  };
  q('#csModelRefresh').onclick = () => fillModels(true);
  fillModels(false);
  d.querySelector('form').addEventListener('submit', async (e) => {
    if (e.submitter && e.submitter.value !== 'save') return;
    e.preventDefault();
    const p = { id };
    const title = q('#csTitle').value.trim();
    if (title && title !== (st.title || '')) p.title = title;
    if (q('#csModel').value && q('#csModel').value !== st.model) p.model = q('#csModel').value;
    if (q('#csThinking').value !== (st.thinking || '')) p.thinking = q('#csThinking').value || 'default';
    if (q('#csFast').value !== (st.fast || '')) p.fast = q('#csFast').value;
    const ex = (q('input[name=csExec]:checked') || {}).value;
    if (ex && ex !== (st.exec_host || 'auto')) p.exec_host = ex;
    const ap = (q('input[name=csApproval]:checked') || {}).value;
    if (ap && ap !== st.approval) p.approval = ap;
    const off = [...d.querySelectorAll('#csTools input')].filter((x) => !x.checked).map((x) => x.value).sort();
    const offBefore = tools.filter((x) => !x.enabled).map((x) => x.name).sort();
    if (off.join('\n') !== offBefore.join('\n')) p.tools_disabled = off;
    const persona = q('#csPersona').value.trim();
    if (persona !== (st.persona || '')) p.persona = persona;
    if (Object.keys(p).length === 1) { d.close(); return; }
    q('#csSave').disabled = true;
    try {
      const r = await cmCall('ui.chat.settings.set', p);
      const s = (S.sessions || []).find((x) => x.id === id);
      if (s) { s.title = r.title || s.title; s.model = r.model; }
      if (id === S.current) { setModelChip(r.model); if (r.title) $('title').textContent = r.title; }
      chatRail();
      d.close();
      toast(tt('已儲存對話設定。', 'Conversation settings saved.'));
    } catch (err) { q('#csSave').disabled = false; cmErr(err); }
  });
  d.showModal();
  q('#csTitle').focus();
}

// ── wiring: header ⚙, composer model chip ──
(function wireChatMenu() {
  const review = $('reviewBtn');
  const gear = document.createElement('button');
  gear.type = 'button';
  gear.className = 'btn ghost small icon';
  gear.id = 'chatSettingsBtn';
  gear.dataset.write = '';
  gear.hidden = true;
  gear.textContent = '⚙';
  gear.title = tt('對話設定', 'Conversation settings');
  gear.setAttribute('aria-label', gear.title);
  gear.onclick = () => openChatSettings(S.current);
  review.parentNode.insertBefore(gear, review);
  // Shown exactly when the review button is (app.js: the chat view with a conversation open).
  new MutationObserver(() => { gear.hidden = review.hidden; }).observe(review, { attributes: true, attributeFilter: ['hidden'] });
  const chip = $('modelChip');
  if (chip) chip.onclick = (e) => { e.preventDefault(); if (CM.menu && CM.menu.focus === chip) { cmClose(); return; } openModelPicker(chip); };
  setModelChip('');
  // Back on the tab: what was read there is read now.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible' || !S.current || S.view !== 'chat') return;
    const s = (S.sessions || []).find((x) => x.id === S.current);
    if (isUnread(s)) { markRead(S.current); chatRail(); }
  });
})();
