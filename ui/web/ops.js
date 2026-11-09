// seagent web UI: the operations views — overview (this host, agents, devices, alerts, audit
// tail), agents (delegation tree + fleet board), devices (nodes, pairing, cluster), approvals
// (every open gate / question across sessions) and audit (filterable, hash-chain verify).
// Data: `ui.ops.status` (crates/seagent/src/ops/opsview.rs, polled every 3 s while connected),
// `ui.fleet`, `ui.devices`, `cluster.status`, `audit.query`, `audit.verify`, `gate.answer`.
// Uses app.js globals: S, $, esc, t, VIEWS, showView, openSession, answerPending, toast, LANG.
'use strict';

const OPS = { data: null, timer: null, err: null, seenAudit: 0, devices: null, fleet: null, cluster: null };
const ov = (x) => esc(x === undefined || x === null ? '' : String(x));
const L = (zh, en) => (LANG === 'en' ? en : zh);
const pct = (x) => (x === undefined || x === null ? '—' : (Math.round(x * 10) / 10).toFixed(x >= 10 ? 0 : 1) + '%');
function size(n) {
  if (!n && n !== 0) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
}
function rate(n) { return size(n || 0) + '/s'; }
function dur(s) {
  s = Math.max(0, Math.floor(s || 0));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${s % 60}s`;
}
const hhmm = (ms) => { const d = new Date(ms); return d.toTimeString().slice(0, 8); };
const level = (p, w, c) => (p >= c ? 'crit' : p >= w ? 'warn' : '');
function secH(n, title, aside) { return `<div class="sec-h"><span class="n">${n}</span><h3>${ov(title)}</h3>${aside ? `<span class="aside">${aside}</span>` : ''}</div>`; }

// A trend line over the last samples (values scaled to `max`, or to their own peak).
function spark(vals, max, w, h) {
  w = w || 300; h = h || 54;
  if (!vals.length) return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"></svg>`;
  const peak = max || Math.max(1, ...vals);
  const step = vals.length > 1 ? w / (vals.length - 1) : w;
  const pts = vals.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (Math.min(v, peak) / peak) * (h - 6)).toFixed(1)}`);
  const grid = [0.25, 0.5, 0.75].map((f) => `<line class="grid" x1="0" x2="${w}" y1="${(h * f).toFixed(1)}" y2="${(h * f).toFixed(1)}"/>`).join('');
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${grid}<polygon class="area" points="0,${h} ${pts.join(' ')} ${((vals.length - 1) * step).toFixed(1)},${h}"/><polyline class="line" points="${pts.join(' ')}"/></svg>`;
}
const series = (k) => ((OPS.data && OPS.data.series) || []).map((s) => Number(s[k]) || 0);

// ── polling ──
async function opsPoll() {
  if (!S.arp) return;
  try { OPS.data = await S.arp.call('ui.ops.status'); OPS.err = null; }
  catch (e) { OPS.err = e.message; }
  // The rail's running markers follow the same poll (a sub-agent's end is not always an event
  // on the global subscription).
  const run = OPS.data ? (OPS.data.sessions || {}).running || 0 : 0;
  if (OPS.data && run !== (S.sessions || []).filter((s) => s.running).length) loadSessions();
  opsStrip();
  if (S.view === 'ops') renderOps($('view-ops'), true);
}
function opsStart() {
  clearInterval(OPS.timer);
  opsPoll();
  OPS.timer = setInterval(() => { if (!document.hidden) opsPoll(); }, 3000);
}
// Global session events: refresh the agents view while it is open.
function opsEvent(p) {
  if (S.view === 'agents' && p.event && (p.event.type === 'turn_start' || p.event.type === 'turn_end')) VIEWS.agents.render($('view-agents'));
}

// ── topbar status strip (always visible) ──
function opsStrip() {
  const d = OPS.data;
  const el = $('strip');
  if (!el) return;
  if (!d) { el.innerHTML = OPS.err ? `<span class="metric crit"><span class="k">ops</span><span class="v">${ov(OPS.err).slice(0, 40)}</span></span>` : ''; return; }
  const h = d.host || {};
  const disk = (h.disks || [])[0];
  const dp = disk && disk.total ? 100 - (disk.free * 100) / disk.total : null;
  const pend = S.pending ? S.pending.size : 0;
  const m = (k, v, p, cls, extra) => `<span class="metric ${cls || ''} ${extra || ''}"${extra && extra.includes('link') ? ` data-go="${extra.split(' ')[1] || ''}"` : ''}><span class="k">${k}</span><span class="v">${v}</span>${p === null || p === undefined ? '' : `<span class="bar"><i style="width:${Math.min(100, p)}%"></i></span>`}</span>`;
  el.innerHTML = [
    m('CPU', pct(h.cpu_pct), h.cpu_pct, level(h.cpu_pct, 70, 90)),
    m(L('記憶體', 'MEM'), pct(h.mem && h.mem.pct), h.mem && h.mem.pct, level(h.mem && h.mem.pct, 80, 92)),
    dp === null ? '' : m(L('磁碟', 'DISK'), pct(dp), dp, level(dp, 85, 95), 'opt'),
    m(L('代理', 'AGENTS'), `${(d.sessions || {}).running || 0}`, null, '', 'link agents'),
    m(L('核准', 'APPROVE'), String(pend), null, pend ? 'warn' : '', 'link approvals'),
    m(L('今日', 'TODAY'), '$' + ((d.today || {}).cost_usd || 0).toFixed(2), null, '', 'opt'),
  ].join('');
  for (const x of el.querySelectorAll('[data-go]')) x.onclick = () => showView(x.dataset.go);
}

// ── 01 overview ──
function renderOps(el, live) {
  const d = OPS.data;
  if (!d) { el.innerHTML = `<div class="ops"><p class="dim">${OPS.err ? ov(OPS.err) : '<span class="star spin"></span>'}</p></div>`; return; }
  // Keep scroll position and any open <details> across live refreshes.
  const top = el.scrollTop;
  const h = d.host || {};
  const dm = d.daemon || {};
  const pend = [...S.pending.values()];
  const running = (d.agents || []).filter((a) => a.running);
  const alerts = d.alerts || [];
  const disk = (h.disks || [])[0];
  const dp = disk && disk.total ? 100 - (disk.free * 100) / disk.total : 0;
  const kpi = (k, v, sub, cls, go, sp) => `<div class="kpi ${cls || ''}${go ? ' link' : ''}"${go ? ` data-go="${go}"` : ''}><span class="k">${k}</span><span class="v">${v}</span><span class="s">${sub}</span>${sp || ''}</div>`;
  let html = '<div class="ops">';
  html += '<div class="kpis">'
    + kpi(L('執行中代理', 'Running agents'), running.length, `${(d.sessions || {}).total || 0} ${L('個對話', 'sessions')}`, '', 'agents', spark(series('agents'), 0, 64, 22))
    + kpi(L('待核准', 'Awaiting approval'), pend.length, pend.length ? L('需要人處理', 'needs a human') : L('沒有待辦', 'nothing waiting'), pend.length ? 'warn' : '', 'approvals')
    + kpi(L('告警', 'Alerts'), alerts.length, alerts.length ? ov(alerts[0].title).slice(0, 40) : L('一切正常', 'all clear'), alerts.some((a) => a.severity === 'error') ? 'crit' : alerts.length ? 'warn' : '')
    + kpi('CPU', `${Math.round(h.cpu_pct || 0)}<small>%</small>`, `load ${(h.load || []).map((x) => x.toFixed(2)).join(' ')}`, level(h.cpu_pct, 70, 90), '', spark(series('cpu'), 100, 64, 22))
    + kpi(L('記憶體', 'Memory'), `${Math.round((h.mem || {}).pct || 0)}<small>%</small>`, `${size((h.mem || {}).total - (h.mem || {}).available)} / ${size((h.mem || {}).total)}`, level((h.mem || {}).pct, 80, 92), '', spark(series('mem'), 100, 64, 22))
    + kpi(L('今日花費', 'Spend today'), `<small>$</small>${((d.today || {}).cost_usd || 0).toFixed(2)}`, `${((d.today || {}).tokens || 0).toLocaleString()} tokens · ${(d.today || {}).calls || 0} ${L('次', 'calls')}`, '')
    + '</div>';

  html += '<div class="cols"><div class="c8 stack">';
  // Agents (live)
  html += `<section>${secH('01', L('代理', 'Agents'), `<button data-go="agents">${L('全部 →', 'All →')}</button>`)}${agentTree((d.agents || []).slice(0, 14), true)}</section>`;
  // Trends
  html += `<section>${secH('02', L('趨勢', 'Trends'), L('最近 6 分鐘 · 每 3 秒取樣', 'last 6 min · 3 s samples'))}<div class="trends">
    ${trend('CPU', pct(h.cpu_pct), series('cpu'), 100)}
    ${trend(L('記憶體', 'Memory'), pct((h.mem || {}).pct), series('mem'), 100)}
    ${trend(L('網路 ↓', 'Net ↓'), rate((h.net || {}).rx_bps), series('rx'), 0)}
    ${trend(L('執行中代理', 'Running agents'), String(running.length), series('agents'), 0)}
  </div></section>`;
  const tail = ((d.audit || {}).tail || []).slice().reverse();
  const head = (d.audit || {}).head || {};
  html += `<section>${secH('03', L('稽核串流', 'Audit stream'), `seq ${ov(head.seq || 0)} · <code>${ov(String(head.hash || '').slice(0, 12))}</code> <button data-go="audit">${L('查詢 →', 'Query →')}</button>`)}<div class="stream">${tail.length ? tail.map((r) => evRow(r, r.seq > OPS.seenAudit && OPS.seenAudit > 0)).join('') : `<div class="none">${L('還沒有稽核紀錄。', 'No audit records yet.')}</div>`}</div></section>`;
  html += '</div><div class="c4 stack">';
  // Host
  html += `<section>${secH('04', L('主機', 'Host'), ov(h.hostname))}<dl class="facts">
    <dt>${L('系統', 'OS')}</dt><dd title="${ov(h.os)}">${ov(h.os)}</dd>
    <dt>${L('核心', 'Kernel')}</dt><dd>${ov(h.kernel)} · ${ov(h.arch)}</dd>
    <dt>CPU</dt><dd>${ov(h.cpus)} ${L('核', 'cores')} · ${pct(h.cpu_pct)}</dd>
    <dt>${L('開機', 'Uptime')}</dt><dd>${dur(h.uptime_s)}</dd>
    <dt>seagentd</dt><dd>v${ov(dm.version)} · pid ${ov((dm.proc || {}).pid)} · ${dur((d.ts - dm.started_ms) / 1000)}</dd>
    <dt>RSS</dt><dd>${size((dm.proc || {}).rss_bytes)} · ${ov((dm.proc || {}).threads)} thr · ${ov((dm.proc || {}).fds)} fd</dd>
    <dt>${L('網路', 'Net')}</dt><dd>↓ ${rate((h.net || {}).rx_bps)} · ↑ ${rate((h.net || {}).tx_bps)}</dd>
    <dt>${L('模型', 'Model')}</dt><dd>${ov(dm.model)}</dd>
  </dl><div style="margin-top:12px">${(h.disks || []).map((x) => { const p = x.total ? 100 - (x.free * 100) / x.total : 0; return `<div class="disk"><div class="dl"><span>${ov(x.label)}</span><span class="n">${pct(p)} · ${size(x.total - x.free)} / ${size(x.total)}</span></div><div class="meter ${level(p, 85, 95)}"><i style="width:${p.toFixed(1)}%"></i></div><span class="p" title="${ov(x.path)}">${ov(x.path)}</span></div>`; }).join('')}</div></section>`;
  // Approvals + audit
  html += `<section>${secH('05', L('待核准', 'Approvals'), pend.length ? `<button data-go="approvals">${L('處理 →', 'Review →')}</button>` : '')}${pend.length ? pend.slice(0, 5).map((e) => pendRow(e.p)).join('') : `<div class="none">${L('沒有等待中的核准或提問。', 'Nothing is waiting for a human.')}</div>`}</section>`;
  // Alerts + services
  html += `<section>${secH('06', L('告警', 'Alerts'))}${alerts.length ? alerts.map((a) => `<div class="alert"><span class="light ${a.severity === 'error' ? 'crit' : 'warn'}" style="margin-top:6px"></span><div><div>${ov(a.title)}</div>${a.detail ? `<div class="d">${ov(a.detail)}</div>` : ''}</div></div>`).join('') : `<div class="none"><span class="star ok" style="--size:9px"></span> ${L('沒有告警', 'No alerts')}</div>`}
    ${secH('07', L('服務', 'Services'))}<div class="slist">
      <div class="srow"><span class="light ok"></span><span>seagentd<span class="sub">${ov((dm.paths || {}).data)}</span></span><span class="r">v${ov(dm.version)}</span></div>
      ${(d.channels || []).map((c) => `<div class="srow"><span class="light ok"></span><span>${ov(c.name)}<span class="sub">${ov(c.kind)}</span></span><span class="r">${L('頻道', 'channel')}</span></div>`).join('')}
      ${(d.mcp || []).map((m) => `<div class="srow"><span class="light ${m.running ? 'ok' : ''}"></span><span>${ov(m.name)}<span class="sub">MCP · ${ov(m.tools)} ${L('個工具', 'tools')}</span></span><span class="r">${m.running ? L('執行', 'up') : L('待命', 'idle')}</span></div>`).join('')}
      ${OPS.devices ? (OPS.devices.nodes || []).map((n) => `<div class="srow"><span class="light ok"></span><span>${ov(n.name || n.id)}<span class="sub">${ov(n.platform || '')}</span></span><span class="r">${L('裝置', 'node')}</span></div>`).join('') : ''}
    </div></section>`;
  html += '</div>';
  html += '</div></div>';
  OPS.seenAudit = Math.max(OPS.seenAudit, ...(tail.map((r) => r.seq || 0)), 0);
  el.innerHTML = html;
  if (live) el.scrollTop = top;
  bindCommon(el);
}
function trend(k, v, vals, max) { return `<div class="trend"><div class="th"><span class="k">${k}</span><span class="v">${v}</span></div>${spark(vals, max)}</div>`; }
function evRow(r, fresh) {
  const a = r.actor || {};
  return `<div class="ev${fresh ? ' fresh' : ''}" title="${ov(a.kind)}:${ov(a.name)}${a.role ? ' (' + ov(a.role) + ')' : ''}${r.session ? ' · ' + ov(r.session) : ''}"><span class="ts">${hhmm(r.ts)}</span><span class="kd">${ov(r.kind)}</span><span class="tg">${ov(a.name)} → ${ov(r.target)}</span><span class="oc ${ov(r.outcome)}">${ov(r.outcome)}</span></div>`;
}
function pendRow(p) {
  return `<div class="srow" style="grid-template-columns:14px 1fr auto"><span class="light warn"></span><span>${p.kind === 'approval' ? `<strong>${ov(p.tool)}</strong> · ${ov(p.gate)}` : L('提問', 'Question')}<span class="sub">${ov(p.kind === 'approval' ? (p.summary || p.reason) : p.question).slice(0, 120)}</span></span><span class="r"><a href="#" data-open="${ov(p.session)}">${ov(sessName(p.session)).slice(0, 24)}</a></span></div>`;
}
function sessName(id) { const s = (S.sessions || []).find((x) => x.id === id); return s ? (s.title || s.id) : (id || '—'); }

// The delegation tree: roots in recency order, children under their parent with guides.
function agentTree(list, compact) {
  if (!list.length) return `<div class="none">${L('最近 24 小時沒有代理活動。', 'No agent activity in the last 24 hours.')}</div>`;
  const ids = new Set(list.map((a) => a.id));
  const kids = (id) => list.filter((a) => a.parent === id);
  const out = [];
  const walk = (a, depth, lastFlags) => {
    out.push([a, depth, lastFlags]);
    const ks = kids(a.id);
    ks.forEach((k, i) => walk(k, depth + 1, lastFlags.concat(i === ks.length - 1)));
  };
  for (const r of list.filter((a) => !a.parent || !ids.has(a.parent))) walk(r, 0, []);
  const head = `<div class="tree-row head"><span></span><span>${L('代理', 'Agent')}</span><span class="m">${L('模型', 'Model')}</span><span class="c">${L('訊息', 'Msgs')}</span><span class="u">${L('更新', 'Updated')}</span></div>`;
  return '<div class="tree">' + head + out.slice(0, compact ? 14 : 400).map(([a, depth, flags]) => {
    const ind = flags.map((last, i) => (i === flags.length - 1 ? (last ? '└─ ' : '├─ ') : (last ? '   ' : '│  '))).join('');
    return `<div class="tree-row" data-open="${ov(a.id)}"><span>${a.running ? '<span class="star pulse" style="--size:11px"></span>' : '<span class="light"></span>'}</span><span class="t">${depth ? `<span class="ind">${ind}</span>` : ''}<span>${ov(a.title || a.id)}</span><span class="id">${ov(a.id).slice(-8)}</span></span><span class="m" title="${ov(a.model)}">${ov(a.model || '—')}</span><span class="c">${ov(a.messages)}</span><span class="u">${a.running ? `<span style="color:var(--gold-400)">${L('執行中', 'running')}</span>` : ago(a.updated_ms)}</span></div>`;
  }).join('') + '</div>';
}

function bindCommon(el) {
  for (const x of el.querySelectorAll('[data-go]')) x.onclick = () => showView(x.dataset.go);
  for (const x of el.querySelectorAll('[data-open]')) x.onclick = (e) => { e.preventDefault(); if (x.dataset.open) openSession(x.dataset.open); };
}

VIEWS.ops = {
  title: () => (OPS.data && OPS.data.host ? `${OPS.data.host.hostname}` : L('營運總覽', 'Operations')),
  render(el) { renderOps(el, false); if (!OPS.devices) S.arp.call('ui.devices').then((d) => { OPS.devices = d; }).catch(() => {}); },
};

// ── 03 agents ──
VIEWS.agents = {
  title: () => L('代理與委派', 'Agents & delegation'),
  async render(el) {
    const [fleet, st] = await Promise.all([S.arp.call('ui.fleet').catch(() => null), S.arp.call('ui.ops.status').catch(() => OPS.data)]);
    if (S.view !== 'agents') return;
    if (st) OPS.data = st;
    const agents = (st && st.agents) || [];
    const c = (fleet && fleet.counts) || {};
    const fa = (fleet && fleet.agents) || [];
    const board = ((fleet && fleet.board) || []).slice(-20).reverse();
    let h = '<div class="ops"><div class="kpis">'
      + `<div class="kpi"><span class="k">${L('執行中', 'Running')}</span><span class="v">${agents.filter((a) => a.running).length}</span><span class="s">${L('個對話', 'sessions')}</span></div>`
      + `<div class="kpi"><span class="k">${L('子代理執行', 'Sub-agents running')}</span><span class="v">${ov(c.running || 0)}</span><span class="s">${L('委派中', 'delegated')}</span></div>`
      + `<div class="kpi"><span class="k">${L('完成', 'Done')}</span><span class="v">${ov(c.done || 0)}</span><span class="s">${L('子代理', 'sub-agents')}</span></div>`
      + `<div class="kpi ${c.failed ? 'crit' : ''}"><span class="k">${L('失敗', 'Failed')}</span><span class="v">${ov(c.failed || 0)}</span><span class="s">${L('子代理', 'sub-agents')}</span></div>`
      + `<div class="kpi"><span class="k">${L('檔案租約', 'File leases')}</span><span class="v">${ov(c.leased_files || 0)}</span><span class="s">${L('並行寫入保護', 'parallel-write guard')}</span></div>`
      + `<div class="kpi"><span class="k">${L('24 小時內', 'Last 24 h')}</span><span class="v">${agents.length}</span><span class="s">${L('個有活動', 'active')}</span></div>`
      + '</div><div class="cols">';
    h += `<section class="c12">${secH('01', L('委派樹', 'Delegation tree'), L('點一列打開該對話', 'click a row to open it'))}${agentTree(agents, false)}</section>`;
    h += `<section class="c7">${secH('02', L('子代理', 'Sub-agents'))}${fa.length ? '<table class="kv"><tr><th>id</th><th>' + L('層', 'Depth') + '</th><th>' + L('狀態', 'State') + '</th><th>tokens</th><th>' + L('花費', 'Spend') + '</th><th>' + L('目標', 'Goal') + '</th></tr>' + fa.map((a) => `<tr><td class="mono"><a href="#" data-open="${ov(a.session_id || a.id)}">${ov(String(a.id || a.session_id || '?').slice(0, 12))}</a></td><td>${ov(a.depth ?? 0)}</td><td>${a.state === 'running' ? `<span style="color:var(--gold-400)">${L('執行中', 'running')}</span>` : a.state === 'failed' ? `<span class="crit">${ov(a.state)}</span>` : ov(a.state || '—')}</td><td class="mono">${ov((a.input_tokens || 0) + (a.output_tokens || 0))}</td><td class="mono">$${Number(a.spend_usd || 0).toFixed(3)}</td><td>${ov(a.goal || a.label || '—')}</td></tr>`).join('') + '</table>' : `<div class="none">${L('目前沒有子代理。根代理用 delegate_task 或 sessions_spawn 派遣。', 'No sub-agents. A root agent dispatches them with delegate_task or sessions_spawn.')}</div>`}</section>`;
    h += `<section class="c5">${secH('03', L('共用公告板', 'Shared board'))}<div class="stream">${board.length ? board.map((e) => `<div class="ev" style="grid-template-columns:64px 90px 1fr"><span class="ts">${hhmm(e.ts_ms)}</span><span class="kd">${ov(e.kind || '')}</span><span class="tg" title="${ov(e.text)}">${ov(e.text || '')}</span></div>`).join('') : `<div class="none">${L('公告板是空的。', 'The board is empty.')}</div>`}</div></section>`;
    h += '</div></div>';
    el.innerHTML = h;
    bindCommon(el);
  },
};

// ── LAN: paired phones / browsers / PCs (`devices.*`), pairing card, discovery (`discovery.list`,
// `lan.probe`, `lan.connect`). The QR code is an SVG the server renders (seagent_app::qr).
function lanSection(d, lan) {
  if (!d) return ''; // not an admin: the device list needs admin scope
  const on = lan && lan.lan;
  const devs = d.devices || [], pend = d.pending || [];
  let h = `<section class="c12">${secH('05', L('區域網路裝置', 'LAN devices'), on ? `<button data-lanpair data-write>${L('配對裝置', 'Pair a device')}</button> <button data-lanscan>${L('掃描網路', 'Scan network')}</button>` : '')}`;
  if (!on) h += `<div class="none">${L('區域網路模式未開啟。在設定精靈勾選「允許這個網路上的裝置連線」，或設定', 'LAN mode is off. Tick "Allow devices on this network to connect" in the setup wizard, or set')} <code>[app.exposure] lan = true</code>.</div>`;
  else h += `<p class="dim">${L('本機指紋', 'This host')} <code>${ov((lan.identity && lan.identity.sas) || '—')}</code> · ${ov(lan.address || '')} · ${lan.discovery ? L('mDNS 廣播中', 'advertised over mDNS') : L('不廣播', 'not advertised')}</p>`;
  h += '<div id="lanPair"></div>';
  if (pend.length) h += '<div class="slist">' + pend.map((p) => `<div class="srow"><span class="light warn"></span><span><strong>${ov(p.name)}</strong> <span class="faint">${ov(p.platform)}</span><span class="sub">${L('配對碼', 'code')} ${ov(p.code)} · ${ov(p.ip)} · ${L('確認對方畫面顯示的指紋與本機相同再核准', 'approve only if the device shows the same fingerprint as this host')}</span></span><span class="r"><button class="btn small" data-lanapprove="${ov(p.code)}" data-write>${L('核准', 'Approve')}</button> <button class="btn ghost small" data-lanreject="${ov(p.code)}" data-write>${L('拒絕', 'Reject')}</button></span></div>`).join('') + '</div>';
  h += '<div class="slist">' + (devs.length ? devs.map((x) => `<div class="srow"><span class="light ok"></span><span><strong>${ov(x.name)}</strong> <span class="faint mono">${ov(x.id).slice(0, 12)}</span><span class="sub">${ov(x.platform || '—')} · ${ov(x.scope)} · ${L('最近使用', 'seen')} ${ago(x.lastSeenMs)}</span></span><span class="r"><button class="btn ghost small" data-lanrevoke="${ov(x.id)}" data-write>${L('撤銷', 'Revoke')}</button></span></div>`).join('') : `<div class="none">${L('還沒有配對的裝置。', 'No paired devices yet.')}</div>`) + '</div>';
  h += '<div id="lanFound"></div></section>';
  if (typeof devSecSection === 'function') h += devSecSection(d, lan); // devsec.js
  return h;
}
function bindLan(el) {
  const rerender = () => VIEWS.devices.render(el);
  if (typeof devSecBind === 'function') devSecBind(el, rerender); // devsec.js
  const act = async (fn, ok) => { try { await fn(); if (ok) toast(ok); rerender(); } catch (e) { toast(e.message, true); } };
  for (const b of el.querySelectorAll('[data-lanapprove]')) b.onclick = () => act(() => S.arp.call('devices.approve', { code: b.dataset.lanapprove }), L('已核准', 'Approved'));
  for (const b of el.querySelectorAll('[data-lanreject]')) b.onclick = () => act(() => S.arp.call('devices.reject', { code: b.dataset.lanreject }), L('已拒絕', 'Rejected'));
  for (const b of el.querySelectorAll('[data-lanrevoke]')) b.onclick = () => { if (confirm(L('撤銷後這台裝置要重新配對。確定？', 'The device will have to pair again. Revoke?'))) act(() => S.arp.call('devices.revoke', { id: b.dataset.lanrevoke }), L('已撤銷', 'Revoked')); };
  const pair = el.querySelector('[data-lanpair]');
  if (pair) pair.onclick = async () => {
    try {
      const o = await S.arp.call('devices.pair.create', { ttlMin: 10 });
      const code = o.code.slice(0, 4) + '-' + o.code.slice(4);
      el.querySelector('#lanPair').innerHTML = `<div class="cols"><div class="c5" style="max-width:260px;background:#fff;padding:8px;border-radius:8px">${o.qrSvg || ''}</div><div class="c7"><p>${L('用手機相機掃描（會開啟主控台並自動配對），或在 SE Agent App 掃描。', 'Scan with the phone camera (opens this console and pairs it) or with the SE Agent app.')}</p><p>${L('或在裝置上輸入', 'Or type on the device')}: <code>${ov(o.address.replace(/^https?:\/\//, ''))}</code> · ${L('配對碼', 'code')} <strong class="mono" style="font-size:20px">${ov(code)}</strong></p><p>${L('主機指紋', 'Host fingerprint')} <strong class="mono">${ov(o.sas || '—')}</strong> — ${L('裝置上顯示的必須相同', 'the device must show the same')}</p><p class="dim">${L('10 分鐘內有效，QR 只能用一次。', 'Valid 10 minutes; the QR code works once.')}</p></div></div>`;
    } catch (e) { toast(e.message, true); }
  };
  const scan = el.querySelector('[data-lanscan]');
  if (scan) scan.onclick = async () => {
    const box = el.querySelector('#lanFound');
    box.innerHTML = '<span class="star spin"></span>';
    try {
      const r = await S.arp.call('discovery.list', { timeoutMs: 2500 });
      const hosts = (r.hosts || []).filter((x) => !x.self);
      box.innerHTML = secH('06', L('這個網路上的 SE Agent', 'SE Agent on this network')) + '<div class="slist">' + (hosts.length ? hosts.map((x, i) => `<div class="srow"><span class="light ok"></span><span><strong>${ov(x.name)}</strong> <span class="faint mono">${ov(x.address)}</span><span class="sub">${L('指紋', 'fingerprint')} ${ov(x.sas)}</span></span><span class="r"><button class="btn small" data-lanconnect="${i}" data-write>${L('連線', 'Connect')}</button></span></div>`).join('') : `<div class="none">${L('沒有找到（對方需開啟區域網路模式；有些網路會擋 multicast）。', 'None found (the other host must be in LAN mode; some networks block multicast).')}</div>`) + '</div>';
      for (const b of box.querySelectorAll('[data-lanconnect]')) b.onclick = () => lanConnect(hosts[+b.dataset.lanconnect], rerender);
    } catch (e) { box.innerHTML = `<p class="bad">${ov(e.message)}</p>`; }
  };
}
// PC-to-PC: the other host shows an 8-character code (`seagent pair code` / its console); this
// host checks the fingerprint, asks the user to compare, then pairs and adds it as a cluster node.
async function lanConnect(host, done) {
  try {
    const p = await S.arp.call('lan.probe', { address: host.address });
    if (host.fpPrefix && !p.fingerprint.startsWith(host.fpPrefix)) throw new Error(L('對方憑證與廣播內容不符，已停止', 'the certificate does not match the announcement; stopped'));
    const code = prompt(L(`在 ${host.name} 上產生配對碼（裝置頁 → 配對裝置），輸入那 8 碼。\n對方指紋應為 ${p.sas}`, `Create a pairing code on ${host.name} (Devices → Pair a device) and type its 8 characters.\nIts fingerprint must read ${p.sas}`));
    if (!code) return;
    toast(L('等待對方核准…', 'Waiting for the other host to approve…'));
    const r = await S.arp.call('lan.connect', { address: host.address, code, fingerprint: p.fingerprint, fpPrefix: host.fpPrefix, name: host.name });
    toast(L(`已連線並加入叢集節點 ${r.node}`, `Paired; added cluster node ${r.node}`));
    done();
  } catch (e) { toast(e.message, true); }
}

// ── 04 devices ──
VIEWS.devices = {
  title: () => L('裝置與叢集', 'Devices & cluster'),
  async render(el) {
    el.innerHTML = '<div class="ops"><span class="star spin"></span></div>';
    const [dev, cl, desks, lanDev, lan] = await Promise.all([S.arp.call('ui.devices').catch((e) => ({ error: e.message })), S.arp.call('cluster.status').catch(() => null), S.arp.call('view.desktop.list').catch(() => []), S.arp.call('devices.list').catch(() => null), S.arp.call('lan.status').catch(() => null)]);
    if (S.view !== 'devices') return;
    OPS.devices = dev;
    const nodes = dev.nodes || [], paired = dev.paired || [], pending = dev.pending || [];
    const ha = (cl && cl.ha) || {};
    const cnodes = (cl && cl.nodes) || [];
    let h = '<div class="ops"><div class="kpis">'
      + `<div class="kpi"><span class="k">${L('連線中', 'Connected')}</span><span class="v">${nodes.length}</span><span class="s">${L('裝置節點', 'device nodes')}</span></div>`
      + `<div class="kpi"><span class="k">${L('已配對', 'Paired')}</span><span class="v">${paired.length}</span><span class="s">${paired.filter((p) => !p.connected).length} ${L('離線', 'offline')}</span></div>`
      + `<div class="kpi ${pending.length ? 'warn' : ''}"><span class="k">${L('等待配對', 'Pairing')}</span><span class="v">${pending.length}</span><span class="s">${L('需核准', 'need approval')}</span></div>`
      + `<div class="kpi"><span class="k">${L('叢集節點', 'Cluster nodes')}</span><span class="v">${cnodes.length || 1}</span><span class="s">${cnodes.filter((n) => n.alive).length || 1} ${L('存活', 'alive')}</span></div>`
      + `<div class="kpi"><span class="k">HA</span><span class="v" style="font-size:22px;padding-top:8px">${ha.enabled ? ov(ha.role) : L('單機', 'single')}</span><span class="s">${ha.enabled ? 'epoch ' + ov(ha.epoch) : '[ha] enabled = false'}</span></div>`
      + `<div class="kpi"><span class="k">Workers</span><span class="v">${ov((cl && cl.workers && cl.workers.count) || 0)}</span><span class="s">${cl && cl.workers ? `${ov(cl.workers.completed)} ${L('完成', 'done')}` : L('未啟用', 'off')}</span></div>`
      + '</div><div class="cols">';
    if (dev.error) h += `<p class="bad c12">${ov(dev.error)}</p>`;
    h += `<section class="c7">${secH('01', L('裝置節點', 'Device nodes'))}<div class="slist">${nodes.length ? nodes.map((n) => `<div class="srow"><span class="light ok"></span><span><strong>${ov(n.name || n.id)}</strong> <span class="faint mono">${ov(n.id)}</span><span class="sub">${ov(n.platform || '—')} · ${(n.commands || []).length} ${L('個指令', 'commands')}</span></span><span class="r">${L('連線自', 'since')} ${ago(n.connected_since && n.connected_since < 1e12 ? n.connected_since * 1000 : n.connected_since)}</span></div>`).join('') : `<div class="none">${L('沒有節點連線。在另一台機器執行', 'No nodes connected. On another machine run')} <code>seagent node --setup-code CODE</code>.</div>`}
      ${paired.filter((p) => !p.connected).map((p) => `<div class="srow"><span class="light"></span><span>${ov(p.name || p.id)}<span class="sub">${ov(p.platform || '—')}</span></span><span class="r faint">${L('離線', 'offline')}</span></div>`).join('')}</div>
      ${pending.length ? secH('02', L('等待配對', 'Pending pairing')) + '<div class="slist">' + pending.map((p) => `<div class="srow"><span class="light warn"></span><span>${ov(p.name || p.id)}<span class="sub">${ov(p.platform || '')} · code ${ov(p.code || '')}</span></span><span class="r"><button class="btn small" data-pair="${ov(p.code || p.id)}" data-write>${L('核准', 'Approve')}</button></span></div>`).join('') + '</div>' : ''}</section>`;
    h += `<section class="c7">${secH('03', L('桌面與虛擬機', 'Desktops & VMs'))}<div class="slist">${(desks || []).map((d) => `<div class="srow"><span class="light ${d.running ? 'ok' : ''}"></span><span><strong>${ov(d.label || d.id)}</strong> <span class="faint mono">${ov(d.id)}</span><span class="sub">${ov(d.kind)}${d.accel ? ' · ' + ov(d.accel) : ''} · ${ov(d.width)}×${ov(d.height)} · ${d.controller === 'human' ? L('人工控制中', 'human in control') : L('代理控制', 'agent in control')}${d.kind === 'vm' && !d.imageBuilt ? ' · ' + L('映像未建置（seagent vm desktop build）', 'image not built (seagent vm desktop build)') : ''}</span></span><span class="r">${d.kind === 'vm' && d.imageBuilt ? (d.running ? `<button class="btn ghost small" data-vmstop="${ov(d.id)}" data-write>${L('關機', 'Stop')}</button>` : `<button class="btn small" data-vmstart="${ov(d.id)}" data-write>${L('啟動', 'Start')}</button>`) : (d.running ? L('執行中', 'running') : L('未執行', 'off'))}</span></div>`).join('') || `<div class="none">${L('沒有桌面。', 'No desktops.')}</div>`}</div></section>`;
    h += `<section class="c5">${secH('04', L('叢集', 'Cluster'), `<button data-page="cluster">${L('管理 →', 'Manage →')}</button>`)}<div class="slist">${(cnodes.length ? cnodes : [{ node: (cl && cl.self) || 'local', alive: true, self: true, role: ha.role || 'single' }]).map((n) => `<div class="srow"><span class="light ${n.alive ? 'ok' : 'crit'}"></span><span><strong>${ov(n.node)}</strong>${n.self ? ` <span class="faint">${L('本機', 'this')}</span>` : ''}<span class="sub">${ov(n.role || '—')} · ${ov(n.version || '')} ${ov(n.advertise || n.url || '')}</span></span><span class="r">${ov((n.running || []).length)} ${L('執行', 'run')}</span></div>`).join('')}</div></section>`;
    h += lanSection(lanDev, lan);
    h += '</div></div>';
    el.innerHTML = h;
    bindCommon(el);
    bindLan(el);
    for (const b of el.querySelectorAll('[data-page]')) b.onclick = () => { S.pageNav = 'showNodes'; openPage(b.dataset.page); };
    for (const b of el.querySelectorAll('[data-vmstart]')) b.onclick = async () => { b.disabled = true; b.textContent = L('開機中…', 'Booting…'); try { await S.arp.call('view.vm.start', { name: b.dataset.vmstart.replace(/^vm:/, '') }); toast(L('桌面 VM 已啟動', 'Desktop VM started')); } catch (e) { toast(e.message, true); } VIEWS.devices.render(el); };
    for (const b of el.querySelectorAll('[data-vmstop]')) b.onclick = async () => { b.disabled = true; try { await S.arp.call('view.vm.stop', { name: b.dataset.vmstop.replace(/^vm:/, '') }); } catch (e) { toast(e.message, true); } VIEWS.devices.render(el); };
    for (const b of el.querySelectorAll('[data-pair]')) b.onclick = async () => { try { await S.arp.call('node.pair.approve', { code: b.dataset.pair }); toast(L('已核准', 'Approved')); VIEWS.devices.render(el); } catch (e) { toast(e.message, true); } };
  },
};

// ── 05 approvals: waiting, standing grants, exec policy, recent decisions ──
const EXEC_LEVELS = ['deny', 'allowlist', 'full'];
const ASK_LEVELS = ['off', 'on-miss', 'always'];
function grantRow(g, revocable) {
  return `<tr><td class="mono">${ov(g.kind)}</td><td class="mono">${ov(g.pattern)}</td><td>${ov(g.source || '—')}</td><td class="mono">${g.last_used_at ? new Date(g.last_used_at * 1000).toLocaleString() : '—'}</td><td class="mono">${g.expires_at ? new Date(g.expires_at * 1000).toLocaleDateString() : L('永不過期', 'never')}</td><td>${revocable ? `<button class="btn ghost small" data-revoke="${ov(g.id)}" data-write>${L('撤銷', 'Revoke')}</button>` : `<span class="faint">${L('設定檔', 'config')}</span>`}</td></tr>`;
}
function execPolicyBox(p) {
  const opt = (xs, cur) => xs.map((x) => `<option${x === cur ? ' selected' : ''}>${x}</option>`).join('');
  return `<div class="toolbar"><label class="dim">${L('執行安全', 'Exec security')} <select id="exSecurity" data-write>${opt(EXEC_LEVELS, p.security)}</select></label><label class="dim">${L('詢問時機', 'Ask')} <select id="exAsk" data-write>${opt(ASK_LEVELS, p.ask)}</select></label><label class="dim">${L('無人可問', 'Ask fallback')} <select id="exFallback" data-write>${opt(EXEC_LEVELS, p.askFallback)}</select></label><button class="btn small" id="exSave" data-write>${L('儲存', 'Save')}</button></div>`;
}
function agentPolicyTable(agents, exec) {
  if (!agents || !agents.length) return `<div class="none">${L('沒有具名代理；主代理沿用全域政策。', 'No named agents; the main agent inherits the global policy.')}</div>`;
  return '<table class="kv"><tr><th>' + L('代理', 'Agent') + '</th><th>' + L('模型', 'Model') + '</th><th>' + L('角色', 'Role') + '</th><th>' + L('核准預設', 'Approval') + '</th><th>' + L('執行', 'Exec') + '</th><th>' + L('沙箱', 'Sandbox') + '</th><th>' + L('工具限制', 'Tools') + '</th></tr>' +
    agents.map((a) => {
      const r = a.role || {};
      const known = r.status !== 'unknown';
      const policy = r.policy || r;
      const deny = [...(r.deny || []), ...(r.write_deny || [])];
      return `<tr><td><strong>${ov(a.id)}</strong>${a.default ? ` <span class="faint">${L('預設', 'default')}</span>` : ''}</td><td class="mono">${ov(a.model || '—')}</td><td>${r.id ? `<span class="mono">${ov(r.id)}</span>` : `<span class="faint">${L('無', 'none')}</span>`}${known ? '' : ` <span class="crit">unknown</span>`}</td><td>${known ? ov(policy.approval || '—') : '<span class="crit">unknown</span>'}</td><td class="mono">${ov(exec.security || '—')} / ${ov(exec.ask || '—')}</td><td>${ov(exec.sandbox || '—')}</td><td class="mono">${ov([...(a.tools_deny || []), ...deny].join(', ') || '—')}</td></tr>`;
    }).join('') + '</table>';
}
VIEWS.approvals = {
  title: () => L('核准與提問', 'Approvals & questions'),
  async render(el) {
    const items = [...S.pending.values()].map((e) => e.p);
    let recent = [];
    let grants = null;
    try { recent = await S.arp.call('audit.query', { kind: 'approval', limit: 30 }); } catch {}
    try { grants = await S.arp.call('ui.approvals.grants.list'); } catch (e) { grants = { error: e.message }; }
    if (S.view !== 'approvals') return;
    let h = `<div class="ops"><section>${secH('01', L('等待中', 'Waiting'), `${items.length}`)}`;
    h += items.length ? '<div id="apList" style="display:grid;gap:10px"></div>' : `<div class="none"><span class="star ok" style="--size:9px"></span> ${L('沒有等待中的核准或提問。代理需要你時會出現在這裡，也會跳出通知。', 'Nothing is waiting. When an agent needs you it shows up here and as a notification.')}</div>`;
    h += `</section><section>${secH('02', L('常設授權', 'Standing grants'), `<button data-go="security">${L('安全態勢 →', 'Posture →')}</button>`)}`;
    if (!grants || grants.error) {
      h += `<p class="bad">${ov(grants && grants.error || 'unavailable')}</p>`;
    } else {
      const gs = grants.grants || [], cfg = grants.config || [];
      h += gs.length || cfg.length ? '<table class="kv"><tr><th>' + L('類型', 'Kind') + '</th><th>' + L('樣式', 'Pattern') + '</th><th>' + L('來源', 'Source') + '</th><th>' + L('上次使用', 'Last used') + '</th><th>' + L('到期', 'Expires') + '</th><th></th></tr>' + gs.map((g) => grantRow(g, true)).join('') + cfg.map((g) => grantRow(g, false)).join('') + '</table>' : `<div class="none">${L('沒有常設授權。', 'No standing grants.')}</div>`;
      h += `<p class="dim">${L(`常設授權預設 ${grants.grant_ttl_days} 天後到期；撤銷立刻生效。`, `Standing grants expire after ${grants.grant_ttl_days} days by default; revocation is immediate.`)}</p>`;
    }
    h += `</section><section>${secH('03', L('執行政策', 'Exec policy'), L('主機預設與各代理的實際權限', 'host defaults and what each agent may do'))}`;
    if (grants && !grants.error) {
      h += execPolicyBox(grants.exec || {});
      h += agentPolicyTable((grants.agents || {}).agents, { security: (grants.exec || {}).security, ask: (grants.exec || {}).ask, sandbox: ((grants.agents || {}).sandbox || {}).mode });
    }
    h += `</section><section>${secH('04', L('最近的決定', 'Recent decisions'), L('來自稽核紀錄', 'from the audit trail'))}`;
    h += recent.length ? '<table class="kv"><tr><th>' + L('時間', 'Time') + '</th><th>' + L('類型', 'Kind') + '</th><th>' + L('誰', 'Who') + '</th><th>' + L('對象', 'Target') + '</th><th>' + L('結果', 'Outcome') + '</th><th>' + L('對話', 'Session') + '</th></tr>' + recent.slice().reverse().map((r) => `<tr><td class="mono">${new Date(r.ts).toLocaleString()}</td><td class="mono">${ov(r.kind)}</td><td>${ov((r.actor || {}).name)}${(r.actor || {}).role ? ` <span class="faint">${ov(r.actor.role)}</span>` : ''}</td><td class="mono">${ov(r.target)}</td><td class="${/deny|reject/.test(r.outcome) ? 'crit' : 'ok'}">${ov(r.outcome)}</td><td class="mono">${r.session ? `<a href="#" data-open="${ov(r.session)}">${ov(r.session).slice(0, 10)}</a>` : ''}</td></tr>`).join('') + '</table>' : `<div class="none">${L('還沒有核准紀錄。', 'No approval records yet.')}</div>`;
    h += '</section></div>';
    el.innerHTML = h;
    const list = el.querySelector('#apList');
    for (const p of items) {
      const wrap = document.createElement('div');
      wrap.innerHTML = `<div class="label" style="margin-bottom:4px">${ov(sessName(p.session))} · <a href="#" data-open="${ov(p.session)}">${L('打開對話', 'open conversation')}</a></div>`;
      wrap.appendChild(pendingBox(p));
      list && list.appendChild(wrap);
    }
    for (const b of el.querySelectorAll('[data-revoke]')) b.onclick = async () => {
      b.disabled = true;
      try { const r = await S.arp.call('ui.approvals.grant.revoke', { id: b.dataset.revoke }); toast(L(`已撤銷 ${r.removed} 筆授權`, `Revoked ${r.removed} grant(s)`)); VIEWS.approvals.render(el); }
      catch (e) { toast(e.message, true); b.disabled = false; }
    };
    const save = el.querySelector('#exSave');
    if (save) save.onclick = async () => {
      save.disabled = true;
      try {
        await S.arp.call('ui.exec.policy.set', { security: el.querySelector('#exSecurity').value, ask: el.querySelector('#exAsk').value, ask_fallback: el.querySelector('#exFallback').value });
        toast(L('執行政策已儲存', 'Exec policy saved'));
        VIEWS.approvals.render(el);
      } catch (e) { toast(e.message, true); save.disabled = false; }
    };
    bindCommon(el);
  },
};

// ── 06 security posture: what is exposed, and what every agent may do ──
function sevClass(s) { return s === 'critical' ? 'crit' : s === 'warn' ? 'warn' : ''; }
VIEWS.security = {
  title: () => L('安全態勢', 'Security posture'),
  async render(el) {
    el.innerHTML = '<div class="ops"><span class="star spin"></span></div>';
    let d;
    try { d = await S.arp.call('ui.security.status'); } catch (e) { el.innerHTML = `<div class="ops"><p class="bad">${ov(e.message)}</p></div>`; return; }
    if (S.view !== 'security') return;
    const app = d.app || {}, surfaces = d.surfaces || [], findings = d.findings || [], warnings = d.warnings || [], channels = d.channels || [], agents = d.agents || [], tokens = d.scoped_tokens || [];
    const exposed = surfaces.filter((s) => s.enabled && !s.loopback);
    const bad = findings.filter((f) => f.severity === 'critical' || f.severity === 'warn');
    const sv = (x) => (x ? `<span class="star ok" style="--size:9px"></span>` : `<span class="light warn"></span>`);
    let h = '<div class="ops"><div class="kpis">'
      + `<div class="kpi ${exposed.length ? 'crit' : ''}"><span class="k">${L('對外監聽', 'Exposed listeners')}</span><span class="v">${exposed.length}</span><span class="s">${exposed.length ? L('需確認每一層', 'check every layer') : L('只在 loopback', 'loopback only')}</span></div>`
      + `<div class="kpi ${bad.length ? 'warn' : ''}"><span class="k">${L('風險發現', 'Findings')}</span><span class="v">${bad.length}</span><span class="s">${findings.length} ${L('項（含提示）', 'total (with info)')}</span></div>`
      + `<div class="kpi"><span class="k">${L('權杖', 'Tokens')}</span><span class="v">${(app.token && app.token.set ? 1 : 0) + tokens.length}</span><span class="s">${tokens.length} ${L('具範圍', 'scoped')}</span></div>`
      + `<div class="kpi ${channels.some((c) => c.open) ? 'warn' : ''}"><span class="k">${L('頻道', 'Channels')}</span><span class="v">${channels.length}</span><span class="s">${channels.filter((c) => c.open).length} ${L('開放', 'open')}</span></div>`
      + `<div class="kpi"><span class="k">${L('代理', 'Agents')}</span><span class="v">${agents.length}</span><span class="s">${L('可用的執行/工具政策', 'effective exec/tool policy')}</span></div>`
      + '</div><div class="cols">';
    // Surfaces
    h += `<section class="c7">${secH('01', L('監聽面', 'Listening surfaces'), `${surfaces.length}`)}<div class="slist">`;
    h += surfaces.length ? surfaces.map((s) => `<div class="srow"><span class="light ${s.enabled ? (s.loopback ? 'ok' : 'warn') : ''}"></span><span><strong>${ov(s.name)}</strong> <span class="mono faint">${ov(s.listen)}</span><span class="sub">${s.enabled ? (s.loopback ? L('僅本機', 'loopback') : L('可由網路連線', 'network reachable')) : L('未啟用', 'disabled')} · auth ${ov(s.auth)}${s.tls ? ' · TLS' : ''}${s.behind_proxy ? ' · proxy' : ''}${s.rate_limit ? ' · rate-limit' : ''}</span>${s.warning ? `<span class="sub crit">${ov(s.warning)}</span>` : ''}${(s.origins || []).length ? `<span class="sub faint">origins: ${ov(s.origins.join(', '))}</span>` : ''}</span><span class="r">${s.allow_public ? L('已允許公開', 'public opt-in') : L('未允許公開', 'no public opt-in')}</span></div>`).join('') : `<div class="none">${L('沒有監聽面。', 'No listening surfaces.')}</div>`;
    h += `</div>${warnings.length ? `<div class="verify badv" style="margin-top:10px">${warnings.map((w) => `<div>⚠ ${ov(w)}</div>`).join('')}</div>` : ''}</section>`;
    // App endpoints / tokens
    h += `<section class="c5">${secH('02', L('App server 與權杖', 'App server & tokens'), app.enabled ? L('已啟用', 'enabled') : L('未啟用', 'disabled'))}`;
    if (app.status === 'unknown') h += `<p class="bad">${ov(app.error || 'unknown')}</p>`;
    else h += `<dl class="facts">
      <dt>${L('監聽', 'Listen')}</dt><dd class="mono">${ov(app.listen)}</dd>
      <dt>${L('管理權杖', 'Admin token')}</dt><dd>${app.token && app.token.set ? `<span class="ok">${L('已設定', 'set')}</span>` : `<span class="crit">${L('未設定', 'not set')}</span>`}</dd>
      <dt>${L('登入', 'Dashboard auth')}</dt><dd>${app.dashboard_auth && app.dashboard_auth.enabled ? ov(app.dashboard_auth.provider) : L('關閉（只用權杖）', 'off (token only)')}</dd>
      <dt>${L('端點', 'Endpoints')}</dt><dd>${[app.openai_api && 'OpenAI /v1', app.nodes && 'nodes /node', app.terminal && L('終端機', 'terminal'), app.a2a && app.a2a.enabled && 'A2A', app.metrics_public && '/metrics (public)', app.scim && 'SCIM'].filter(Boolean).map(ov).join(' · ') || L('控制台', 'console only')}</dd>
      <dt>${L('TLS / proxy', 'TLS / proxy')}</dt><dd>${app.tls ? 'TLS' : L('無原生 TLS', 'no native TLS')}${app.behind_proxy ? ' · behind proxy' : ''}</dd>
      <dt>Origins</dt><dd class="mono">${ov((app.allow_origins || []).join(', ') || L('僅同源', 'same-origin only'))}</dd>
    </dl>`;
    if (tokens.length) h += '<table class="kv" style="margin-top:10px"><tr><th>' + L('名稱', 'Name') + '</th><th>scope</th><th>org / team</th></tr>' + tokens.map((t) => `<tr><td>${ov(t.name || '—')}</td><td class="mono">${ov(t.scope)}</td><td class="mono">${ov([t.org, t.team].filter(Boolean).join(' / ') || '—')}</td></tr>`).join('') + '</table>';
    h += '</section>';
    // Findings
    h += `<section class="c12">${secH('03', L('風險與建議', 'Findings & fixes'), L('來自 seagent security audit 的同一組檢查', 'the same checks as seagent security audit'))}`;
    h += findings.length ? '<table class="kv"><tr><th>' + L('等級', 'Severity') + '</th><th>id</th><th>' + L('問題', 'Finding') + '</th><th>' + L('建議', 'Fix') + '</th></tr>' + findings.map((f) => `<tr><td class="${sevClass(f.severity)}">${ov(f.severity)}</td><td class="mono faint">${ov(f.id)}</td><td><strong>${ov(f.title)}</strong>${f.detail ? `<span class="sub">${ov(f.detail)}</span>` : ''}</td><td class="mono">${ov(f.fix || '—')}</td></tr>`).join('') + '</table>' : `<div class="none"><span class="star ok" style="--size:9px"></span> ${L('沒有風險發現。', 'No findings.')}</div>`;
    h += '</section>';
    // Channels
    h += `<section class="c6">${secH('04', L('頻道', 'Channels'), `${channels.length}`)}<div class="slist">${channels.length ? channels.map((c) => `<div class="srow"><span class="light ${c.open ? 'warn' : 'ok'}"></span><span><strong>${ov(c.name)}</strong> <span class="faint">${ov(c.kind)}</span><span class="sub">${c.listening ? `${L('監聽', 'listen')} ${ov(c.listen)}` : L('外送／輪詢', 'outbound / polling')}${c.default_chat ? ` · default ${ov(c.default_chat)}` : ''}${c.public_url ? ' · public URL' : ''}</span></span><span class="r">${c.open ? L('任何人可進', 'open to anyone') : L('允許清單', 'allowlisted')} · ${c.secret_configured ? L('已簽章', 'signed') : L('無密鑰', 'no secret')}</span></div>`).join('') : `<div class="none">${L('沒有設定頻道。', 'No channels configured.')}</div>`}</div></section>`;
    // Agents
    h += `<section class="c6">${secH('05', L('代理能力', 'Agent capabilities'), `${agents.length}`)}${agentPolicyTable(agents, { security: (d.exec || {}).security, ask: (d.exec || {}).ask, sandbox: (d.sandbox || {}).mode || (d.sandbox || {}).status })}<p class="dim">${L('未知的角色一律顯示 unknown，不當成安全。', 'Unknown roles always show as unknown, never as safe.')}</p></section>`;
    h += '</div></div>';
    el.innerHTML = h;
    bindCommon(el);
  },
};

// ── 06 audit ──
const AUD = { kind: '', actor: '', outcome: '', session: '', limit: 200, verify: null };
VIEWS.audit = {
  title: () => L('稽核紀錄', 'Audit trail'),
  async render(el) {
    let rows = [];
    let err = '';
    const q = { limit: AUD.limit };
    for (const k of ['kind', 'actor', 'outcome', 'session']) if (AUD[k]) q[k] = AUD[k];
    try { rows = await S.arp.call('audit.query', q); } catch (e) { err = e.message; }
    if (S.view !== 'audit') return;
    const v = AUD.verify;
    let h = '<div class="ops"><section>';
    h += secH('01', L('完整性', 'Integrity'), '');
    h += v ? `<div class="verify ${v.ok ? 'good' : 'badv'}"><span class="star ${v.ok ? 'ok' : 'crit'}" style="--size:14px"></span><div><strong>${v.ok ? L('雜湊鏈完整', 'Hash chain intact') : L('雜湊鏈斷裂', 'Hash chain broken')}</strong> · ${ov(v.events ?? '')} ${L('筆', 'records')} · seq ${ov(v.first_seq ?? '')}–${ov(v.last_seq ?? '')} · ${ov(v.segments ?? '')} ${L('個區段', 'segment(s)')}${v.error ? ` · <span class="crit">${ov(v.error)}</span>` : ''}<br><code>head ${ov(v.head || '')}</code>${v.anchor ? `<br><code>anchor ${ov(v.anchor)}</code>` : ''}</div><span style="margin-left:auto"><button class="btn ghost small" id="auVerify" data-read>${L('重新驗證', 'Verify again')}</button></span></div>`
      : `<div class="verify"><span class="star" style="--size:14px"></span><div>${L('每筆稽核紀錄都串在 SHA-256 雜湊鏈上；竄改、刪除或重排任何一筆，驗證都會從那裡斷掉。', 'Every record is chained with SHA-256; editing, deleting or reordering any line breaks verification from that point.')}</div><span style="margin-left:auto"><button class="btn small" id="auVerify" data-read>${L('驗證雜湊鏈', 'Verify chain')}</button></span></div>`;
    h += '</section><section>' + secH('02', L('事件', 'Events'), `${rows.length} ${L('筆', 'shown')}`);
    h += `<div class="toolbar"><input type="search" id="auKind" placeholder="${L('類型（如 auth、approval、gate）', 'kind (auth, approval, gate…)')}" value="${ov(AUD.kind)}" data-read><input type="search" id="auActor" placeholder="${L('執行者', 'actor')}" value="${ov(AUD.actor)}" data-read><input type="search" id="auSess" placeholder="session" value="${ov(AUD.session)}" data-read><select id="auOut" data-read><option value="">${L('所有結果', 'any outcome')}</option>${['allow', 'deny', 'ok', 'error'].map((o) => `<option${AUD.outcome === o ? ' selected' : ''}>${o}</option>`).join('')}</select><select id="auLim" data-read>${[100, 200, 500, 1000].map((n) => `<option${AUD.limit === n ? ' selected' : ''}>${n}</option>`).join('')}</select><button class="btn ghost small" id="auGo" data-read>${L('查詢', 'Query')}</button><button class="btn ghost small" id="auCsv" data-read>CSV</button><button class="btn ghost small" id="auReport" data-read>${L('稽核報告（30 天）', 'Audit report (30 d)')}</button></div>`;
    h += err ? `<p class="bad">${ov(err)}</p>` : rows.length ? '<table class="kv"><tr><th>seq</th><th>' + L('時間', 'Time') + '</th><th>' + L('類型', 'Kind') + '</th><th>' + L('執行者', 'Actor') + '</th><th>' + L('對象', 'Target') + '</th><th>' + L('結果', 'Outcome') + '</th><th>session</th></tr>' + rows.slice().reverse().map((r) => `<tr><td class="mono faint">${ov(r.seq)}</td><td class="mono">${new Date(r.ts).toLocaleString()}</td><td class="mono" style="color:var(--gold-300)">${ov(r.kind)}</td><td>${ov((r.actor || {}).kind)}:${ov((r.actor || {}).name)}${(r.actor || {}).ip ? ` <span class="faint mono">${ov(r.actor.ip)}</span>` : ''}</td><td class="mono">${ov(r.target)}</td><td class="${/deny|error/.test(r.outcome) ? 'crit' : /allow|ok/.test(r.outcome) ? 'ok' : ''}">${ov(r.outcome)}</td><td class="mono">${r.session ? `<a href="#" data-open="${ov(r.session)}">${ov(r.session).slice(0, 10)}</a>` : ''}</td></tr>`).join('') + '</table>' : `<div class="none">${L('沒有符合的紀錄。', 'No matching records.')}</div>`;
    h += '</section><section>' + secH('03', L('對話覆核', 'Session reviews'), '');
    let reviews = [];
    try { reviews = await S.arp.call('session.review.list', { limit: 50 }); } catch {}
    h += reviews.length ? '<table class="kv"><tr><th>' + L('對話', 'Session') + '</th><th>' + L('狀態', 'Status') + '</th><th>' + L('覆核者', 'Reviewer') + '</th><th>' + L('時間', 'Time') + '</th><th>' + L('註記', 'Note') + '</th></tr>' + reviews.map((r) => `<tr><td class="mono"><a href="#" data-open="${ov(r.session)}">${ov(sessName(r.session)).slice(0, 40)}</a></td><td class="${r.status === 'flagged' ? 'crit' : 'ok'}">${ov(r.status)}</td><td>${ov(r.by)}</td><td class="mono">${new Date(r.at_ms).toLocaleString()}</td><td>${ov(r.note || '')}</td></tr>`).join('') + '</table>' : `<div class="none">${L('還沒有覆核紀錄。在對話頁右上角的「覆核」標記。', 'No reviews yet. Mark one from the Review button in a conversation.')}</div>`;
    h += '</section></div>';
    if (S.view !== 'audit') return;
    el.innerHTML = h;
    bindCommon(el);
    el.querySelector('#auReport').onclick = async () => {
      try {
        const r = await S.arp.call('audit.report', { from_ms: Date.now() - 30 * 86400000, to_ms: Date.now(), format: 'html' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([r.text || JSON.stringify(r, null, 2)], { type: 'text/html' }));
        a.download = `seagent-audit-report-${new Date().toISOString().slice(0, 10)}.html`;
        a.click();
      } catch (e) { toast(e.message, true); }
    };
    const go = () => { AUD.kind = el.querySelector('#auKind').value.trim(); AUD.actor = el.querySelector('#auActor').value.trim(); AUD.session = el.querySelector('#auSess').value.trim(); AUD.outcome = el.querySelector('#auOut').value; AUD.limit = +el.querySelector('#auLim').value; VIEWS.audit.render(el); };
    el.querySelector('#auGo').onclick = go;
    for (const i of el.querySelectorAll('.toolbar input')) i.onkeydown = (e) => { if (e.key === 'Enter') go(); };
    el.querySelector('#auVerify').onclick = async () => { try { AUD.verify = await S.arp.call('audit.verify'); } catch (e) { AUD.verify = { ok: false, error: e.message }; } VIEWS.audit.render(el); };
    el.querySelector('#auCsv').onclick = () => {
      const cell = (x) => `"${String(x ?? '').replace(/"/g, '""')}"`;
      const csv = 'seq,ts,kind,actor_kind,actor,role,ip,target,outcome,session\n' + rows.map((r) => [r.seq, new Date(r.ts).toISOString(), r.kind, (r.actor || {}).kind, (r.actor || {}).name, (r.actor || {}).role, (r.actor || {}).ip, r.target, r.outcome, r.session].map(cell).join(',')).join('\n');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
      a.download = `seagent-audit-${Date.now()}.csv`;
      a.click();
    };
  },
};

// ── 08 control hub: every Control UI page as a grid (replaces pages.js' button list) ──
function showControlHub() {
  S.pageNav = 'showControl';
  const groups = {};
  for (const [id, p] of Object.entries(PAGES)) (groups[p.group] = groups[p.group] || []).push([id, p]);
  return showPanel(L('所有頁面', 'All pages'), async () => Object.entries(groups).map(([g, ps]) => `<h3>${ov(g)}</h3><div class="hub">${ps.map(([id, p]) => `<button data-page="${ov(id)}"><span>${ov(p.title)}</span><span class="id">${ov(id)}</span></button>`).join('')}</div>`).join(''),
    () => { for (const b of $('panelBody').querySelectorAll('[data-page]')) b.onclick = () => openPage(b.dataset.page); });
}
$('showControl').onclick = showControlHub;
