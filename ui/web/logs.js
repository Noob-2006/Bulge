// seagent web UI: the Logs page. Two views share the page that pages.js registers as `logs`:
//   · 工具呼叫 (default): one row per tool call from the tool-call log (`toollog.history`,
//     crates/seagent/src/ops/toollog.rs) — filter by session, tool and result, a failures-only
//     switch, and one-click export (JSONL / CSV / HTML) of exactly the rows on screen.
//   · 系統日誌: the daemon log tail from pages.js; its 3-second poll is off unless 自動更新.
// Nothing here polls: the page reads when it opens, when a filter changes, or on 重新整理.
// Uses pages.js globals (PAGES, CP, call, v, when, download, note, act, q, qa, openPage, NOTE)
// and app.js ones ($, esc). Loaded after pages.js.
'use strict';

(function logsPage() {
  if (typeof PAGES === 'undefined' || !PAGES.logs) return;
  const daemonLog = PAGES.logs;
  const TL = { tab: 'tools', session: '', tool: '', status: '', since: '24h', grep: '', limit: 500, last: null, follow: false };

  const css = `
.tl-tabs { display: flex; gap: 6px; margin: 0 0 12px; }
.tl-tabs .btn[aria-pressed="true"] { border-color: var(--gold, #d4a24c); color: var(--text-1, inherit); }
.tl-bar { display: flex; flex-wrap: wrap; gap: 6px 8px; align-items: center; margin: 0 0 10px; }
.tl-bar select, .tl-bar input { max-width: 100%; }
.tl-sum { display: flex; flex-wrap: wrap; gap: 6px 14px; margin: 0 0 10px; font-size: 13px; }
.tl-sum .bad, .tl-row.bad .tl-res { color: var(--crit, #e5484d); }
.tl-chip { border: 1px solid var(--thread-2, #444); border-radius: 999px; padding: 1px 8px; cursor: pointer; background: none; color: inherit; font: inherit; }
.tl-chip[aria-pressed="true"] { border-color: var(--gold, #d4a24c); }
.tl-wrap { overflow-x: auto; border: 1px solid var(--thread-2, #444); border-radius: var(--radius, 8px); max-height: 62vh; }
.tl-table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
.tl-table th, .tl-table td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--thread, #333); vertical-align: top; }
.tl-table th { position: sticky; top: 0; background: var(--crimson-950, #1a1012); color: var(--text-3, #999); font-weight: 600; white-space: nowrap; }
:root[data-theme="daylight"] .tl-table th { background: #fbf7f1; }
.tl-table td.tl-t, .tl-table td.tl-ms { white-space: nowrap; color: var(--text-3, #999); }
.tl-table td.tl-ms { text-align: right; font-variant-numeric: tabular-nums; }
.tl-table td.tl-a, .tl-table td.tl-e { font-family: var(--mono, monospace); word-break: break-word; }
.tl-row.bad td { background: color-mix(in srgb, var(--crit, #e5484d) 9%, transparent); }
.tl-res { white-space: nowrap; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--ok, #3fb950); }
.tl-sid { cursor: pointer; text-decoration: underline dotted; }
@media (max-width: 640px) { .tl-table .tl-hide-sm { display: none; } }`;
  if (!document.getElementById('tl-style')) {
    const s = document.createElement('style');
    s.id = 'tl-style';
    s.textContent = css;
    document.head.appendChild(s);
  }

  const params = (extra) => {
    const p = { limit: TL.limit };
    for (const k of ['session', 'tool', 'grep']) if (TL[k]) p[k] = TL[k];
    if (TL.status) p.status = TL.status;
    if (TL.since) p.since = TL.since;
    return Object.assign(p, extra || {});
  };
  const short = (s) => String(s || '').slice(0, 15);
  const ms = (n) => (n >= 10000 ? (n / 1000).toFixed(1) + ' s' : (n || 0) + ' ms');

  function tabs() {
    const b = (id, label) => `<button class="btn ghost small" data-tl-tab="${id}" data-read aria-pressed="${TL.tab === id}">${label}</button>`;
    return `<div class="tl-tabs">${b('tools', '工具呼叫')}${b('daemon', '系統日誌')}</div>`;
  }

  function table(recs) {
    if (!recs.length) return '<p class="dim">沒有符合的工具呼叫。工具呼叫會在 daemon 執行工作時記錄（<code>[tool_log]</code>）。</p>';
    // Newest first on screen; the export keeps the log's oldest-first order.
    const rows = recs.slice().reverse().map((r) => `<tr class="tl-row${r.ok ? '' : ' bad'}">
      <td class="tl-t">${v(when(r.ts))}</td>
      <td class="tl-hide-sm"><span class="tl-sid" data-tl-session="${v(r.session)}" title="${v(r.session)}">${v(short(r.session))}</span></td>
      <td><b>${v(r.tool)}</b></td>
      <td class="tl-res">${r.ok ? '成功' : r.gate ? `閘門擋下（${v(r.gate)}）` : '失敗'}</td>
      <td class="tl-ms">${v(ms(r.ms))}</td>
      <td class="tl-a">${v(r.args)}</td>
      <td class="tl-e">${v(r.err || '')}</td></tr>`).join('');
    return `<div class="tl-wrap"><table class="tl-table"><thead><tr><th>時間</th><th class="tl-hide-sm">對話</th><th>工具</th><th>結果</th><th>耗時</th><th>參數</th><th>錯誤</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  async function renderTools() {
    const r = await call('toollog.history', params());
    TL.last = r;
    const t = r.totals || { tools: [] };
    const recs = r.records || [];
    // The session list comes from the calls themselves (plus the current filter), so a filter
    // never points at a session that has no calls in range.
    const sessions = [...new Set(recs.map((x) => x.session).concat(TL.session ? [TL.session] : []))].filter(Boolean);
    const tools = (t.tools || []).map((x) => x.tool).concat(TL.tool && !(t.tools || []).some((x) => x.tool === TL.tool) ? [TL.tool] : []);
    const opt = (val, label, cur) => `<option value="${v(val)}"${val === cur ? ' selected' : ''}>${v(label)}</option>`;
    const since = [['1h', '最近 1 小時'], ['24h', '最近 24 小時'], ['7d', '最近 7 天'], ['', '全部保留期間']];
    const bar = `<div class="tl-bar">
      <select id="tlSession" data-read>${opt('', '所有對話', TL.session)}${sessions.map((s) => opt(s, short(s), TL.session)).join('')}</select>
      <select id="tlTool" data-read>${opt('', '所有工具', TL.tool)}${tools.map((x) => opt(x, x, TL.tool)).join('')}</select>
      <select id="tlStatus" data-read>${opt('', '成功與失敗', TL.status)}${opt('ok', '只看成功', TL.status)}${opt('error', '只看失敗', TL.status)}</select>
      <select id="tlSince" data-read>${since.map(([k, l]) => opt(k, l, TL.since)).join('')}</select>
      <select id="tlLimit" data-read>${[200, 500, 2000, 10000].map((n) => opt(String(n), n + ' 筆', String(TL.limit))).join('')}</select>
      <input type="text" id="tlGrep" data-read placeholder="搜尋參數或錯誤…（Enter）" size="18" value="${v(TL.grep)}">
      <button class="btn ghost small" id="tlFail" data-read aria-pressed="${TL.status === 'error'}">只看失敗</button>
      <button class="btn ghost small" id="tlRefresh" data-read>重新整理</button>
      <span class="dim">匯出畫面上的 ${recs.length} 筆：</span>
      <button class="btn small" data-tl-export="jsonl" data-read>JSONL</button>
      <button class="btn small" data-tl-export="csv" data-read>CSV</button>
      <button class="btn small" data-tl-export="html" data-read>HTML</button></div>`;
    const chips = (t.tools || []).slice(0, 12).map((x) => `<button class="tl-chip" data-tl-tool="${v(x.tool)}" data-read aria-pressed="${TL.tool === x.tool}">${v(x.tool)} ${x.calls}${x.failed ? ` · <span class="bad">${x.failed} 失敗</span>` : ''}</button>`).join('');
    const sum = `<div class="tl-sum"><span><b>${t.matched || 0}</b> 次呼叫</span><span class="${t.failed ? 'bad' : ''}"><b>${t.failed || 0}</b> 失敗</span><span>${t.sessions || 0} 個對話</span>${(t.matched || 0) > recs.length ? `<span class="dim">顯示最新 ${recs.length} 筆</span>` : ''}</div>`;
    return `${tabs()}${bar}${sum}<div class="tl-sum">${chips}</div>${table(recs)}${NOTE}<p class="dim">${v(r.file || '')}</p>`;
  }

  function afterTools() {
    const reload = () => openPage('logs');
    const set = (k, val) => { TL[k] = val; reload(); };
    q('#tlSession').onchange = (e) => set('session', e.target.value);
    q('#tlTool').onchange = (e) => set('tool', e.target.value);
    q('#tlStatus').onchange = (e) => set('status', e.target.value);
    q('#tlSince').onchange = (e) => set('since', e.target.value);
    q('#tlLimit').onchange = (e) => set('limit', +e.target.value);
    q('#tlGrep').onkeydown = (e) => { if (e.key === 'Enter') set('grep', e.target.value.trim()); };
    q('#tlFail').onclick = () => set('status', TL.status === 'error' ? '' : 'error');
    q('#tlRefresh').onclick = reload;
    for (const c of qa('[data-tl-tool]')) c.onclick = () => set('tool', TL.tool === c.dataset.tlTool ? '' : c.dataset.tlTool);
    for (const s of qa('[data-tl-session]')) s.onclick = () => set('session', s.dataset.tlSession);
    // Same filters and limit as the table: the file holds exactly the rows on screen.
    for (const b of qa('[data-tl-export]')) b.onclick = async () => {
      const r = await act(() => call('toollog.history', params({ format: b.dataset.tlExport })));
      if (!r) return;
      download(r.filename, r.content, r.mime);
      note(`已匯出 ${r.count} 筆（${r.filename}）`);
    };
  }

  function bindTabs() {
    for (const b of qa('[data-tl-tab]')) b.onclick = () => { TL.tab = b.dataset.tlTab; openPage('logs'); };
  }

  PAGES.logs = {
    title: daemonLog.title,
    group: daemonLog.group,
    async render() {
      if (TL.tab !== 'daemon') {
        // The daemon tail's auto-refresh belongs to its own tab only.
        clearInterval(CP.logTimer); CP.logTimer = null;
        return renderTools();
      }
      return tabs() + (await daemonLog.render());
    },
    after() {
      bindTabs();
      if (TL.tab !== 'daemon') return afterTools();
      const r = daemonLog.after && daemonLog.after();
      // pages.js polls the tail every 3 s from here. Every `ui.logs` read is an audited admin
      // call (an audit record plus a rewrite of the chain head), so an open page wrote to disk
      // around the clock: the tail now refreshes on demand unless 自動更新 is switched on.
      if (!TL.follow) { clearInterval(CP.logTimer); CP.logTimer = null; }
      const btn = q('#logRefresh');
      if (btn) btn.insertAdjacentHTML('afterend', ` <label class="check"><input type="checkbox" id="tlFollow" data-read${TL.follow ? ' checked' : ''}> 自動更新（每 3 秒）</label>`);
      const box = q('#tlFollow');
      if (box) box.onchange = () => { TL.follow = box.checked; openPage('logs'); };
      for (const p of qa('p.dim')) if (!TL.follow && p.textContent.includes('每 3 秒自動更新')) p.textContent = p.textContent.replace('每 3 秒自動更新，離開這一頁就停止。', '按「重新整理」更新；需要時可開啟自動更新。');
      return r;
    },
  };
})();
