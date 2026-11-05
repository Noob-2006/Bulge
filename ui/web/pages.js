// ark web UI: Control UI pages (OpenClaw ui/src/pages/*) — channels, skills, skill workshop,
// cron, usage, config, secrets, terminal, dashboards/apps/portals, workboard, agents, claws,
// lobsterdex, memory import, meetings, worktrees, cloud workers, search, systems, custodian,
// labs, about, profile, and this file's own model providers / devices / plugins / logs pages.
// Backed by `ui.*` ARP methods (crates/ark/src/ops/ui_methods.rs and ops/webui.rs) plus the
// kernel's kanban.*/schedule.list and pairing.* methods.
// Uses app.js globals: S, $, esc, showPanel, row, openSession, openPluginPanel; surfaces.js: showBoards, openBoard.
'use strict';

const CP = { term: null, timer: null, log: null, logTimer: null, logTail: [], logFile: '' };
const v = (x) => esc(x === undefined || x === null ? '' : String(x));
const call = (m, p) => S.arp.call(m, p || {});
const when = (ms) => (ms ? new Date(typeof ms === 'number' && ms < 1e12 ? ms * 1000 : ms).toLocaleString() : '—');
const bytes = (n) => (n > 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : n > 1024 ? (n / 1024).toFixed(1) + ' KB' : (n || 0) + ' B');
const body = () => $('panelBody');
const q = (sel) => body().querySelector(sel);
const qa = (sel) => body().querySelectorAll(sel);
function note(msg, bad) { const n = q('.cp-note'); if (n) { n.textContent = msg; n.classList.toggle('bad', !!bad); } }
async function act(fn, ok) { try { const r = await fn(); if (ok) note(typeof ok === 'function' ? ok(r) : ok); return r; } catch (e) { note(e.message, true); return null; } }
function download(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: type || 'text/plain' }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
// Shrink a picked image to a square JPEG under the profile avatar limit (256 KiB).
function shrink(file, max) {
  return new Promise((res, rej) => {
    const img = new Image();
    img.onload = () => {
      const side = Math.min(max || 512, Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = c.height = side;
      const g = c.getContext('2d');
      const s = Math.min(side / img.width, side / img.height);
      g.drawImage(img, (side - img.width * s) / 2, (side - img.height * s) / 2, img.width * s, img.height * s);
      let q = 0.9;
      let url = c.toDataURL('image/jpeg', q);
      while (url.length > 240 * 1024 && q > 0.4) { q -= 0.1; url = c.toDataURL('image/jpeg', q); }
      res(url);
    };
    img.onerror = () => rej(new Error('無法讀取這張圖片'));
    img.src = URL.createObjectURL(file);
  });
}
const NOTE = '<p class="cp-note dim"></p>';

// Pages this file adds on top of `ui.pages` (crates/ark/src/ops/ui_methods.rs). `showControl`
// appends them to the nav group each one declares, so the Rust page order stays authoritative.
const EXTRA_PAGES = ['fleet', 'cluster', 'models', 'devices', 'plugins', 'logs'];

// The logs page state (file / level / grep / limit) lives in CP.log; the tail renderer escapes
// every record and marks the timestamp and level up with CSS classes.
function cpLogParams() {
  const s = CP.log || {};
  return { file: s.file || '', level: s.level || '', grep: s.grep || '', limit: s.limit || 200 };
}
function cpLogHtml(tail) {
  if (!tail.length) return '<span class="dim">沒有符合的日誌記錄。</span>';
  return tail.map((r) => `<span class="cp-log-line"><span class="cp-log-ts">${v(when(r.ts))}</span> <span class="cp-log-lv lv-${v(r.level || 'info')}">${v(r.level || 'info')}</span> <span class="cp-log-target">${v(r.target || '')}</span> ${v(r.text)}</span>`).join('');
}

const PAGES = {
  channels: { title: '頻道', group: '控制', async render() {
    const [c, pair] = await Promise.all([call('ui.channels'), call('pairing.list').catch(() => ({ pending: [], approved: [] }))]);
    let h = '<table class="kv"><tr><th>啟用</th><th>名稱</th><th>類型</th><th>狀態</th><th>私訊政策</th><th>允許</th><th>管理員</th><th>憑證</th></tr>';
    for (const ch of c.channels) {
      h += row([`<input type="checkbox" data-enable="${v(ch.name)}"${ch.enabled === false ? '' : ' checked'}${ch.plugin ? ' disabled' : ''}>`, v(ch.name), v(ch.kind), ch.running ? '執行中' : ch.enabled === false ? '停用' : '未執行',
        `<select data-ch="${v(ch.name)}">${['pairing', 'allowlist', 'open', 'disabled'].map((p) => `<option${p === ch.dm_policy ? ' selected' : ''}>${p}</option>`).join('')}</select>`,
        v((ch.allow || []).join(', ') || '—'), v((ch.admins || []).join(', ') || '—'), v((ch.credentials || []).join(', ') || '—')]);
    }
    h += '</table>';
    if (!c.channels.length) h = '<p class="dim">尚未設定頻道。執行 <code>ark channels add</code> 或 <code>ark setup</code>。</p>';
    const pend = pair.pending || [];
    if (pend.length) h += '<h3>等待配對的使用者</h3><p class="dim">配對碼 1 小時內有效；輸入對方收到的配對碼以核准。</p><table class="kv">' + pend.map((p, i) => row([v(p.channel), v(p.sender_name || p.sender), `<span class="dim">${when(p.created)}</span>`, `<input type="text" data-code="${i}" placeholder="配對碼" size="8">`, `<button class="btn small" data-approve="${v(p.channel)}" data-idx="${i}">核准</button>`])).join('') + '</table>';
    return h + NOTE + '<p class="dim">變更頻道設定後需重新啟動 daemon（/restart）。憑證請在「秘密」頁或 <code>ark channels</code> 設定。</p>';
  }, after() {
    for (const s of qa('[data-ch]')) s.onchange = () => act(() => call('ui.channels.set', { name: s.dataset.ch, key: 'dm_policy', value: JSON.stringify(s.value) }), '已儲存；重新啟動後生效');
    for (const b of qa('[data-enable]')) b.onchange = () => act(() => call('ui.channels.set', { name: b.dataset.enable, key: 'enabled', value: String(b.checked) }), '已儲存；重新啟動後生效');
    for (const b of qa('[data-approve]')) b.onclick = async () => { const code = q(`[data-code="${b.dataset.idx}"]`).value.trim(); if (await act(() => call('pairing.approve', { channel: b.dataset.approve, code }), '已核准')) openPage('channels'); };
  } },

  skills: { title: '技能', group: '代理', async render() {
    const list = await call('ui.skills.list');
    return '<input type="text" class="cp-filter" placeholder="篩選技能…"><table class="kv cp-list"><tr><th>啟用</th><th>名稱</th><th>來源</th><th>說明</th></tr>' +
      list.map((s) => `<tr data-name="${v(s.name)}"><td><input type="checkbox" data-toggle="${v(s.name)}"${s.enabled ? ' checked' : ''}></td><td><a href="#" data-skill="${v(s.name)}">${v(s.name)}</a></td><td class="dim">${v(s.source)}</td><td>${v(s.description)}</td></tr>`).join('') + '</table>' + NOTE + '<div class="cp-detail"></div>';
  }, after() {
    q('.cp-filter').oninput = (e) => { const f = e.target.value.toLowerCase(); for (const r of qa('tr[data-name]')) r.hidden = !r.textContent.toLowerCase().includes(f); };
    for (const c of qa('[data-toggle]')) c.onchange = () => act(() => call('ui.skills.toggle', { name: c.dataset.toggle, enabled: c.checked }), c.checked ? '已啟用' : '已停用');
    for (const a of qa('[data-skill]')) a.onclick = async (e) => {
      e.preventDefault();
      const s = await act(() => call('ui.skills.get', { name: a.dataset.skill }));
      if (s) q('.cp-detail').innerHTML = `<h3>${v(s.name)} <span class="dim">${v(s.source)}</span></h3><p>${v(s.description)}</p><pre class="cp-pre">${v(s.body)}</pre>${s.files.length ? `<p class="dim">檔案：${v(s.files.join(', '))}</p>` : ''}`;
    };
  } },

  'skill-workshop': { title: '技能工坊', group: '代理', async render() {
    const [list, arch] = await Promise.all([call('ui.skills.workshop.list'), call('ui.skills.workshop.archived').catch(() => [])]);
    return `<p class="dim">在使用者技能目錄建立或修改技能（SKILL.md）。封存的版本可以還原。</p><table class="kv">${list.map((s) => row([`<a href="#" data-edit="${v(s.name)}">${v(s.name)}</a>`, v(s.description), `<span class="dim">${when(s.updated_ms)}</span>`, `<button class="btn ghost small" data-del="${v(s.name)}">封存</button>`])).join('')}</table>
      ${arch.length ? `<h3>封存</h3><table class="kv">${arch.map((a) => row([`<code>${v(a.name)}</code>`, `<span class="dim">${when(a.archived_ms)}</span>`, `<button class="btn ghost small" data-restore="${v(a.name)}">還原</button>`])).join('')}</table>` : ''}
      <h3>編輯</h3><p><input type="text" id="wsName" placeholder="名稱（小寫、數字、- _ .）"></p><p><input type="text" id="wsDesc" placeholder="說明（模型在技能索引看到的文字）"></p>
      <p><textarea id="wsBody" class="cp-area" rows="12" placeholder="# 技能內容（Markdown）"></textarea></p><p><button class="btn" id="wsSave">儲存</button></p>${NOTE}`;
  }, after() {
    for (const a of qa('[data-edit]')) a.onclick = async (e) => { e.preventDefault(); const s = await act(() => call('ui.skills.get', { name: a.dataset.edit })); if (s) { $('wsName').value = s.name; $('wsDesc').value = s.description; $('wsBody').value = s.body.trim(); note(s.editable ? '可編輯的使用者技能' : '此技能不是使用者技能，儲存會失敗'); } };
    for (const b of qa('[data-restore]')) b.onclick = async () => { if (await act(() => call('ui.skills.workshop.restore', { name: b.dataset.restore }), '已還原')) openPage('skill-workshop'); };
    for (const b of qa('[data-del]')) b.onclick = async () => { if (confirm(`封存技能 ${b.dataset.del}？`) && await act(() => call('ui.skills.workshop.delete', { name: b.dataset.del }))) openPage('skill-workshop'); };
    $('wsSave').onclick = async () => { if (await act(() => call('ui.skills.workshop.save', { name: $('wsName').value.trim(), description: $('wsDesc').value.trim(), body: $('wsBody').value }), '已儲存')) setTimeout(() => openPage('skill-workshop'), 400); };
  } },

  cron: { title: '排程', group: '控制', async render() {
    const jobs = await call('schedule.list');
    const edit = CP.cronEdit;
    return '<table class="kv"><tr><th>啟用</th><th>排程</th><th>提示</th><th>下次</th><th>上次結果</th><th></th></tr>' +
      jobs.map((j) => row([`<input type="checkbox" data-en="${v(j.id)}"${j.enabled ? ' checked' : ''}>`, `<code>${v(j.cron)}</code>`, v(j.prompt), `<span class="dim">${when(j.next_run)}</span>`,
        j.last_session ? `<a href="#" data-open="${v(j.last_session)}">${v((j.last_result || '').slice(0, 100) || '查看對話')}</a>` : `<span class="dim">${v((j.last_result || '').slice(0, 120))}</span>`,
        `<button class="btn ghost small" data-run="${v(j.id)}">立即執行</button> <button class="btn ghost small" data-edit="${v(j.id)}">編輯</button> <button class="btn ghost small" data-rm="${v(j.id)}">刪除</button>`])).join('') + '</table>' +
      `<h3>${edit ? '編輯排程' : '新增排程'}</h3><p><input type="text" id="cronExpr" placeholder="cron 運算式，例如 0 9 * * *" value="${v(edit ? edit.cron : '')}"></p><p><input type="text" id="cronPrompt" placeholder="要執行的提示" value="${v(edit ? edit.prompt : '')}"></p><p><input type="text" id="cronModel" placeholder="模型（選填）" value="${v(edit && edit.model ? edit.model : '')}"></p><p><button class="btn" id="cronAdd">${edit ? '儲存' : '新增'}</button>${edit ? ' <button class="btn ghost small" id="cronCancel">取消</button>' : ''}</p>${NOTE}`;
  }, after() {
    const done = () => { CP.cronEdit = null; return openPage('cron'); };
    for (const c of qa('[data-en]')) c.onchange = () => act(() => call('ui.cron.enable', { id: c.dataset.en, enabled: c.checked }), '已更新');
    for (const b of qa('[data-run]')) b.onclick = () => act(() => call('ui.cron.run', { id: b.dataset.run }), '已在背景執行');
    for (const b of qa('[data-edit]')) b.onclick = async () => { const jobs = await call('schedule.list'); CP.cronEdit = jobs.find((j) => j.id === b.dataset.edit) || null; openPage('cron'); };
    for (const a of qa('[data-open]')) a.onclick = (e) => { e.preventDefault(); $('panelDialog').close(); openSession(a.dataset.open); };
    for (const b of qa('[data-rm]')) b.onclick = async () => { if (confirm('刪除這個排程？') && await act(() => call('ui.cron.remove', { id: b.dataset.rm }))) done(); };
    if ($('cronCancel')) $('cronCancel').onclick = done;
    $('cronAdd').onclick = async () => {
      const p = { cron: $('cronExpr').value, prompt: $('cronPrompt').value, model: $('cronModel').value };
      const r = CP.cronEdit ? await act(() => call('ui.cron.update', { ...p, id: CP.cronEdit.id }), '已儲存（下次執行時間已重算）') : await act(() => call('ui.cron.add', p), '已新增');
      if (r) done();
    };
  } },

  usage: { title: '用量', group: '控制', async render() {
    const days = +(CP.usageDays || 30);
    const u = await call('ui.usage', { days });
    const max = Math.max(1, ...u.daily.map((d) => d.input + d.output));
    return `<p><select id="usageDays" data-read>${[1, 7, 30, 90].map((d) => `<option value="${d}"${d === days ? ' selected' : ''}>最近 ${d} 天</option>`).join('')}</select> <select id="usageFmt" data-read><option value="models-csv">模型 CSV</option><option value="daily-csv">每日 CSV</option><option value="sessions-csv">對話 CSV</option><option value="json">JSON</option></select> <button class="btn ghost small" id="usageCsv" data-read>匯出</button></p>
      <p>${u.sessions_count} 個對話 · ${u.total.tokens.toLocaleString()} tokens · $${u.total.cost_usd.toFixed(4)}</p>
      <div class="cp-bars">${u.daily.map((d) => `<div title="${v(d.day)}: ${d.input + d.output} tokens" style="height:${Math.round(((d.input + d.output) / max) * 100)}%"></div>`).join('')}</div>
      <h3>模型</h3><table class="kv"><tr><th>模型</th><th>呼叫</th><th>輸入</th><th>輸出</th><th>快取讀</th><th>快取寫</th><th>費用</th></tr>${u.models.map((m) => row([v(m.model), m.calls, m.input, m.output, m.cache_read, m.cache_write, m.cost_usd === null ? '—' : '$' + m.cost_usd.toFixed(4)])).join('')}</table>
      <h3>用量最高的對話</h3><table class="kv">${u.top_sessions.map((s) => row([`<a href="#" data-open="${v(s.id)}">${v(s.title || s.id)}</a>`, s.tokens.toLocaleString()])).join('')}</table>${NOTE}`;
  }, after() {
    $('usageDays').onchange = (e) => { CP.usageDays = e.target.value; openPage('usage'); };
    $('usageCsv').onclick = async () => {
      const r = await act(() => call('ui.usage.export', { days: +(CP.usageDays || 30), format: $('usageFmt').value }));
      if (r) { download(r.filename, r.content, r.type || 'text/csv'); note('已匯出 ' + r.filename); }
    };
    for (const a of qa('[data-open]')) a.onclick = (e) => { e.preventDefault(); $('panelDialog').close(); openSession(a.dataset.open); };
  } },

  config: { title: '設定檔', group: '設定', async render() {
    const [c, backups] = await Promise.all([call('ui.config.get'), call('ui.config.backups').catch(() => [])]);
    CP.cfgOriginal = c.text;
    return `<p class="dim">${v(c.path)}${c.error ? ` · <span class="bad">${v(c.error)}</span>` : ' · 有效'}</p>
      <p><input type="text" id="cfgKey" placeholder="鍵，例如 model.default"> <input type="text" id="cfgVal" placeholder='值（TOML，例如 "openai/gpt-5" 或 true）'></p>
      <p><button class="btn small" id="cfgSet">設定單一鍵</button> <button class="btn ghost small" id="cfgUnset">移除鍵</button> <span class="dim">寫入後重新啟動 daemon 才生效。</span></p>
      <textarea id="cfgText" class="cp-area mono" rows="18">${v(c.text)}</textarea>
      <p><button class="btn" id="cfgSave">驗證並儲存整份</button> <button class="btn ghost small" id="cfgDiscard">捨棄變更</button> <span id="cfgDiff" class="dim"></span></p>
      <p class="dim">${c.redacted ? '含遮蔽值（"***"）時無法整份儲存；請改用單一鍵或「秘密」頁。' : '儲存前會驗證並備份。'}</p>
      <h3>先前的版本</h3>${backups.length ? '<table class="kv">' + backups.slice(0, 20).map((b) => row([`<code>${v(String(b).split('/').pop())}</code>`, `<button class="btn ghost small" data-restore="${v(b)}">還原</button>`])).join('') + '</table>' : '<p class="dim">還沒有備份（每次儲存或還原都會留一份）。</p>'}${NOTE}`;
  }, after() {
    const diff = () => {
      const now = $('cfgText').value.split('\n');
      const was = (CP.cfgOriginal || '').split('\n');
      const lines = [];
      for (let i = 0; i < Math.max(now.length, was.length); i++) if ((now[i] || '') !== (was[i] || '')) lines.push(i + 1);
      $('cfgDiff').textContent = lines.length ? `${lines.length} 行有未儲存的變更（第 ${lines.slice(0, 6).join(', ')}${lines.length > 6 ? '…' : ''} 行）` : '沒有變更';
    };
    $('cfgText').oninput = diff; diff();
    $('cfgDiscard').onclick = () => { $('cfgText').value = CP.cfgOriginal || ''; diff(); note('已捨棄變更'); };
    $('cfgSet').onclick = () => act(() => call('ui.config.set', { key: $('cfgKey').value.trim(), value: $('cfgVal').value }), (r) => r.message);
    $('cfgUnset').onclick = () => act(() => call('ui.config.unset', { key: $('cfgKey').value.trim() }), (r) => r.message);
    $('cfgSave').onclick = () => act(() => call('ui.config.save', { text: $('cfgText').value }), '已儲存（舊版已備份）；重新啟動 daemon 後生效');
    for (const b of qa('[data-restore]')) b.onclick = async () => { if (confirm('以這個備份取代目前設定？目前版本也會先備份一份。') && await act(() => call('ui.config.restore', { path: b.dataset.restore }), '已還原；重新啟動 daemon 後生效')) openPage('config'); };
  } },

  secrets: { title: '秘密', group: '設定', async render() {
    const s = await call('ui.secrets.list');
    return `<p class="dim">只顯示名稱，永遠不會回傳值。在設定中以 <code>{{secret:NAME}}</code> 引用。</p>
      ${s.missing.length ? `<p class="bad">設定引用但尚未設定：${v(s.missing.join(', '))}</p>` : ''}
      <table class="kv"><tr><th>名稱</th><th>狀態</th><th></th></tr>${s.secrets.map((x) => row([`<code>${v(x.name)}</code>`, x.referenced ? '已引用' : '<span class="dim">未引用</span>', `<button class="btn ghost small" data-copy="${v(x.name)}">複製引用</button> <button class="btn ghost small" data-del="${v(x.name)}">刪除</button>`])).join('')}</table>
      <h3>設定秘密</h3><p><input type="text" id="secName" placeholder="名稱" autocomplete="off"></p><p><input type="password" id="secVal" placeholder="值" autocomplete="new-password"></p><p><button class="btn" id="secSet">儲存</button></p>
      <h3>批次貼上</h3><p class="dim">每行一個 <code>NAME=value</code>（從其他工具複製的金鑰清單）；空行與 <code>#</code> 開頭會被忽略。</p><p><textarea id="secBulk" class="cp-area mono" rows="5" placeholder="BRAVE_API_KEY=..."></textarea></p><p><button class="btn small" id="secBulkSave">匯入</button></p>${NOTE}`;
  }, after() {
    for (const b of qa('[data-copy]')) b.onclick = () => navigator.clipboard.writeText(`{{secret:${b.dataset.copy}}}`).then(() => note('已複製引用'));
    for (const b of qa('[data-del]')) b.onclick = async () => {
      if (!confirm(`刪除秘密 ${b.dataset.del}？`)) return;
      const r = await act(() => call('ui.secrets.delete', { name: b.dataset.del }));
      if (r && r.removed === false) note('沒有這個秘密', true); else if (r) openPage('secrets');
    };
    $('secSet').onclick = async () => { const r = await act(() => call('ui.secrets.set', { name: $('secName').value.trim(), value: $('secVal').value })); $('secVal').value = ''; if (r) openPage('secrets'); };
    $('secBulkSave').onclick = async () => {
      const lines = $('secBulk').value.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
      let n = 0;
      for (const line of lines) {
        const i = line.indexOf('=');
        if (i < 1) { note('已忽略無法解析的行：' + line, true); continue; }
        if (await act(() => call('ui.secrets.set', { name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() }))) n++;
      }
      if (n) { $('secBulk').value = ''; note(`已匯入 ${n} 項`); openPage('secrets'); }
    };
  } },

  terminal: { title: '終端機', group: '控制', async render() {
    const st = await call('ui.terminal.status');
    if (!st.enabled) return '<p class="dim">終端機已停用。在 config.toml 設定 <code>[app] terminal = true</code> 並重新啟動 daemon 後可使用（等同 daemon 使用者的完整 shell）。</p>';
    return `<pre class="cp-term" id="termOut" tabindex="0"></pre><p><input type="text" id="termIn" placeholder="輸入指令，Enter 送出" autocomplete="off"> </p>
      <p><button class="btn ghost small" id="termCtrlC">Ctrl+C</button> <button class="btn ghost small" id="termTab">Tab</button> <button class="btn ghost small" id="termClose">關閉 shell</button></p>${NOTE}`;
  }, async after() {
    if (!$('termOut')) return;
    if (!CP.term) { const r = await act(() => call('ui.terminal.open', { cols: 100, rows: 30 })); if (!r) return; CP.term = { id: r.id, offset: 0 }; }
    const out = $('termOut');
    // Strip ANSI control sequences; the PTY output is shown as plain text.
    const clean = (s) => s.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, '').replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, '').replace(/\r(?!\n)/g, '');
    const poll = async () => {
      if (!CP.term || !$('panelDialog').open || !$('termOut')) { clearInterval(CP.timer); CP.timer = null; return; }
      try {
        const r = await call('ui.terminal.read', { id: CP.term.id, offset: CP.term.offset });
        CP.term.offset = r.offset;
        if (r.data) { out.textContent = (out.textContent + clean(r.data)).slice(-200000); out.scrollTop = out.scrollHeight; }
        if (r.exited) { note('shell 已結束（按「關閉 shell」再重新開啟）'); CP.term = null; }
      } catch (e) { if (/no terminal/.test(e.message)) { note('shell 已結束（重新開啟以繼續）'); CP.term = null; } else note(e.message, true); }
    };
    clearInterval(CP.timer); CP.timer = setInterval(poll, 300); poll();
    const write = (data) => CP.term && call('ui.terminal.write', { id: CP.term.id, data }).catch((e) => note(e.message, true));
    // Keep the PTY width in step with the panel so wrapped output stays aligned.
    const fit = () => { const cols = Math.max(40, Math.floor((out.clientWidth || 700) / 7.5)); if (CP.term) call('ui.terminal.resize', { id: CP.term.id, cols, rows: 30 }).catch(() => {}); };
    window.addEventListener('resize', fit); fit();
    $('termIn').onkeydown = (e) => { if (e.key === 'Enter') { write($('termIn').value + '\n'); $('termIn').value = ''; } };
    $('termCtrlC').onclick = () => write('\x03');
    $('termTab').onclick = () => { write($('termIn').value + '\t'); $('termIn').value = ''; };
    $('termClose').onclick = async () => { if (CP.term) await call('ui.terminal.close', { id: CP.term.id }).catch(() => {}); CP.term = null; note('已關閉'); };
    $('termIn').focus();
  } },

  dashboards: { title: '儀表板', group: '代理', async render() {
    const a = await call('ui.apps');
    const f = (CP.dashQ || '').toLowerCase();
    const list = a.canvas.filter((d) => !f || `${d.title} ${d.kind || ''}`.toLowerCase().includes(f));
    if (CP.dashSort === 'title') list.sort((x, y) => String(x.title).localeCompare(String(y.title)));
    return `<p><button class="btn small" id="dashAll" data-read>對話儀表板總覽</button> <input type="text" id="dashQ" data-read placeholder="篩選 canvas 文件…" value="${v(CP.dashQ || '')}"> <select id="dashSort" data-read><option value="new">最新</option><option value="title"${CP.dashSort === 'title' ? ' selected' : ''}>標題</option></select> <span class="dim">${list.length} / ${a.canvas.length}</span></p><h3>Canvas 文件</h3>` +
      (list.length ? '<table class="kv">' + list.map((d) => row([`<a href="${v(d.url)}" target="_blank" rel="noopener">${v(d.title)}</a>`, `<span class="dim">${v(d.kind || '')}</span>`, `<span class="dim">${v(d.created || '')}</span>`])).join('') + '</table>' : '<p class="dim">沒有符合的 canvas 文件。</p>');
  }, after() {
    $('dashAll').onclick = () => (typeof showBoards === 'function' ? showBoards() : null);
    $('dashQ').oninput = (e) => { CP.dashQ = e.target.value; openPage('dashboards'); };
    $('dashSort').onchange = (e) => { CP.dashSort = e.target.value; openPage('dashboards'); };
  } },

  apps: { title: '應用程式', group: '代理', async render() {
    const a = await call('ui.apps');
    S.cpPanels = a.panels;
    return '<h3>外掛面板</h3>' + (a.panels.length ? '<table class="kv">' + a.panels.map((p, i) => row([`<a href="#" data-panel="${i}">${v(p.title || p.id)}</a>`, `<span class="dim">${v(p.plugin)}</span>`])).join('') + '</table>' : '<p class="dim">沒有外掛提供面板。</p>') +
      '<h3>MCP Apps</h3>' + (a.mcp_apps.length ? '<table class="kv">' + a.mcp_apps.map((t) => row([v(t.name), `<span class="dim">${v(t.server)}</span>`, v(t.description)])).join('') + '</table>' : '<p class="dim">沒有 MCP App 工具。</p>') +
      '<h3>MCP 伺服器</h3><table class="kv">' + a.mcp.map((m) => row([v(m.name), m.running ? '執行中' : '停止', `${m.tools} 個工具`])).join('') + '</table>';
  }, after() { for (const b of qa('[data-panel]')) b.onclick = (e) => { e.preventDefault(); const p = S.cpPanels[+b.dataset.panel]; openPluginPanel(p.plugin, { id: p.id, title: p.title }); }; } },

  portals: { title: '入口', group: '代理', async render() {
    const a = await call('ui.apps');
    if (!a.portals.length && !a.canvas.length) return '<p class="dim">沒有外掛掛載的頁面或 canvas 文件。</p>';
    return '<p class="dim">外掛掛載的 HTTP 頁面與 canvas 文件（在新分頁開啟）；「檢查」會在瀏覽器裡試探一次。' + '</p><table class="kv"><tr><th>頁面</th><th>來源</th><th>狀態</th></tr>' +
      a.portals.map((p) => row([`<a href="${v(p.url)}" target="_blank" rel="noopener">${v(p.name)}</a>`, '<span class="dim">外掛</span>', `<button class="btn ghost small" data-read data-probe="${v(p.url)}">檢查</button> <span class="dim" data-state="${v(p.url)}"></span>`])).join('') +
      a.canvas.map((d) => row([`<a href="${v(d.url)}" target="_blank" rel="noopener">${v(d.title)}</a>`, '<span class="dim">canvas</span>', `<button class="btn ghost small" data-read data-probe="${v(d.url)}">檢查</button> <span class="dim" data-state="${v(d.url)}"></span>`])).join('') + '</table>';
  }, after() {
    for (const b of qa('[data-probe]')) b.onclick = async () => {
      const out = q(`[data-state="${b.dataset.probe}"]`);
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 4000);
      try { const r = await fetch(b.dataset.probe, { method: 'GET', signal: ctl.signal, credentials: 'same-origin' }); out.textContent = r.ok ? '可存取' : `HTTP ${r.status}`; out.classList.toggle('bad', !r.ok); }
      catch (e) { out.textContent = '無法存取'; out.classList.add('bad'); }
      finally { clearTimeout(timer); }
    };
  } },

  workboard: { title: '工作看板', group: '代理', async render() {
    const boards = await call('kanban.boards');
    const cur = CP.board || (boards.find((b) => b.current) || boards[0] || { meta: { slug: '' } }).meta.slug;
    const b = await call('kanban.board', cur ? { board: cur } : {});
    const cols = b.workflow.columns;
    let h = `<p><select id="wbBoard" data-read>${boards.map((x) => `<option value="${v(x.meta.slug)}"${x.meta.slug === b.board ? ' selected' : ''}>${v(x.meta.name || x.meta.slug)}</option>`).join('')}</select> <input type="text" id="wbNew" placeholder="新看板 slug" size="12"> <button class="btn ghost small" id="wbNewBtn">新增看板</button></p><div class="cp-cols">`;
    for (const c of cols) {
      h += `<section><h4>${v(c.icon || '')} ${v(c.label)}</h4>` + b.tasks.filter((t) => t.status === c.key).map((t) =>
        `<div class="cp-card"><div><a href="#" data-card="${v(t.id)}"><code>${v(t.id)}</code></a> ${v(t.title)}</div><div class="dim">${v(t.assignee || '')}</div><select data-move="${v(t.id)}"><option value="">移到…</option>${cols.filter((x) => x.key !== c.key).map((x) => `<option value="${v(x.key)}">${v(x.label)}</option>`).join('')}</select></div>`).join('') + '</section>';
    }
    return h + `</div><div class="cp-detail"></div><h3>新增卡片</h3><p><input type="text" id="wbTitle" placeholder="標題"></p><p><input type="text" id="wbAssignee" placeholder="指派（profile，選填）"></p><p><button class="btn" id="wbAdd">新增</button></p>${NOTE}`;
  }, after() {
    const board = () => $('wbBoard') && $('wbBoard').value;
    if ($('wbBoard')) $('wbBoard').onchange = () => { CP.board = board(); openPage('workboard'); };
    if ($('wbNewBtn')) $('wbNewBtn').onclick = async () => { const slug = $('wbNew').value.trim(); if (slug && await act(() => call('kanban.board_create', { slug, name: slug, switch: true }), '已新增看板')) { CP.board = slug; openPage('workboard'); } };
    for (const s of qa('[data-move]')) s.onchange = async () => { if (s.value && await act(() => call('kanban.move', { board: board(), id: s.dataset.move, status: s.value }))) openPage('workboard'); };
    // Card detail (OpenClaw workboard card panel): notes, comments and the two terminal actions.
    for (const a of qa('[data-card]')) a.onclick = async (e) => {
      e.preventDefault();
      const t = await act(() => call('kanban.show', { board: board(), id: a.dataset.card }));
      if (!t) return;
      CP.card = t.task.id;
      q('.cp-detail').innerHTML = `<h3>${v(t.task.id)} ${v(t.task.title)}</h3>
        <p class="dim">${v(t.task.status)} · 優先級 ${v(t.task.priority)} · ${v(t.task.assignee || '未指派')}</p>
        ${t.task.body ? `<pre class="cp-pre">${v(t.task.body)}</pre>` : ''}
        <h4>留言（${(t.comments || []).length}）</h4>${(t.comments || []).map((c) => `<p><strong>${v(c.actor || c.author || '')}</strong>：${v(c.body || c.text)}</p>`).join('') || '<p class="dim">沒有留言。</p>'}
        <p><input type="text" id="wbComment" placeholder="留言…"> <button class="btn small" id="wbSay">送出</button></p>
        <p><button class="btn ghost small" id="wbDone">完成</button> <button class="btn ghost small" id="wbArchive">封存</button></p>`;
      $('wbSay').onclick = async () => { const body = $('wbComment').value.trim(); if (body && await act(() => call('kanban.comment', { board: board(), id: CP.card, body }), '已留言')) a.click(); };
      $('wbDone').onclick = async () => { if (await act(() => call('kanban.complete', { board: board(), id: CP.card }), '已完成')) openPage('workboard'); };
      $('wbArchive').onclick = async () => { if (confirm('封存這張卡片？') && await act(() => call('kanban.archive', { board: board(), id: CP.card }), '已封存')) openPage('workboard'); };
    };
    $('wbAdd').onclick = async () => { if (await act(() => call('kanban.create', { board: board(), title: $('wbTitle').value.trim(), assignee: $('wbAssignee').value.trim() }))) openPage('workboard'); };
  } },

  agents: { title: '代理', group: '代理', async render() {
    const a = await call('ui.agents');
    return `<table class="kv">${row(['預設模型', v(a.default.model)])}${row(['工作目錄', v(a.workspace)])}</table>
      <h3>代理定義</h3>${a.agents.length ? '<table class="kv"><tr><th>ID</th><th>名稱</th><th>模型</th><th>說明</th><th></th></tr>' + a.agents.map((x) => row([`<code>${v(x.id)}</code>`, v(x.def.emoji + ' ' + x.def.name), v(x.def.model || '（預設）'), v(x.def.description),
        `${x.def.default ? '<span class="dim">預設</span> ' : `<button class="btn ghost small" data-default="${v(x.id)}">設為預設</button> `}<button class="btn ghost small" data-del-agent="${v(x.id)}">刪除</button>`])).join('') + '</table>' : '<p class="dim">沒有 [agents.*] 定義。可在「Claws」頁新增。</p>'}
      ${a.bindings && a.bindings.length ? `<h3>頻道綁定</h3><table class="kv">${a.bindings.map((b) => row([v(b.channel || b.kind || ''), `<code>${v(b.agent || b.id || '')}</code>`])).join('')}</table>` : ''}
      <h3>身分檔案</h3><p>${a.files.map((f) => `<button class="btn ghost small" data-file="${v(f.name)}">${v(f.name)}${f.exists ? '' : '（新）'}</button>`).join(' ')}</p>
      <div id="agFile" hidden><textarea id="agText" class="cp-area" rows="14"></textarea><p><button class="btn" id="agSave">儲存</button></p></div>${NOTE}`;
  }, after() {
    for (const b of qa('[data-file]')) b.onclick = async () => { const f = await act(() => call('ui.agents.file.get', { name: b.dataset.file })); if (!f) return; CP.agentFile = f.name; $('agFile').hidden = false; $('agText').value = f.content; note(f.name); };
    for (const b of qa('[data-default]')) b.onclick = async () => { if (await act(() => call('ui.config.set', { key: `agents.${b.dataset.default}.default`, value: 'true' }), '已設為預設')) openPage('agents'); };
    for (const b of qa('[data-del-agent]')) b.onclick = async () => { if (confirm(`刪除代理 ${b.dataset.delAgent} 的 [agents.*] 定義？`) && await act(() => call('ui.config.unset', { key: `agents.${b.dataset.delAgent}` }), '已刪除；重新啟動 daemon 後生效')) openPage('agents'); };
    $('agSave').onclick = () => act(() => call('ui.agents.file.set', { name: CP.agentFile, content: $('agText').value }), '已儲存');
  } },

  claws: { title: 'Claws', group: '代理', async render() {
    const a = await call('ui.agents');
    return `<p class="dim">每個具名代理是一個 <code>[agents.&lt;id&gt;]</code> 定義；頻道可用 bindings 指到它。</p>
      ${a.agents.length ? a.agents.map((x) => `<div class="cp-card"><strong>${v(x.def.emoji)} ${v(x.def.name)}</strong> <code>${v(x.id)}</code> <span class="dim">${v(x.def.model || '預設模型')}${x.def.default ? ' · 預設' : ''}</span><div class="dim">${v(x.def.description)}</div></div>`).join('') : '<p class="dim">還沒有代理。</p>'}
      <h3>新增代理</h3><p><input type="text" id="clawId" placeholder="ID（英數、- _）"></p><p><input type="text" id="clawName" placeholder="顯示名稱"></p><p><input type="text" id="clawEmoji" placeholder="表情符號（選填）" size="4"></p><p><input type="text" id="clawDesc" placeholder="用途"></p><p><input type="text" id="clawModel" placeholder="模型 provider/model（選填）"></p><p><button class="btn" id="clawAdd">新增</button></p>${NOTE}`;
  }, after() {
    $('clawAdd').onclick = async () => {
      const id = $('clawId').value.trim();
      if (!/^[A-Za-z0-9_-]+$/.test(id)) return note('ID 只能用英數、- 或 _', true);
      const set = (k, val) => call('ui.config.set', { key: `agents.${id}.${k}`, value: JSON.stringify(val) });
      const saved = [];
      // Partial writes are undone: a rejected model must not leave a half-built agent behind.
      const done = await act(async () => {
        for (const [k, val] of [['name', $('clawName').value.trim() || id], ['emoji', $('clawEmoji').value.trim()], ['description', $('clawDesc').value.trim()], ['model', $('clawModel').value.trim()]]) {
          if (!val) continue;
          await set(k, val);
          saved.push(k);
        }
        return true;
      }, '已新增');
      if (done) setTimeout(() => openPage('claws'), 400);
      else if (saved.length) { for (const k of saved) await call('ui.config.unset', { key: `agents.${id}.${k}` }).catch(() => {}); note('新增失敗，已回復寫入一半的設定', true); }
    };
  } },

  lobsterdex: { title: 'Lobsterdex', group: '代理', async render() {
    const l = await call('ui.lobsterdex');
    return '<h3>工作流程</h3>' + (l.workflows.length ? '<table class="kv">' + l.workflows.map((w) => row([v(w.name), v(w.description), w.error ? `<span class="bad">${v(w.error)}</span>` : `${w.stages} 個階段`, `<span class="dim">${v(w.path)}</span>`])).join('') + '</table>' : '<p class="dim">工作目錄、workflows/ 與資料目錄下沒有 .lobster 檔案。</p>') +
      '<h3>暫停中的執行</h3>' + ((l.paused || []).length ? '<table class="kv">' + l.paused.map((r) => row([v(r.gate), v(r.prompt), `<code>${v(r.approvalId)}</code>`])).join('') + '</table>' : '<p class="dim">沒有。</p>');
  } },

  'memory-import': { title: '匯入記憶', group: '代理', async render() {
    const p = await call('ui.memory.plan');
    if (!p.providers.length) return '<p class="dim">這台機器上找不到 OpenClaw、Hermes、Claude Code 或 Codex 的資料。</p>';
    return `<p class="dim">匯入目的地：<code>${v(p.dest)}</code>（以 § 分隔；已存在的項目會標示）</p><p><label class="check"><input type="checkbox" id="memReplace"> 取代已存在的項目</label></p>` + p.providers.map((pr) => `<section class="cp-prov"><h3>${v(pr.id)} <span class="dim">${v(pr.path)}</span></h3>${pr.error ? `<p class="bad">${v(pr.error)}</p>` : ''}
      ${pr.items.length ? `<p><label class="check"><input type="checkbox" data-all="${v(pr.id)}" checked> 全選（${pr.items.length} 項，已存在 ${pr.items.filter((i) => i.existing).length} 項）</label></p>` : ''}
      ${pr.items.map((it) => `<label class="check"><input type="checkbox" data-prov="${v(pr.id)}" value="${it.id}" checked> <span class="dim">${v(it.file)}</span> ${v(it.text.slice(0, 160))}${it.existing ? ' <span class="dim">（已存在）</span>' : ''}</label>`).join('') || '<p class="dim">沒有記憶項目。</p>'}
      ${pr.items.length ? `<p><button class="btn small" data-import="${v(pr.id)}">匯入選取的項目</button></p>` : ''}</section>`).join('') + NOTE;
  }, after() {
    for (const a of qa('[data-all]')) a.onchange = () => { for (const c of qa(`[data-prov="${a.dataset.all}"]`)) c.checked = a.checked; };
    for (const b of qa('[data-import]')) b.onclick = () => {
      const items = [...qa(`[data-prov="${b.dataset.import}"]:checked`)].map((c) => +c.value);
      if (!items.length) return note('沒有選取任何項目', true);
      if (confirm(`匯入 ${items.length} 項記憶？`)) act(() => call('ui.memory.apply', { provider: b.dataset.import, items, replace: $('memReplace').checked }), (r) => `已匯入 ${r.imported} 項。${r.summary}`);
    };
  } },

  meetings: { title: '會議', group: '代理', async render() {
    const list = await call('ui.transcripts.list', { query: CP.meetQ || '' });
    return `<p><input type="text" id="meetQ" placeholder="搜尋逐字稿…" value="${v(CP.meetQ || '')}"></p>` + (list.length ? '<table class="kv"><tr><th>標題</th><th>來源</th><th>開始</th><th>段落</th></tr>' + list.map((t) => row([`<a href="#" data-t="${v(t.id)}">${v(t.title || t.id)}</a>`, v(t.source || ''), `<span class="dim">${when(t.started_ms)}</span>`, t.segments])).join('') + '</table>' : '<p class="dim">沒有會議逐字稿（會議機器人與語音通話會寫入資料目錄的 transcripts/）。</p>') + '<div class="cp-detail"></div>' + NOTE;
  }, after() {
    // Reader with in-transcript search and both export formats (OpenClaw meetings view).
    const show = async (id, query) => {
      const t = await act(() => call('ui.transcripts.get', { id, query: query || '' }));
      if (!t) return;
      CP.meet = t.id;
      const segs = t.segments || [];
      q('.cp-detail').innerHTML = `<h3>${v(t.title)}</h3>${t.summary ? `<p>${v(t.summary)}</p>` : ''}
        <p><input type="text" id="tQ" placeholder="在逐字稿中搜尋…（Enter）" value="${v(query || '')}"> <span class="dim">${query ? `${t.matches} / ${t.segments_total} 段符合` : `${t.segments_total || segs.length} 段`}</span></p>
        <div class="cp-pre">${segs.map((s) => `<p><strong>${v(s.speaker)}</strong>：${v(s.text)}</p>`).join('') || '<p class="dim">沒有符合的段落。</p>'}</div>
        <p><button class="btn ghost small" id="meetExport" data-read>匯出 Markdown</button> <button class="btn ghost small" id="meetJsonl" data-read>匯出 JSONL</button></p>`;
      $('meetExport').onclick = async () => { const r = await call('ui.transcripts.export', { id: CP.meet }); download(r.filename, r.content, 'text/markdown'); };
      $('meetJsonl').onclick = async () => { const r = await call('ui.transcripts.export', { id: CP.meet, format: 'jsonl' }); download(r.filename, r.content, 'application/jsonl'); };
      $('tQ').onkeydown = (e) => { if (e.key === 'Enter') show(CP.meet, e.target.value); };
    };
    $('meetQ').onchange = (e) => { CP.meetQ = e.target.value; openPage('meetings'); };
    for (const a of qa('[data-t]')) a.onclick = (e) => { e.preventDefault(); show(a.dataset.t, ''); };
  } },

  worktrees: { title: 'Worktrees', group: '控制', async render() {
    const ws = store.get('ark.workspace') || '';
    let list;
    try { list = await call('ui.worktrees.list', ws ? { workspace: ws } : {}); } catch (e) { return `<p class="dim">${v(e.message)}</p>`; }
    return '<table class="kv"><tr><th>路徑</th><th>分支</th><th>HEAD</th><th></th></tr>' + list.map((w) => row([v(w.path), v(w.branch), `<code>${v(w.head)}</code>`, w.ark ? `<button class="btn ghost small" data-rm="${v(w.path)}">移除</button>` : ''])).join('') + '</table>' +
      '<h3>新增 worktree</h3><p><input type="text" id="wtName" placeholder="名稱（英數、- _ .）"> <button class="btn small" id="wtCreate">在 ark/&lt;名稱&gt; 分支建立</button></p>' +
      '<p><button class="btn ghost small" id="wtDry" data-read>預覽清理</button> <button class="btn ghost small" id="wtPrune">清理空的 ark worktree</button></p>' + NOTE;
  }, after() {
    const ws = store.get('ark.workspace') || undefined;
    for (const b of qa('[data-rm]')) b.onclick = async () => { if (confirm(`移除 ${b.dataset.rm}？未提交的變更會遺失。`) && await act(() => call('ui.worktrees.remove', { name: b.dataset.rm, workspace: ws }))) openPage('worktrees'); };
    if ($('wtCreate')) $('wtCreate').onclick = async () => { if (await act(() => call('ui.worktrees.create', { name: $('wtName').value.trim(), workspace: ws }), '已建立 worktree')) openPage('worktrees'); };
    if ($('wtDry')) $('wtDry').onclick = () => act(() => call('ui.worktrees.prune', { dry_run: true, workspace: ws }), (r) => r.pruned.length ? '會清理：' + r.pruned.join(', ') : '沒有可清理的');
    if ($('wtPrune')) $('wtPrune').onclick = async () => { if (confirm('清理沒有提交、乾淨的 ark worktree？') && await act(() => call('ui.worktrees.prune', { dry_run: false, workspace: ws }))) openPage('worktrees'); };
  } },

  'cloud-workers': { title: '雲端工作環境', group: '控制', async render() {
    const e = await call('ui.environments');
    return `<table class="kv">${row(['沙箱模式', v(e.sandbox.mode || 'off')])}${row(['後端', v(e.sandbox.backend || '—')])}${row(['範圍', v(e.sandbox.scope || '—')])}${row(['根目錄', v(e.root)])}</table>
      <h3>環境</h3>${e.environments.length ? '<table class="kv">' + e.environments.map((x) => row([`<code>${v(x.id)}</code>`, bytes(x.bytes), `<span class="dim">${when(x.modified_ms)}</span>`, `<button class="btn ghost small" data-rm="${v(x.id)}">銷毀</button>`])).join('') + '</table>' : '<p class="dim">沒有沙箱環境。在 config.toml 設定 <code>[exec.sandbox]</code>。</p>'}${NOTE}`;
  }, after() { for (const b of qa('[data-rm]')) b.onclick = async () => { if (confirm(`銷毀環境 ${b.dataset.rm}（刪除其工作目錄）？`) && await act(() => call('ui.environments.destroy', { id: b.dataset.rm }))) openPage('cloud-workers'); }; } },

  search: { title: '搜尋', group: '設定', async render() {
    const w = await call('ui.websearch.status');
    return `<h3>網頁搜尋</h3><p>目前使用：<strong>${v(w.route || '—')}</strong>${w.error ? ` · <span class="bad">${v(w.error)}</span>` : ''}</p>
      <p><select id="wsProv"><option value="">自動偵測</option>${w.providers.map((p) => `<option value="${v(p.id)}"${p.id === w.pinned ? ' selected' : ''}>${v(p.label)}${p.configured ? ' ✓' : ''}</option>`).join('')}</select></p>
      <table class="kv">${w.providers.map((p) => row([v(p.label), p.configured ? '已設定' : '<span class="dim">未設定</span>', p.auto_detect ? '<span class="dim">自動偵測</span>' : ''])).join('')}</table>
      <h3>搜尋對話</h3><p><input type="text" id="sessQ" placeholder="關鍵字"></p><div class="cp-detail"></div>
      <p><button class="btn ghost small" id="wsTest">測試一次搜尋</button> <span id="wsResult" class="dim"></span></p>${NOTE}`;
  }, after() {
    $('wsProv').onchange = async (e) => { if (await act(() => call('ui.websearch.set', { provider: e.target.value }), '已儲存')) openPage('search'); };
    $('wsTest').onclick = async () => {
      $('wsResult').textContent = '測試中…';
      const r = await act(() => call('ui.websearch.test', { query: 'ark web ui', run: true }));
      $('wsResult').textContent = r ? (r.ok ? `${r.provider}：${r.count} 筆、${r.took_ms} ms` : '失敗：' + r.error) : '';
    };
    $('sessQ').onchange = async (e) => {
      const hits = await call('ui.search', { query: e.target.value });
      q('.cp-detail').innerHTML = hits.length ? '<table class="kv">' + hits.map((h) => row([`<a href="#" data-open="${v(h.session)}">${v(h.title || h.session)}</a>`, v(h.snippet)])).join('') + '</table>' : '<p class="dim">沒有結果。</p>';
      for (const a of qa('[data-open]')) a.onclick = (ev) => { ev.preventDefault(); $('panelDialog').close(); openSession(a.dataset.open); };
    };
  } },

  systems: { title: '系統', group: '設定', async render() {
    const s = await call('ui.systems');
    return `<table class="kv">${row(['版本', v(s.version)])}${row(['PID', s.pid])}${row(['設定', v(s.paths.config)])}${row(['資料', `${v(s.paths.data)}（${bytes(s.data_bytes)}）`])}${row(['對話', s.sessions])}${row(['最近啟動', s.recent_starts.length])}</table>
      ${s.service.length ? `<h3>服務檢查</h3><ul>${s.service.map((i) => `<li><code>${v(i.code)}</code> ${v(i.message)}${i.fix ? ` <span class="dim">→ ${v(i.fix)}</span>` : ''}</li>`).join('')}</ul>` : ''}
      <h3>備份 <span class="dim">${v(s.backup_dir)}</span></h3><table class="kv">${s.backups.map((b) => row([v(b.path), bytes(b.bytes), `<span class="dim">${when(b.ts)}</span>`])).join('')}</table>
      <p><button class="btn small" id="sysBackup">立即備份</button></p>
      <h3>快照</h3><table class="kv">${s.snapshots.map((x) => row([`<code>${v(x.id)}</code>`, v(x.label), `<span class="dim">${when(x.ts)}</span>`])).join('')}</table>${NOTE}`;
  }, after() { $('sysBackup').onclick = async () => { if (await act(() => call('ui.systems.backup'), (r) => '已建立 ' + r.path)) setTimeout(() => openPage('systems'), 600); }; } },

  custodian: { title: '看守', group: '設定', async render() {
    const c = await call('ui.custodian');
    S.cpAlerts = c.alerts;
    if (!c.alerts.length) return '<p>一切正常，沒有需要處理的事項。</p>' + NOTE;
    return '<table class="kv">' + c.alerts.map((a, i) => {
      const id = String(a.id || '');
      const act2 = id.startsWith('cron:') ? ` <button class="btn ghost small" data-run-alert="${v(id.slice(5))}">立即執行</button>`
        : id.startsWith('secret:') ? ' <button class="btn ghost small" data-secrets="1">去「秘密」頁</button>' : '';
      return row([a.severity === 'error' ? '<span class="bad">錯誤</span>' : '警告', `<strong>${v(a.title)}</strong><div class="dim">${v(a.detail)}</div>`, `<button class="btn ghost small" data-ask="${i}">請 agent 解釋</button>${act2}`]);
    }).join('') + '</table>' + NOTE;
  }, after() {
    for (const b of qa('[data-run-alert]')) b.onclick = () => act(() => call('ui.cron.run', { id: b.dataset.runAlert }), '已在背景執行');
    for (const b of qa('[data-secrets]')) b.onclick = () => openPage('secrets');
    for (const b of qa('[data-ask]')) b.onclick = async () => {
      const a = S.cpAlerts[+b.dataset.ask];
      const r = await act(() => call('session.create', { title: '看守：' + a.title }));
      if (!r) return;
      await call('session.submit', { id: r.id, text: `ark 的看守頁回報了這個問題，請調查原因並提出修正（先不要改設定）：\n\n${a.title}\n${a.detail || ''}`, source: 'web' });
      $('panelDialog').close(); await loadSessions(); openSession(r.id);
    };
  } },

  labs: { title: '實驗功能', group: '設定', async render() {
    const l = await call('ui.labs');
    return '<table class="kv">' + l.map((x) => row([`<input type="checkbox" data-lab="${v(x.id)}"${x.enabled ? ' checked' : ''}>`, `<strong>${v(x.title)}</strong><div class="dim">${v(x.description)}</div>`, `<code>${v(x.key)}</code>`])).join('') + '</table>' + NOTE;
  }, after() { for (const c of qa('[data-lab]')) c.onchange = () => act(() => call('ui.labs.set', { id: c.dataset.lab, enabled: c.checked }), '已儲存；新對話生效'); } },

  about: { title: '關於', group: '設定', async render() {
    const a = await call('ui.about');
    return `<table class="kv">${row(['ark', v(a.version)])}${row(['平台', v(a.target)])}${row(['授權', v(a.license)])}${row(['Profile', v(a.profile)])}${row(['更新頻道', v(a.update_channel)])}</table>
      <h3>上游</h3><ul>${a.upstreams.map((u) => `<li>${v(u.name)}（${v(u.license)}） <a href="${v(u.url)}" target="_blank" rel="noopener">${v(u.url)}</a></li>`).join('')}</ul>`;
  } },

  profile: { title: '個人資料', group: '設定', async render() {
    const p = await call('ui.profile');
    return `<p>${p.avatar ? `<img class="cp-avatar" src="${v(p.avatar)}" alt="">` : ''}</p>
      <p><input type="text" id="pfName" placeholder="顯示名稱" value="${v(p.display_name || '')}"></p><p><input type="file" id="pfAvatar" accept="image/png,image/jpeg,image/webp"></p><p><button class="btn" id="pfSave">儲存</button></p>
      <table class="kv">${row(['Profile', v(p.profile)])}${row(['所有 profile', v((p.profiles || []).join(', '))])}${row(['模型', v(p.model)])}</table><p class="dim">切換 profile：<code>ark profile use &lt;name&gt;</code></p>${NOTE}`;
  }, after() {
    $('pfSave').onclick = async () => {
      const f = $('pfAvatar').files[0];
      await act(async () => {
        const avatar = f ? await shrink(f, 512) : undefined;
        return call('ui.profile.set', avatar ? { display_name: $('pfName').value, avatar } : { display_name: $('pfName').value });
      }, '已儲存');
      if ($('pfName').value.trim()) openPage('profile');
    };
  } },

  models: { title: '模型', group: '設定', async render() {
    const m = await call('ui.models.list');
    const refs = (m.models || []).map((x) => x.ref);
    const pick = (id) => `<select data-fill="${id}"><option value="">從清單選…</option>${refs.map((r) => `<option value="${v(r)}">${v(r)}</option>`).join('')}</select>`;
    let h = '<table class="kv"><tr><th>供應商</th><th>位址</th><th>憑證來源</th><th>金鑰</th><th>宣告的模型</th><th></th></tr>';
    for (const p of m.providers || []) {
      h += row([
        `<strong>${v(p.label)}</strong> <code>${v(p.id)}</code>`,
        p.base_url ? `<code>${v(p.base_url)}</code>` : '<span class="dim">—</span>',
        `<code>${v(p.key_source)}</code>`,
        p.keyless ? '<span class="dim">免金鑰</span>' : p.keyed ? '✓' : '<span class="bad">✗</span>',
        v((p.models || []).join(', ') || '（未宣告）'),
        p.keyless ? '' : `<input type="password" placeholder="新金鑰" autocomplete="new-password" size="12"> <button class="btn ghost small" data-key="${v(p.id)}">設定金鑰</button> <button class="btn ghost small" data-nokey="${v(p.id)}">移除金鑰</button>`,
      ]);
    }
    h += '</table>';
    h += `<h3>路由</h3>
      <p>預設 <input type="text" id="mdDefault" list="mdRefs" size="28" value="${v(m.default)}"> ${pick('mdDefault')}</p>
      <p>備援 <input type="text" id="mdFallback" list="mdRefs" size="48" value="${v((m.fallback || []).join(', '))}" placeholder="以逗號分隔，依序嘗試"> ${pick('mdFallback')}</p>
      <p>輔助 <input type="text" id="mdAux" list="mdRefs" size="28" value="${v(m.aux)}"> ${pick('mdAux')}</p>
      <p><button class="btn" id="mdSave">儲存路由</button> <button class="btn ghost small" id="mdCheck" data-read>檢查</button> <span class="dim">留空表示移除設定；變更對新對話生效。</span></p>
      <datalist id="mdRefs">${refs.map((r) => `<option value="${v(r)}"></option>`).join('')}</datalist>
      <div class="cp-detail" id="mdOut"></div>`;
    return h + NOTE + '<p class="dim">金鑰只寫入 vault 或設定檔，頁面永遠不會顯示已儲存的值。</p>';
  }, after() {
    // The picker only fills the text box (it is not a second source of truth): saving always
    // sends what the inputs show.
    for (const s of qa('[data-fill]')) s.onchange = () => {
      const box = $(s.dataset.fill);
      if (!s.value || !box) return;
      if (s.dataset.fill === 'mdFallback') {
        const cur = box.value.split(',').map((x) => x.trim()).filter(Boolean);
        if (!cur.includes(s.value)) cur.push(s.value);
        box.value = cur.join(', ');
      } else box.value = s.value;
      s.value = '';
    };
    $('mdSave').onclick = async () => {
      const fallback = $('mdFallback').value.split(',').map((x) => x.trim()).filter(Boolean);
      const r = await act(() => call('ui.models.set', { default: $('mdDefault').value.trim(), fallback, aux: $('mdAux').value.trim() }));
      if (r) { await openPage('models'); note('已儲存路由；新對話生效'); }
    };
    $('mdCheck').onclick = async () => {
      const r = await act(() => call('ui.models.check'));
      if (!r) return;
      $('mdOut').innerHTML = `<h3>檢查結果 <span class="dim">${r.ok ? '全部可用' : '有問題'}</span></h3>` +
        (r.checks.length ? '<table class="kv"><tr><th>模型</th><th>供應商</th><th>憑證</th><th>結果</th></tr>' + r.checks.map((c) => row([`<code>${v(c.ref)}</code>`, v(c.provider), `<code>${v(c.key_source)}</code>`, `${c.ok ? '✓' : '<span class="bad">✗</span>'} <span class="dim">${v(c.detail)}</span>`])).join('') + '</table>' : '<p class="dim">設定裡沒有可檢查的模型引用。</p>');
      note(r.ok ? `檢查通過（${r.checks.length} 項）` : '有模型無法使用', !r.ok);
    };
    for (const b of qa('[data-key]')) b.onclick = async () => {
      const inp = b.closest('tr').querySelector('input[type="password"]');
      const key = inp ? inp.value : '';
      if (!key.trim()) return note('請先輸入金鑰', true);
      const r = await act(() => call('ui.models.key', { provider: b.dataset.key, key }));
      if (inp) inp.value = '';
      if (r) { await openPage('models'); note(`已儲存金鑰（${r.source || 'vault'}${r.name ? '：' + r.name : ''}）`); }
    };
    for (const b of qa('[data-nokey]')) b.onclick = async () => {
      if (!confirm(`移除 ${b.dataset.nokey} 的金鑰？`)) return;
      const r = await act(() => call('ui.models.key', { provider: b.dataset.nokey, key: '' }));
      if (r) { await openPage('models'); note(r.removed ? '已移除金鑰' : '沒有可移除的金鑰', !r.removed); }
    };
  } },

  // C10: every agent in the tree — state, spend, files it holds, and the shared board.
  fleet: { title: '代理動態', group: '控制', async render() {
    const d = await call('ui.fleet');
    const agents = d.agents || [];
    const counts = d.counts || {};
    const board = (d.board || []).slice(-12).reverse();
    let h = `<p class="dim">執行中 ${v(counts.running || 0)} · 完成 ${v(counts.done || 0)} · 失敗 ${v(counts.failed || 0)} · 檔案租約 ${v(counts.leased_files || 0)}</p>`;
    h += '<h3>代理</h3>';
    h += agents.length ? '<table class="kv"><tr><th>代理</th><th>層</th><th>狀態</th><th>用量</th><th>花費</th><th>目標</th><th>擁有的檔案</th></tr>' + agents.map((a) => row([
      `<code>${v(a.id || a.session_id || '?')}</code>`,
      v(a.depth ?? 0),
      a.state === 'running' ? '<span class="ok">執行中</span>' : `<span class="dim">${v(a.state || '—')}</span>`,
      `${v((a.input_tokens || 0) + (a.output_tokens || 0))} tokens`,
      `$${(a.spend_usd || 0).toFixed ? a.spend_usd.toFixed(3) : v(a.spend_usd || 0)}`,
      v(a.goal || a.label || '—'),
      (a.owned_files || []).length ? (a.owned_files || []).map((f) => `<code>${v(f)}</code>`).join(' ') : '<span class="dim">—</span>',
    ])).join('') + '</table>' : '<p class="dim">目前沒有子代理。根代理用 <code>delegate_task</code> 或 <code>sessions_spawn</code> 派遣。</p>';
    h += '<h3>共用公告板</h3>';
    h += board.length ? '<table class="kv"><tr><th>時間</th><th>種類</th><th>代理</th><th>內容</th></tr>' + board.map((e) => row([
      `<span class="dim">${when(e.ts_ms)}</span>`, v(e.kind || ''), `<code>${v((e.session || '').slice(0, 10))}</code>`, v(e.text || ''),
    ])).join('') + '</table>' : '<p class="dim">公告板是空的。</p>';
    const paused = ((d.limits || {}).paused) || [];
    if (paused.length) h += `<h3>暫停中</h3><p class="dim">${paused.map((p) => `${v(p.session)}：${v(p.reason)}（<code>ark fleet resume ${v(p.session)}</code>）`).join('<br>')}</p>`;
    return h;
  } },

  // ent-062: the central console — every node (shared registry + registered remote nodes), HA
  // lease, worker pool, sessions across nodes and the signed managed policy. Reads are metadata
  // (operator / auditor may open the page); every button is an admin-only `cluster.*` method.
  cluster: { title: '叢集', group: '控制', async render() {
    const d = await call('cluster.status');
    const ha = d.ha || {};
    const p = d.policy || {};
    const w = d.workers;
    let h = `<p>${ha.enabled ? `本節點 <strong>${v(ha.node)}</strong> · ${ha.role === 'leader' ? '<span class="ok">leader</span>' : 'standby'} · epoch ${v(ha.epoch)} · 租約 ${v(ha.lease_secs)} 秒${ha.leader ? ` · 目前 leader：<code>${v(ha.leader.node)}</code>（epoch ${v(ha.leader.epoch)}）` : ''}` : `本節點 <strong>${v(d.self)}</strong> · 未啟用高可用（<code>[ha] enabled</code>）`}
      ${ha.enabled && ha.role === 'leader' ? ' <button class="btn ghost small" id="clStep">交出租約</button>' : ''}</p>`;
    if (ha.error) h += `<p class="bad">${v(ha.error)}</p>`;
    h += '<h3>節點</h3><table class="kv"><tr><th></th><th>節點</th><th>角色</th><th>epoch</th><th>執行中</th><th>版本</th><th>來源</th><th>位址</th><th>政策</th><th></th></tr>' + (d.nodes || []).map((n) => row([
      n.alive ? '<span class="ok">●</span>' : '<span class="dim">○</span>',
      `<strong>${v(n.node)}</strong>${n.self ? ' <span class="dim">（本機）</span>' : ''}`,
      v(n.role || '—'), v(n.epoch ?? '—'), v((n.running || []).length), v(n.version || '—'), v(n.source || ''),
      `<code>${v(n.advertise || n.url || '')}</code>${n.error ? ` <span class="bad">${v(n.error)}</span>` : ''}`,
      v(n.policy_version ?? '—'),
      n.source === 'remote' ? `<button class="btn ghost small" data-rmnode="${v(n.name || n.node)}">移除</button>` : '',
    ])).join('') + '</table>';
    h += `<details><summary>登記遠端節點</summary><p class="dim">不共用資料目錄的節點：填它的 app 位址與存放唯讀 token 的金庫秘密名稱（<code>ark secrets set NAME …</code>）。推送政策需要另一個存 admin token 的秘密。</p>
      <input id="clName" placeholder="名稱"> <input id="clUrl" placeholder="https://node:8640"> <input id="clTok" placeholder="唯讀 token 秘密名稱"> <input id="clAdm" placeholder="admin token 秘密名稱（選填）"> <button class="btn small" id="clAdd">登記</button></details>`;
    if (w) h += `<h3>Worker 池</h3><p class="dim">${v(w.count)} 個 · 派送 ${v(w.dispatch)} · 完成 ${v(w.completed)} · 重派 ${v(w.redispatched)} · 佇列 ${v((w.queue || []).length)}</p>` + '<table class="kv"><tr><th>#</th><th>pid</th><th>狀態</th><th>重啟</th><th>上次結束</th></tr>' + (w.workers || []).map((x) => row([v(x.index), v(x.pid ?? '—'), x.session ? `執行 <code>${v(x.session)}</code>` : x.alive ? '閒置' : '<span class="bad">停止</span>', v(x.restarts), v(x.last_exit || '')])).join('') + '</table>';
    const agents = d.agents || [];
    h += '<h3>代理</h3><table class="kv"><tr><th>節點</th><th>具名代理</th><th>執行中</th><th>子代理</th></tr>' + agents.map((a) => row([v(a.node), v((a.agents || []).join(', ') || '（預設）'), v(a.running), v(a.fleet ? `${a.fleet.running || 0} 執行 / ${a.fleet.done || 0} 完成` : '—')])).join('') + '</table>';
    const sess = (d.sessions || []).filter((x) => x.running).concat((d.sessions || []).filter((x) => !x.running).slice(0, 20));
    h += '<h3>Session</h3><table class="kv"><tr><th></th><th>id</th><th>節點</th><th>標題</th><th>訊息</th><th>更新</th></tr>' + sess.map((x) => row([x.running ? '<span class="ok">▶</span>' : '', `<code>${v(x.id)}</code>`, v(x.node || '—'), v(x.title || ''), v(x.messages ?? ''), `<span class="dim">${when(x.updated_ms)}</span>`])).join('') + '</table>';
    h += `<h3>受管政策</h3><p>釘選公鑰：${p.pinned_key_id ? `<code>${v(p.pinned_key_id)}</code>` : '<span class="dim">未設定（/etc/ark/managed.toml 的 <code>[managed] cluster_key</code>）</span>'} · 生效 v${v(p.active_version ?? '—')} · 已安裝 v${v(p.installed ? p.installed.version : '—')} · 已發佈 v${v(p.published ? p.published.version : '—')}${p.restart_required ? ' · <span class="bad">重新啟動 arkd 才會生效</span>' : ''}</p>
      ${p.error ? `<p class="bad">${v(p.error)}</p>` : ''}
      <details><summary>發佈已簽章的政策</summary><p class="dim">在管理員電腦上 <code>ark cluster policy sign policy.toml --version N</code> 產生 bundle，貼上 JSON。節點只接受用釘選公鑰簽、版本更新的 bundle。</p>
      <textarea id="clBundle" rows="6" style="width:100%"></textarea><br><button class="btn small" id="clPub">發佈</button> <button class="btn ghost small" id="clPush">推送到遠端節點</button> <button class="btn ghost small" id="clPull">立即拉取</button></details>${NOTE}`;
    return h;
  }, after() {
    if ($('clStep')) $('clStep').onclick = async () => { if (confirm('把 leader 租約交給 standby？本節點進行中的 session 會中斷並由新 leader 續跑。') && await act(() => call('ha.stepdown'), '已交出租約')) openPage('cluster'); };
    if ($('clAdd')) $('clAdd').onclick = async () => { if (await act(() => call('cluster.node.add', { name: $('clName').value.trim(), url: $('clUrl').value.trim(), token_secret: $('clTok').value.trim(), admin_secret: $('clAdm').value.trim() }), '已登記')) openPage('cluster'); };
    for (const b of qa('[data-rmnode]')) b.onclick = async () => { if (confirm(`移除節點 ${b.dataset.rmnode}？`) && await act(() => call('cluster.node.remove', { name: b.dataset.rmnode }))) openPage('cluster'); };
    if ($('clPub')) $('clPub').onclick = async () => { if (await act(() => call('cluster.policy.publish', { bundle: $('clBundle').value.trim() }), (r) => `已發佈 v${r.published}`)) openPage('cluster'); };
    if ($('clPush')) $('clPush').onclick = () => act(() => call('cluster.policy.push'), (r) => (r.nodes || []).map((n) => `${n.node}：${n.ok ? '已套用' : n.error}`).join('；') || '沒有登記的遠端節點');
    if ($('clPull')) $('clPull').onclick = () => act(() => call('cluster.policy.pull'), (r) => r.installed ? `已安裝 v${r.installed}，重新啟動後生效` : '已是最新');
  } },

  devices: { title: '裝置', group: '控制', async render() {
    const d = await call('ui.devices');
    const nodes = d.nodes || [];
    const paired = d.paired || [];
    const pending = d.pending || [];
    const isPaired = (id) => paired.some((x) => x.id === id);
    let h = '<h3>連線中的節點</h3>';
    h += nodes.length ? '<table class="kv"><tr><th>節點</th><th>平台</th><th>指令</th><th>連線自</th><th></th></tr>' + nodes.map((n) => row([
      `<strong>${v(n.name || n.id)}</strong> <code>${v(n.id)}</code>`,
      v(n.platform || '—'),
      `${(n.commands || []).length} 個`,
      `<span class="dim">${when(n.connected_since)}</span>`,
      `<button class="btn ghost small" data-ren="${v(n.id)}" data-name="${v(n.name || '')}"${isPaired(n.id) ? '' : ' disabled'}>重新命名</button> <button class="btn ghost small" data-rm="${v(n.id)}" data-name="${v(n.name || '')}">移除</button>`,
    ])).join('') + '</table>' : '<p class="dim">沒有節點連線。在另一台機器執行 <code>ark node connect</code>。</p>';
    h += '<h3>已配對</h3>';
    h += paired.length ? '<table class="kv"><tr><th>裝置</th><th>平台</th><th>狀態</th><th>核准時間</th><th>佇列</th><th></th></tr>' + paired.map((p) => row([
      `<strong>${v(p.name || p.id)}</strong> <code>${v(p.id)}</code>`,
      v(p.platform || '—'),
      p.connected ? '執行中' : '<span class="dim">離線</span>',
      `<span class="dim">${when(p.approved_at)}</span>`,
      `${p.queued || 0}`,
      `<button class="btn ghost small" data-ren="${v(p.id)}" data-name="${v(p.name || '')}">重新命名</button> <button class="btn ghost small" data-rm="${v(p.id)}" data-name="${v(p.name || '')}">移除</button>`,
    ])).join('') + '</table>' : '<p class="dim">還沒有配對的裝置。</p>';
    h += '<h3>等待配對</h3>';
    h += pending.length ? '<table class="kv"><tr><th>配對碼</th><th>裝置</th><th>平台</th><th></th></tr>' + pending.map((p) => row([
      `<code>${v(p.code)}</code>`, v(p.name || p.id || ''), v(p.platform || '—'),
      `<button class="btn small" data-approve="${v(p.code)}">核准</button> <button class="btn ghost small" data-reject="${v(p.code)}">拒絕</button>`,
    ])).join('') + '</table>' : '<p class="dim">沒有等待中的配對請求。</p>';
    return h + NOTE + '<p class="dim">配對碼在 1 小時內有效；也可以在主機上執行 <code>ark nodes approve &lt;code&gt;</code>。</p>';
  }, after() {
    for (const b of qa('[data-ren]')) b.onclick = async () => {
      const name = (prompt('新的裝置名稱', b.dataset.name || '') || '').trim();
      if (!name) return;
      if (await act(() => call('ui.devices.rename', { id: b.dataset.ren, name }), '已重新命名')) openPage('devices');
    };
    for (const b of qa('[data-rm]')) b.onclick = async () => {
      if (!confirm(`移除裝置「${b.dataset.name || b.dataset.rm}」？之後需要重新配對。`)) return;
      if (await act(() => call('ui.devices.remove', { id: b.dataset.rm }), '已移除')) openPage('devices');
    };
    for (const b of qa('[data-approve]')) b.onclick = async () => {
      const r = await act(() => call('ui.devices.approve', { code: b.dataset.approve }));
      if (r) { await openPage('devices'); note('已核准 ' + (r.approved || '')); }
    };
    for (const b of qa('[data-reject]')) b.onclick = async () => {
      const r = await act(() => call('ui.devices.reject', { code: b.dataset.reject }));
      if (r) { await openPage('devices'); note(r.rejected ? '已拒絕配對請求' : '這個配對碼已經失效', !r.rejected); }
    };
  } },

  plugins: { title: '外掛', group: '代理', async render() {
    const p = await call('ui.plugins');
    const list = p.plugins || [];
    const mcp = p.mcp || [];
    let h = '<h3>外掛</h3>';
    h += list.length ? '<table class="kv"><tr><th>啟用</th><th>外掛</th><th>版本</th><th>來源</th><th>工具</th><th>路由</th><th>UI</th><th>說明</th></tr>' + list.map((x) => row([
      `<input type="checkbox" data-plugin="${v(x.name)}"${x.enabled ? ' checked' : ''}>`,
      `<strong>${v(x.name)}</strong>`,
      v(x.version || '—'),
      `<span class="dim">${v(x.source || '')}</span>`,
      `${x.tools || 0}`,
      `${(x.routes || []).length}`,
      `${(x.ui || []).length}`,
      v(x.description || ''),
    ])).join('') + '</table>' : '<p class="dim">沒有安裝外掛。</p>';
    h += '<h3>MCP 伺服器</h3>';
    h += mcp.length ? '<table class="kv"><tr><th>啟用</th><th>伺服器</th><th>狀態</th><th>工具</th></tr>' + mcp.map((x) => row([
      `<input type="checkbox" data-mcp="${v(x.name)}"${x.enabled === false ? '' : ' checked'}>`,
      `<strong>${v(x.name)}</strong>`,
      x.running ? '執行中' : '<span class="dim">停止</span>',
      `${x.tools || 0}`,
    ])).join('') + '</table>' : '<p class="dim">沒有 MCP 伺服器（<code>[mcp.*]</code>）。</p>';
    return h + NOTE + '<p class="dim">勾選只會寫入設定：外掛與 MCP 伺服器在重新啟動 daemon 之後（以及新開的對話）才會套用變更。</p>';
  }, after() {
    for (const c of qa('[data-plugin]')) c.onchange = () => act(() => call('ui.plugins.set', { name: c.dataset.plugin, enabled: c.checked }), (r) => r.message || (c.checked ? '已啟用；重新啟動 daemon 後生效' : '已停用；重新啟動 daemon 後生效'));
    for (const c of qa('[data-mcp]')) c.onchange = () => act(() => call('ui.mcp.set', { name: c.dataset.mcp, enabled: c.checked }), (r) => r.message || (c.checked ? '已啟用；重新啟動 daemon 後生效' : '已停用；重新啟動 daemon 後生效'));
  } },

  logs: { title: '日誌', group: '控制', async render() {
    // A new render always stops the previous auto-refresh interval, whichever page follows.
    clearInterval(CP.logTimer); CP.logTimer = null;
    const files = ((await call('ui.logs.files')).files) || [];
    const st = CP.log || {};
    const file = files.some((f) => f.name === st.file) ? st.file : '';
    const level = st.level || '';
    const grep = st.grep || '';
    const limit = [200, 500, 2000].includes(+st.limit) ? +st.limit : 200;
    CP.log = { file, level, grep, limit };
    const r = await call('ui.logs', cpLogParams());
    CP.logTail = r.tail || [];
    CP.logFile = r.file || '';
    const levels = [['', '所有等級'], ['error', '錯誤'], ['warn', '警告以上'], ['info', '資訊以上'], ['debug', '含 debug']];
    return `<p><select id="logFile" data-read><option value=""${file ? '' : ' selected'}>即時日誌</option>${files.map((f) => `<option value="${v(f.name)}"${f.name === file ? ' selected' : ''}>${v(f.name)} · ${bytes(f.bytes)}</option>`).join('')}</select>
      <select id="logLevel" data-read>${levels.map(([k, t]) => `<option value="${k}"${k === level ? ' selected' : ''}>${v(t)}</option>`).join('')}</select>
      <select id="logLimit" data-read>${[200, 500, 2000].map((n) => `<option value="${n}"${n === limit ? ' selected' : ''}>${n} 行</option>`).join('')}</select>
      <input type="text" id="logGrep" data-read placeholder="grep…（Enter）" size="14" value="${v(grep)}">
      <button class="btn ghost small" id="logRefresh" data-read>重新整理</button> <button class="btn ghost small" id="logDownload" data-read>下載</button> <span class="dim" id="logMeta"></span></p>
      <pre class="cp-log" id="logTail">${cpLogHtml(CP.logTail)}</pre>${NOTE}
      <p class="dim">${v(CP.logFile)} · 每 3 秒自動更新，離開這一頁就停止。</p>`;
  }, after() {
    const paint = (tail, path) => {
      CP.logTail = tail || [];
      CP.logFile = path || CP.logFile;
      const out = q('#logTail');
      if (out) { out.innerHTML = cpLogHtml(CP.logTail); out.scrollTop = out.scrollHeight; }
      const meta = q('#logMeta');
      if (meta) meta.textContent = `${CP.logTail.length} 行`;
    };
    const poll = async () => {
      const out = q('#logTail');
      if (CP.page !== 'logs' || !out || !$('panelDialog').open) { clearInterval(CP.logTimer); CP.logTimer = null; return; }
      try { const r = await call('ui.logs', cpLogParams()); paint(r.tail, r.file); }
      catch (e) { note(e.message, true); }
    };
    paint(CP.logTail, CP.logFile);
    clearInterval(CP.logTimer); CP.logTimer = setInterval(poll, 3000);
    const reload = () => openPage('logs');
    q('#logFile').onchange = (e) => { CP.log = { ...cpLogParams(), file: e.target.value }; reload(); };
    q('#logLevel').onchange = (e) => { CP.log = { ...cpLogParams(), level: e.target.value }; reload(); };
    q('#logLimit').onchange = (e) => { CP.log = { ...cpLogParams(), limit: +e.target.value }; reload(); };
    q('#logGrep').onkeydown = (e) => { if (e.key === 'Enter') { CP.log = { ...cpLogParams(), grep: e.target.value.trim() }; reload(); } };
    q('#logRefresh').onclick = poll;
    q('#logDownload').onclick = () => download(`ark-${String(CP.logFile || 'log').split('/').pop()}`, CP.logTail.map((r) => `${when(r.ts)} ${r.level || 'info'} ${r.target || ''} ${r.text}`).join('\n') + '\n', 'text/plain');
  } },
};

async function openPage(id) {
  const p = PAGES[id];
  if (!p) return showControl();
  CP.page = id;
  await showPanel(p.title, () => p.render(), () => p.after && p.after());
}

function showControl() {
  const groups = {};
  for (const [id, p] of Object.entries(PAGES)) (groups[p.group] = groups[p.group] || []).push([id, p]);
  // EXTRA_PAGES: this file's own pages, appended to their group after the `ui.pages` order so
  // they show up even when the Rust list does not name them yet (no duplicate entries).
  for (const id of EXTRA_PAGES) {
    const p = PAGES[id];
    if (!p) continue;
    const g = (groups[p.group] = groups[p.group] || []);
    if (!g.some(([x]) => x === id)) g.push([id, p]);
  }
  return showPanel('控制台', async () => Object.entries(groups).map(([g, ps]) => `<h3>${v(g)}</h3><p class="cp-nav">${ps.map(([id, p]) => `<button class="btn ghost small" data-page="${v(id)}">${v(p.title)}</button>`).join(' ')}</p>`).join(''),
    () => { for (const b of qa('[data-page]')) b.onclick = () => openPage(b.dataset.page); });
}

if ($('showControl')) $('showControl').onclick = showControl;
// Deep links: #page=<id> (e.g. from the Telegram Mini App or a bookmark), once connected.
(function deepLink() {
  const id = new URLSearchParams(location.hash.slice(1)).get('page');
  if (!id || !PAGES[id]) return;
  const wait = setInterval(() => { if (S.arp && S.sessions) { clearInterval(wait); openPage(id); } }, 200);
  setTimeout(() => clearInterval(wait), 20000);
})();
