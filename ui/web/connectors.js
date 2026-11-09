// seagent web UI: Settings → Connections. Everything that used to need a terminal command —
// MCP servers (`seagent mcp add|rm|test|login|pins`), skills (`seagent skills install|…`),
// plugins (`seagent plugins …`), chat channels (`seagent channel add|test`), webhooks
// (`seagent webhook …`), ACP agents and A2A peers — set up from forms.
// Backed by `ui.connectors.*` (crates/seagent/src/ops/connectors.rs, ops/channels_setup.rs)
// plus the existing ui.skills.* / ui.plugins* / pairing.* / ui.devices methods. Writes apply to the running
// daemon where they can (`applied`), otherwise the page offers the one-click restart.
// Uses app.js globals (S, $, esc, LANG, showView) and pages.js ones (PAGES, EXTRA_PAGES,
// openPage, note, act, NOTE). Wrapped in a function so its names never collide with theirs.
'use strict';

(function connectorsPage() {
  if (typeof PAGES !== 'object') return;
  const rpc = (m, p) => S.arp.call(m, p || {});
  const L = (zh, en) => (LANG === 'en' ? en : zh);
  const E = (x) => esc(x === undefined || x === null ? '' : String(x));
  const B = () => $('panelBody');
  const one = (sel) => B().querySelector(sel);
  const all = (sel) => B().querySelectorAll(sel);
  // Page state survives re-renders (every action re-opens the page).
  const CN = { tab: 'mcp', form: null, view: null, results: {}, importRows: null, importSrc: null, presetQ: '', skillQ: '', skillHits: null, pluginHits: null, market: null, chanKind: '' };
  const TABS = [
    ['mcp', 'MCP 伺服器', 'MCP servers'], ['skills', '技能', 'Skills'], ['plugins', '外掛', 'Plugins'], ['channels', '聊天頻道', 'Chat channels'],
    ['webhooks', 'Webhook', 'Webhooks'], ['hooks', 'Hooks／Gmail', 'Hooks / Gmail'], ['agents', '代理（ACP／A2A）', 'Agents (ACP / A2A)'], ['devices', '裝置', 'Devices'],
  ];
  const reopen = () => openPage('connections');
  const light = (st) => `<span class="light ${st === 'running' || st === true ? 'ok' : st === 'error' ? 'crit' : st === 'restart' || st === 'lazy' ? 'warn' : ''}" title="${E(st)}"></span>`;
  // What happened to the last write: applied to the running daemon now, or waiting for a restart.
  let LAST = null;
  const RESTART = (r) => {
    r = r && typeof r === 'object' ? r : LAST;
    if (r && r.applied === true) return L('已儲存並套用到執行中的 daemon。', 'Saved and applied to the running daemon.');
    const why = r && (r.why || (r.live && r.live.why));
    if (r && r.restart) return L('已儲存；這項變更要重新啟動 daemon 才生效', 'Saved; this change applies after a daemon restart') + (why ? ` (${why})` : '') + L('。按上方的「重新啟動 daemon」。', '. Use “Restart daemon” above.');
    if (r && r.applied === false && why) return L('已儲存，但還沒啟動：', 'Saved, but not running yet: ') + why;
    return L('已儲存。', 'Saved.');
  };
  // Stdio consent: the exact line `seagent mcp add` prints, confirmed before anything runs.
  const consentOk = (r, verb) => confirm(L('這會讓 SE Agent 在這台電腦執行以下程式：', 'This lets SE Agent run this program on this machine:') + '\n\n' + r.consent + (r.warning ? '\n\n⚠ ' + r.warning : '') + '\n\n' + verb);
  const btn = (label, data, cls) => `<button class="btn ${cls || 'ghost'} small" ${data}>${E(label)}</button>`;
  const field = (label, input, hint) => `<label class="cn-field"><span>${E(label)}</span>${input}${hint ? `<small class="dim">${E(hint)}</small>` : ''}</label>`;
  const text = (id, val, ph, type) => `<input type="${type || 'text'}" id="${id}" value="${E(val)}" placeholder="${E(ph || '')}" autocomplete="off" spellcheck="false">`;
  const val = (id) => { const el = one('#' + id); return el ? el.value.trim() : ''; };
  const checked = (id) => { const el = one('#' + id); return !!(el && el.checked); };
  // A result box: {ok, error, …} from a test call, shown next to what was tested.
  const resultBox = (r) => {
    if (!r) return '';
    if (r.ok === false || r.error) return `<div class="cn-res bad"><strong>${E(L('失敗', 'Failed'))}${r.stage ? ' · ' + E(r.stage) : ''}</strong><pre class="cp-pre">${E(r.error || JSON.stringify(r, null, 2))}</pre>${r.hint ? `<p class="dim">${E(r.hint)}</p>` : ''}</div>`;
    return `<div class="cn-res ok">${r.text ? `<pre class="cp-pre">${E(r.text)}</pre>` : `<strong>${E(L('成功', 'OK'))}</strong>${r.ms !== undefined ? ` <span class="dim">${r.ms} ms</span>` : ''}`}</div>`;
  };
  async function run(fn, okMsg) {
    try {
      const r = await fn();
      if (r && r.ok === false && r.error) { note(r.error, true); return r; }
      if (r && (r.applied !== undefined || r.restart !== undefined)) LAST = r;
      if (okMsg) note(typeof okMsg === 'function' ? okMsg(r) : okMsg);
      return r;
    } catch (e) { note(e.message, true); return null; }
  }
  const fileB64 = (file) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split('base64,')[1] || ''); r.onerror = () => rej(new Error(file.name + ': ' + L('讀取失敗', 'could not be read'))); r.readAsDataURL(file); });
  const fileText = (file) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.onerror = () => rej(new Error(file.name)); r.readAsText(file); });

  // Key/value rows (env, headers, extra channel keys): [{key, value, secret, keep, ref, set}].
  function kvRows(id, rows, secretByDefault) {
    const r = (rows && rows.length ? rows : [{ key: '', value: '', secret: !!secretByDefault }]).map((x, i) => `<div class="cn-kv" data-kv="${id}" data-i="${i}">
      <input type="text" data-k value="${E(x.key)}" placeholder="${E(L('名稱', 'NAME'))}" spellcheck="false">
      <input type="${x.secret ? 'password' : 'text'}" data-v value="${E(x.keep ? '' : x.value)}" placeholder="${E(x.keep || x.ref ? L('（不變）', '(unchanged)') : L('值', 'value'))}" spellcheck="false" autocomplete="new-password"${x.keep ? ' data-keep="1"' : ''}>
      <label class="cn-inline"><input type="checkbox" data-s${x.secret ? ' checked' : ''}> ${E(L('秘密', 'secret'))}</label>
      ${x.ref ? `<span class="dim" title="vault">${x.set ? '🔒' : '⚠'} ${E(x.ref)}</span>` : ''}
      <button type="button" class="btn ghost small icon" data-kvdel>✕</button></div>`).join('');
    return `<div class="cn-kvs" id="${id}">${r}</div><button type="button" class="btn ghost small" data-kvadd="${id}">＋ ${E(L('新增一列', 'Add row'))}</button>`;
  }
  function readKv(id) {
    // A masked literal the form never saw (`data-keep`) stays as stored unless retyped; a
    // `{{secret:NAME}}` reference is sent back as is.
    return [...all(`[data-kv="${id}"]`)].map((row) => {
      const v = row.querySelector('[data-v]');
      return { key: row.querySelector('[data-k]').value.trim(), value: v.value, secret: row.querySelector('[data-s]').checked, keep: v.dataset.keep === '1' && v.value === '' };
    }).filter((x) => x.key);
  }
  function bindKv() {
    for (const b of all('[data-kvadd]')) b.onclick = () => {
      const box = one('#' + b.dataset.kvadd);
      const tmp = document.createElement('div');
      tmp.innerHTML = kvRows(b.dataset.kvadd, [{ key: '', value: '' }]);
      box.appendChild(tmp.querySelector('.cn-kv'));
      bindKv();
    };
    for (const b of all('[data-kvdel]')) b.onclick = () => b.closest('.cn-kv').remove();
    for (const c of all('.cn-kv [data-s]')) c.onchange = () => { c.closest('.cn-kv').querySelector('[data-v]').type = c.checked ? 'password' : 'text'; };
  }

  // ───────────────────────── MCP ─────────────────────────
  async function mcpTab() {
    const [l, ov] = await Promise.all([rpc('ui.connectors.mcp.list'), rpc('ui.connectors.overview').catch(() => null)]);
    CN.overview = ov;
    let h = `<p class="cn-bar">${btn(L('＋ 新增伺服器', '+ Add server'), 'data-mcpnew', '')} ${btn(L('從預設清單', 'From presets'), 'data-view="presets"')} ${btn(L('匯入 mcp.json（Claude／Cursor／VS Code）', 'Import mcp.json (Claude / Cursor / VS Code)'), 'data-view="import"')}</p>`;
    if (CN.form && CN.form.section === 'mcp') h += mcpForm(CN.form);
    if (CN.view === 'presets') h += await presetsView();
    if (CN.view === 'import') h += await importView();
    const rows = l.servers || [];
    h += rows.length ? `<table class="kv cn-table"><tr><th></th><th>${E(L('啟用', 'On'))}</th><th>${E(L('名稱', 'Name'))}</th><th>${E(L('傳輸', 'Transport'))}</th><th>${E(L('目標', 'Target'))}</th><th>${E(L('工具', 'Tools'))}</th><th></th></tr>` + rows.map((s) => {
      const st = s.error ? 'error' : !s.enabled ? 'disabled' : s.running ? 'running' : s.live ? 'lazy' : 'restart';
      const r = CN.results['mcp:' + s.name];
      return `<tr><td>${light(st)}</td><td><input type="checkbox" data-mcpon="${E(s.name)}"${s.enabled ? ' checked' : ''}${s.editable ? '' : ' disabled'}></td><td><strong>${E(s.name)}</strong>${s.auth === 'oauth' ? ` <span class="chip">${s.logged_in ? L('已登入', 'signed in') : L('需登入', 'sign-in needed')}</span>` : ''}${s.error ? `<div class="bad small">${E(s.error)}</div>` : ''}</td>
        <td>${E(s.transport)}</td><td class="mono cn-target" title="${E(s.target)}">${E(s.target)}</td><td>${s.live ? s.tools : '—'}</td>
        <td class="cn-actions">${btn(L('測試並列出工具', 'Test & list tools'), `data-mcptest="${E(s.name)}"`)} ${s.editable ? btn(L('編輯', 'Edit'), `data-mcpedit="${E(s.name)}"`) : ''} ${btn(L('工具定義', 'Tool pins'), `data-mcppindiff="${E(s.name)}"`)} ${s.auth === 'oauth' ? btn(s.logged_in ? L('重新登入', 'Sign in again') : L('登入', 'Sign in'), `data-mcplogin="${E(s.name)}"`) + (s.logged_in ? ' ' + btn(L('登出', 'Sign out'), `data-mcplogout="${E(s.name)}"`) : '') : ''} ${s.editable ? btn(L('移除', 'Remove'), `data-mcprm="${E(s.name)}"`) : ''}</td></tr>` + (r ? `<tr><td></td><td colspan="6">${mcpResult(s.name, r)}</td></tr>` : '');
    }).join('') + '</table>' : `<p class="dim">${E(L('還沒有 MCP 伺服器。新增一個、從預設清單挑，或匯入其他工具的 mcp.json。', 'No MCP servers yet. Add one, pick a preset, or import another tool\'s mcp.json.'))}</p>`;
    for (const w of l.warnings || []) h += `<p class="bad small">${E(w)}</p>`;
    return h;
  }
  function mcpResult(name, r) {
    if (r.pins) return `<div class="cn-res"><strong>${E(L('工具定義（rug-pull 防護）', 'Tool pins (rug-pull guard)'))}</strong> <span class="dim">${r.pins.pinned} ${E(L('個已釘選', 'pinned'))}</span>${r.pins.changes.length ? `<table class="kv">${r.pins.changes.map((c) => `<tr><td class="mono">${E(c.tool)}</td><td><span class="chip">${E(c.state)}</span></td><td><pre class="cp-pre">${E(JSON.stringify(c.now, null, 2))}</pre></td></tr>`).join('')}</table>` : `<p class="dim">${E(L('每個工具都和核准時一樣。', 'Every tool matches what was approved.'))}</p>`}<p>${btn(L('重新核准目前的定義', 'Re-approve current definitions'), `data-mcppins="${E(name)}"`)} ${btn(L('忘記釘選（下次載入重新釘選）', 'Forget pins (re-pinned on next load)'), `data-mcpforget="${E(name)}"`)}</p></div>`;
    if (r.login) return `<div class="cn-res"><p>${r.login.url ? `${E(L('在瀏覽器完成授權：', 'Finish signing in in the browser:'))} <a href="${E(r.login.url)}" target="_blank" rel="noopener">${E(L('開啟授權頁', 'Open the sign-in page'))}</a> <span class="dim">${E(L('（瀏覽器模式要在執行 SE Agent 的這台電腦上開啟）', '(browser mode: open it on the machine running SE Agent)'))}</span>` : ''}${r.login.user_code ? `${E(L('到', 'Go to'))} <a href="${E(r.login.verification_uri)}" target="_blank" rel="noopener">${E(r.login.verification_uri)}</a> ${E(L('輸入代碼', 'and enter'))} <strong class="mono">${E(r.login.user_code)}</strong>` : ''}</p><p class="dim">${E(L('狀態', 'State'))}: ${E(r.login.state)}${r.login.error ? ' · ' + E(r.login.error) : ''}</p>${btn(L('檢查狀態', 'Check status'), `data-mcploginpoll="${E(name)}"`)} ${btn(L('改用裝置代碼', 'Use a device code'), `data-mcplogindev="${E(name)}"`)}</div>`;
    if (r.ok === false) return resultBox(r);
    const tools = r.tools || [];
    return `<div class="cn-res ok"><strong>${E(L('連線成功', 'Connected'))}</strong> <span class="dim">${r.ms} ms · ${tools.length} ${E(L('個工具', 'tools'))}${r.resolved ? ' · ' + E(r.resolved) : ''}</span>
      ${(r.withheld || []).length ? `<p class="bad">${E(L('工具定義變了，暫停使用：', 'Tools changed since approval and are withheld:'))} ${E(r.withheld.map((w) => w.tool + ' (' + w.why + ')').join(', '))} ${btn(L('重新核准', 'Re-approve'), `data-mcppins="${E(name)}"`)}</p>` : ''}
      <table class="kv">${tools.map((t) => `<tr><td><input type="checkbox" data-mcptool="${E(name)}" data-tool="${E(t.name)}"${t.exposed ? ' checked' : ''}></td><td class="mono">${E(t.name)}</td><td>${t.read_only ? `<span class="chip">${E(L('唯讀', 'read-only'))}</span>` : ''}</td><td class="dim">${E(t.description)}</td></tr>`).join('')}</table>
      <p class="dim">${E(L('取消勾選即停用該工具（寫入 exclude_tools）。', 'Untick a tool to turn it off (written to exclude_tools).'))}</p></div>`;
  }
  function mcpForm(f) {
    const s = f.spec || { transport: 'stdio', env: [], headers: [], enabled: true, auth: 'none', trust: 'full' };
    const tr = s.transport || 'stdio';
    const args = (s.args || []).map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(' ');
    const isPlugin = f.section === 'plugins';
    return `<section class="cn-form" id="cnForm"><h3>${E(f.original ? L('編輯', 'Edit') + ' ' + f.original : isPlugin ? L('新增程序外掛', 'Add a process plugin') : L('新增 MCP 伺服器', 'Add an MCP server'))}</h3>
      ${field(L('名稱', 'Name'), text('fName', f.name || '', 'github'), L('英數字、- 或 _；工具名稱會是 mcp__名稱__工具', 'letters, digits, - or _; tools become mcp__name__tool'))}
      ${isPlugin ? '' : field(L('傳輸方式', 'Transport'), `<select id="fTransport"><option value="stdio"${tr === 'stdio' ? ' selected' : ''}>stdio（${E(L('本機指令', 'local command'))}）</option><option value="http"${tr === 'http' ? ' selected' : ''}>Streamable HTTP</option><option value="sse"${tr === 'sse' ? ' selected' : ''}>HTTP + SSE (legacy)</option></select>`)}
      <div data-tr="stdio"${tr === 'stdio' || isPlugin ? '' : ' hidden'}>
        ${field(L('指令', 'Command'), text('fCommand', s.command || '', 'npx'), L('Windows 會依 PATHEXT 找 npx.cmd 等；也可填完整路徑', 'resolved like the server will be started (PATHEXT on Windows); or give a full path'))}
        ${field(L('參數', 'Arguments'), text('fArgs', args, '-y @modelcontextprotocol/server-filesystem /path'), L('以空白分隔；含空白的參數用引號', 'space separated; quote an argument with spaces'))}
        ${field(L('工作目錄（選填）', 'Working directory (optional)'), text('fCwd', s.cwd || '', ''))}
        <div class="cn-field"><span>${E(L('環境變數', 'Environment'))}</span>${kvRows('fEnv', s.env, false)}<small class="dim">${E(L('勾選「秘密」的值存進金庫，設定檔只放 {{secret:…}} 參照。', 'Values marked secret go to the vault; the config only gets a {{secret:…}} reference.'))}</small></div>
      </div>
      <div data-tr="http"${tr !== 'stdio' && !isPlugin ? '' : ' hidden'}>
        ${field('URL', text('fUrl', s.url || '', 'https://mcp.example.com/mcp'))}
        <div class="cn-field"><span>${E(L('HTTP 標頭', 'HTTP headers'))}</span>${kvRows('fHeaders', s.headers, true)}<small class="dim">${E(L('例如 Authorization = Bearer …（勾選秘密）', 'e.g. Authorization = Bearer … (mark it secret)'))}</small></div>
        ${field(L('驗證', 'Authentication'), `<select id="fAuth"><option value="none">${E(L('無／標頭', 'none / headers'))}</option><option value="oauth"${s.auth === 'oauth' ? ' selected' : ''}>OAuth 2.1</option></select>`)}
      </div>
      <details><summary>${E(L('進階', 'Advanced'))}</summary>
        ${field(L('逾時（秒）', 'Timeout (s)'), text('fTimeout', s.timeout_secs || '', '30', 'number'))}
        ${isPlugin ? '' : field(L('信任', 'Trust'), `<select id="fTrust"><option value="full">${E(L('完全信任', 'full'))}</option><option value="untrusted"${s.trust === 'untrusted' ? ' selected' : ''}>${E(L('不信任：非唯讀工具要核准', 'untrusted: non-read-only tools need approval'))}</option></select>`)}
        <label class="cn-inline"><input type="checkbox" id="fEnabled"${s.enabled === false ? '' : ' checked'}> ${E(L('啟用', 'Enabled'))}</label>
        ${(s.advanced || []).length ? `<p class="dim">${E(L('其他設定會保留：', 'Other keys are kept:'))} ${E(s.advanced.join(', '))}</p>` : ''}
      </details>
      <p>${btn(L('測試連線', 'Test connection'), 'data-ftest')} ${btn(L('儲存', 'Save'), 'data-fsave', '')} ${btn(L('取消', 'Cancel'), 'data-fcancel')}</p>
      <div id="fResult">${CN.formResult ? (isPlugin ? resultBox(CN.formResult) + (CN.formResult.declares ? `<pre class="cp-pre">${E(JSON.stringify(CN.formResult.declares, null, 2))}</pre>` : '') : mcpResult(f.name || 'draft', CN.formResult)) : ''}</div></section>`;
  }
  function readSpec(section) {
    const tr = section === 'plugins' ? 'stdio' : val('fTransport') || 'stdio';
    const spec = { transport: tr, enabled: checked('fEnabled'), trust: val('fTrust') || 'full' };
    const t = +val('fTimeout');
    if (t > 0) spec.timeout_secs = t;
    if (tr === 'stdio') Object.assign(spec, { command: val('fCommand'), args: val('fArgs'), cwd: val('fCwd'), env: readKv('fEnv') });
    else Object.assign(spec, { url: val('fUrl'), headers: readKv('fHeaders'), auth: val('fAuth') });
    return spec;
  }
  function bindForm() {
    const f = CN.form;
    if (!f || !one('#cnForm')) return;
    bindKv();
    const tsel = one('#fTransport');
    if (tsel) tsel.onchange = () => { for (const d of all('[data-tr]')) d.hidden = (d.dataset.tr === 'stdio') !== (tsel.value === 'stdio'); };
    one('[data-fcancel]').onclick = () => { CN.form = null; CN.formResult = null; reopen(); };
    one('[data-ftest]').onclick = async () => {
      const name = val('fName') || 'draft';
      const m = f.section === 'plugins' ? 'ui.connectors.plugins.process.test' : 'ui.connectors.mcp.test';
      const test = (q) => (f.section === 'plugins' ? rpc('ui.connectors.plugins.process.test', q) : rpc('ui.connectors.mcp.test', q));
      const q = { name, spec: readSpec(f.section) };
      // A stdio draft starts a program: the consent line first, the test only after "OK".
      if (q.spec.transport === 'stdio') {
        const c = await run(() => test(q));
        if (c && c.consent_required) {
          if (!consentOk(c, L('現在啟動它來測試？', 'Start it now to test?'))) { note(L('沒有執行任何程式', 'Nothing was run')); return; }
          f.consented = c.consent;
          q.consent = true;
        } else if (c) { CN.formResult = c; one('#fResult').innerHTML = mcpResult(name, c); return; }
      }
      one('#fResult').innerHTML = `<span class="star spin"></span> ${E(L('連線中…', 'Connecting…'))}`;
      const r = await run(() => test(q));
      CN.formResult = r || { ok: false, error: m + ' failed' };
      one('#fResult').innerHTML = f.section === 'plugins' ? resultBox(CN.formResult) + (CN.formResult.declares ? `<pre class="cp-pre">${E(JSON.stringify(CN.formResult.declares, null, 2))}</pre>` : '') : mcpResult(name, CN.formResult);
    };
    one('[data-fsave]').onclick = async () => {
      const p = { name: val('fName'), spec: readSpec(f.section) };
      if (f.original) p.original = f.original;
      const save = (q) => (f.section === 'plugins' ? rpc('ui.connectors.plugins.process.save', q) : rpc('ui.connectors.mcp.save', q));
      let r = await run(() => save(p));
      if (r && r.consent_required) {
        // Already confirmed for the test with the very same line: no second prompt.
        if (f.consented !== r.consent && !consentOk(r, L('確定要儲存並啟動？', 'Save and start it?'))) { note(L('未儲存', 'Not saved')); return; }
        r = await run(() => save({ ...p, consent: true }));
      }
      if (r && r.ok) { CN.form = null; CN.formResult = null; await reopen(); note(RESTART(r)); }
    };
  }
  async function presetsView() {
    const list = await rpc('ui.connectors.mcp.presets', { q: CN.presetQ });
    return `<section class="cn-form"><h3>${E(L('預設的 MCP 伺服器', 'MCP server presets'))}</h3><p>${text('presetQ', CN.presetQ, L('搜尋：github、notion、calendar…', 'Search: github, notion, calendar…'))} ${btn(L('關閉', 'Close'), 'data-view=""')}</p>
      <table class="kv">${list.slice(0, 60).map((p) => `<tr><td><strong>${E(p.name)}</strong><div class="dim small">${E(p.description)}</div></td><td><span class="chip">${E(p.auth)}</span></td><td>${(p.env || []).map((e) => `<input type="${e.secret ? 'password' : 'text'}" data-penv="${E(p.name)}" data-key="${E(e.name)}" placeholder="${E(e.name + (e.prompt ? ' — ' + e.prompt : ''))}" autocomplete="new-password">`).join('')}</td><td>${btn(L('加入', 'Add'), `data-padd="${E(p.name)}"`, '')}</td></tr>`).join('')}</table>
      ${list.length > 60 ? `<p class="dim">${list.length - 60} ${E(L('項未顯示，請縮小搜尋', 'more; narrow the search'))}</p>` : ''}</section>`;
  }
  async function importView() {
    const c = await rpc('ui.connectors.mcp.import');
    const rows = CN.importRows;
    return `<section class="cn-form"><h3>${E(L('匯入 mcp.json', 'Import an mcp.json'))}</h3>
      <p class="dim">${E(L('支援 Claude Desktop／Claude Code、Cursor、VS Code、Windsurf 的格式（mcpServers 或 servers）。看起來像金鑰的環境變數會移進金庫。', 'Claude Desktop / Claude Code, Cursor, VS Code and Windsurf formats (mcpServers or servers). Credential-looking env values move to the vault.'))}</p>
      ${(c.candidates || []).length ? `<p>${E(L('在這台電腦找到：', 'Found on this machine:'))}</p><table class="kv">${c.candidates.map((x) => `<tr><td>${E(x.label)}</td><td class="mono small">${E(x.path)}</td><td>${x.servers} ${E(L('個伺服器', 'servers'))}</td><td>${btn(L('預覽', 'Preview'), `data-icand="${E(x.path)}"`)}</td></tr>`).join('')}</table>` : `<p class="dim">${E(L('沒有在常見位置找到其他工具的 mcp.json；可以選檔案或貼上內容。', 'No other client config found in the usual places; pick a file or paste it.'))}</p>`}
      <p><input type="file" id="importFile" accept=".json,application/json"> ${btn(L('關閉', 'Close'), 'data-view=""')}</p>
      <p><textarea id="importText" class="cp-area mono" rows="5" placeholder='{"mcpServers": {"name": {"command": "npx", "args": ["…"]}}}'></textarea></p><p>${btn(L('預覽貼上的內容', 'Preview pasted text'), 'data-ipaste')}</p>
      ${rows ? `<table class="kv"><tr><th></th><th>${E(L('名稱', 'Name'))}</th><th>${E(L('傳輸', 'Transport'))}</th><th>${E(L('目標', 'Target'))}</th><th></th></tr>${rows.map((r) => `<tr><td><input type="checkbox" data-iname="${E(r.name)}"${r.error || (r.exists && !r.imported) ? '' : ' checked'}${r.error ? ' disabled' : ''}></td><td><strong>${E(r.name)}</strong>${r.exists ? ` <span class="chip">${E(L('已存在', 'exists'))}</span>` : ''}</td><td>${E(r.transport || '')}</td><td class="mono small">${E(r.target || '')}</td><td>${r.error ? `<span class="bad">${E(r.error)}</span>` : r.imported ? `<span class="chip">${E(L('已匯入', 'imported'))}</span>` : r.skipped ? E(r.skipped) : (r.secrets || []).length ? `<span class="dim">${E(L('秘密 → 金庫：', 'secrets → vault:'))} ${E(r.secrets.join(', '))}</span>` : ''}${r.placeholders ? `<div class="dim">${E(L('含 ${…} 占位符，匯入後請檢查', 'contains ${…} placeholders: check after importing'))}</div>` : ''}</td></tr>`).join('')}</table>
      <p><label class="cn-inline"><input type="checkbox" id="importOverwrite"> ${E(L('覆蓋同名的伺服器', 'Replace servers with the same name'))}</label> ${btn(L('匯入勾選的', 'Import selected'), 'data-iapply', '')}</p>` : ''}</section>`;
  }
  function bindMcp() {
    bindForm();
    one('[data-mcpnew]').onclick = () => { CN.form = { section: 'mcp' }; CN.formResult = null; reopen(); };
    for (const b of all('[data-view]')) b.onclick = () => { CN.view = b.dataset.view || null; CN.importRows = null; reopen(); };
    for (const c of all('[data-mcpon]')) c.onchange = () => run(() => rpc('ui.connectors.mcp.enable', { name: c.dataset.mcpon, enabled: c.checked }), RESTART);
    for (const b of all('[data-mcptest]')) b.onclick = async () => {
      b.disabled = true; b.textContent = L('連線中…', 'Connecting…');
      CN.results['mcp:' + b.dataset.mcptest] = (await run(() => rpc('ui.connectors.mcp.test', { name: b.dataset.mcptest }))) || { ok: false, error: L('呼叫失敗', 'call failed') };
      reopen();
    };
    for (const b of all('[data-mcpedit]')) b.onclick = async () => { const s = await run(() => rpc('ui.connectors.mcp.get', { name: b.dataset.mcpedit })); if (s) { CN.form = { section: 'mcp', name: s.name, original: s.name, spec: s }; CN.formResult = null; reopen(); } };
    for (const b of all('[data-mcprm]')) b.onclick = async () => { if (confirm(L(`移除 MCP 伺服器 ${b.dataset.mcprm}？（設定檔會先備份）`, `Remove MCP server ${b.dataset.mcprm}? (the config is backed up first)`)) && await run(() => rpc('ui.connectors.mcp.remove', { name: b.dataset.mcprm }))) { await reopen(); note(RESTART()); } };
    const login = async (name, mode) => { const r = await run(() => rpc('ui.connectors.mcp.login', { name, mode })); if (r) { CN.results['mcp:' + name] = { login: r }; if (r.url) window.open(r.url, '_blank', 'noopener'); reopen(); } };
    for (const b of all('[data-mcplogin]')) b.onclick = () => login(b.dataset.mcplogin, 'browser');
    for (const b of all('[data-mcplogindev]')) b.onclick = () => login(b.dataset.mcplogindev, 'device');
    for (const b of all('[data-mcploginpoll]')) b.onclick = async () => { const r = await run(() => rpc('ui.connectors.mcp.login.status', { name: b.dataset.mcploginpoll })); if (r) { CN.results['mcp:' + b.dataset.mcploginpoll] = r.state === 'done' ? null : { login: r }; await reopen(); if (r.state === 'done') note(L('已登入', 'Signed in')); } };
    for (const b of all('[data-mcppindiff]')) b.onclick = async () => { const r = await run(() => rpc('ui.connectors.mcp.pins.diff', { name: b.dataset.mcppindiff })); if (r) { CN.results['mcp:' + b.dataset.mcppindiff] = { pins: r }; reopen(); } };
    for (const b of all('[data-mcpforget]')) b.onclick = async () => { if (confirm(L('忘記這個伺服器的工具釘選？下次載入時會把當時的定義當成已核准。', 'Forget this server\'s tool pins? Whatever it serves on the next load becomes the approved version.')) && await run(() => rpc('ui.connectors.mcp.pins.forget', { name: b.dataset.mcpforget }), RESTART)) { CN.results['mcp:' + b.dataset.mcpforget] = null; reopen(); } };
    for (const b of all('[data-mcplogout]')) b.onclick = async () => { if (await run(() => rpc('ui.connectors.mcp.logout', { name: b.dataset.mcplogout }), L('已登出', 'Signed out'))) reopen(); };
    for (const b of all('[data-mcppins]')) b.onclick = async () => { if (await run(() => rpc('ui.connectors.mcp.pins.accept', { name: b.dataset.mcppins }), L('已重新核准', 'Re-approved'))) { CN.results['mcp:' + b.dataset.mcppins] = null; reopen(); } };
    for (const c of all('[data-mcptool]')) c.onchange = () => run(() => rpc('ui.connectors.mcp.tool', { name: c.dataset.mcptool, tool: c.dataset.tool, enabled: c.checked }), (r) => (r.enabled ? L('已啟用 ', 'Turned on ') : L('已停用 ', 'Turned off ')) + c.dataset.tool + ' — ' + RESTART());
    const pq = one('#presetQ');
    if (pq) pq.onkeydown = (e) => { if (e.key === 'Enter') { CN.presetQ = pq.value.trim(); reopen(); } };
    for (const b of all('[data-padd]')) b.onclick = async () => {
      const env = {};
      for (const i of all(`[data-penv="${b.dataset.padd}"]`)) env[i.dataset.key] = i.value;
      const r = await run(() => rpc('ui.connectors.mcp.preset.add', { preset: b.dataset.padd, env }));
      if (r && r.ok) { CN.view = null; await reopen(); note(RESTART() + (r.oauth ? ' ' + L('這個伺服器用 OAuth：按「登入」。', 'This server uses OAuth: press Sign in.') : '')); }
    };
    const preview = async (p) => { const r = await run(() => rpc('ui.connectors.mcp.import', p)); if (r) { CN.importRows = r.servers; CN.importSrc = p; reopen(); } };
    for (const b of all('[data-icand]')) b.onclick = () => preview({ candidate: b.dataset.icand });
    if (one('[data-ipaste]')) one('[data-ipaste]').onclick = () => preview({ text: one('#importText').value });
    if (one('#importFile')) one('#importFile').onchange = async (e) => { const f = e.target.files[0]; if (f) preview({ text: await fileText(f) }); };
    if (one('[data-iapply]')) one('[data-iapply]').onclick = async () => {
      const names = [...all('[data-iname]')].filter((c) => c.checked).map((c) => c.dataset.iname);
      if (!names.length) { note(L('沒有勾選任何伺服器', 'Nothing selected'), true); return; }
      const r = await run(() => rpc('ui.connectors.mcp.import', { ...CN.importSrc, apply: true, names, overwrite: checked('importOverwrite') }));
      if (r) { CN.importRows = r.servers; await reopen(); const n = r.servers.filter((x) => x.imported).length; note(`${n} ${L('個已匯入。', 'imported.')} ${RESTART()}`, r.servers.some((x) => x.error && names.includes(x.name))); }
    };
  }

  // ───────────────────────── skills ─────────────────────────
  async function skillsTab() {
    const [list, bundled] = await Promise.all([rpc('ui.skills.list'), rpc('ui.connectors.skills.bundled').catch(() => ({ skills: [] }))]);
    const notInstalled = (bundled.skills || []).filter((s) => !s.installed);
    const SOURCES = ['all', 'official', 'github', 'clawhub', 'skills-sh', 'lobehub', 'browse-sh', 'well-known'];
    let h = `<section class="cn-form"><h3>${E(L('安裝技能', 'Install a skill'))}</h3>
      ${field(L('識別碼、GitHub owner/repo/路徑或網址', 'Identifier, GitHub owner/repo/path, or URL'), text('skId', '', '@owner/skill · owner/repo/skills/name · https://…/SKILL.md'))}
      <div class="cn-row">${field(L('名稱（選填）', 'Name (optional)'), text('skName', '', ''))}${field(L('分類（選填）', 'Category (optional)'), text('skCat', '', ''))}</div>
      <p><label class="cn-inline"><input type="checkbox" id="skForce"> ${E(L('覆蓋已安裝的版本', 'Replace an installed copy'))}</label> ${btn(L('安裝', 'Install'), 'data-skinstall', '')}</p>
      <p>${E(L('或從這台裝置選：', 'Or pick from this device:'))} <label class="btn ghost small">${E(L('資料夾…', 'Folder…'))}<input type="file" id="skDir" webkitdirectory multiple hidden></label> <label class="btn ghost small">${E(L('SKILL.md 或 .zip…', 'SKILL.md or .zip…'))}<input type="file" id="skFile" accept=".md,.zip" hidden></label>
      <span class="dim">${E(L('一樣經過隔離、簽章與安全掃描。', 'Goes through the same quarantine, signature and safety scan.'))}</span></p>
      <h4>${E(L('搜尋登錄', 'Search registries'))}</h4><p>${text('skQ', CN.skillQ, L('例如 pdf、weather', 'e.g. pdf, weather'))} <select id="skSrc">${SOURCES.map((s) => `<option${s === (CN.skillSrc || 'all') ? ' selected' : ''}>${s}</option>`).join('')}</select> ${btn(L('搜尋', 'Search'), 'data-sksearch')}</p>
      ${CN.skillHits ? (CN.skillHits.length ? `<table class="kv">${CN.skillHits.map((m) => `<tr><td class="mono">${E(m.identifier)}</td><td><span class="chip">${E(m.source)}</span> <span class="chip">${E(m.trust_level || '')}</span></td><td class="dim">${E(m.description)}</td><td>${btn(L('安裝', 'Install'), `data-skid="${E(m.identifier)}"`, '')}</td></tr>`).join('')}</table>` : `<p class="dim">${E(L('沒有結果', 'No results'))}</p>`) : ''}
      <p>${btn(L('檢查更新', 'Check for updates'), 'data-skcheck')} ${btn(L('全部更新', 'Update all'), 'data-skupdate')} ${btn(L('來源（taps）', 'Sources (taps)'), 'data-sktaps')}</p>
      ${CN.skillTaps !== undefined ? `<pre class="cp-pre">${E(CN.skillTaps)}</pre><p>${text('skTap', '', 'owner/repo')} ${btn(L('加入來源', 'Add source'), 'data-sktap="add"')} ${btn(L('移除來源', 'Remove source'), 'data-sktap="remove"')}</p>` : ''}
      <div id="skResult">${resultBox(CN.skillResult)}</div></section>`;
    if (notInstalled.length) h += `<h3>${E(L('內建但尚未安裝', 'Bundled, not installed'))}</h3><table class="kv">${notInstalled.map((s) => `<tr><td><strong>${E(s.name)}</strong></td><td class="dim">${E(s.category || '')}</td><td>${E(s.description)}</td><td>${btn(L('安裝', 'Install'), `data-skid="${E(s.name)}"`, '')}</td></tr>`).join('')}</table>`;
    h += `<h3>${E(L('已安裝', 'Installed'))} <span class="dim">${list.length}</span></h3><input type="text" class="cp-filter" id="skFilter" placeholder="${E(L('篩選…', 'Filter…'))}">
      <table class="kv cp-list"><tr><th>${E(L('啟用', 'On'))}</th><th>${E(L('名稱', 'Name'))}</th><th>${E(L('來源', 'Source'))}</th><th>${E(L('說明', 'Description'))}</th><th></th></tr>${list.map((s) => `<tr data-row="${E(s.name)}"><td><input type="checkbox" data-sktoggle="${E(s.name)}"${s.enabled ? ' checked' : ''}></td><td><strong>${E(s.name)}</strong></td><td class="dim">${E(s.source)}</td><td>${E(s.description)}</td><td class="cn-actions">${btn(L('檢視', 'View'), `data-skview="${E(s.name)}"`)} ${btn(L('設定需求', 'Setup'), `data-sksetup="${E(s.name)}"`)} ${s.source === 'bundled' ? '' : btn(L('移除', 'Remove'), `data-skrm="${E(s.name)}" data-src="${E(s.source)}"`)}</td></tr>`).join('')}</table>
      ${CN.skillSetup ? skillSetupBox(CN.skillSetup) : ''}
      <div class="cp-detail" id="skDetail">${CN.skillView ? `<h3>${E(CN.skillView.name)} <span class="dim">${E(CN.skillView.source)}</span></h3><pre class="cp-pre">${E(CN.skillView.body)}</pre>${CN.skillView.files.length ? `<p class="dim">${E(CN.skillView.files.join(', '))}</p>` : ''}` : ''}</div>`;
    return h;
  }
  function skillSetupBox(s) {
    return `<section class="cn-form" id="skSetup"><h3>${E(L('設定', 'Setup'))} ${E(s.name)} <span class="chip">${E(s.ready)}</span></h3>${s.env.length ? s.env.map((e) => field(`${e.name}${e.optional ? L('（選填）', ' (optional)') : ''}`, `<input type="password" data-skenv="${E(e.name)}" placeholder="${E(e.set ? L('已在金庫（留空＝不變）', 'in the vault (leave empty to keep)') : e.prompt)}" autocomplete="new-password">`, [e.help, e.required_for].filter(Boolean).join(' · '))).join('') + `<p class="dim">${E(L('值存進金庫，技能執行時才以環境變數提供。', 'Values go to the vault and reach the skill as environment variables when it runs.'))}</p><p>${btn(L('儲存到金庫', 'Save to the vault'), 'data-sksetupsave', '')} ${btn(L('關閉', 'Close'), 'data-sksetupclose')}</p>` : `<p class="dim">${E(L('這個技能不需要設定環境變數。', 'This skill needs no environment setup.'))}</p><p>${btn(L('關閉', 'Close'), 'data-sksetupclose')}</p>`}${s.remaining && s.remaining.length ? `<p class="bad">${E(L('仍缺：', 'Still missing: '))}${E(s.remaining.join(', '))}</p>` : ''}</section>`;
  }
  function bindSkills() {
    for (const b of all('[data-sksetup]')) b.onclick = async () => { const r = await run(() => rpc('ui.connectors.skills.setup', { name: b.dataset.sksetup })); if (r) { CN.skillSetup = r; reopen(); } };
    if (one('[data-sksetupclose]')) one('[data-sksetupclose]').onclick = () => { CN.skillSetup = null; reopen(); };
    if (one('[data-sksetupsave]')) one('[data-sksetupsave]').onclick = async () => {
      const values = {};
      for (const i of all('[data-skenv]')) if (i.value) values[i.dataset.skenv] = i.value;
      const r = await run(() => rpc('ui.connectors.skills.setup.save', { name: CN.skillSetup.name, values }));
      if (r) { CN.skillSetup = r; await reopen(); note(r.remaining.length ? L('仍缺：', 'Still missing: ') + r.remaining.join(', ') : L('已存進金庫；技能可以用了。', 'Stored in the vault; the skill is ready.'), r.remaining.length > 0); }
    };
    // A failed call already put its error in the note; re-rendering would wipe it.
    const done = async (r) => { if (!r) { const x = one('#skResult'); if (x) x.innerHTML = ''; return; } CN.skillResult = r; await reopen(); if (r && r.ok) note(L('完成；新的對話會用到它。', 'Done; new conversations will use it.')); };
    const install = async (id) => { if (!id) { note(L('請填識別碼', 'Give an identifier'), true); return; } one('#skResult').innerHTML = '<span class="star spin"></span>'; const r = await run(() => rpc('ui.connectors.skills.install', { id, name: val('skName'), category: val('skCat'), force: checked('skForce') })); await done(r || null); };
    one('[data-skinstall]').onclick = () => install(val('skId'));
    for (const b of all('[data-skid]')) b.onclick = () => install(b.dataset.skid);
    one('[data-sksearch]').onclick = async () => { CN.skillQ = val('skQ'); CN.skillSrc = val('skSrc'); one('#skResult').innerHTML = '<span class="star spin"></span>'; const r = await run(() => rpc('ui.connectors.skills.search', { q: CN.skillQ, source: CN.skillSrc })); CN.skillHits = r ? r.results : []; reopen(); };
    one('#skQ').onkeydown = (e) => { if (e.key === 'Enter') one('[data-sksearch]').click(); };
    one('[data-skcheck]').onclick = async () => done(await run(() => rpc('ui.connectors.skills.check')));
    one('[data-skupdate]').onclick = async () => done(await run(() => rpc('ui.connectors.skills.update', {})));
    one('[data-sktaps]').onclick = async () => { const r = await run(() => rpc('ui.connectors.skills.taps')); CN.skillTaps = r ? r.text : ''; reopen(); };
    for (const b of all('[data-sktap]')) b.onclick = async () => { const r = await run(() => rpc('ui.connectors.skills.tap', { action: b.dataset.sktap, repo: val('skTap') })); if (r) { CN.skillTaps = (await rpc('ui.connectors.skills.taps')).text; done(r); } };
    const upload = async (files) => {
      if (!files.length) return;
      one('#skResult').innerHTML = '<span class="star spin"></span>';
      try {
        const list = [];
        for (const f of files) list.push({ path: f.webkitRelativePath || f.name, data: await fileB64(f) });
        const label = (files[0].webkitRelativePath || files[0].name).split('/')[0];
        await done(await run(() => rpc('ui.connectors.skills.upload', { files: list, label, name: val('skName'), category: val('skCat'), force: checked('skForce') })));
      } catch (e) { note(e.message, true); }
    };
    one('#skDir').onchange = (e) => upload([...e.target.files]);
    one('#skFile').onchange = (e) => upload([...e.target.files]);
    one('#skFilter').oninput = (e) => { const f = e.target.value.toLowerCase(); for (const r of all('tr[data-row]')) r.hidden = !r.textContent.toLowerCase().includes(f); };
    for (const c of all('[data-sktoggle]')) c.onchange = () => run(() => rpc('ui.connectors.skills.enable', { name: c.dataset.sktoggle, enabled: c.checked }), RESTART);
    for (const b of all('[data-skview]')) b.onclick = async () => { const s = await run(() => rpc('ui.skills.get', { name: b.dataset.skview })); if (s) { CN.skillView = s; reopen(); } };
    for (const b of all('[data-skrm]')) b.onclick = async () => {
      const n = b.dataset.skrm;
      if (!confirm(L(`移除技能 ${n}？`, `Remove skill ${n}?`))) return;
      // Hub installs uninstall; a skill written by hand (or in the workshop) is archived instead.
      let r = await run(() => rpc('ui.connectors.skills.uninstall', { name: n }));
      if (!r && b.dataset.src === 'user') r = await run(() => rpc('ui.skills.workshop.delete', { name: n }), L('已封存（可在技能工坊還原）', 'Archived (restore it in the skill workshop)'));
      if (r) done(r.text ? r : { ok: true, text: L('已移除', 'Removed') });
    };
  }

  // ───────────────────────── plugins ─────────────────────────
  async function pluginsTab() {
    const p = await rpc('ui.plugins');
    const list = p.plugins || [];
    let h = `<section class="cn-form"><h3>${E(L('安裝外掛', 'Install a plugin'))}</h3>
      ${field(L('名稱、路徑、git+網址、owner/repo、clawhub:套件 或 外掛@市集', 'Name, path, git+URL, owner/repo, clawhub:package or plugin@marketplace'), text('plSpec', '', 'clawhub:pdf-desk'))}
      <p><label class="cn-inline"><input type="checkbox" id="plForce"> ${E(L('強制（覆蓋／同意新增的權限）', 'Force (replace / accept widened capabilities)'))}</label> ${btn(L('安裝', 'Install'), 'data-plinstall', '')} ${btn(L('全部更新', 'Update all'), 'data-plupdate')}</p>
      <p>${text('plQ', '', L('搜尋目錄與 ClawHub', 'Search the catalog and ClawHub'))} ${btn(L('搜尋', 'Search'), 'data-plsearch')} ${text('plMkt', '', L('市集：路徑、網址或 owner/repo', 'Marketplace: path, URL or owner/repo'))} ${btn(L('瀏覽市集', 'Browse marketplace'), 'data-plmkt')}</p>
      ${CN.pluginHits ? `<table class="kv">${CN.pluginHits.map((x) => `<tr><td class="mono">${E(x.name)}</td><td><span class="chip">${E(x.source || x.family || '')}</span></td><td class="dim">${E(x.description)}</td><td>${btn(L('安裝', 'Install'), `data-plid="${E(x.install || x.name)}"`, '')}</td></tr>`).join('') || `<tr><td class="dim">${E(L('沒有結果', 'No results'))}</td></tr>`}</table>` : ''}
      <div id="plResult">${resultBox(CN.pluginResult)}</div></section>
      <p class="cn-bar">${btn(L('＋ 新增程序外掛（[plugins.*]）', '+ Add a process plugin ([plugins.*])'), 'data-plnew', '')} ${btn(L('外掛的 MCP 目錄', 'Plugin MCP catalog'), 'data-plmcps')}</p>`;
    if (CN.pluginMcps) h += `<section class="cn-form"><h3>${E(L('可選的 MCP 伺服器（plugins mcps）', 'Optional MCP servers (plugins mcps)'))}</h3><p>${text('plMcpQ', CN.pluginMcpQ || '', L('篩選', 'Filter'))} ${btn(L('關閉', 'Close'), 'data-plmcpsclose')}</p><table class="kv">${CN.pluginMcps.map((m) => `<tr><td><strong>${E(m.name)}</strong></td><td><span class="chip">${E(m.transport)}</span>${m.auth ? ` <span class="chip">${E(m.auth)}</span>` : ''}</td><td class="dim">${E(m.description)}</td><td class="mono small">${E(m.url || [m.command].concat(m.args || []).join(' '))}</td><td>${btn(L('加入', 'Add'), `data-plmcpadd="${E(m.name)}"`, '')}</td></tr>`).join('') || `<tr><td class="dim">${E(L('沒有符合的項目', 'Nothing matches'))}</td></tr>`}</table></section>`;
    if (CN.form && CN.form.section === 'plugins') h += mcpForm(CN.form);
    h += list.length ? `<table class="kv cn-table"><tr><th>${E(L('啟用', 'On'))}</th><th>${E(L('外掛', 'Plugin'))}</th><th>${E(L('版本', 'Version'))}</th><th>${E(L('來源', 'Source'))}</th><th>${E(L('工具', 'Tools'))}</th><th>${E(L('說明', 'Description'))}</th><th></th></tr>${list.map((x) => `<tr><td><input type="checkbox" data-plon="${E(x.name)}"${x.enabled ? ' checked' : ''}></td><td><strong>${E(x.name)}</strong></td><td>${E(x.version || '—')}</td><td class="dim">${E(x.source)}</td><td>${x.tools || 0}</td><td class="dim">${E(x.description)}</td>
      <td class="cn-actions">${btn(L('詳情', 'Details'), `data-plinspect="${E(x.name)}"`)} ${x.source === 'process' ? btn(L('測試', 'Test'), `data-pltest="${E(x.name)}"`) + ' ' + btn(L('編輯', 'Edit'), `data-pledit="${E(x.name)}"`) + ' ' + btn(L('移除', 'Remove'), `data-plprm="${E(x.name)}"`) : x.source === 'builtin' ? '' : btn(L('更新', 'Update'), `data-plup="${E(x.name)}"`) + ' ' + btn(L('解除安裝', 'Uninstall'), `data-plrm="${E(x.name)}"`)}</td></tr>${CN.results['pl:' + x.name] ? `<tr><td></td><td colspan="6">${resultBox(CN.results['pl:' + x.name])}${CN.results['pl:' + x.name].declares || CN.results['pl:' + x.name].detail ? `<pre class="cp-pre">${E(JSON.stringify(CN.results['pl:' + x.name].declares || CN.results['pl:' + x.name].detail, null, 2))}</pre>` : ''}</td></tr>` : ''}`).join('')}</table>` : `<p class="dim">${E(L('沒有外掛。', 'No plugins.'))}</p>`;
    return h;
  }
  function bindPlugins() {
    bindForm();
    const done = async (r) => { if (!r) { const x = one('#plResult'); if (x) x.innerHTML = ''; return; } CN.pluginResult = r; await reopen(); if (r && r.ok) note(RESTART()); };
    const install = async (spec) => { if (!spec) { note(L('請填外掛', 'Give a plugin'), true); return; } one('#plResult').innerHTML = '<span class="star spin"></span>'; done(await run(() => rpc('ui.connectors.plugins.install', { spec, force: checked('plForce') }))); };
    one('[data-plinstall]').onclick = () => install(val('plSpec'));
    one('[data-plupdate]').onclick = async () => done(await run(() => rpc('ui.connectors.plugins.update', { force: checked('plForce') })));
    one('[data-plsearch]').onclick = async () => { const r = await run(() => rpc('ui.connectors.plugins.search', { q: val('plQ') })); CN.pluginHits = r || []; reopen(); };
    one('[data-plmkt]').onclick = async () => { const r = await run(() => rpc('ui.connectors.plugins.marketplace', { source: val('plMkt') })); if (r) { CN.pluginHits = (r.plugins || []).map((x) => ({ ...x, source: r.name, install: `${x.name}@${r.name}` })); reopen(); } };
    for (const b of all('[data-plid]')) b.onclick = () => install(b.dataset.plid);
    for (const c of all('[data-plon]')) c.onchange = () => run(() => rpc('ui.plugins.set', { name: c.dataset.plon, enabled: c.checked }), () => RESTART({ restart: true, why: L('外掛在 daemon 啟動時載入', 'plugins load when the daemon starts') }));
    for (const b of all('[data-plinspect]')) b.onclick = async () => { const r = await run(() => rpc('ui.connectors.plugins.inspect', { name: b.dataset.plinspect })); if (r) { CN.results['pl:' + b.dataset.plinspect] = { ok: true, detail: r }; reopen(); } };
    for (const b of all('[data-plup]')) b.onclick = async () => done(await run(() => rpc('ui.connectors.plugins.update', { name: b.dataset.plup })));
    for (const b of all('[data-plrm]')) b.onclick = async () => { if (confirm(L(`解除安裝 ${b.dataset.plrm}？`, `Uninstall ${b.dataset.plrm}?`))) done(await run(() => rpc('ui.connectors.plugins.uninstall', { name: b.dataset.plrm }))); };
    one('[data-plmcps]').onclick = async () => { CN.pluginMcps = (await run(() => rpc('ui.connectors.plugins.mcps', { q: CN.pluginMcpQ || '' }))) || []; reopen(); };
    if (one('[data-plmcpsclose]')) one('[data-plmcpsclose]').onclick = () => { CN.pluginMcps = null; reopen(); };
    if (one('#plMcpQ')) one('#plMcpQ').onkeydown = async (e) => { if (e.key === 'Enter') { CN.pluginMcpQ = e.target.value.trim(); CN.pluginMcps = (await run(() => rpc('ui.connectors.plugins.mcps', { q: CN.pluginMcpQ }))) || []; reopen(); } };
    for (const b of all('[data-plmcpadd]')) b.onclick = async () => {
      let r = await run(() => rpc('ui.connectors.plugins.mcp.install', { name: b.dataset.plmcpadd }));
      if (r && r.consent_required) { if (!consentOk(r, L('加入並啟動？', 'Add and start it?'))) { note(L('未加入', 'Not added')); return; } r = await run(() => rpc('ui.connectors.plugins.mcp.install', { name: b.dataset.plmcpadd, consent: true })); }
      if (r && r.ok) { CN.pluginMcps = null; CN.tab = 'mcp'; await reopen(); note((r.text || '') + ' — ' + RESTART(r)); }
    };
    one('[data-plnew]').onclick = () => { CN.form = { section: 'plugins' }; CN.formResult = null; reopen(); };
    for (const b of all('[data-pltest]')) b.onclick = async () => { b.textContent = L('啟動中…', 'Starting…'); CN.results['pl:' + b.dataset.pltest] = (await run(() => rpc('ui.connectors.plugins.process.test', { name: b.dataset.pltest }))) || { ok: false, error: 'failed' }; reopen(); };
    for (const b of all('[data-pledit]')) b.onclick = async () => { const s = await run(() => rpc('ui.connectors.plugins.process.get', { name: b.dataset.pledit })); if (s) { CN.form = { section: 'plugins', name: s.name, original: s.name, spec: s }; CN.formResult = null; reopen(); } };
    for (const b of all('[data-plprm]')) b.onclick = async () => { if (confirm(L(`移除 [plugins.${b.dataset.plprm}]？`, `Remove [plugins.${b.dataset.plprm}]?`)) && await run(() => rpc('ui.connectors.plugins.process.remove', { name: b.dataset.plprm }))) { await reopen(); note(RESTART()); } };
  }

  // ───────────────────────── chat channels ─────────────────────────
  const STATUS = { running: ['執行中', 'running'], restart: ['待重新啟動', 'restart to start'], error: ['錯誤', 'error'], disabled: ['停用', 'disabled'] };
  async function channelsTab() {
    const [l, k, pair] = await Promise.all([rpc('ui.connectors.channels.list'), rpc('ui.connectors.channels.kinds'), rpc('pairing.list').catch(() => ({ pending: [], approved: [] }))]);
    CN.kinds = k;
    let h = `<p class="cn-bar">${btn(L('＋ 新增頻道', '+ Add a channel'), 'data-chnew', '')}</p>`;
    if (CN.chanForm) h += channelForm(CN.chanForm, k);
    const rows = l.channels || [];
    h += rows.length ? `<table class="kv cn-table"><tr><th></th><th>${E(L('啟用', 'On'))}</th><th>${E(L('名稱', 'Name'))}</th><th>${E(L('平台', 'Platform'))}</th><th>${E(L('狀態', 'Status'))}</th><th>${E(L('私訊', 'DMs'))}</th><th>${E(L('允許', 'Allowed'))}</th><th></th></tr>${rows.map((c) => `<tr><td>${light(c.status)}</td><td><input type="checkbox" data-chon="${E(c.name)}"${c.enabled ? ' checked' : ''}${c.editable ? '' : ' disabled'}></td><td><strong>${E(c.name)}</strong></td><td>${E(c.label)}</td><td>${E(L(...(STATUS[c.status] || [c.status, c.status])))}${c.detail ? `<div class="${c.status === 'error' ? 'bad' : 'dim'} small">${E(c.detail)}</div>` : ''}</td><td>${E(c.dm_policy)}</td><td class="small">${E((c.allow || []).join(', ') || L('（沒人；需配對）', '(nobody; pairing)'))}</td>
      <td class="cn-actions">${btn(L('傳送測試訊息', 'Send test message'), `data-chtest="${E(c.name)}" data-chat="${E(c.default_chat || '')}" data-hint="${E(c.chat_hint || '')}"`)} ${c.verify ? btn(L('檢查憑證', 'Check credentials'), `data-chverify="${E(c.name)}"`) : ''} ${c.editable ? btn(L('編輯', 'Edit'), `data-chedit="${E(c.name)}"`) + ' ' + btn(L('移除', 'Remove'), `data-chrm="${E(c.name)}"`) : ''}</td></tr>${CN.results['ch:' + c.name] ? `<tr><td></td><td colspan="7">${CN.results['ch:' + c.name].ok ? `<div class="cn-res ok">${E(CN.results['ch:' + c.name].identity ? L('憑證有效：', 'Credentials work: ') + CN.results['ch:' + c.name].identity : CN.results['ch:' + c.name].chat ? L('已送出到 ', 'Sent to ') + CN.results['ch:' + c.name].chat + ' (' + CN.results['ch:' + c.name].via + ')' : L('設定可用', 'Configuration builds'))}</div>` : resultBox(CN.results['ch:' + c.name])}</td></tr>` : ''}`).join('')}</table>` : `<p class="dim">${E(L('還沒有聊天頻道。', 'No chat channels yet.'))}</p>`;
    const pend = pair.pending || [];
    const appr = pair.approved || [];
    h += `<h3>${E(L('私訊配對', 'DM pairing'))}</h3><p class="dim">${E(L('dm_policy = pairing 時，陌生人會收到一次性配對碼；輸入對方給你的碼以核准。', 'With dm_policy = pairing a stranger gets a one-time code; type the code they give you to let them in.'))}</p>`;
    h += pend.length ? `<table class="kv">${pend.map((p, i) => `<tr><td>${E(p.channel)}</td><td>${E(p.sender_name || p.sender)}</td><td><input type="text" data-pcode="${i}" placeholder="${E(L('配對碼', 'code'))}" size="8"></td><td>${btn(L('核准', 'Approve'), `data-papprove="${E(p.channel)}" data-i="${i}"`, '')}</td></tr>`).join('')}</table>` : `<p class="dim">${E(L('沒有等待中的配對。', 'No pending pairing requests.'))}</p>`;
    if (appr.length) h += `<table class="kv"><tr><th>${E(L('頻道', 'Channel'))}</th><th>${E(L('使用者', 'User'))}</th><th></th></tr>${appr.map((a) => `<tr><td>${E(a.channel)}</td><td>${E(a.name || a.sender)} <span class="dim mono">${E(a.sender)}</span></td><td>${btn(L('撤銷', 'Revoke'), `data-prevoke="${E(a.channel)}" data-sender="${E(a.sender)}"`)}</td></tr>`).join('')}</table>`;
    return h;
  }
  function channelForm(f, k) {
    const kind = f.kind || CN.chanKind || 'telegram';
    const spec = (k.kinds || []).find((x) => x.kind === kind);
    const fv = f.fields || {};
    const pol = f.policy || {};
    const allowV = Array.isArray(pol.allow) ? pol.allow.join(', ') : pol.allow || '';
    const kinds = [...(k.kinds || []).map((x) => [x.kind, x.label]), ...(k.all || []).filter((x) => !(k.kinds || []).some((y) => y.kind === x)).map((x) => [x, x])];
    const fieldHtml = spec ? spec.fields.map((x) => {
      const cur = fv[x.key];
      if (x.type === 'bool') return `<label class="cn-inline cn-field"><input type="checkbox" data-cf="${E(x.key)}" data-type="bool"${cur === true ? ' checked' : ''}> ${E(x.label)}</label>`;
      if (x.type === 'secret') return field(x.label + (x.required ? ' *' : ''), `<input type="password" data-cf="${E(x.key)}" data-type="secret" placeholder="${E(cur && cur.set ? L('已設定（留空＝不變）', 'set (leave empty to keep)') : x.hint)}" autocomplete="new-password">`, cur && cur.ref ? '🔒 ' + cur.ref : cur && cur.set === false ? '⚠ ' + L('金庫裡沒有這個秘密', 'not in the vault') : '');
      return field(x.label + (x.required ? ' *' : ''), `<input type="${x.type === 'number' ? 'number' : 'text'}" data-cf="${E(x.key)}" data-type="${x.type}" value="${E(cur === undefined ? '' : cur)}" placeholder="${E(x.hint)}" spellcheck="false">`);
    }).join('') : `<div class="cn-field"><span>${E(L('設定（key = TOML 值）', 'Settings (key = TOML value)'))}</span>${kvRows('chExtra', f.extra || [], false)}<small class="dim">${E(L('這個平台沒有引導表單；欄位名稱見 docs/channel-guide.md。儲存前會用平台模組驗證。', 'No guided form for this platform; see docs/channel-guide.md for its keys. The platform module validates them before saving.'))}</small></div>`;
    return `<section class="cn-form" id="chForm"><h3>${E(f.original ? L('編輯頻道', 'Edit channel') + ' ' + f.original : L('新增聊天頻道', 'Add a chat channel'))}</h3>
      ${field(L('平台', 'Platform'), `<select id="chKind"${f.original ? ' disabled' : ''}>${kinds.map(([v, l]) => `<option value="${E(v)}"${v === kind ? ' selected' : ''}>${E(l)}</option>`).join('')}</select>`, spec ? spec.help : '')}
      ${field(L('名稱', 'Name'), text('chName', f.name || (f.original ? '' : kind.replace(/[^a-z0-9_-]/gi, '')), ''))}
      ${fieldHtml}
      ${spec && (f.extra || []).length ? `<div class="cn-field"><span>${E(L('其他設定', 'Other settings'))}</span>${kvRows('chExtra', f.extra, false)}</div>` : ''}
      <h4>${E(L('誰可以跟 SE Agent 說話', 'Who may talk to SE Agent'))}</h4>
      ${field(L('私訊政策', 'DM policy'), `<select id="chDm">${[['pairing', L('配對（陌生人要配對碼）', 'pairing (strangers need a code)')], ['allowlist', L('只限允許清單', 'allow list only')], ['open', L('任何人', 'anyone')], ['disabled', L('關閉私訊', 'no DMs')]].map(([v, l]) => `<option value="${v}"${(pol.dm_policy || 'pairing') === v ? ' selected' : ''}>${E(l)}</option>`).join('')}</select>`)}
      ${field(L('允許的使用者（以逗號分隔）', 'Allowed users (comma separated)'), text('chAllow', allowV, '123456789, @amy'))}
      ${field(L('預設聊天（測試訊息與 channel_send 用）', 'Default chat (test messages and channel_send)'), text('chDefault', pol.default_chat || '', spec ? spec.chat_hint : ''))}
      <label class="cn-inline"><input type="checkbox" id="chMention"${pol.require_mention === false ? '' : ' checked'}> ${E(L('群組裡要 @提及 才回答', 'In groups, answer only when mentioned'))}</label>
      ${field(L('隱私告知（選填）', 'Privacy notice (optional)'), text('chPrivacy', pol.privacy_notice || '', L('首次對話前送出一次', 'sent once before the first reply')))}
      <p>${btn(L('儲存並驗證', 'Validate and save'), 'data-chsave', '')} ${btn(L('取消', 'Cancel'), 'data-chcancel')}</p></section>`;
  }
  function bindChannels() {
    bindKv();
    one('[data-chnew]').onclick = () => { CN.chanForm = { kind: CN.chanKind || 'telegram' }; reopen(); };
    const ks = one('#chKind');
    if (ks) ks.onchange = () => { CN.chanKind = ks.value; CN.chanForm = { kind: ks.value }; reopen(); };
    if (one('[data-chcancel]')) one('[data-chcancel]').onclick = () => { CN.chanForm = null; reopen(); };
    if (one('[data-chsave]')) one('[data-chsave]').onclick = async () => {
      const f = CN.chanForm;
      const fields = {};
      for (const i of all('[data-cf]')) fields[i.dataset.cf] = i.dataset.type === 'bool' ? i.checked : i.value.trim();
      const p = { name: val('chName'), kind: f.kind || val('chKind'), fields, extra: one('#chExtra') ? readKv('chExtra') : [],
        policy: { dm_policy: val('chDm'), allow: val('chAllow'), default_chat: val('chDefault'), require_mention: checked('chMention'), privacy_notice: val('chPrivacy') } };
      if (f.original) p.original = f.original;
      const r = await run(() => rpc('ui.connectors.channels.save', p));
      if (r && r.ok) { CN.chanForm = null; await reopen(); note((r.checked === 'built' ? L('設定已通過平台模組驗證。', 'The platform module accepted the settings. ') : '') + RESTART()); }
    };
    for (const c of all('[data-chon]')) c.onchange = () => run(() => rpc('ui.connectors.channels.enable', { name: c.dataset.chon, enabled: c.checked }), RESTART);
    for (const b of all('[data-chtest]')) b.onclick = async () => {
      let chat = b.dataset.chat;
      if (!chat) { chat = (prompt(L('傳到哪個聊天？', 'Send to which chat?') + (b.dataset.hint ? `\n(${b.dataset.hint})` : '')) || '').trim(); if (!chat) return; }
      b.disabled = true;
      CN.results['ch:' + b.dataset.chtest] = (await run(() => rpc('ui.connectors.channels.test', { name: b.dataset.chtest, chat }))) || { ok: false, error: L('呼叫失敗', 'call failed') };
      reopen();
    };
    for (const b of all('[data-chverify]')) b.onclick = async () => { b.disabled = true; CN.results['ch:' + b.dataset.chverify] = (await run(() => rpc('ui.connectors.channels.verify', { name: b.dataset.chverify }))) || { ok: false, error: 'failed' }; reopen(); };
    for (const b of all('[data-chedit]')) b.onclick = async () => { const g = await run(() => rpc('ui.connectors.channels.get', { name: b.dataset.chedit })); if (g) { CN.chanForm = { ...g, original: g.name }; reopen(); } };
    for (const b of all('[data-chrm]')) b.onclick = async () => { if (confirm(L(`移除頻道 ${b.dataset.chrm}？（金庫裡的憑證保留）`, `Remove channel ${b.dataset.chrm}? (its credentials stay in the vault)`)) && await run(() => rpc('ui.connectors.channels.remove', { name: b.dataset.chrm }))) { await reopen(); note(RESTART()); } };
    for (const b of all('[data-papprove]')) b.onclick = async () => { const code = one(`[data-pcode="${b.dataset.i}"]`).value.trim(); if (await run(() => rpc('pairing.approve', { channel: b.dataset.papprove, code }), L('已核准', 'Approved'))) reopen(); };
    for (const b of all('[data-prevoke]')) b.onclick = async () => { if (confirm(L('撤銷後對方要重新配對。確定？', 'They will have to pair again. Revoke?')) && await run(() => rpc('pairing.revoke', { channel: b.dataset.prevoke, sender: b.dataset.sender }), L('已撤銷', 'Revoked'))) reopen(); };
  }

  // ───────────────────────── webhooks ─────────────────────────
  async function webhooksTab() {
    const l = await rpc('ui.connectors.webhooks.list');
    const chans = l.channels || [];
    if (!chans.length) return `<p class="dim">${E(L('Webhook 訂閱掛在 webhook 頻道上。先到「聊天頻道」新增一個 Webhook 頻道（填聽取位址）。', 'Webhook subscriptions live on a webhook channel. Add a Webhook channel (with a listen address) under Chat channels first.'))}</p>${btn(L('新增 Webhook 頻道', 'Add a webhook channel'), 'data-whchan', '')}`;
    let h = CN.whSecret ? `<div class="cn-res ok"><strong>${E(L('簽章密鑰（只顯示這一次）', 'Signing secret (shown once)'))}</strong><pre class="cp-pre">${E(CN.whSecret)}</pre></div>` : '';
    for (const c of chans) {
      h += `<h3>${E(c.channel)} <span class="dim mono">${E(c.listen || '')}</span></h3>`;
      h += c.subscriptions.length ? `<table class="kv"><tr><th>${E(L('路由', 'Route'))}</th><th>${E(L('路徑', 'Path'))}</th><th>${E(L('送到', 'Delivers to'))}</th><th>${E(L('提示', 'Prompt'))}</th><th></th></tr>${c.subscriptions.map((s) => `<tr><td><strong>${E(s.route)}</strong>${s.enabled ? '' : ` <span class="chip">${E(L('停用', 'off'))}</span>`}</td><td class="mono">POST ${E(s.path)}</td><td>${E(s.cron_job ? 'cron ' + s.cron_job : s.deliver)}</td><td class="dim small">${E(s.prompt || '')}</td><td class="cn-actions">${btn(L('傳送測試', 'Send test'), `data-whtest="${E(c.channel)}" data-route="${E(s.route)}"`)} ${btn(L('移除', 'Remove'), `data-whrm="${E(c.channel)}" data-route="${E(s.route)}"`)}</td></tr>${CN.results['wh:' + c.channel + ':' + s.route] ? `<tr><td colspan="5">${(() => { const r = CN.results['wh:' + c.channel + ':' + s.route]; return r.ok ? `<div class="cn-res ok">HTTP ${E(r.status)} <pre class="cp-pre">${E(r.body)}</pre></div>` : resultBox(r); })()}</td></tr>` : ''}`).join('')}</table>` : `<p class="dim">${E(L('沒有訂閱。', 'No subscriptions.'))}</p>`;
      if ((c.static_routes || []).length) h += `<p class="dim">${E(L('設定檔裡的固定路由：', 'Routes from config.toml:'))} ${E(c.static_routes.join(', '))}</p>`;
      h += `<details><summary>${E(L('新增訂閱', 'Add a subscription'))}</summary>${field(L('路由名稱', 'Route name'), `<input type="text" data-whname="${E(c.channel)}" placeholder="deploys">`)}${field(L('提示範本', 'Prompt template'), `<input type="text" data-whprompt="${E(c.channel)}" placeholder="${E(L('部署完成：{payload}', 'A deploy finished: {payload}'))}">`)}${field(L('送到（選填）', 'Deliver to (optional)'), `<input type="text" data-whdeliver="${E(c.channel)}" placeholder="reply · telegram:123456789">`)}<p>${btn(L('訂閱', 'Subscribe'), `data-whsub="${E(c.channel)}"`, '')}</p></details>`;
    }
    return h;
  }
  function bindWebhooks() {
    if (one('[data-whchan]')) one('[data-whchan]').onclick = () => { CN.tab = 'channels'; CN.chanKind = 'webhook'; CN.chanForm = { kind: 'webhook' }; reopen(); };
    for (const b of all('[data-whsub]')) b.onclick = async () => {
      const ch = b.dataset.whsub;
      const spec = {};
      const pr = one(`[data-whprompt="${ch}"]`).value.trim();
      const dl = one(`[data-whdeliver="${ch}"]`).value.trim();
      if (pr) spec.prompt = pr;
      if (dl) spec.deliver = dl;
      const r = await run(() => rpc('ui.connectors.webhooks.subscribe', { channel: ch, route: one(`[data-whname="${ch}"]`).value.trim(), spec }));
      if (r) { CN.whSecret = r.secret; await reopen(); note(L('已訂閱：', 'Subscribed: ') + 'POST ' + r.path); }
    };
    for (const b of all('[data-whrm]')) b.onclick = async () => { if (confirm(L(`移除訂閱 ${b.dataset.route}？`, `Remove subscription ${b.dataset.route}?`)) && await run(() => rpc('ui.connectors.webhooks.remove', { channel: b.dataset.whrm, route: b.dataset.route }), L('已移除', 'Removed'))) { CN.whSecret = null; reopen(); } };
    for (const b of all('[data-whtest]')) b.onclick = async () => { CN.results['wh:' + b.dataset.whtest + ':' + b.dataset.route] = (await run(() => rpc('ui.connectors.webhooks.test', { channel: b.dataset.whtest, route: b.dataset.route }))) || { ok: false, error: 'failed' }; reopen(); };
  }

  // ───────────────────────── agents: ACP / A2A ─────────────────────────
  async function agentsTab() {
    const [acp, a2a] = await Promise.all([rpc('ui.connectors.acp.list'), rpc('ui.connectors.a2a.list')]);
    const f = CN.acpForm;
    let h = `<h3>${E(L('外部 ACP 代理', 'External ACP agents'))}</h3><p class="dim">${E(L('SE Agent 可以委派工作給這些編碼代理（seagent acp-client）。', 'Coding agents SE Agent can delegate to (seagent acp-client).'))}</p>
      <table class="kv"><tr><th></th><th>${E(L('名稱', 'Name'))}</th><th>${E(L('指令', 'Command'))}</th><th>${E(L('說明', 'Description'))}</th><th></th></tr>${(acp.agents || []).map((a) => `<tr><td>${light(a.resolved ? 'running' : 'error')}</td><td><strong>${E(a.name)}</strong>${a.preset && !a.configured ? ` <span class="chip">${E(L('預設', 'preset'))}</span>` : ''}</td><td class="mono small" title="${E(a.resolved || L('找不到這個程式', 'program not found'))}">${E(a.command_line)}</td><td class="dim">${E(a.description || '')}</td><td class="cn-actions">${btn(a.editable ? L('編輯', 'Edit') : L('自訂', 'Customize'), `data-acpedit="${E(a.name)}"`)} ${a.editable ? btn(L('移除', 'Remove'), `data-acprm="${E(a.name)}"`) : ''}</td></tr>`).join('')}</table>
      <p>${btn(L('＋ 新增 ACP 代理', '+ Add an ACP agent'), 'data-acpnew', '')}</p>`;
    if (f) h += `<section class="cn-form"><h3>${E(f.name ? f.name : L('新增 ACP 代理', 'New ACP agent'))}</h3>${field(L('名稱', 'Name'), text('acpName', f.name || '', 'my-agent'))}${field(L('指令', 'Command'), text('acpCmd', f.command || '', 'npx'))}${field(L('參數', 'Arguments'), text('acpArgs', (f.args || []).join(' '), '-y @zed-industries/claude-code-acp'))}${field(L('說明', 'Description'), text('acpDesc', f.description || '', ''))}
      ${field(L('權限模式', 'Permission mode'), `<select id="acpMode"><option value="">${E(L('預設', 'default'))}</option>${['approve-reads', 'approve-all', 'deny-all'].map((m) => `<option${f.permission_mode === m ? ' selected' : ''}>${m}</option>`).join('')}</select>`)}
      <div class="cn-field"><span>${E(L('環境變數', 'Environment'))}</span>${kvRows('acpEnv', [], true)}</div><p>${btn(L('儲存', 'Save'), 'data-acpsave', '')} ${btn(L('取消', 'Cancel'), 'data-acpcancel')}</p></section>`;
    h += `<h3>A2A</h3><p><label class="cn-inline"><input type="checkbox" id="a2aOn"${a2a.enabled ? ' checked' : ''}> ${E(L('讓其他代理經 A2A 呼叫這個 SE Agent', 'Let other agents call this SE Agent over A2A'))}</label>${a2a.app_enabled ? '' : ` <span class="bad small">${E(L('App Server 未啟用（[app] enabled = true）', 'the app server is off ([app] enabled = true)'))}</span>`}</p>
      <h4>${E(L('可以呼叫的遠端代理', 'Remote agents SE Agent may call'))}</h4><table class="kv">${(a2a.agents || []).map((a) => `<tr><td><strong>${E(a.name)}</strong></td><td class="mono small">${E(a.url)}</td><td>${E((a.capabilities || []).join(', '))}</td><td>${a.token ? '🔒' : ''}</td><td class="cn-actions">${btn(L('測試', 'Test'), `data-a2atest="${E(a.name)}"`)} ${btn(L('移除', 'Remove'), `data-a2arm="${E(a.name)}"`)}</td></tr>${CN.results['a2a:' + a.name] ? `<tr><td colspan="5">${CN.results['a2a:' + a.name].ok ? `<div class="cn-res ok">${E(CN.results['a2a:' + a.name].agent || '')} · ${CN.results['a2a:' + a.name].skills} skills</div>` : resultBox(CN.results['a2a:' + a.name])}</td></tr>` : ''}`).join('') || `<tr><td class="dim">${E(L('沒有', 'None'))}</td></tr>`}</table>
      <div class="cn-row">${text('a2aName', '', L('名稱', 'name'))} ${text('a2aUrl', '', 'https://agent.example.com')} ${text('a2aTok', '', L('Bearer token（選填）', 'bearer token (optional)'), 'password')} ${text('a2aCaps', '', L('能力，以逗號分隔', 'capabilities, comma separated'))} ${btn(L('加入', 'Add'), 'data-a2aadd', '')}</div>
      <h4>${E(L('允許呼叫這裡的客戶端（peers）', 'Clients allowed to call this agent (peers)'))}</h4><table class="kv">${(a2a.peers || []).map((p) => `<tr><td><strong>${E(p.name)}</strong></td><td>${p.set ? '🔒 ' + E(p.ref || '') : '⚠ ' + E(L('秘密未設定', 'secret not set'))}</td><td>${btn(L('移除', 'Remove'), `data-peerrm="${E(p.name)}"`)}</td></tr>`).join('') || `<tr><td class="dim">${E(L('沒有（只接受 app token）', 'None (only the app token)'))}</td></tr>`}</table>
      <div class="cn-row">${text('peerName', '', L('名稱', 'name'))} ${text('peerTok', '', L('token（至少 16 字）', 'token (16+ characters)'), 'password')} ${btn(L('產生', 'Generate'), 'data-peergen')} ${btn(L('加入', 'Add'), 'data-peeradd', '')}</div>`;
    return h;
  }
  function bindAgents() {
    bindKv();
    one('[data-acpnew]').onclick = () => { CN.acpForm = {}; reopen(); };
    for (const b of all('[data-acpedit]')) b.onclick = async () => { const l = await rpc('ui.connectors.acp.list'); CN.acpForm = (l.agents || []).find((a) => a.name === b.dataset.acpedit) || {}; reopen(); };
    if (one('[data-acpcancel]')) one('[data-acpcancel]').onclick = () => { CN.acpForm = null; reopen(); };
    if (one('[data-acpsave]')) one('[data-acpsave]').onclick = async () => {
      const r = await run(() => rpc('ui.connectors.acp.save', { name: val('acpName'), command: val('acpCmd'), args: val('acpArgs'), description: val('acpDesc'), permission_mode: val('acpMode'), env: readKv('acpEnv') }));
      if (r && r.ok) { CN.acpForm = null; await reopen(); note(r.warning ? '⚠ ' + r.warning : L('已儲存', 'Saved'), !!r.warning); }
    };
    for (const b of all('[data-acprm]')) b.onclick = async () => { if (confirm(L(`移除 ${b.dataset.acprm}？`, `Remove ${b.dataset.acprm}?`)) && await run(() => rpc('ui.connectors.acp.remove', { name: b.dataset.acprm }))) reopen(); };
    one('#a2aOn').onchange = (e) => run(() => rpc('ui.connectors.a2a.enable', { enabled: e.target.checked }), RESTART);
    one('[data-a2aadd]').onclick = async () => { if (await run(() => rpc('ui.connectors.a2a.agent.save', { name: val('a2aName'), url: val('a2aUrl'), token: val('a2aTok'), capabilities: val('a2aCaps').split(',').map((x) => x.trim()).filter(Boolean) }))) { await reopen(); note(RESTART()); } };
    for (const b of all('[data-a2atest]')) b.onclick = async () => { CN.results['a2a:' + b.dataset.a2atest] = (await run(() => rpc('ui.connectors.a2a.agent.test', { name: b.dataset.a2atest }))) || { ok: false, error: 'failed' }; reopen(); };
    for (const b of all('[data-a2arm]')) b.onclick = async () => { if (confirm(L(`移除 ${b.dataset.a2arm}？`, `Remove ${b.dataset.a2arm}?`)) && await run(() => rpc('ui.connectors.a2a.agent.remove', { name: b.dataset.a2arm }))) reopen(); };
    one('[data-peergen]').onclick = () => { const a = new Uint8Array(24); crypto.getRandomValues(a); one('#peerTok').type = 'text'; one('#peerTok').value = [...a].map((x) => x.toString(16).padStart(2, '0')).join(''); note(L('把這個 token 交給對方，加入後就不會再顯示。', 'Give this token to the peer; it is not shown again after adding.')); };
    one('[data-peeradd]').onclick = async () => { if (await run(() => rpc('ui.connectors.a2a.peer.save', { name: val('peerName'), token: val('peerTok') }))) { await reopen(); note(RESTART()); } };
    for (const b of all('[data-peerrm]')) b.onclick = async () => { if (confirm(L(`移除 peer ${b.dataset.peerrm}？`, `Remove peer ${b.dataset.peerrm}?`)) && await run(() => rpc('ui.connectors.a2a.peer.remove', { name: b.dataset.peerrm }))) reopen(); };
  }

  // ───────────────────────── hooks / Gmail ─────────────────────────
  async function hooksTab() {
    const [h, g] = await Promise.all([rpc('ui.connectors.hooks.list'), rpc('ui.connectors.gmail.status').catch((e) => ({ error: e.message }))]);
    const sw = (data, on) => `<input type="checkbox" ${data}${on ? ' checked' : ''}>`;
    let out = `<h3>${E(L('Shell hooks（[[hooks]]，第一次使用要同意）', 'Shell hooks ([[hooks]], first use needs consent)'))}</h3>`;
    out += (h.shell || []).length ? `<table class="kv"><tr><th>${E(L('事件', 'Event'))}</th><th>${E(L('指令', 'Command'))}</th><th>${E(L('同意', 'Consent'))}</th><th></th></tr>${h.shell.map((x) => `<tr><td>${E(x.event)}</td><td class="mono small">${E(x.command)}</td><td>${E(x.consent)}</td><td class="cn-actions">${x.consent === 'approved' ? btn(L('撤銷', 'Revoke'), `data-hkrevoke="${E(x.command)}"`) : btn(L('同意', 'Approve'), `data-hkapprove="${E(x.command)}"`, '')}</td></tr>`).join('')}</table>` : `<p class="dim">${E(L('沒有 shell hook。', 'No shell hooks.'))}</p>`;
    out += `<h3>${E(L('內建 hooks', 'Bundled hooks'))}</h3><table class="kv">${(h.bundled || []).map((x) => `<tr><td>${sw(`data-hkon="${E(x.name)}"`, x.enabled)}</td><td><strong>${E(x.name)}</strong></td><td class="dim">${E(x.events)}</td><td>${E(x.description)}</td></tr>`).join('')}</table>`;
    out += `<h3>${E(L('Hook 套件', 'Hook packs'))}</h3>${(h.packs || []).length ? `<table class="kv">${h.packs.map((x) => `<tr><td>${sw(`data-hkon="${E(x.name)}"`, x.enabled)}</td><td><strong>${E(x.name)}</strong> <span class="chip">${E(x.source)}</span></td><td class="dim">${E((x.events || []).join(', '))}</td><td>${E(x.description)}</td></tr>`).join('')}</table>` : `<p class="dim">${E(L('沒有安裝 hook 套件。', 'No hook packs installed.'))}</p>`}
      <p>${E(L('安裝套件（含 HOOK.md 的資料夾）：', 'Install a pack (a folder with HOOK.md):'))} <label class="btn ghost small">${E(L('選資料夾…', 'Folder…'))}<input type="file" id="hkDir" webkitdirectory multiple hidden></label> <span class="dim">${E(L('先經內建掃描與 before_install hooks；裝好後預設停用。', 'Goes through the built-in scan and before_install hooks; installed disabled.'))}</span></p>`;
    out += `<h3>Gmail</h3>`;
    if (g && g.account) out += `<p>${light(g.error ? 'error' : g.enabled ? 'running' : '')} ${E(g.account)} · ${E(g.label || '')} · <span class="mono small">${E(g.topic || '')}</span>${g.error ? ` <span class="bad">${E(g.error)}</span>` : ''}</p><p class="dim">push: http://${E((g.serve || {}).bind)}:${E((g.serve || {}).port)}${E((g.serve || {}).path)} · ${E(g.historyId ? 'history ' + g.historyId : L('尚未開始', 'not seeded yet'))}</p><p><label class="cn-inline">${sw('id="gmOn"', g.enabled)} ${E(L('啟用', 'Enabled'))}</label> ${btn(L('立即建立 watch', 'Watch now'), 'data-gmwatch')} ${btn(L('清除游標', 'Reset cursor'), 'data-gmreset')}</p>`;
    else out += `<p class="dim">${E(L('收到新郵件時讓 SE Agent 處理：Gmail watch 經 Google Pub/Sub 推送到這台機器。', 'Let SE Agent handle new mail: a Gmail watch pushes through Google Pub/Sub to this machine.'))}</p>`;
    out += `<details${g && g.account ? '' : ' open'}><summary>${E(g && g.account ? L('修改 Gmail 設定', 'Change the Gmail setup') : L('設定 Gmail', 'Set up Gmail'))}</summary>
      ${field(L('Gmail 帳號', 'Gmail account'), text('gmAccount', (g && g.account) || '', 'me@gmail.com'))}
      ${field(L('Pub/Sub 主題', 'Pub/Sub topic'), text('gmTopic', (g && g.topic) || '', 'projects/<project>/topics/<topic>'))}
      <div class="cn-row">${field(L('標籤', 'Label'), text('gmLabel', (g && g.label) || 'INBOX', 'INBOX'))}${field(L('訂閱名稱（選填）', 'Subscription (optional)'), text('gmSub', (g && g.subscription) || '', ''))}</div>
      <div class="cn-row">${field(L('聽取位址', 'Bind'), text('gmBind', ((g && g.serve) || {}).bind || '127.0.0.1', ''))}${field(L('埠', 'Port'), text('gmPort', ((g && g.serve) || {}).port || '8788', '', 'number'))}${field(L('路徑', 'Path'), text('gmPath', ((g && g.serve) || {}).path || '/gmail-pubsub', ''))}</div>
      <h4>${E(L('憑證（存進金庫）', 'Credentials (stored in the vault)'))}</h4>
      ${['push_token', 'client_id', 'client_secret', 'refresh_token', 'access_token'].map((k) => field(k, `<input type="password" data-gm="${k}" placeholder="${E(g && g.account ? L('留空＝不變', 'leave empty to keep') : '')}" autocomplete="new-password">`)).join('')}
      <p class="dim">${E(L('OAuth：client_id + client_secret + refresh_token，或一個 access_token。', 'OAuth: client_id + client_secret + refresh_token, or one access_token.'))}</p>
      <p>${btn(L('儲存 Gmail 設定', 'Save the Gmail setup'), 'data-gmsave', '')}</p></details>`;
    return out;
  }
  function bindHooks() {
    for (const b of all('[data-hkapprove]')) b.onclick = async () => { if (await run(() => rpc('ui.connectors.hooks.approve', { command: b.dataset.hkapprove }), RESTART)) reopen(); };
    for (const b of all('[data-hkrevoke]')) b.onclick = async () => { if (confirm(L('撤銷這個 hook 的同意？', 'Revoke consent for this hook?')) && await run(() => rpc('ui.connectors.hooks.revoke', { command: b.dataset.hkrevoke }), RESTART)) reopen(); };
    for (const c of all('[data-hkon]')) c.onchange = () => run(() => rpc('ui.connectors.hooks.enable', { name: c.dataset.hkon, enabled: c.checked }), RESTART);
    one('#hkDir').onchange = async (e) => {
      const files = [...e.target.files];
      if (!files.length) return;
      try {
        const list = [];
        for (const f of files) list.push({ path: f.webkitRelativePath || f.name, data: await fileB64(f) });
        const r = await run(() => rpc('ui.connectors.hooks.install', { files: list }));
        if (r) { await reopen(); note(r.text + ' — ' + RESTART(r)); }
      } catch (err) { note(err.message, true); }
    };
    if (one('#gmOn')) one('#gmOn').onchange = (e) => run(() => rpc('ui.connectors.gmail.enable', { enabled: e.target.checked }), RESTART);
    if (one('[data-gmwatch]')) one('[data-gmwatch]').onclick = () => run(() => rpc('ui.connectors.gmail.watch'), (r) => (r.historyId ? 'history ' + r.historyId : r.text || 'ok'));
    if (one('[data-gmreset]')) one('[data-gmreset]').onclick = () => run(() => rpc('ui.connectors.gmail.reset'), (r) => r.text);
    one('[data-gmsave]').onclick = async () => {
      const p = { account: val('gmAccount'), topic: val('gmTopic'), label: val('gmLabel'), subscription: val('gmSub'), bind: val('gmBind'), port: val('gmPort'), path: val('gmPath') };
      for (const i of all('[data-gm]')) if (i.value) p[i.dataset.gm] = i.value;
      const r = await run(() => rpc('ui.connectors.gmail.setup', p));
      if (r) { await reopen(); note(L('Gmail 已設定：', 'Gmail set up: ') + (r.pushEndpoint || '') + ' — ' + RESTART(r)); }
    };
  }

  // ───────────────────────── devices ─────────────────────────
  async function devicesTab() {
    return `<p>${E(L('手機、平板與其他電腦用 QR 碼或配對碼加入：區域網路配對、指紋比對與撤銷都在「裝置」頁。節點（seagent node）的核准也在那裡。', 'Phones, tablets and other computers join with a QR code or pairing code: LAN pairing, fingerprint checks and revoking live on the Devices view, as do node approvals (seagent node).'))}</p>
      <p>${btn(L('開啟裝置頁（配對裝置）', 'Open Devices (pair a device)'), 'data-godev', '')} ${btn(L('節點與配對請求', 'Nodes and pairing requests'), 'data-gonodes')}</p>
      <h3>${E(L('節點設定碼（seagent node）', 'Node setup code (seagent node)'))}</h3><p class="dim">${E(L('讓另一台電腦以節點身分加入：產生一次性設定碼，在那台電腦執行顯示的指令或掃 QR 碼。', 'Let another computer join as a node: make a one-time code, then run the shown command on it or scan the QR code.'))}</p>
      <div class="cn-row">${text('ncUrl', '', L('網址（選填；預設用區域網路位址）', 'URL (optional; LAN address by default)'))} ${text('ncTtl', '10', L('有效分鐘', 'valid minutes'), 'number')} ${btn(L('產生設定碼', 'Make a setup code'), 'data-ncmake', '')}</div>
      ${CN.setupCode ? `<div class="cn-res ok cn-qr">${CN.setupCode.qr_svg ? `<div class="cn-qrimg">${CN.setupCode.qr_svg}</div>` : ''}<div><p>${E(L('在那台電腦上執行：', 'On the other computer run:'))}</p><pre class="cp-pre">${E(CN.setupCode.command)}</pre><p class="dim">${E(L('單次使用，', 'Single use, valid '))}${CN.setupCode.ttl_min} ${E(L('分鐘內有效。', 'minutes.'))} ${E(CN.setupCode.url || '')}</p>${CN.setupCode.nodes_enabled ? '' : `<p class="bad">${E(L('[app] nodes = false：App Server 目前不接受節點。', '[app] nodes = false: the app server does not accept nodes yet.'))}</p>`}</div></div>` : ''}`;
  }
  function bindDevices() {
    one('[data-godev]').onclick = () => showView('devices');
    one('[data-gonodes]').onclick = () => openPage('devices');
    one('[data-ncmake]').onclick = async () => { const r = await run(() => rpc('ui.connectors.nodes.setup_code', { url: val('ncUrl'), ttl_min: +val('ncTtl') || 10 })); if (r) { CN.setupCode = r; reopen(); } };
  }

  const RENDER = { mcp: [mcpTab, bindMcp], skills: [skillsTab, bindSkills], plugins: [pluginsTab, bindPlugins], channels: [channelsTab, bindChannels], webhooks: [webhooksTab, bindWebhooks], hooks: [hooksTab, bindHooks], agents: [agentsTab, bindAgents], devices: [devicesTab, bindDevices] };

  PAGES.connections = {
    get title() { return L('連線', 'Connections'); },
    group: '設定',
    async render() {
      const tab = RENDER[CN.tab] ? CN.tab : 'mcp';
      let body;
      try { body = await RENDER[tab][0](); } catch (e) { body = `<p class="bad">${E(e.message)}</p>`; }
      const ov = await rpc('ui.connectors.overview').catch(() => null);
      const pend = (ov && ov.pending_restart) || [];
      const banner = pend.length ? `<div class="cn-res bad cn-banner"><strong>${E(L('需要重新啟動 daemon 才生效：', 'A daemon restart applies: '))}</strong> ${pend.map((x) => `${E(x.kind)} <span class="dim">(${E(x.why)})</span>`).join(' · ')} ${btn(L('重新啟動 daemon', 'Restart daemon'), 'data-cnrestart', '')}</div>` : '';
      return `<p class="dim">${E(L('技能、MCP、外掛、聊天頻道與其他連線都在這裡設定，不需要終端機。每次寫入都會先驗證並備份設定檔（「設定檔」頁可還原）。', 'Skills, MCP, plugins, chat channels and every other connection are set up here — no terminal needed. Every write is validated and the config is backed up first (restore it on the Config page).'))}</p>
        <nav class="cn-tabs" role="tablist">${TABS.map(([id, zh, en]) => `<button class="btn ${id === tab ? '' : 'ghost'} small" role="tab" aria-selected="${id === tab}" data-cntab="${id}">${E(L(zh, en))}</button>`).join('')}</nav>
        ${banner}${NOTE}<div class="cn-body" data-tab="${tab}">${body}</div>`;
    },
    after() {
      for (const b of all('[data-cntab]')) b.onclick = () => { CN.tab = b.dataset.cntab; CN.form = null; CN.view = null; reopen(); };
      const rb = one('[data-cnrestart]');
      if (rb) rb.onclick = async () => {
        if (!confirm(L('重新啟動 daemon？執行中的對話先跑完（最多 30 秒），之後自動恢復。', 'Restart the daemon? Running turns get up to 30 s to finish, then resume after the restart.'))) return;
        const r = await run(() => rpc('ui.connectors.restart', { drain_secs: 30 }));
        if (r) { note(r.text); rb.disabled = true; setTimeout(() => reopen(), 8000); }
      };
      const tab = RENDER[CN.tab] ? CN.tab : 'mcp';
      try { RENDER[tab][1](); } catch (e) { note(e.message, true); }
    },
  };
  if (Array.isArray(EXTRA_PAGES) && !EXTRA_PAGES.includes('connections')) EXTRA_PAGES.push('connections');
  // Settings → Connections (app.js renders the Settings page and calls this for the button).
  window.openConnections = (tab) => { if (tab) CN.tab = tab; S.pageNav = 'showSettings'; return openPage('connections'); };
  // Deep link: #page=connections&tab=channels (pages.js only knows its own pages at load time).
  const h = new URLSearchParams(location.hash.slice(1));
  if (h.get('page') === 'connections') {
    if (RENDER[h.get('tab')]) CN.tab = h.get('tab');
    const wait = setInterval(() => { if (S.arp && S.sessions) { clearInterval(wait); window.openConnections(); } }, 200);
    setTimeout(() => clearInterval(wait), 20000);
  }
})();
