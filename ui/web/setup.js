// seagent setup wizard. Two ways in:
// - first run: the one-time setup token from the URL fragment (#token=…) in the
//   x-seagent-setup-token header to POST /setup/rpc. The token is removed from the address bar at
//   once so it does not linger in history or screenshots. Once setup is done that link is locked.
// - re-run ("重新執行設定精靈" in the console's settings, or a locked link opened by a signed-in
//   admin): the same setup.* methods over POST /arp with the console's own admin credential. The
//   form starts from the current config (secrets only as "stored"), and only what the person
//   changes is sent; applying restarts the agent and returns to the console.
// Anyone else gets a page that says what to do instead — never a dead form or a raw error.
'use strict';
(function () {
  const $ = (id) => document.getElementById(id);
  const frag = new URLSearchParams(location.hash.replace(/^#/, ''));
  const token = frag.get('token') || sessionStorage.getItem('seagent.setup') || '';
  if (frag.get('token')) {
    sessionStorage.setItem('seagent.setup', token);
    history.replaceState(null, '', location.pathname + (frag.has('rerun') ? '#rerun' : ''));
  }
  // The console's credential (same origin): the app token or a device token.
  const consoleToken = (() => { try { return localStorage.getItem('seagent.token') || ''; } catch { return ''; } })();
  let mode = 'link'; // 'link' (setup token) | 'admin' (console credential, re-run)
  let configured = {};
  let seq = 0;

  async function rpcLink(method, params) {
    const r = await fetch('/setup/rpc', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-seagent-setup-token': token },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++seq, method, params: params || {} }),
      credentials: 'omit',
      cache: 'no-store',
    });
    const j = await r.json();
    if (j.error) throw Object.assign(new Error(j.error.message || 'error'), { code: j.error.code });
    return j.result;
  }
  async function rpcAdmin(method, params) {
    const headers = { 'content-type': 'application/json' };
    if (consoleToken) headers.authorization = 'Bearer ' + consoleToken;
    const r = await fetch('/arp', { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: ++seq, method, params: params || {} }), credentials: 'same-origin', cache: 'no-store' });
    if (r.status === 401 || r.status === 403) throw Object.assign(new Error('forbidden'), { forbidden: true, status: r.status });
    const j = await r.json();
    if (j.error) throw Object.assign(new Error(j.error.message || 'error'), { code: j.error.code });
    return j.result;
  }
  // A call that finds the link locked (setup was finished meanwhile) moves to the re-run when
  // this browser holds an admin credential; otherwise the locked page explains what to do.
  async function rpc(method, params) {
    if (mode === 'admin') return rpcAdmin(method, params);
    try {
      return await rpcLink(method, params);
    } catch (e) {
      if (e.code === -32001 && /locked/.test(e.message) && (await enterAdmin())) return rpcAdmin(method, params);
      if (e.code === -32001) { blocked(e.message, true); throw Object.assign(new Error(friendly(e.message)), { shown: true }); }
      throw e;
    }
  }

  // The server's reasons, in words the person can act on.
  function friendly(msg) {
    const m = String(msg || '');
    if (/locked/.test(m)) return '設定已經完成；一次性設定連結因此鎖定（這是安全措施，避免別人拿舊連結改掉你的設定）。';
    if (/expired/.test(m)) return '這個設定連結已過期。';
    if (/no setup link/.test(m)) return '目前沒有有效的設定連結。';
    if (/setup token/.test(m)) return '這個設定連結無效。';
    if (/forbidden/.test(m)) return '你在這個瀏覽器登入的身分不是管理者，不能修改整台 SE Agent 的設定。';
    return m;
  }

  function say(el, text, kind) {
    el.textContent = text || '';
    el.className = 'status' + (kind ? ' ' + kind : '');
  }

  function blocked(reason, locked) {
    $('wizard').hidden = true;
    $('intro').hidden = true;
    $('blocked').hidden = false;
    // Nothing to step through here.
    $('stepNav').style.display = 'none';
    $('blockedReason').textContent = friendly(reason);
    const how = $('blockedHow');
    if (locked || /locked|forbidden/.test(String(reason))) {
      how.textContent = '要修改設定：開啟主控台，到「設定」按「重新執行設定精靈」（需要管理者身分）。在這台電腦上也可以執行 seagent setup link --reopen 取得新的一次性連結。';
      $('blockedActions').hidden = false;
    }
  }

  // Re-run mode: is this browser signed in as an admin of this agent?
  let adminTried = null;
  async function enterAdmin() {
    if (adminTried) return adminTried;
    adminTried = (async () => {
      try {
        const s = await rpcAdmin('setup.status');
        if (!s || !s.token_valid) return false;
        mode = 'admin';
        statusCache = s;
        return true;
      } catch (e) {
        adminError = e;
        return false;
      }
    })();
    return adminTried;
  }
  let statusCache = null;
  let adminError = null;

  let providers = [];
  let priceInfo = null;
  let modelPrices = {};
  let modelContexts = {};
  const current = () => providers.find((p) => p.id === $('provider').value);

  // Prices are looked up on this machine (models.dev price list or the snapshots built into SE
  // Agent), USD per million tokens, input / output.
  const fmtPrice = (p) => {
    const f = (x) => (x >= 100 ? x.toFixed(0) : x >= 0.1 ? x.toFixed(2) : String(+x.toFixed(4)));
    return '$' + f(p.in) + ' / $' + f(p.out);
  };
  const priceSource = (p) => (!p ? '—' : p.kind === 'config' ? '設定檔' : p.kind === 'snapshot' ? '內建快照' + (p.date ? ' ' + String(p.date).slice(0, 7) : '') : 'models.dev');
  function agoLong(ms) {
    const d = Math.max(0, (Date.now() - ms) / 1000);
    if (d < 90) return '剛剛';
    if (d < 5400) return Math.round(d / 60) + ' 分鐘前';
    if (d < 129600) return Math.round(d / 3600) + ' 小時前';
    return Math.round(d / 86400) + ' 天前';
  }
  function priceLegend() {
    const el = $('priceLegend');
    if (!Object.keys(modelPrices).length || !priceInfo) { el.hidden = true; return; }
    const src = priceInfo.registry
      ? '價格：models.dev · ' + (priceInfo.fetched_ms ? agoLong(priceInfo.fetched_ms) + '更新' : '已快取')
      : '價格：內建快照 ' + priceInfo.snapshot + '（尚未連線更新）';
    el.textContent = src + '　·　美元／每百萬 tokens，輸入 / 輸出';
    el.title = '價格在本機查表，不是每次向雲端詢問：SE Agent 使用 models.dev 公開價目表（快取在本機，背景更新），沒有網路時用內建的官方文件價格快照。對話的費用＝供應商 API 回報的 token 數 × 這個價格，是估算，不是帳單。';
    el.className = 'hint price-legend' + (priceInfo.registry ? '' : ' snap');
    el.hidden = false;
  }

  const keyStored = () => mode === 'admin' && configured.key_stored && current() && current().id === configured.provider;
  function syncProvider() {
    const p = current();
    const custom = $('provider').value === '_custom';
    $('customFields').hidden = !custom;
    $('keyField').hidden = !custom && p && !p.needs_key;
    $('baseUrl').placeholder = p ? p.base_url : 'https://…/v1';
    if (keyStored()) {
      $('apiKey').placeholder = '已儲存 — 留空沿用；輸入新金鑰即更換';
      $('keyHint').textContent = '金鑰已存在 ' + (configured.key_env || '保管庫') + '（不會顯示）。';
    } else {
      $('apiKey').placeholder = '';
      $('keyHint').textContent = p && p.has_key && p.needs_key ? '保管庫或環境中已有 ' + p.key_env + '；留空即沿用。' : '';
    }
    tested = null;
    say($('testStatus'), '');
    // Before a successful test: the provider's built-in list (the console pickers' offline list).
    modelPrices = (p && p.prices) || {};
    modelContexts = (p && p.contexts) || {};
    setModels(p ? p.models || [] : [], p ? p.recommended : '', p ? 'builtin' : 'none');
    // Nothing to type for these: fetch the live list right away.
    if (p && (!p.needs_key || p.has_key || keyStored())) testProvider(true);
  }

  // ── the model list: every model the provider offers, one click to choose ──
  // Aligned columns like the console's picker (name | context | input / output | price source),
  // always open, with type-to-filter above it; "other…" at the end reveals a text field for a
  // name the list does not have.
  const OTHER = ' other';
  let modelList = [];
  let pickedModel = '';
  let modelSource = 'none';
  let tested = null;
  let shownModels = [];

  function setModels(list, recommended, source) {
    const seen = new Set();
    modelList = (list || []).filter((m) => m && !seen.has(m) && seen.add(m));
    modelSource = source;
    const keep = pickedModel && (modelList.includes(pickedModel) || pickedModel === OTHER) ? pickedModel : '';
    pickedModel = keep || (recommended && modelList.includes(recommended) ? recommended : modelList[0] || '');
    $('modelFilter').value = '';
    drawModels();
    $('modelHint').textContent = source === 'live'
      ? '供應商 API 回傳的全部模型；點一下即可選擇，也可在上方輸入文字篩選。'
      : source === 'builtin' && modelList.length
        ? '內建清單。測試連線成功後會換成這把金鑰實際可用的模型。'
        : '輸入金鑰後會自動測試連線，並在這裡列出可用的模型。';
  }

  function drawModels() {
    const q = $('modelFilter').value.trim().toLowerCase();
    shownModels = modelList.filter((m) => !q || m.toLowerCase().includes(q));
    if (q && shownModels.length && !shownModels.includes(pickedModel) && pickedModel !== OTHER) pickedModel = shownModels[0];
    const box = $('model');
    const rows = shownModels.map((m, i) => {
      const pr = modelPrices[m];
      const ctx = modelContexts[m];
      const r = document.createElement('div');
      r.className = 'mrow';
      r.id = 'mrow-' + i;
      r.setAttribute('role', 'option');
      r.dataset.m = m;
      r.setAttribute('aria-selected', String(m === pickedModel));
      if (pr) r.title = fmtPrice(pr) + ' 每百萬 tokens（輸入 / 輸出）· ' + priceSource(pr);
      for (const [cls, text] of [['mn', m], ['mc', ctx ? Math.round(ctx / 1000) + 'k' : ''], ['mp', pr ? fmtPrice(pr) : '—'], ['ms', priceSource(pr)]]) r.append(Object.assign(document.createElement('span'), { className: cls, textContent: text }));
      return r;
    });
    const other = document.createElement('div');
    other.className = 'mrow other';
    other.id = 'mrow-other';
    other.setAttribute('role', 'option');
    other.dataset.m = OTHER;
    other.setAttribute('aria-selected', String(pickedModel === OTHER));
    other.append(Object.assign(document.createElement('span'), { className: 'mn', textContent: '其他（自行輸入模型名稱）…' }));
    box.replaceChildren(...rows, other);
    const sel = box.querySelector('[aria-selected="true"]');
    if (sel) { box.setAttribute('aria-activedescendant', sel.id); sel.scrollIntoView({ block: 'nearest' }); } else box.removeAttribute('aria-activedescendant');
    $('modelOtherField').hidden = pickedModel !== OTHER;
    priceLegend();
    $('modelCount').textContent = modelList.length ? (q ? shownModels.length + ' / ' : '') + modelList.length + ' 個' + (modelSource === 'live' ? '（即時）' : '（內建）') : '';
  }

  function pick(m) {
    pickedModel = m;
    for (const r of $('model').children) r.setAttribute('aria-selected', String(r.dataset.m === m));
    const sel = $('model').querySelector('[aria-selected="true"]');
    if (sel) { $('model').setAttribute('aria-activedescendant', sel.id); sel.scrollIntoView({ block: 'nearest' }); }
    $('modelOtherField').hidden = m !== OTHER;
    if (m === OTHER) $('modelOther').focus();
  }

  function chosenModel() {
    return pickedModel === OTHER ? $('modelOther').value.trim() : pickedModel;
  }

  function providerParams() {
    const custom = $('provider').value === '_custom';
    const out = { provider: custom ? $('customId').value.trim() : $('provider').value };
    const base = $('baseUrl').value.trim();
    if (base) out.base_url = base;
    if ($('apiKey').value) out.api_key = $('apiKey').value;
    return out;
  }

  const testKey = () => JSON.stringify(providerParams());

  // `auto`: started by leaving the key field / choosing a provider rather than by the button —
  // stays quiet about a missing key.
  async function testProvider(auto) {
    const st = $('testStatus');
    const p = current();
    if (auto === true && p && p.needs_key && !p.has_key && !keyStored() && !$('apiKey').value) return;
    const key = testKey();
    say(st, '連線中…');
    $('testProvider').disabled = true;
    try {
      const r = await rpc('setup.test_provider', providerParams());
      if (key !== testKey()) return; // the provider or key changed meanwhile
      tested = key;
      if (!r.ok) {
        say(st, '✗ ' + friendly(r.error), 'error');
        return;
      }
      say(st, '✓ 連線成功，' + r.count + ' 個模型', 'ok');
      modelPrices = r.prices || {};
      modelContexts = r.contexts || {};
      setModels(r.models || [], r.recommended, 'live');
      if (auto !== true) {
        // The whole list at once, ready to click.
        $('stepModel').scrollIntoView({ behavior: 'smooth', block: 'start' });
        $('model').focus({ preventScroll: true });
      }
    } catch (e) {
      if (!e.shown) say(st, '✗ ' + friendly(e.message), 'error');
    } finally {
      $('testProvider').disabled = false;
    }
  }

  function radio(name) {
    const el = document.querySelector('input[name="' + name + '"]:checked');
    return el ? el.value : '';
  }

  // Re-run: the console login is sent only when it was changed (an unchanged OIDC login keeps its
  // stored client secret; an unchanged token login stays as it is).
  function authParams() {
    const a = { mode: radio('auth') };
    if (a.mode === 'oidc') {
      a.issuer = $('oidcIssuer').value.trim();
      a.client_id = $('oidcClient').value.trim();
      if ($('oidcSecret').value) a.client_secret = $('oidcSecret').value;
    }
    if (mode !== 'admin') return a;
    const was = configured.auth || {};
    const same = a.mode === (was.mode || 'token') && (a.mode !== 'oidc' || (a.issuer === (was.issuer || '') && a.client_id === (was.client_id || '') && !a.client_secret));
    return same ? null : a;
  }

  async function apply(ev) {
    ev.preventDefault();
    const st = $('applyStatus');
    const params = providerParams();
    // Re-run: the endpoint field holds the configured one; sent only when changed.
    if (mode === 'admin' && params.base_url && params.base_url === (configured.base_url || '') && params.provider === configured.provider) delete params.base_url;
    params.model = chosenModel();
    if (!params.provider || !params.model) {
      say(st, '請選擇供應商與模型', 'error');
      return;
    }
    if (radio('security')) params.security = radio('security');
    if ($('workspace').value.trim()) params.workspace = $('workspace').value.trim();
    const auth = authParams();
    if (auth) params.auth = auth;
    if ($('channelKind').value) {
      params.channel = { kind: $('channelKind').value, token: $('channelToken').value };
      if ($('channelOwner').value.trim()) params.channel.owner = $('channelOwner').value.trim();
    }
    params.autostart = $('autostart').checked;
    // LAN mode (docs/cross-platform.md): devices on this network may pair.
    params.lan = $('lan').checked;
    $('apply').disabled = true;
    say(st, '寫入設定中…');
    try {
      const r = await rpc('setup.apply', params);
      sessionStorage.removeItem('seagent.setup');
      // Inside the SE Agent app (apps/desktop): "start automatically" also sets the app's login
      // item / Android boot start. The app only lets this page call autostart_get/autostart_set.
      const tauri = window.__TAURI__ && window.__TAURI__.core;
      if (tauri) tauri.invoke('autostart_set', { enabled: params.autostart }).catch(() => {});
      for (const id of ['apiKey', 'oidcSecret', 'channelToken']) $(id).value = '';
      $('wizard').hidden = true;
      $('intro').hidden = true;
      $('done').hidden = false;
      $('doneLog').replaceChildren(...(r.lines || []).map((l) => Object.assign(document.createElement('li'), { textContent: l })));
      // A re-run goes back to the console this browser is already signed in to.
      const back = mode === 'admin' ? '/' : r.console_url;
      $('consoleLink').href = back;
      waitForRestart(back);
    } catch (e) {
      if (!e.shown) say(st, '✗ ' + friendly(e.message), 'error');
      $('apply').disabled = false;
    }
  }

  // The daemon restarts with the new config; go to the console once it answers again.
  function waitForRestart(url) {
    let tries = 0;
    const tick = async () => {
      tries++;
      try {
        const r = await fetch('/health', { cache: 'no-store' });
        if (r.ok && tries > 3) {
          location.replace(url);
          return;
        }
      } catch (_) { /* restarting */ }
      if (tries < 60) setTimeout(tick, 1000);
    };
    setTimeout(tick, 1500);
  }

  // Re-run: the page says so, and the form starts from what the config already has.
  function rerunLook(s) {
    document.title = 'SE Agent 重新設定';
    document.querySelector('.setup header .kicker').textContent = 'Re-run setup';
    document.querySelector('.setup header h1').textContent = '重新設定 SE Agent';
    $('intro').textContent = '你以管理者身分登入，表單已填入目前的設定。只會套用你改動的部分：沒改的設定與已儲存的金鑰（不會顯示）都會保留。套用後 SE Agent 會重新啟動並回到主控台。';
    const sub = document.querySelector('.steps .brand .sub');
    if (sub) sub.textContent = '重新設定';
    const foot = document.querySelector('.steps .foot');
    if (foot) foot.innerHTML = '管理者重新設定。<br>金鑰只進保管庫，不寫入設定檔。';
    $('apply').textContent = '套用並重新啟動';
    const sec = s.configured && s.configured.security;
    for (const el of document.querySelectorAll('input[name="security"]')) el.checked = el.value === sec;
    const au = (s.configured && s.configured.auth) || {};
    for (const el of document.querySelectorAll('input[name="auth"]')) el.checked = el.value === (au.mode || 'token');
    $('oidcFields').hidden = au.mode !== 'oidc';
    if (au.mode === 'oidc') {
      $('oidcIssuer').value = au.issuer || '';
      $('oidcClient').value = au.client_id || '';
      if (au.client_secret_stored) $('oidcSecret').placeholder = '已儲存 — 留空沿用';
    }
    const ch = (s.configured && s.configured.channels) || [];
    if (ch.length) {
      const sel = $('channelKind');
      sel.options[0].textContent = '不變更（已設定：' + ch.join('、') + '）';
    }
  }

  async function start() {
    let s = null;
    let why = '';
    if (token) {
      try {
        s = await rpcLink('setup.status');
      } catch (e) {
        why = e.message;
      }
      if (s && !s.token_valid) { why = s.locked ? 'locked' : s.reason || 'invalid setup token'; s = null; }
    }
    // No (valid) link: a signed-in admin re-runs setup.
    if (!s && (await enterAdmin())) s = statusCache;
    if (!s) {
      if (adminError && adminError.forbidden && consoleToken) blocked('forbidden', true);
      else blocked(why || (frag.has('rerun') ? 'locked' : 'no setup link'), /locked/.test(why) || frag.has('rerun'));
      return;
    }
    configured = s.configured || {};
    providers = s.providers || [];
    priceInfo = s.prices || null;
    const sel = $('provider');
    sel.replaceChildren(...providers.map((p) => Object.assign(document.createElement('option'), { value: p.id, textContent: p.label + (p.has_key && p.needs_key ? '（已有金鑰）' : '') })));
    sel.append(Object.assign(document.createElement('option'), { value: '_custom', textContent: '自訂 OpenAI 相容端點' }));
    const cur = configured.model;
    if (cur) {
      const [pid, ...rest] = cur.split('/');
      if (providers.some((p) => p.id === pid)) sel.value = pid;
      else if (mode === 'admin' && configured.base_url) { sel.value = '_custom'; $('customId').value = pid; }
      pickedModel = rest.join('/');
    }
    if (mode === 'admin') {
      if (configured.base_url) $('baseUrl').value = configured.base_url;
      rerunLook(s);
    }
    $('workspace').value = s.workspace || '';
    $('lan').checked = !!s.lan;
    $('modeHint').textContent = s.mode === 'system'
      ? '系統服務模式：設定在 ' + s.paths.config + '，資料在 ' + s.paths.data + '。'
      : '使用者模式：設定在 ' + s.paths.config + '。';
    syncProvider();
    $('wizard').hidden = false;
  }

  $('provider').addEventListener('change', syncProvider);
  $('testProvider').addEventListener('click', () => testProvider(false));
  // A key that was not tested yet is tested as soon as the field is left.
  const autoTest = () => { if ($('apiKey').value && tested !== testKey()) testProvider(true); };
  $('apiKey').addEventListener('change', autoTest);
  $('apiKey').addEventListener('blur', autoTest);
  $('baseUrl').addEventListener('change', () => { if (tested !== null && tested !== testKey()) testProvider(true); });
  $('modelFilter').addEventListener('input', drawModels);
  $('modelFilter').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); $('model').focus(); }
  });
  $('model').addEventListener('click', (e) => { const r = e.target.closest('.mrow'); if (r) pick(r.dataset.m); });
  // Keyboard: ↑↓ / PgUp PgDn / Home End move the selection; typing goes back to the filter.
  $('model').addEventListener('keydown', (e) => {
    const all = [...shownModels, OTHER];
    let i = all.indexOf(pickedModel);
    const step = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 }[e.key];
    if (step) { e.preventDefault(); i = Math.max(0, Math.min(all.length - 1, (i < 0 ? -1 : i) + step)); pick(all[i]); }
    else if (e.key === 'Home' || e.key === 'End') { e.preventDefault(); pick(all[e.key === 'Home' ? 0 : all.length - 1]); }
    else if (e.key === 'Enter') { e.preventDefault(); if (pickedModel === OTHER) $('modelOther').focus(); }
    else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey && e.key !== ' ') { e.preventDefault(); const f = $('modelFilter'); f.focus(); f.value += e.key; drawModels(); }
  });
  $('blockedConsole').addEventListener('click', () => { location.href = '/'; });
  $('wizard').addEventListener('submit', apply);
  for (const el of document.querySelectorAll('input[name="auth"]')) el.addEventListener('change', () => { $('oidcFields').hidden = radio('auth') !== 'oidc'; });
  $('channelKind').addEventListener('change', () => { $('channelFields').hidden = !$('channelKind').value; });
  // Step rail: highlight the section in view; a section counts as done once a field in it has a value.
  const links = [...document.querySelectorAll('#stepNav a')];
  const mark = () => {
    let cur = links[0];
    for (const a of links) { const f = document.querySelector(a.getAttribute('href')); if (f && f.getBoundingClientRect().top < innerHeight * 0.4) cur = a; }
    for (const a of links) {
      a.classList.toggle('on', a === cur);
      const f = document.querySelector(a.getAttribute('href'));
      a.classList.toggle('done', !!f && ([...f.querySelectorAll('input:not([type=radio]):not([type=checkbox]), select')].some((i) => i.value) || (a.getAttribute('href') === '#stepModel' && !!chosenModel())));
    }
  };
  addEventListener('scroll', mark, { passive: true });
  document.addEventListener('input', mark);
  setTimeout(mark, 300);
  start();
})();
