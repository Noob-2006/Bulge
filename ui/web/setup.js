// seagent first-run setup wizard. Talks to POST /setup/rpc (JSON-RPC 2.0) with the one-time setup
// token from the URL fragment (#token=…) in the x-seagent-setup-token header. The token is removed
// from the address bar at once so it does not linger in history or screenshots.
'use strict';
(function () {
  const $ = (id) => document.getElementById(id);
  const frag = new URLSearchParams(location.hash.replace(/^#/, ''));
  const token = frag.get('token') || sessionStorage.getItem('seagent.setup') || '';
  if (frag.get('token')) {
    sessionStorage.setItem('seagent.setup', token);
    history.replaceState(null, '', location.pathname);
  }
  let seq = 0;

  async function rpc(method, params) {
    const r = await fetch('/setup/rpc', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-seagent-setup-token': token },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++seq, method, params: params || {} }),
      credentials: 'omit',
      cache: 'no-store',
    });
    const j = await r.json();
    if (j.error) throw new Error(j.error.message || 'error');
    return j.result;
  }

  function say(el, text, kind) {
    el.textContent = text || '';
    el.className = 'status' + (kind ? ' ' + kind : '');
  }

  function blocked(reason) {
    $('wizard').hidden = true;
    $('blocked').hidden = false;
    $('blockedReason').textContent = reason;
  }

  let providers = [];
  let priceInfo = null;
  let modelPrices = {};
  const current = () => providers.find((p) => p.id === $('provider').value);

  // Prices are looked up on this machine (models.dev price list or the snapshots built into SE
  // Agent), USD per million tokens, input / output.
  const fmtPrice = (p) => {
    const f = (x) => (x >= 100 ? x.toFixed(0) : x >= 0.1 ? x.toFixed(2) : String(+x.toFixed(4)));
    return '$' + f(p.in) + ' / $' + f(p.out);
  };
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

  function syncProvider() {
    const p = current();
    const custom = $('provider').value === '_custom';
    $('customFields').hidden = !custom;
    $('keyField').hidden = !custom && p && !p.needs_key;
    $('baseUrl').placeholder = p ? p.base_url : 'https://…/v1';
    $('keyHint').textContent = p && p.has_key && p.needs_key ? '保管庫或環境中已有 ' + p.key_env + '；留空即沿用。' : '';
    tested = null;
    say($('testStatus'), '');
    // Before a successful test: the provider's built-in list (the console pickers' offline list).
    modelPrices = (p && p.prices) || {};
    setModels(p ? p.models || [] : [], p ? p.recommended : '', p ? 'builtin' : 'none');
    // Nothing to type for these: fetch the live list right away.
    if (p && (!p.needs_key || p.has_key)) testProvider(true);
  }

  // ── the model list: every model the provider offers, one click to choose ──
  // A scrollable listbox (always open) with type-to-filter above it; "other…" at the end reveals
  // a text field for a name the list does not have.
  const OTHER = ' other';
  let modelList = [];
  let pickedModel = '';
  let modelSource = 'none';
  let tested = null;

  function setModels(list, recommended, source) {
    const seen = new Set();
    modelList = (list || []).filter((m) => m && !seen.has(m) && seen.add(m));
    modelSource = source;
    const keep = pickedModel && modelList.includes(pickedModel) ? pickedModel : '';
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
    const sel = $('model');
    const shown = modelList.filter((m) => !q || m.toLowerCase().includes(q));
    const opts = shown.map((m) => {
      const pr = modelPrices[m];
      return Object.assign(document.createElement('option'), { value: m, textContent: pr ? m + '　·　' + fmtPrice(pr) : m, title: pr ? fmtPrice(pr) + ' 每百萬 tokens（輸入 / 輸出）' : '' });
    });
    const other = Object.assign(document.createElement('option'), { value: OTHER, textContent: '其他（自行輸入模型名稱）…', className: 'other' });
    sel.replaceChildren(...opts, other);
    // Tall enough to show a typical provider's whole list at once; longer lists scroll.
    sel.size = Math.max(4, Math.min(shown.length + 1, 16));
    if (pickedModel === OTHER) sel.value = OTHER;
    else if (shown.includes(pickedModel)) sel.value = pickedModel;
    else if (q && shown.length) sel.value = shown[0];
    else sel.selectedIndex = -1;
    $('modelOtherField').hidden = sel.value !== OTHER;
    priceLegend();
    $('modelCount').textContent = modelList.length ? (q ? shown.length + ' / ' : '') + modelList.length + ' 個' + (modelSource === 'live' ? '（即時）' : '（內建）') : '';
    const cur = sel.selectedOptions[0];
    if (cur) cur.scrollIntoView({ block: 'nearest' });
  }

  function chosenModel() {
    const v = $('model').value;
    return v === OTHER ? $('modelOther').value.trim() : v;
  }

  function providerParams() {
    const custom = $('provider').value === '_custom';
    const out = { provider: custom ? $('customId').value.trim() : $('provider').value };
    if ($('baseUrl').value.trim()) out.base_url = $('baseUrl').value.trim();
    if ($('apiKey').value) out.api_key = $('apiKey').value;
    return out;
  }

  const testKey = () => JSON.stringify(providerParams());

  // `auto`: started by leaving the key field / choosing a provider rather than by the button —
  // stays quiet about a missing key.
  async function testProvider(auto) {
    const st = $('testStatus');
    const p = current();
    if (auto === true && p && p.needs_key && !p.has_key && !$('apiKey').value) return;
    const key = testKey();
    say(st, '連線中…');
    $('testProvider').disabled = true;
    try {
      const r = await rpc('setup.test_provider', providerParams());
      if (key !== testKey()) return; // the provider or key changed meanwhile
      tested = key;
      if (!r.ok) {
        say(st, '✗ ' + r.error, 'error');
        return;
      }
      say(st, '✓ 連線成功，' + r.count + ' 個模型', 'ok');
      modelPrices = r.prices || {};
      setModels(r.models || [], r.recommended, 'live');
      // The whole list at once, ready to click.
      $('stepModel').scrollIntoView({ behavior: 'smooth', block: 'start' });
      $('model').focus({ preventScroll: true });
    } catch (e) {
      say(st, '✗ ' + e.message, 'error');
    } finally {
      $('testProvider').disabled = false;
    }
  }

  function radio(name) {
    const el = document.querySelector('input[name="' + name + '"]:checked');
    return el ? el.value : '';
  }

  async function apply(ev) {
    ev.preventDefault();
    const st = $('applyStatus');
    const params = providerParams();
    params.model = chosenModel();
    if (!params.provider || !params.model) {
      say(st, '請選擇供應商與模型', 'error');
      return;
    }
    params.security = radio('security');
    if ($('workspace').value.trim()) params.workspace = $('workspace').value.trim();
    params.auth = { mode: radio('auth') };
    if (params.auth.mode === 'oidc') {
      params.auth.issuer = $('oidcIssuer').value.trim();
      params.auth.client_id = $('oidcClient').value.trim();
      if ($('oidcSecret').value) params.auth.client_secret = $('oidcSecret').value;
    }
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
      $('consoleLink').href = r.console_url;
      waitForRestart(r.console_url);
    } catch (e) {
      say(st, '✗ ' + e.message, 'error');
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

  async function start() {
    if (!token) {
      blocked('這個網址沒有設定權杖。');
      return;
    }
    let s;
    try {
      s = await rpc('setup.status');
    } catch (e) {
      blocked(e.message);
      return;
    }
    if (!s.token_valid) {
      blocked(s.locked ? '設定已完成，精靈已鎖定。' : (s.reason || '設定連結無效或已過期。'));
      return;
    }
    providers = s.providers || [];
    priceInfo = s.prices || null;
    const sel = $('provider');
    sel.replaceChildren(...providers.map((p) => Object.assign(document.createElement('option'), { value: p.id, textContent: p.label + (p.has_key && p.needs_key ? '（已有金鑰）' : '') })));
    sel.append(Object.assign(document.createElement('option'), { value: '_custom', textContent: '自訂 OpenAI 相容端點' }));
    const cur = s.configured && s.configured.model;
    if (cur) {
      const [pid, ...rest] = cur.split('/');
      if (providers.some((p) => p.id === pid)) sel.value = pid;
      pickedModel = rest.join('/');
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
  $('model').addEventListener('change', () => {
    pickedModel = $('model').value;
    $('modelOtherField').hidden = pickedModel !== OTHER;
    if (pickedModel === OTHER) $('modelOther').focus();
  });
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
      a.classList.toggle('done', !!f && [...f.querySelectorAll('input:not([type=radio]):not([type=checkbox]), select')].some((i) => i.value));
    }
  };
  addEventListener('scroll', mark, { passive: true });
  document.addEventListener('input', mark);
  setTimeout(mark, 300);
  start();
})();
