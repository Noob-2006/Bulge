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
  const current = () => providers.find((p) => p.id === $('provider').value);

  function syncProvider() {
    const p = current();
    const custom = $('provider').value === '_custom';
    $('customFields').hidden = !custom;
    $('keyField').hidden = !custom && p && !p.needs_key;
    $('baseUrl').placeholder = p ? p.base_url : 'https://…/v1';
    $('keyHint').textContent = p && p.has_key && p.needs_key ? '保管庫或環境中已有 ' + p.key_env + '；留空即沿用。' : '';
    $('models').replaceChildren();
  }

  function providerParams() {
    const custom = $('provider').value === '_custom';
    const out = { provider: custom ? $('customId').value.trim() : $('provider').value };
    if ($('baseUrl').value.trim()) out.base_url = $('baseUrl').value.trim();
    if ($('apiKey').value) out.api_key = $('apiKey').value;
    return out;
  }

  async function testProvider() {
    const st = $('testStatus');
    say(st, '連線中…');
    $('testProvider').disabled = true;
    try {
      const r = await rpc('setup.test_provider', providerParams());
      if (!r.ok) {
        say(st, '✗ ' + r.error, 'error');
        return;
      }
      say(st, '✓ 連線成功，' + r.count + ' 個模型', 'ok');
      const dl = $('models');
      dl.replaceChildren(...r.models.map((m) => Object.assign(document.createElement('option'), { value: m })));
      if (!$('model').value && r.models.length) {
        const pref = ['sonnet', 'flash', 'chat', 'plus', 'latest'];
        $('model').value = pref.map((p) => r.models.find((m) => m.includes(p))).find(Boolean) || r.models[0];
      }
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
    params.model = $('model').value.trim();
    if (!params.provider || !params.model) {
      say(st, '請選擇供應商並填入模型名稱', 'error');
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
    const sel = $('provider');
    sel.replaceChildren(...providers.map((p) => Object.assign(document.createElement('option'), { value: p.id, textContent: p.label + (p.has_key && p.needs_key ? '（已有金鑰）' : '') })));
    sel.append(Object.assign(document.createElement('option'), { value: '_custom', textContent: '自訂 OpenAI 相容端點' }));
    const cur = s.configured && s.configured.model;
    if (cur) {
      const [pid, ...rest] = cur.split('/');
      if (providers.some((p) => p.id === pid)) sel.value = pid;
      $('model').value = rest.join('/');
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
  $('testProvider').addEventListener('click', testProvider);
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
