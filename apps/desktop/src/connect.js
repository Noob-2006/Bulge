// Connect / pair with an SE Agent host on the LAN (iOS always; Android "another computer").
// Identity = SHA-256 of the host's TLS certificate: pinned from the QR code, or shown here and on
// the host for the user to compare (8-character code flow). Pairing and the pinned tunnel are in
// Rust (src-tauri/src/commands.rs, tls.rs); this page only collects input.
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let pending = null; // {args for pair_host, short}

  function status(msg, kind) {
    $('status').textContent = msg || '';
    $('status').className = 'status ' + (kind || '');
  }
  const err = (e) => String((e && e.message) || e);

  function hostItem(h, buttons) {
    const li = document.createElement('li');
    const meta = document.createElement('div');
    meta.append(Object.assign(document.createElement('strong'), { textContent: h.name }), Object.assign(document.createElement('span'), { className: 'faint mono small', textContent: h.address + (h.fingerprint ? ' · ' + h.fingerprint : '') }));
    const act = document.createElement('div');
    act.className = 'actions';
    for (const [label, cls, fn] of buttons) {
      const b = Object.assign(document.createElement('button'), { className: 'btn small ' + cls, textContent: label });
      b.addEventListener('click', fn);
      act.append(b);
    }
    li.append(meta, act);
    return li;
  }

  async function open(id) {
    status(SE.t('connecting'));
    try {
      await SE.invoke('host_open', { id });
    } catch (e) {
      status(err(e), 'bad');
    }
  }

  async function loadPaired() {
    const hosts = await SE.invoke('hosts_list');
    $('paired').replaceChildren(...hosts.map((h) => hostItem(h, [
      [SE.t('open'), '', () => open(h.id)],
      [SE.t('forget'), 'ghost', async (ev) => {
        // window.confirm is not available in every mobile WebView: tap twice instead.
        const b = ev.currentTarget;
        if (!b.dataset.armed) {
          b.dataset.armed = '1';
          b.textContent = SE.t('forgetAsk');
          setTimeout(() => { delete b.dataset.armed; b.textContent = SE.t('forget'); }, 4000);
          return;
        }
        await SE.invoke('host_forget', { id: h.id });
        loadPaired();
      }],
    ])));
    $('pairedNone').hidden = hosts.length > 0;
    return hosts;
  }

  async function discover() {
    $('nearbyState').hidden = false;
    $('nearbyState').textContent = SE.t('searching');
    $('rescan').disabled = true;
    try {
      const found = await SE.invoke('discover_hosts');
      $('nearby').replaceChildren(...found.map((h) => hostItem({ name: h.name, address: h.address }, [[SE.t('pair'), '', () => {
        $('address').value = h.address;
        $('address').dataset.fpPrefix = h.fpPrefix || '';
        $('code').focus();
      }]])));
      $('nearbyState').hidden = found.length > 0;
      $('nearbyState').textContent = SE.t('noneFound');
    } catch (e) {
      $('nearbyState').textContent = err(e);
    } finally {
      $('rescan').disabled = false;
    }
  }

  function ask(args, short) {
    pending = args;
    $('fp').textContent = short;
    $('confirm').hidden = false;
    $('confirm').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  async function pair() {
    if (!pending) return;
    $('doPair').disabled = true;
    status(SE.t('pairing'));
    try {
      const h = await SE.invoke('pair_host', { args: pending });
      pending = null;
      $('confirm').hidden = true;
      $('code').value = '';
      await loadPaired();
      await open(h.id);
    } catch (e) {
      status(err(e), 'bad');
    } finally {
      $('doPair').disabled = false;
    }
  }

  async function fromSetupCode(text) {
    const sc = await SE.invoke('parse_setup_code', { text });
    if (sc.fingerprint) {
      // The QR carried the pin: still show it, the user can compare with the host's screen.
      ask({ setupCode: text }, sc.short);
      return;
    }
    const p = await SE.invoke('probe_host', { address: sc.address });
    ask({ setupCode: text, fingerprint: p.fingerprint }, p.short);
  }

  async function scan() {
    status('');
    try {
      const perm = await SE.invoke('plugin:barcode-scanner|request_permissions');
      if (perm && perm.camera && perm.camera !== 'granted') {
        status('Camera permission was denied.', 'bad');
        return;
      }
      const r = await SE.invoke('plugin:barcode-scanner|scan', { formats: ['QR_CODE'], windowed: false });
      if (r && r.content) await fromSetupCode(r.content.trim());
    } catch (e) {
      status(err(e), 'bad');
    }
  }

  $('codeForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    status('');
    const address = $('address').value.trim();
    const code = $('code').value.trim();
    // A pasted seagent-pair:// link or bare setup code works here too.
    if (/^(seagent-pair|oc-pair):\/\//i.test(address) || (address.length > 40 && !address.includes('.'))) {
      try { await fromSetupCode(address); } catch (e) { status(err(e), 'bad'); }
      return;
    }
    try {
      const p = await SE.invoke('probe_host', { address });
      ask({ address, code, fingerprint: p.fingerprint, fpPrefix: $('address').dataset.fpPrefix || null }, p.short);
    } catch (e) {
      status(err(e), 'bad');
    }
  });
  $('doPair').addEventListener('click', pair);
  $('cancelPair').addEventListener('click', () => { pending = null; $('confirm').hidden = true; status(''); });
  $('rescan').addEventListener('click', discover);
  $('scan').addEventListener('click', scan);
  $('useLocal').addEventListener('click', async () => {
    await SE.invoke('set_mode', { mode: 'local' });
    location.href = 'index.html';
  });
  $('address').addEventListener('input', () => { delete $('address').dataset.fpPrefix; });

  (async function main() {
    const info = await SE.invoke('app_info');
    $('iosNotice').hidden = info.platform !== 'ios';
    $('useLocal').hidden = !info.canRunLocal || !(info.platform === 'android' || info.platform === 'ios');
    $('scan').hidden = !(info.platform === 'ios' || info.platform === 'android');
    const hosts = await loadPaired();
    // One paired host and we just launched: go straight to it (it may be offline: stay here then).
    if (hosts.length === 1 && !sessionStorage.getItem('seagent.connect.seen')) {
      sessionStorage.setItem('seagent.connect.seen', '1');
      open(hosts[0].id);
    }
    discover();
  })().catch((e) => status(err(e), 'bad'));
})();
