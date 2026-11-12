// Splash: shows the boot sequence run by the app (src-tauri/src/boot.rs) — locate the agent,
// write the initial config, start the background service, wait for it, then the window moves on
// to the agent's own setup wizard or console. Errors get Retry + Copy details.
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const STEPS = ['locate', 'bootstrap', 'service', 'health', 'route'];
  let last = null;

  function renderSteps(cur, failed) {
    const at = STEPS.indexOf(cur);
    $('steps').replaceChildren(...STEPS.map((s, i) => {
      const li = document.createElement('li');
      const dot = Object.assign(document.createElement('span'), { className: 'star' });
      if (i < at || cur === 'done') dot.classList.add('ok');
      else if (i === at) dot.classList.add(failed ? 'crit' : 'pulse');
      else dot.classList.add('off');
      li.append(dot, document.createTextNode(SE.t('s_' + s)));
      if (i === at && !failed) li.className = 'current';
      return li;
    }));
  }

  function render(s) {
    last = s;
    // The supervisor's "restarting…" screen (src-tauri/src/supervise.rs) has no boot steps.
    $('steps').hidden = s.step === 'restarting';
    if (s.title) $('title').textContent = s.title;
    $('fill').style.width = Math.max(4, s.progress || 0) + '%';
    $('bar').setAttribute('aria-valuenow', String(s.progress || 0));
    $('bar').classList.toggle('bad', !!s.error);
    renderSteps(s.step, !!s.error);
    $('details').textContent = (s.log || []).join('\n') + (s.error ? '\n\nerror: ' + s.error : '');
    if (s.error) {
      $('progress').hidden = false;
      $('failed').hidden = false;
      $('error').textContent = s.error;
      $('logo').className = 'star logo crit';
    } else {
      $('failed').hidden = true;
      $('logo').className = 'star glow pulse logo';
    }
  }

  async function boot() {
    $('failed').hidden = true;
    $('copied').hidden = true;
    try {
      render(await SE.invoke('boot_start'));
    } catch (e) {
      render({ step: 'locate', progress: 0, error: String(e && e.message || e), log: [] });
    }
  }

  $('retry').addEventListener('click', boot);
  $('copy').addEventListener('click', async () => {
    const text = 'SE Agent — startup details\n' + navigator.userAgent + '\n\n' + $('details').textContent;
    $('copied').hidden = !(await SE.copy(text));
  });
  $('toggle').addEventListener('click', () => {
    const d = $('details');
    d.hidden = !d.hidden;
    $('toggle').textContent = SE.t(d.hidden ? 'show' : 'hide');
  });

  $('chooseLocal').addEventListener('click', async () => {
    await SE.invoke('set_mode', { mode: 'local' });
    $('choose').hidden = true;
    $('progress').hidden = false;
    boot();
  });
  $('chooseRemote').addEventListener('click', async () => {
    await SE.invoke('set_mode', { mode: 'remote' });
    location.href = 'connect.html';
  });
  $('pairInstead').addEventListener('click', async () => {
    await SE.invoke('set_mode', { mode: 'remote' });
    location.href = 'connect.html';
  });

  async function main() {
    SE.listen('boot', render);
    let info;
    try {
      info = await SE.invoke('app_info');
    } catch (e) {
      render({ step: 'locate', progress: 0, error: String(e && e.message || e), log: [] });
      return;
    }
    $('version').textContent = 'v' + info.version;
    if (info.mode === 'remote') {
      location.replace('connect.html');
      return;
    }
    // iOS: the agent runs in this app by default; pairing a computer stays one tap away.
    if (info.platform === 'ios') {
      $('iosNotice').hidden = false;
      $('pairInstead').hidden = false;
    }
    if (info.platform === 'android' && !info.mode) {
      $('progress').hidden = true;
      $('choose').hidden = false;
      return;
    }
    // The app is bringing a stopped agent back (after the setup wizard, a crash): show that and
    // wait; the app returns to the console by itself. Retry stays available if it fails.
    if (location.hash === '#restarting') {
      render(await SE.invoke('boot_state'));
      return;
    }
    // A boot may already be running (started in the background): show it, else start one.
    const s = await SE.invoke('boot_state');
    if (s.running || s.url) render(s);
    if (!s.running) boot();
  }

  renderSteps('locate', false);
  main();
})();
