// The built-in VM panel, shared by the first-run wizard (setup.js, `setup.vm_*` with the setup
// token) and the console's Settings → Virtual machine page (pages.js, `ui.vm.*` with the app
// token). Shows which hypervisor runtime and accelerator are in use, whether the guest image is
// ready, which sandbox the tools run in right now and what it can reach; one click sets up /
// repairs the VM (verify the shipped files, boot a test VM, run `uname -a` in it). On Windows
// without the Windows Hypervisor Platform it offers a button that only opens the Windows
// Features dialog — the user turns the feature on, SE Agent never changes system settings.
'use strict';
(function () {
  const esc = (s) => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const row = (k, val) => `<tr><th>${esc(k)}</th><td>${val}</td></tr>`;
  const IMAGE = { ready: '就緒 (ready)', missing: '缺少 (missing)', damaged: '損壞 (damaged)' };

  function html(st) {
    const rt = st.runtime || {};
    const img = st.image || {};
    const act = st.active || {};
    const accel = st.accel ? `${esc(st.accel.label)}${st.accel.hardware ? '' : ' <span class="bad">— 軟體模擬，較慢</span>'}` : '<span class="dim">—</span>';
    const runtime = rt.path
      ? `${esc(rt.kind || '')} ${rt.version ? esc(rt.version) : ''} <span class="dim">(${esc(rt.source)})</span><div class="dim mono">${esc(rt.path)}</div>`
      : '<span class="bad">找不到 hypervisor (missing)</span>';
    const image = `${img.state === 'ready' ? '<span class="ok">✓</span> ' : '<span class="bad">✗</span> '}${esc(IMAGE[img.state] || img.state)}${img.source ? ` <span class="dim">(${esc(img.source)})</span>` : ''}${img.detail ? `<div class="bad">${esc(img.detail)}</div>` : ''}${img.pinned ? `<div class="dim">pin: ${esc(img.pinned)}</div>` : ''}`;
    const active = `${act.microvm ? '<span class="ok">✓ microVM</span>' : `<span class="bad">${esc(act.level)}</span>`} <span class="dim">(${esc(act.backend)}${act.provider ? ' via ' + esc(act.provider) : ''})</span>`;
    const reach = (st.reach || []).map((r) => `<li>${esc(r)}</li>`).join('');
    const advice = (st.advice || []).map((a) => `<div class="vm-advice"><p>${esc(a.text)}</p>${a.action ? `<button type="button" class="btn small secondary" data-vm-action="${esc(a.action)}">${esc(a.button || a.action)}</button>` : ''}</div>`).join('');
    return `<p class="vm-message"><strong>${esc(st.message)}</strong></p>
      <table class="kv vm-status">
        ${row('目前的沙箱 (active sandbox)', active)}
        ${row('Hypervisor', runtime)}
        ${row('硬體加速 (acceleration)', accel)}
        ${row('Guest image', image)}
        ${row('內建 VM (bundled)', st.bundled ? '是 (shipped with this app)' : '<span class="dim">否 — development / server install</span>')}
      </table>
      <p><strong>可以存取 (what it can reach)</strong></p><ul class="vm-reach">${reach}</ul>
      ${advice}
      <p class="row"><button type="button" class="btn small" data-vm-action="repair">設定／修復 VM (Set up / repair VM)</button> <span class="vm-progress status" role="status" aria-live="polite"></span></p>
      <div class="vm-result"></div>`;
  }

  function resultHtml(r) {
    const steps = (r.steps || []).map((s) => `<li>${s.ok ? '<span class="ok">✓</span>' : '<span class="bad">✗</span>'} ${esc(s.name)} — ${esc(s.detail)}</li>`).join('');
    return `<ul class="log">${steps}</ul>${r.uname ? `<p>VM 回應 (guest answered): <code>${esc(r.uname)}</code></p>` : ''}`;
  }

  // `rpc(method, params)` returns a promise of the result; `names` = {status, repair, open}.
  async function mount(el, rpc, names) {
    if (!el) return;
    el.innerHTML = '<p class="dim">讀取 VM 狀態中… (checking the VM)</p>';
    try { draw(el, rpc, names, await rpc(names.status, {}), '', ''); } catch (e) { el.innerHTML = `<p class="bad">${esc(e.message)}</p>`; }
  }

  function draw(el, rpc, names, st, result, progress) {
    el.innerHTML = html(st);
    el.querySelector('.vm-result').innerHTML = result;
    const prog = el.querySelector('.vm-progress');
    prog.textContent = progress;
    for (const b of el.querySelectorAll('[data-vm-action]')) {
      b.addEventListener('click', async () => {
        if (b.dataset.vmAction === 'open_hypervisor_settings') {
          try { await rpc(names.open, {}); prog.textContent = '已開啟「Windows 功能」：勾選 Windows Hypervisor Platform，按確定後重新啟動 Windows。'; } catch (e) { prog.textContent = '✗ ' + e.message; }
          return;
        }
        for (const x of el.querySelectorAll('button')) x.disabled = true;
        prog.textContent = '檢查檔案並啟動測試 VM… (verifying files and booting a test VM)';
        try {
          const r = await rpc(names.repair, {});
          draw(el, rpc, names, r.status || st, resultHtml(r), r.ok ? '✓ VM 可以使用 (the VM works)' : '✗ VM 還不能用 (see the steps below)');
        } catch (e) {
          prog.textContent = '✗ ' + e.message;
          for (const x of el.querySelectorAll('button')) x.disabled = false;
        }
      });
    }
  }

  window.SeagentVm = { html, mount };
})();
