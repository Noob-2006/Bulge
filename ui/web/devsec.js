// Connected devices and the network perimeter, under the LAN devices section of the Devices
// view (ops.js calls devSecSection / devSecBind; docs/SECURITY.md §8). Per device: key binding,
// scope (view only / full control / may approve), last seen and address, revoke; for all of
// them "sign out all devices"; the public-exposure warning and the recent security events
// (lockouts, pairings, refused requests) from the audit stream.
'use strict';

const DEVSEC_SCOPES = [['read', '只能檢視', 'view only'], ['write', '完整操作', 'full control'], ['approve', '也可核准', 'can approve']];

function devSecSection(d, lan) {
  if (!d) return '';
  const devs = d.devices || [];
  let h = `<section class="c12" id="devSec">${secH('07', L('連線裝置與安全', 'Connected devices & security'), devs.length ? `<button class="btn ghost small" data-devsec-signout data-write>${L('登出所有裝置', 'Sign out all devices')}</button>` : '')}`;
  if (lan && lan.publicExposure) h += `<p class="bad"><strong>${L('公開暴露已開啟', 'Public exposure is on')}</strong> — ${ov(lan.warning || '')}</p>`;
  if (lan && (lan.allowSources || []).length) h += `<p class="dim">${L('只接受來源', 'Only these sources')}: <code>${ov(lan.allowSources.join(', '))}</code></p>`;
  if (devs.length) {
    h += '<table class="kv"><tr><th>' + [L('裝置', 'Device'), L('權限', 'Access'), L('裝置金鑰', 'Device key'), L('最近', 'Last seen'), L('位址', 'Address')].join('</th><th>') + '</th></tr>';
    h += devs.map((x) => `<tr><td><strong>${ov(x.name)}</strong> <span class="faint">${ov(x.platform || '')}</span></td>`
      + `<td><select data-devsec-scope="${ov(x.id)}" data-write>${DEVSEC_SCOPES.map(([v, zh, en]) => `<option value="${v}"${x.scope === v ? ' selected' : ''}>${L(zh, en)}</option>`).join('')}${x.scope === 'admin' ? '<option value="admin" selected>admin</option>' : ''}</select></td>`
      + `<td>${x.keyBound ? `<span class="ok">${L('已綁定', 'bound')}</span>` : `<span class="warn" title="${L('舊版 App／瀏覽器：下次啟動時自動綁定', 'older app / browser: binds on its next start')}">${L('未綁定', 'not bound')}</span>`}</td>`
      + `<td>${ago(x.lastSeenMs)}</td><td class="mono">${ov(x.lastIp || '—')}</td></tr>`).join('');
    h += '</table>';
  }
  h += `<div id="devSecEvents" class="dim">${L('載入安全事件…', 'Loading security events…')}</div></section>`;
  return h;
}

async function devSecEvents(box) {
  const kinds = ['auth.lockout', 'device.pair', 'device.bind', 'device.refresh', 'net.refused', 'exposure.public', 'device.revoke_all'];
  try {
    const lists = await Promise.all(kinds.map((kind) => S.arp.call('audit.query', { kind, limit: 10 }).catch(() => [])));
    const evs = lists.flat().sort((a, b) => (b.ts_ms || b.ts || 0) - (a.ts_ms || a.ts || 0)).slice(0, 12);
    box.innerHTML = evs.length
      ? '<div class="slist">' + evs.map((e) => `<div class="srow"><span class="light ${e.outcome === 'ok' ? 'ok' : 'warn'}"></span><span><strong>${ov(e.kind)}</strong> <span class="faint mono">${ov((e.actor && e.actor.ip) || '')}</span><span class="sub">${ov(e.target || '')} · ${ov(e.outcome || '')}${e.detail && e.detail.reason ? ' · ' + ov(e.detail.reason) : ''}</span></span><span class="r faint">${ago(e.ts_ms || e.ts)}</span></div>`).join('') + '</div>'
      : `<div class="none">${L('沒有安全事件。', 'No security events.')}</div>`;
  } catch (e) { box.textContent = e.message; }
}

function devSecBind(el, rerender) {
  const box = el.querySelector('#devSecEvents');
  if (box) devSecEvents(box);
  for (const s of el.querySelectorAll('[data-devsec-scope]')) s.onchange = async () => {
    try { await S.arp.call('devices.scope', { id: s.dataset.devsecScope, scope: s.value }); toast(L('已更新權限', 'Access updated')); } catch (e) { toast(e.message, true); rerender(); }
  };
  const out = el.querySelector('[data-devsec-signout]');
  if (out) out.onclick = async () => {
    if (!confirm(L('所有配對的裝置都要重新配對，開著的連線會立刻中斷。確定？', 'Every paired device will have to pair again and open connections close now. Continue?'))) return;
    try { const r = await S.arp.call('devices.revoke_all', {}); toast(L(`已登出 ${r.revoked} 台裝置`, `Signed out ${r.revoked} device(s)`)); } catch (e) { toast(e.message, true); }
    rerender();
  };
}
