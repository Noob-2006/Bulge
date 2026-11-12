// seagent web UI: the "API keys" Control page (#page=apikeys). Add, view (masked), replace,
// delete and test each provider's key, and see / refresh the provider's live model list.
// Keys go only to the secret vault (`ui.keys.*`, crates/seagent/src/ops/model_keys.rs); the page
// never receives a stored value, only "••••" plus its last four characters.
// Registers itself into pages.js (PAGES / EXTRA_PAGES); uses app.js / pages.js globals: S, $,
// esc, toast, call, row, q, qa, note, act, openPage, NOTE; chat_menu.js: tt, srcLabel.
'use strict';

const KP = { open: null, results: {}, models: {}, bal: {} };
const kpSource = (s) => ({
  vault: 'vault', env: tt('環境變數', 'environment'), config: tt('設定檔（明文）', 'config (plaintext)'),
  'credential store': tt('登入憑證', 'login / credential store'), key_cmd: 'key_cmd', none: tt('不需要', 'not needed'), cloud: tt('雲端憑證', 'cloud credentials'), missing: tt('未設定', 'not set'),
}[s] || s);

// Sources where a key is actually held (the rest — cloud credential chains, keyless servers —
// are offered under "Add a key").
const KP_HELD = ['vault', 'env', 'config', 'credential store', 'key_cmd'];

// A provider's balance as its own endpoint reported it (ui.keys.balance).
const kpCredit = (c) => {
  const n = (x) => Number(x).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  if (c.remaining !== null && c.remaining !== undefined) return `${c.currency} ${n(c.remaining)}${c.limit !== null && c.limit !== undefined ? tt(` / 上限 ${n(c.limit)}`, ` of ${n(c.limit)}`) : ''}`;
  if (c.used !== null && c.used !== undefined) return tt(`已用 ${c.currency} ${n(c.used)}（無上限）`, `${c.currency} ${n(c.used)} used (no limit)`);
  return c.currency;
};
const kpBalance = (p) => {
  if (!p.balance) return `<span class="faint" title="${esc(tt('這個供應商沒有可用金鑰查詢的餘額 API（或設定指向非官方位址），請到供應商的網站查看。', 'This provider has no balance API a key can query (or the config points at a non-official address); check its website.'))}">—</span>`;
  const b = KP.bal[p.id];
  const btn = `<button class="btn ghost small" data-bal="${esc(p.id)}" title="${esc(tt('向供應商查詢帳戶餘額（使用已存的金鑰）', 'Ask the provider for the account balance (with the stored key)'))}">${esc(b ? '↻' : tt('查詢', 'Check'))}</button>`;
  if (!b) return btn;
  if (b.loading) return `<span class="faint">${esc(tt('查詢中…', 'Checking…'))}</span>`;
  if (!b.ok) return `<span class="bad" title="${esc(b.error || '')}">${esc(tt('查詢失敗', 'Failed'))}</span> ${btn}`;
  const credits = (b.credits || []).map(kpCredit).join('<br>') || esc(tt('沒有餘額資料', 'no balance data'));
  return `<span class="bal" title="${esc(tt('供應商回報的實際餘額', 'The real balance the provider reported'))}">${esc(credits).replace(/&lt;br&gt;/g, '<br>')}</span> ${btn}<br><span class="faint">${esc(tt('供應商回報', 'from the provider'))} · ${esc(agoLong(b.fetched_ms))}</span>${b.note ? `<br><span class="warn">${esc(b.note)}</span>` : ''}`;
};

PAGES.apikeys = { get title() { return tt('API 金鑰', 'API keys'); }, group: '設定', async render() {
  const r = await call('ui.keys.list');
  const prices = await pricesStatus();
  const ps = r.providers || [];
  const has = ps.filter((p) => KP_HELD.includes(p.source) || p.in_vault);
  const rest = ps.filter((p) => !has.includes(p)).sort((a, b) => String(a.label).localeCompare(String(b.label)));
  KP.list = ps;
  const res = (id) => { const x = KP.results[id]; return x ? `<div class="res ${x.ok ? 'ok' : 'bad'}">${x.ok ? `✓ ${esc(tt(`可用：${x.models} 個模型`, `works: ${x.models} models`))}${x.sample && x.sample.length ? ' · ' + esc(x.sample.join(', ')) : ''} <span class="faint">${x.ms} ms</span>` : `✗ ${esc(x.error || '')}`}</div>` : ''; };
  const models = (id) => { const m = KP.models[id]; return m ? `<div class="models">${esc(srcLabel(m))}${m.fetched_ms ? ' · ' + esc(new Date(m.fetched_ms).toLocaleString()) : ''}${m.error ? ' · ' + esc(m.error) : ''}\n${esc((m.models || []).map((x) => x.id).join('\n'))}</div>` : ''; };
  const warn = (p) => [
    p.env_override ? `<div class="res bad">${esc(tt(`環境變數 ${p.env_override} 會優先於 vault 的值`, `$${p.env_override} in the environment wins over the vault value`))}</div>` : '',
    p.plaintext_in_config ? `<div class="res bad">${esc(tt('設定檔裡有明文金鑰；在這裡儲存會把它移到 vault 並從設定檔刪除', 'A plaintext key is in the config; saving here moves it to the vault and removes it from the config'))}</div>` : '',
  ].join('');
  const rows = has.map((p) => row([
    `<strong>${esc(p.label)}</strong><br><code>${esc(p.id)}</code>`,
    `<code>${esc(p.name)}</code>`,
    `<span class="masked">${esc(p.masked || '—')}</span>`,
    `${esc(kpSource(p.source))}${p.models_cached ? `<br><span class="faint">${esc(tt(`${p.models_cached} 個模型（快取）`, `${p.models_cached} models cached`))}</span>` : ''}`,
    kpBalance(p),
    `<div class="acts"><button class="btn ghost small" data-test="${esc(p.id)}">${esc(tt('測試', 'Test'))}</button><button class="btn ghost small" data-read data-models="${esc(p.id)}">${esc(tt('模型', 'Models'))}</button><button class="btn ghost small" data-edit="${esc(p.id)}">${esc(p.in_vault ? tt('更換', 'Replace') : tt('存入 vault', 'Store in vault'))}</button>${p.in_vault || p.plaintext_in_config ? `<button class="btn ghost small" data-del="${esc(p.id)}">${esc(tt('刪除', 'Delete'))}</button>` : ''}</div>
      ${KP.open === p.id ? `<div class="edit"><input type="password" data-key="${esc(p.id)}" autocomplete="new-password" spellcheck="false" placeholder="${esc(tt('新的金鑰', 'New key'))}"><button class="btn ghost small" data-trynew="${esc(p.id)}">${esc(tt('先測試', 'Test first'))}</button><button class="btn small" data-save="${esc(p.id)}">${esc(tt('儲存', 'Save'))}</button><button class="btn ghost small" data-cancel>${esc(tt('取消', 'Cancel'))}</button></div>` : ''}
      ${warn(p)}${res(p.id)}${models(p.id)}`,
  ])).join('');
  return `<div class="cm-keys">
    <p class="dim">${esc(tt('金鑰只存在 secret vault（', 'Keys are stored only in the secret vault ('))}<code>${esc(r.vault || '')}</code>${esc(tt('），頁面只顯示最後四個字元。更換後下一個請求就會使用新金鑰。', '); this page only ever shows the last four characters. A replaced key is used from the next request on.'))}</p>
    <p class="kp-prices">${priceSrcHtml(prices)} <span class="faint">${esc(tt('· 畫面上的費用是估算；「餘額」欄是供應商回報的實際數字。', '· costs shown are estimates; the Balance column is what the provider itself reports.'))}</span></p>
    ${has.length ? `<table class="kv"><tr><th>${esc(tt('供應商', 'Provider'))}</th><th>${esc(tt('名稱', 'Name'))}</th><th>${esc(tt('金鑰', 'Key'))}</th><th>${esc(tt('來源', 'Source'))}</th><th>${esc(tt('餘額', 'Balance'))}</th><th></th></tr>${rows}</table>` : `<p class="dim">${esc(tt('還沒有任何金鑰。', 'No keys yet.'))}</p>`}
    <h3>${esc(tt('新增金鑰', 'Add a key'))}</h3>
    <div class="add"><select id="kpProv" aria-label="${esc(tt('供應商', 'Provider'))}"><option value="">${esc(tt('選擇供應商…', 'Choose a provider…'))}</option>${rest.map((p) => `<option value="${esc(p.id)}">${esc(p.label)} (${esc(p.id)})</option>`).join('')}</select><input type="password" id="kpKey" autocomplete="new-password" spellcheck="false" placeholder="${esc(tt('API 金鑰', 'API key'))}" aria-label="${esc(tt('API 金鑰', 'API key'))}"><button class="btn ghost small" id="kpTest">${esc(tt('測試', 'Test'))}</button><button class="btn small" id="kpSave">${esc(tt('儲存', 'Save'))}</button></div>
    <p class="dim" id="kpHint"></p>${res('__new')}
    ${NOTE}</div>`;
}, after() {
  const rerender = () => openPage('apikeys');
  const keyOf = (id) => { const i = q(`input[data-key="${CSS.escape(id)}"]`); return i ? i.value.trim() : ''; };
  for (const b of qa('[data-edit]')) b.onclick = () => { KP.open = b.dataset.edit; rerender().then(() => { const i = q(`input[data-key="${CSS.escape(KP.open)}"]`); if (i) i.focus(); }); };
  for (const b of qa('[data-cancel]')) b.onclick = () => { KP.open = null; rerender(); };
  const test = async (id, key, slot) => {
    note(tt('測試中…', 'Testing…'));
    const r = await act(() => call('ui.keys.test', key ? { provider: id, key } : { provider: id }));
    if (!r) return;
    KP.results[slot || id] = r;
    // Re-render without losing what was typed (a test is often followed by Save).
    const keep = { prov: $('kpProv').value, key: $('kpKey').value, edit: KP.open ? keyOf(KP.open) : '' };
    await rerender();
    $('kpProv').value = keep.prov;
    $('kpKey').value = keep.key;
    const ei = KP.open && q(`input[data-key="${CSS.escape(KP.open)}"]`);
    if (ei) ei.value = keep.edit;
    $('kpProv').dispatchEvent(new Event('change'));
    note(r.ok ? tt('金鑰可用', 'The key works') : tt('金鑰被拒絕', 'The key was refused'), !r.ok);
  };
  for (const b of qa('[data-test]')) b.onclick = () => test(b.dataset.test);
  for (const b of qa('[data-bal]')) b.onclick = async () => {
    const id = b.dataset.bal;
    KP.bal[id] = { loading: true };
    await rerender();
    try { KP.bal[id] = await call('ui.keys.balance', { provider: id }); } catch (e) { KP.bal[id] = { ok: false, error: e.message, fetched_ms: Date.now() }; }
    if (KP.bal[id] && KP.bal[id].supported === false) delete KP.bal[id];
    await rerender();
  };
  for (const b of qa('[data-trynew]')) b.onclick = () => { const k = keyOf(b.dataset.trynew); if (!k) return note(tt('請先輸入金鑰', 'Enter a key first'), true); test(b.dataset.trynew, k); };
  for (const b of qa('[data-save]')) b.onclick = async () => {
    const id = b.dataset.save;
    const k = keyOf(id);
    if (!k) return note(tt('請先輸入金鑰', 'Enter a key first'), true);
    const r = await act(() => call('ui.keys.set', { provider: id, key: k }));
    if (!r) return;
    KP.open = null;
    delete KP.results[id];
    delete KP.models[id];
    if (typeof CM === 'object') CM.models = null;
    await rerender();
    note(tt(`已存入 vault：${r.name}（${r.masked}）`, `Stored in the vault: ${r.name} (${r.masked})`));
  };
  for (const b of qa('[data-del]')) b.onclick = async () => {
    const id = b.dataset.del;
    const ok = typeof cmConfirm === 'function' ? await cmConfirm(tt('刪除金鑰', 'Delete key'), tt(`從 vault 刪除 ${id} 的金鑰？`, `Delete the ${id} key from the vault?`), tt('刪除', 'Delete'), true) : confirm(`Delete ${id}?`);
    if (!ok) return;
    const r = await act(() => call('ui.keys.delete', { provider: id }));
    if (!r) return;
    delete KP.results[id];
    delete KP.models[id];
    if (typeof CM === 'object') CM.models = null;
    await rerender();
    note(r.removed ? tt('已刪除金鑰', 'Key deleted') : tt('沒有可刪除的金鑰', 'There was no key to delete'), !r.removed);
  };
  for (const b of qa('[data-models]')) b.onclick = async () => {
    const id = b.dataset.models;
    note(tt('向供應商抓取模型清單…', 'Fetching the model list from the provider…'));
    const r = await act(() => call('ui.chat.models.list', { provider: id, refresh: true }));
    if (!r) return;
    KP.models[id] = (r.providers || [])[0] || { source: 'builtin', models: [] };
    if (typeof CM === 'object') CM.models = null;
    await rerender();
  };
  const hint = () => {
    const p = (KP.list || []).find((x) => x.id === $('kpProv').value);
    $('kpHint').innerHTML = p ? `${esc(tt('會存成', 'Stored as'))} <code>${esc(p.name)}</code>${p.signup ? ` · <a href="${esc(p.signup)}" target="_blank" rel="noopener noreferrer">${esc(tt('取得金鑰', 'Get a key'))}</a>` : ''}${p.optional ? ' · ' + esc(tt('這個供應商可以不用金鑰', 'this provider also works without a key')) : ''}` : '';
  };
  $('kpProv').onchange = hint;
  // A typed key is tested (and the provider's models listed) as soon as the field is left: no
  // extra click before Save. The same value is not tested twice.
  const autoTest = (input, id, slot) => {
    input.addEventListener('change', () => {
      const k = input.value.trim();
      const want = id();
      if (!k || !want || input.dataset.tested === want + ' ' + k) return;
      input.dataset.tested = want + ' ' + k;
      test(want, k, slot);
    });
  };
  autoTest($('kpKey'), () => $('kpProv').value, '__new');
  for (const i of qa('input[data-key]')) autoTest(i, () => i.dataset.key);
  $('kpTest').onclick = () => { const id = $('kpProv').value, k = $('kpKey').value.trim(); if (!id || !k) return note(tt('請選擇供應商並輸入金鑰', 'Choose a provider and enter a key'), true); test(id, k, '__new'); };
  $('kpSave').onclick = async () => {
    const id = $('kpProv').value, k = $('kpKey').value.trim();
    if (!id || !k) return note(tt('請選擇供應商並輸入金鑰', 'Choose a provider and enter a key'), true);
    const r = await act(() => call('ui.keys.set', { provider: id, key: k }));
    if (!r) return;
    $('kpKey').value = '';
    delete KP.results.__new;
    if (typeof CM === 'object') CM.models = null;
    await rerender();
    note(tt(`已存入 vault：${r.name}（${r.masked}）`, `Stored in the vault: ${r.name} (${r.masked})`));
  };
} };
if (typeof EXTRA_PAGES === 'object' && !EXTRA_PAGES.includes('apikeys')) EXTRA_PAGES.push('apikeys');
