// seagent web UI: the agent's computer (the desktop VM the daemon brings up by itself,
// `[desktop_vm] autostart`). A pill next to the status strip says whether it is being built,
// booting, running or stopped; clicking it starts / retries it or opens the 工作區 on it.
// Polls `view.vm.status` only while the window is visible: every 3 s while it is getting ready,
// every 30 s once it runs.
'use strict';

const AVM = { st: null, timer: null };

function avmPill() {
  let el = document.getElementById('agentVm');
  if (!el) {
    const strip = document.getElementById('strip');
    if (!strip) return null;
    el = document.createElement('button');
    el.id = 'agentVm';
    el.type = 'button';
    el.className = 'btn ghost small agent-vm';
    strip.insertAdjacentElement('afterend', el);
    el.onclick = avmClick;
  }
  return el;
}

function avmText(s) {
  const a = (s && s.agent) || {};
  const vm = a.vm || (s && s.default) || 'desk';
  const secs = a.since_ms ? Math.max(0, Math.round((Date.now() - a.since_ms) / 1000)) : 0;
  const mins = secs >= 60 ? `${Math.floor(secs / 60)} 分` : `${secs} 秒`;
  switch (a.phase) {
    case 'building': return { t: `代理電腦建置中（首次約 10–20 分鐘，已 ${mins}）`, tip: a.message || '', cls: 'warn' };
    case 'starting': return { t: '代理電腦開機中…', tip: vm, cls: 'warn' };
    case 'running': return { t: '代理電腦：執行中', tip: `桌面虛擬機 ${vm}${a.accel ? ' · ' + a.accel : ''}${a.message ? ' · ' + a.message : ''}（點一下在工作區打開）`, cls: 'ok' };
    case 'user-stopped': return { t: '代理電腦已停止（點一下啟動）', tip: '你停止了它；代理會等你再啟動。', cls: 'crit' };
    case 'failed': return { t: '代理電腦啟動失敗（點一下重試）', tip: a.message || '', cls: 'crit' };
    default:
      if (s && !s.enabled) return { t: '', tip: '', cls: '' };
      if (s && !s.autostart) return { t: '代理電腦未自動啟動（點一下啟動）', tip: '[desktop_vm] autostart = false', cls: '' };
      return { t: '代理電腦準備中…', tip: '', cls: 'warn' };
  }
}

function avmDraw() {
  const el = avmPill();
  if (!el) return;
  const v = avmText(AVM.st);
  el.hidden = !v.t;
  el.textContent = v.t;
  el.title = v.tip;
  el.dataset.state = v.cls;
}

async function avmPoll() {
  if (document.hidden || !S.arp) return avmSchedule(3000);
  try { AVM.st = await S.arp.call('view.vm.status'); } catch { AVM.st = null; }
  avmDraw();
  const phase = AVM.st && AVM.st.agent && AVM.st.agent.phase;
  avmSchedule(phase === 'running' || phase === 'user-stopped' || (AVM.st && !AVM.st.enabled) ? 30000 : 3000);
}

function avmSchedule(ms) {
  clearTimeout(AVM.timer);
  AVM.timer = setTimeout(avmPoll, ms);
}

async function avmClick() {
  const a = (AVM.st && AVM.st.agent) || {};
  try {
    if (a.phase === 'running') {
      if (typeof workShow === 'function') await workShow(true);
      return;
    }
    await S.arp.call('view.vm.build');
    toast(a.phase === 'failed' ? '重新嘗試啟動代理電腦…' : '正在啟動代理電腦…');
  } catch (e) { toast(e.message, true); }
  avmSchedule(800);
}

document.addEventListener('visibilitychange', () => { if (!document.hidden) avmSchedule(200); });
avmSchedule(1500);
