// Tiny zh-Hant / English string table for the app's own pages (the agent's wizard and console
// have their own). Elements carry data-i18n="key"; scripts use SE.t('key').
(function () {
  'use strict';
  const zh = (navigator.language || '').toLowerCase().startsWith('zh');
  const S = {
    preparing: ['準備中…', 'Preparing…'],
    chooseTitle: ['要怎麼使用 SE Agent？', 'How do you want to use SE Agent?'],
    localTitle: ['在這支手機上執行', 'Run it on this phone'],
    localHint: ['Agent 以前景服務在手機上常駐，主控台在 http://127.0.0.1:8640。', 'The agent runs here as a foreground service; its console is at http://127.0.0.1:8640.'],
    remoteTitle: ['連線到另一台電腦', 'Connect to another computer'],
    remoteHint: ['在區域網路中找到已安裝 SE Agent 的電腦並配對。', 'Find a computer running SE Agent on your network and pair with it.'],
    failed: ['SE Agent 沒能啟動', 'SE Agent could not start'],
    retry: ['重試', 'Retry'],
    copy: ['複製詳細資訊', 'Copy details'],
    show: ['顯示詳細資訊', 'Show details'],
    hide: ['隱藏詳細資訊', 'Hide details'],
    copied: ['已複製。貼到 issue 或寄給管理員即可。', 'Copied. Paste it into an issue or send it to your admin.'],
    s_locate: ['找到 SE Agent', 'Find SE Agent'],
    s_bootstrap: ['準備主控台設定', 'Prepare the console'],
    s_service: ['安裝並啟動背景服務', 'Install and start the background service'],
    s_health: ['等待 SE Agent 回應', 'Wait for SE Agent'],
    s_route: ['開啟設定精靈或主控台', 'Open the setup wizard or console'],
    // connect page
    connectTitle: ['連線到 SE Agent 主機', 'Connect to an SE Agent host'],
    iosNotice: ['SE Agent 整個在這支 iPhone / iPad 上執行：對話、模型、記憶、技能、排程、MCP、聊天平台與主控台都在手機本機，不需要伺服器。iOS 只不允許兩件事：虛擬機與原生 shell 程式。指令改在 App 內的 WebAssembly 沙箱執行（只看得到工作區與暫存資料夾、沒有網路）。App 在背景時，排程工作由 iOS 的背景任務在系統允許時執行。',
      'SE Agent runs entirely on this iPhone or iPad: chat, models, memory, skills, schedules, MCP, chat platforms and the console all run on the device — no server needed. iOS rules out only two things: virtual machines and native shell programs. Commands run in a WebAssembly sandbox inside the app instead (it sees only the workspace and a temp folder, and has no network). While the app is in the background, scheduled work runs when iOS grants a background task.'],
    iosPairNotice: ['配對電腦是選用的：這支手機本身就在執行 SE Agent。配對後可以在這裡開啟那台電腦的主控台，需要虛擬機或原生 shell 的工作可以交給它。',
      'Pairing a computer is optional: this phone runs SE Agent itself. A paired computer’s console opens here, and work that needs VMs or a native shell can go to it.'],
    pairInstead: ['改為連線到另一台電腦', 'Connect to another computer instead'],
    paired: ['已配對的主機', 'Paired hosts'],
    none: ['還沒有配對任何主機。', 'No hosts paired yet.'],
    open: ['開啟', 'Open'],
    forget: ['移除', 'Forget'],
    forgetAsk: ['再按一次移除（之後要重新配對）', 'Tap again to forget (re-pair later)'],
    nearby: ['區域網路中的主機', 'Hosts on this network'],
    searching: ['搜尋中…', 'Searching…'],
    rescan: ['重新搜尋', 'Search again'],
    noneFound: ['沒有找到。確認電腦上的 SE Agent 已開啟區域網路模式（[app.exposure] lan = true），或在下方手動輸入位址。', 'Nothing found. Make sure LAN mode is on in SE Agent on the computer ([app.exposure] lan = true), or type its address below.'],
    scan: ['掃描 QR 碼', 'Scan QR code'],
    scanHint: ['在電腦上執行 seagent pair code（或在主控台的「裝置」頁）顯示 QR 碼。', 'On the computer run `seagent pair code` (or open Devices in the console) to show the QR code.'],
    orCode: ['或輸入 8 碼配對碼', 'Or type the 8-character code'],
    address: ['主機位址', 'Host address'],
    code: ['配對碼', 'Pairing code'],
    check: ['下一步', 'Next'],
    fpTitle: ['確認主機指紋', 'Confirm the host fingerprint'],
    fpHint: ['電腦上會顯示同樣的指紋。兩邊一致才按「配對」——不一致代表有人攔截連線。', 'The computer shows the same fingerprint. Pair only if both match — a mismatch means someone is intercepting the connection.'],
    pair: ['配對', 'Pair'],
    cancel: ['取消', 'Cancel'],
    pairing: ['配對中…', 'Pairing…'],
    connecting: ['連線中…', 'Connecting…'],
    useLocal: ['改為在這支手機上執行', 'Run the agent on this phone instead'],
  };
  window.SE = {
    zh,
    t: (k) => (S[k] ? S[k][zh ? 0 : 1] : k),
    apply(root) {
      document.documentElement.lang = zh ? 'zh-Hant' : 'en';
      for (const el of (root || document).querySelectorAll('[data-i18n]')) el.textContent = SE.t(el.dataset.i18n);
    },
    invoke(cmd, args) {
      const core = window.__TAURI__ && window.__TAURI__.core;
      if (!core) return Promise.reject(new Error('not running inside the SE Agent app'));
      return core.invoke(cmd, args || {});
    },
    listen(ev, fn) {
      const e = window.__TAURI__ && window.__TAURI__.event;
      return e ? e.listen(ev, (m) => fn(m.payload)) : Promise.resolve(() => {});
    },
    async copy(text) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (_) {
        const ta = Object.assign(document.createElement('textarea'), { value: text });
        document.body.append(ta);
        ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        return ok;
      }
    },
  };
  SE.apply();
})();
