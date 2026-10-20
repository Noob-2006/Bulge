"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

let currentHandle = null; // the run we started and are watching
let running = false;

// ---- settings / key ----------------------------------------------------------

async function loadDefaults() {
  try {
    const d = await invoke("defaults");
    $("model").value = d.model;
    $("base-url").value = d.base_url;
    $("protocol").value = d.protocol;
    $("autonomy").value = d.autonomy;
    $("cpus").value = d.cpus;
    $("ram").value = d.ram_mib;
  } catch (e) {
    /* keep whatever is in the HTML */
  }
  await refreshKeyStatus();
}

async function refreshKeyStatus() {
  const badge = $("key-status");
  try {
    const has = await invoke("key_status", { baseUrl: $("base-url").value.trim() });
    badge.textContent = has ? "已設定" : "未設定";
    badge.className = "badge " + (has ? "ok" : "bad");
  } catch (e) {
    badge.textContent = "無法檢查";
    badge.className = "badge bad";
  }
}

async function saveKey() {
  const msg = $("key-msg");
  const key = $("api-key").value;
  if (!key.trim()) { msg.textContent = "請先貼上金鑰"; msg.className = "msg err"; return; }
  try {
    await invoke("save_key", { baseUrl: $("base-url").value.trim(), key });
    $("api-key").value = "";
    msg.textContent = "已儲存(權限 600)。";
    msg.className = "msg ok";
    await refreshKeyStatus();
  } catch (e) {
    msg.textContent = "儲存失敗:" + e;
    msg.className = "msg err";
  }
}

// ---- workspace ---------------------------------------------------------------

async function pickWorkspace() {
  try {
    const dir = await invoke("pick_workspace");
    if (dir) $("workspace").value = dir;
  } catch (e) {
    $("start-msg").textContent = "選擇資料夾失敗:" + e;
    $("start-msg").className = "msg err";
  }
}

// ---- running a job -----------------------------------------------------------

function setRunning(on) {
  running = on;
  $("start").classList.toggle("hidden", on);
  $("stop").classList.toggle("hidden", !on);
  $("run-status").textContent = on ? "執行中…（代理在沙箱虛擬機裡工作)" : "";
}

async function startJob() {
  const goal = $("goal").value.trim();
  const workspace = $("workspace").value.trim();
  const msg = $("start-msg");
  msg.textContent = ""; msg.className = "msg";
  if (!workspace) { msg.textContent = "請先選擇工作區資料夾。"; msg.className = "msg err"; return; }
  if (!goal) { msg.textContent = "請寫下目標。"; msg.className = "msg err"; return; }

  clearLog();
  $("review").classList.add("hidden");
  $("token-count").textContent = "";

  const args = {
    goal,
    workspace,
    model: $("model").value.trim(),
    base_url: $("base-url").value.trim(),
    protocol: $("protocol").value,
    autonomy: $("autonomy").value,
    network: $("network").checked,
    cpus: Number($("cpus").value) || 2,
    ram_mib: Number($("ram").value) || 1024,
  };

  try {
    currentHandle = await invoke("start_job", { args });
    setRunning(true);
  } catch (e) {
    msg.textContent = "無法開始:" + e;
    msg.className = "msg err";
  }
}

async function stopJob() {
  if (!currentHandle) return;
  try {
    await invoke("stop_job", { handle: currentHandle });
    $("run-status").textContent = "正在停止…";
  } catch (e) {
    /* ignore */
  }
}

// ---- log rendering -----------------------------------------------------------

function clearLog() { $("log").innerHTML = ""; }

function appendLog(node) {
  const log = $("log");
  const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  log.appendChild(node);
  if (atBottom) log.scrollTop = log.scrollHeight;
}

function line(cls, text) {
  const div = document.createElement("div");
  div.className = "ev " + cls;
  div.textContent = text;
  return div;
}

function clip(s, n) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + "…" : s;
}

let runningTokens = 0;

function renderEvent(ev) {
  switch (ev.type) {
    case "step_started":
      appendLog(line("ev-step", `— 第 ${ev.step} 步 —`));
      break;
    case "message": {
      const m = ev.message || {};
      if (m.role === "assistant") {
        for (const b of m.content || []) {
          if (b.type === "text" && b.text.trim()) appendLog(line("ev-assistant", b.text.trim()));
        }
      } else if (m.role === "tool") {
        const b = (m.content || [])[0];
        if (b && b.type === "text") {
          const bad = m.is_error ? " ev-tool-bad" : "";
          appendLog(line("ev-dim" + bad, "↳ " + clip(b.text.replace(/\s+/g, " "), 200)));
        }
      }
      break;
    }
    case "tool_claimed": {
      const args = ev.arguments ? clip(JSON.stringify(ev.arguments), 160) : "";
      const el = line("ev-tool", `🔧 ${ev.name}`);
      if (args) { const a = document.createElement("span"); a.className = "ev-args"; a.textContent = "  " + args; el.appendChild(a); }
      appendLog(el);
      break;
    }
    case "tool_completed":
      appendLog(line(ev.ok ? "ev-tool-ok" : "ev-tool-bad", `${ev.ok ? "✓" : "✗"} ${shortResult(ev)}`));
      break;
    case "usage":
      if (ev.usage) {
        const u = ev.usage;
        runningTokens += (u.input_tokens || 0) + (u.output_tokens || 0) + (u.cache_read_tokens || 0) + (u.cache_write_tokens || 0);
        $("token-count").textContent = runningTokens ? `${runningTokens} tokens` : "";
      }
      break;
    case "plan":
      renderPlan(ev.items || []);
      break;
    case "net_domain":
      appendLog(line("ev-net", `🌐 ${ev.domain} → ${ev.decision}`));
      break;
    case "status_changed":
      appendLog(line("ev-dim", `狀態:${ev.status}${ev.summary ? " — " + ev.summary : ""}`));
      break;
    case "vm_started":
      appendLog(line("ev-dim", "虛擬機已啟動"));
      break;
    case "vm_stopped":
      appendLog(line("ev-dim", `虛擬機已關閉(${ev.reason})`));
      break;
    case "compacted":
      appendLog(line("ev-dim", "(壓縮上下文以省 token)"));
      break;
    case "budget_warning":
      appendLog(line("ev-net", `⚠ 預算接近上限:${ev.kind} ${ev.used}/${ev.limit}`));
      break;
    case "approval_asked":
      appendLog(line("ev-net", `⏸ 等待核准:${ev.kind}`));
      break;
    case "created":
    case "contract":
      break;
    default:
      appendLog(line("ev-dim", ev.type));
  }
}

function shortResult(ev) {
  if (ev.result && typeof ev.result === "object" && ev.result.error) {
    return clip(String(ev.result.error).replace(/\s+/g, " "), 180);
  }
  return "完成";
}

function renderPlan(items) {
  const wrap = document.createElement("div");
  wrap.className = "ev ev-dim";
  wrap.textContent = "📋 計畫:";
  for (const it of items) {
    const row = document.createElement("div");
    const mark = it.status === "done" ? "✓" : it.status === "in_progress" || it.status === "doing" ? "▸" : "·";
    row.textContent = `   ${mark} ${it.title || it.text || ""}`;
    wrap.appendChild(row);
  }
  appendLog(wrap);
}

// ---- diff review / apply -----------------------------------------------------

function showReview(ev) {
  const review = $("review");
  const badge = $("review-status");
  const ok = ev.status === "Succeeded";
  badge.textContent = ev.error ? ("錯誤:" + ev.error) : `${ev.status}`;
  badge.className = "badge " + (ok ? "ok" : "bad");

  const list = $("change-list");
  list.innerHTML = "";
  const changes = ev.changes || [];
  if (changes.length === 0) {
    $("diff").textContent = ev.diff || "";
    const none = document.createElement("div");
    none.className = "hint";
    none.textContent = ev.error ? "" : "這次沒有對工作區做任何改動。";
    list.appendChild(none);
    $("apply").disabled = true;
  } else {
    $("apply").disabled = false;
    for (const c of changes) {
      const row = document.createElement("label");
      row.className = "change" + (c.kind === "deleted" ? " danger-k" : "");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = true;
      cb.dataset.path = c.path;
      cb.disabled = c.kind === "too_large";
      if (cb.disabled) cb.checked = false;
      const ck = document.createElement("span");
      ck.className = "ck";
      ck.textContent = kindLabel(c.kind);
      const path = document.createElement("span");
      path.className = "path";
      path.textContent = c.path;
      const detail = document.createElement("span");
      detail.className = "detail";
      detail.textContent = c.detail;
      row.append(cb, ck, path, detail);
      list.appendChild(row);
    }
    $("diff").textContent = ev.diff || "(無文字 diff)";
  }

  $("apply-msg").textContent = "";
  $("apply-msg").className = "msg";
  review.classList.remove("hidden");
  review.scrollIntoView({ behavior: "smooth", block: "start" });
}

function kindLabel(kind) {
  return { file: "檔案", deleted: "刪除", dir: "資料夾", symlink: "連結", too_large: "過大" }[kind] || kind;
}

function setAll(checked) {
  $("change-list").querySelectorAll("input[type=checkbox]").forEach((cb) => { if (!cb.disabled) cb.checked = checked; });
}

async function applyChanges() {
  if (!currentHandle) return;
  const approved = [];
  $("change-list").querySelectorAll("input[type=checkbox]").forEach((cb) => { if (cb.checked) approved.push(cb.dataset.path); });
  const msg = $("apply-msg");
  if (approved.length === 0) { msg.textContent = "沒有勾選任何項目。"; msg.className = "msg err"; return; }
  $("apply").disabled = true;
  try {
    const report = await invoke("apply_changes", { handle: currentHandle, approved });
    const parts = [`已套用 ${report.applied.length} 項到工作區。`];
    if (report.skipped.length) parts.push(`略過 ${report.skipped.length} 項:` + report.skipped.map((s) => `${s[0]}(${s[1]})`).join("、"));
    msg.textContent = parts.join(" ");
    msg.className = report.skipped.length ? "msg err" : "msg ok";
  } catch (e) {
    msg.textContent = "套用失敗:" + e;
    msg.className = "msg err";
  } finally {
    $("apply").disabled = false;
  }
}

// ---- wire up -----------------------------------------------------------------

listen("job-line", (e) => {
  const p = e.payload;
  if (!currentHandle || p.handle !== currentHandle) return;
  let ev;
  try { ev = JSON.parse(p.line); } catch { return; }
  renderEvent(ev);
});

listen("job-done", (e) => {
  const p = e.payload;
  if (!currentHandle || p.handle !== currentHandle) return;
  setRunning(false);
  $("run-status").textContent = p.error ? "已結束(有錯誤)" : "已完成";
  showReview(p);
});

window.addEventListener("DOMContentLoaded", () => {
  $("toggle-settings").addEventListener("click", () => $("settings").classList.toggle("hidden"));
  $("base-url").addEventListener("change", refreshKeyStatus);
  $("save-key").addEventListener("click", saveKey);
  $("pick-ws").addEventListener("click", pickWorkspace);
  $("start").addEventListener("click", startJob);
  $("stop").addEventListener("click", stopJob);
  $("select-all").addEventListener("click", () => setAll(true));
  $("select-none").addEventListener("click", () => setAll(false));
  $("apply").addEventListener("click", applyChanges);
  loadDefaults();
});
