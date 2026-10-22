"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (id) => document.getElementById(id);

/* ---- markdown (safe) ---- */
const md = window.markdownit({ html: false, linkify: true, breaks: true, typographer: false });
const defaultLink = md.renderer.rules.link_open || ((t, i, o, e, s) => s.renderToken(t, i, o));
md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
  const href = tokens[idx].attrGet("href") || "";
  if (!/^https?:\/\//i.test(href)) tokens[idx].attrSet("href", "#");
  tokens[idx].attrSet("target", "_blank");
  tokens[idx].attrSet("rel", "noopener noreferrer");
  return defaultLink(tokens, idx, options, env, self);
};
function renderMarkdown(text) {
  return DOMPurify.sanitize(md.render(text || ""), { ADD_ATTR: ["target", "rel"] });
}

/* ---- state ---- */
let currentHandle = null;   // the live run we started
let currentJobId = null;    // the store job id of the current conversation (for follow-ups)
let running = false;
let workspacePath = "";
let runningTokens = 0;
const usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, reasoning: 0 };
let stepCount = 0;
let elapsedTimer = null;
let elapsedStart = 0;
const toolEls = {};         // call_id -> tool element
let contextWindow = 128000;

/* ---- helpers ---- */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function clip(s, n) { s = String(s); return s.length > n ? s.slice(0, n) + "…" : s; }

function toast(message, kind) {
  const t = el("div", "toast" + (kind ? " " + kind : ""), message);
  $("toast-root").appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; setTimeout(() => t.remove(), 250); }, 3200);
}

/* ---- transcript container ---- */
function inner() {
  let i = $("transcript").querySelector(".transcript-inner");
  if (!i) {
    i = el("div", "transcript-inner");
    $("transcript").appendChild(i);
  }
  $("empty-state").classList.add("hidden");
  return i;
}
function resetTranscript() {
  const t = $("transcript");
  const existing = t.querySelector(".transcript-inner");
  if (existing) existing.remove();
  $("empty-state").classList.remove("hidden");
  for (const k of Object.keys(toolEls)) delete toolEls[k];
  stepCount = 0; runningTokens = 0;
  usage.input = usage.output = usage.cacheRead = usage.cacheWrite = usage.reasoning = 0;
  $("tokens-wrap").classList.add("hidden");
  $("steps").classList.add("hidden");
}
function appendBlock(node) {
  const i = inner();
  const t = $("transcript");
  const atBottom = t.scrollHeight - t.scrollTop - t.clientHeight < 60;
  i.appendChild(node);
  if (atBottom) t.scrollTop = t.scrollHeight;
}

/* ---- long output collapse (head + expand) ---- */
function collapsiblePre(text, maxLines) {
  maxLines = maxLines || 16;
  const wrap = el("div");
  const pre = el("pre", "tool-pre");
  const lines = String(text).replace(/\s+$/, "").split("\n");
  if (lines.length <= maxLines) {
    pre.textContent = lines.join("\n");
    wrap.appendChild(pre);
    return wrap;
  }
  const head = lines.slice(0, 12).join("\n");
  pre.textContent = head;
  const btn = el("button", "tool-expand", `展開其餘 ${lines.length - 12} 行`);
  let expanded = false;
  btn.addEventListener("click", () => {
    expanded = !expanded;
    pre.textContent = expanded ? lines.join("\n") : head;
    btn.textContent = expanded ? "收合" : `展開其餘 ${lines.length - 12} 行`;
  });
  wrap.append(pre, btn);
  return wrap;
}

/* ---- format a tool result into a node ---- */
function formatToolResult(ok, result) {
  if (result == null) return el("div", "tool-pre", ok ? "(完成)" : "(失敗)");
  if (typeof result === "object") {
    if (result.error) return el("div", "tool-pre", "錯誤:" + String(result.error));
    // exec-shaped
    const parts = [];
    if (typeof result.exit_code === "number") parts.push("exit " + result.exit_code);
    const out = result.stdout && typeof result.stdout === "object" ? result.stdout.text : undefined;
    const err = result.stderr && typeof result.stderr === "object" ? result.stderr.text : undefined;
    if (out !== undefined || err !== undefined) {
      const wrap = el("div");
      if (parts.length) wrap.appendChild(el("div", "ev-sys", parts.join(" · ")));
      if (out && out.trim()) wrap.appendChild(collapsiblePre(out));
      if (err && err.trim()) { const e = collapsiblePre(err); e.firstChild.style.color = "var(--danger)"; wrap.appendChild(e); }
      if ((!out || !out.trim()) && (!err || !err.trim())) wrap.appendChild(el("div", "ev-sys", "(無輸出)"));
      return wrap;
    }
    // generic: a 'text'/'content' field or pretty JSON
    if (typeof result.text === "string") return collapsiblePre(result.text);
    if (typeof result.content === "string") return collapsiblePre(result.content);
    return collapsiblePre(JSON.stringify(result, null, 2));
  }
  return collapsiblePre(String(result));
}

/* ---- event rendering ---- */
function renderEvent(ev) {
  switch (ev.type) {
    case "step_started": {
      stepCount = ev.step;
      $("steps").textContent = "第 " + ev.step + " 步";
      $("steps").classList.remove("hidden");
      appendBlock(el("div", "ev-step", "第 " + ev.step + " 步"));
      break;
    }
    case "message": {
      const m = ev.message || {};
      if (m.role === "assistant") {
        for (const b of m.content || []) {
          if (b.type === "text" && b.text && b.text.trim()) {
            const box = el("div", "msg-assistant");
            const mdv = el("div", "md");
            mdv.innerHTML = renderMarkdown(b.text);
            box.appendChild(mdv);
            appendBlock(box);
          } else if (b.type === "reasoning" && b.text && b.text.trim()) {
            const d = document.createElement("details");
            d.className = "think";
            const sum = el("summary", null, "思考");
            const body = el("div", "think-body", b.text.trim());
            d.append(sum, body);
            appendBlock(d);
          }
        }
      }
      // tool-role result messages are shown inside the tool row (via tool_completed)
      break;
    }
    case "tool_claimed": {
      const tool = el("div", "tool");
      const sum = el("button", "tool-summary");
      sum.append(el("span", "tool-chev", "▾"), el("span", "tool-name", ev.name));
      const argPreview = ev.arguments ? clip(argSummary(ev.name, ev.arguments), 90) : "";
      if (argPreview) sum.appendChild(el("span", "tool-arg", argPreview));
      const mark = el("span", "tool-mark", "…");
      sum.appendChild(mark);
      const body = el("div", "tool-body");
      sum.addEventListener("click", () => tool.classList.toggle("open"));
      tool.append(sum, body);
      tool._mark = mark; tool._body = body;
      toolEls[ev.call_id] = tool;
      appendBlock(tool);
      break;
    }
    case "tool_completed": {
      const tool = toolEls[ev.call_id];
      if (tool) {
        tool._mark.textContent = ev.ok ? "✓" : "✗";
        tool._mark.className = "tool-mark " + (ev.ok ? "ok" : "bad");
        tool._body.innerHTML = "";
        tool._body.appendChild(formatToolResult(ev.ok, ev.result));
        if (!ev.ok) tool.classList.add("open");
      }
      break;
    }
    case "usage": {
      const u = ev.usage || {};
      usage.input += u.input_tokens || 0;
      usage.output += u.output_tokens || 0;
      usage.cacheRead += u.cache_read_tokens || 0;
      usage.cacheWrite += u.cache_write_tokens || 0;
      usage.reasoning += u.reasoning_tokens || 0;
      runningTokens = usage.input + usage.output + usage.cacheRead + usage.cacheWrite;
      updateMeter();
      break;
    }
    case "plan": renderPlan(ev.items || []); break;
    case "net_domain": appendBlock(el("div", "ev-net", "🌐 " + ev.domain + " → " + ev.decision)); break;
    case "status_changed": appendBlock(el("div", "ev-sys", "狀態:" + ev.status + (ev.summary ? " — " + ev.summary : ""))); break;
    case "vm_started": appendBlock(el("div", "ev-sys", "虛擬機已啟動")); break;
    case "vm_stopped": appendBlock(el("div", "ev-sys", "虛擬機已關閉" + (ev.reason ? " (" + ev.reason + ")" : ""))); break;
    case "compacted": appendBlock(el("div", "ev-sys", "(壓縮上下文以省 token)")); break;
    case "budget_warning": appendBlock(el("div", "ev-net", "⚠ 預算接近上限:" + ev.kind + " " + ev.used + "/" + ev.limit)); break;
    case "approval_asked": appendBlock(el("div", "ev-net", "⏸ 等待核准:" + ev.kind)); break;
    case "contract": renderContract(ev.contract || {}); break;
    case "created": break;
    default: appendBlock(el("div", "ev-sys", ev.type));
  }
}

function argSummary(name, args) {
  if (!args || typeof args !== "object") return "";
  if (name === "exec" && args.command) return args.command;
  if (args.path) return args.path;
  if (args.pattern) return args.pattern;
  if (args.file) return args.file;
  return JSON.stringify(args);
}

function renderEgressAsk(id, host, port) {
  const card = el("div", "egress-ask");
  const head = el("div", "egress-head");
  head.append(el("span", "egress-icon", "🌐"), el("span", "egress-q", "代理想連線到 " + host + ":" + port + " — 允許嗎?"));
  const sub = el("div", "egress-sub", "這是沙箱內代理要連到的外部主機(不是模型 API)。允許後本次工作階段會記住這個主機。");
  const actions = el("div", "egress-actions");
  const allow = el("button", "btn btn-primary btn-sm", "允許");
  const deny = el("button", "btn btn-ghost btn-sm", "拒絕");
  const status = el("span", "egress-status", "");
  async function decide(ok) {
    allow.disabled = deny.disabled = true;
    try {
      await invoke("approve_egress", { id, allow: ok });
      status.textContent = ok ? "已允許" : "已拒絕";
      status.className = "egress-status " + (ok ? "ok" : "bad");
    } catch (e) { status.textContent = "失敗:" + e; status.className = "egress-status bad"; allow.disabled = deny.disabled = false; }
  }
  allow.addEventListener("click", () => decide(true));
  deny.addEventListener("click", () => decide(false));
  actions.append(allow, deny, status);
  card.append(head, sub, actions);
  appendBlock(card);
}

// The engine prefixes a user turn with a persisted <turn-context> block (profile,
// lessons, workspace snapshot) for the model; the user only sees what they typed.
const TURN_CONTEXT_CLOSE = "</turn-context>";
function stripTurnContext(text) {
  if (!text.startsWith("<turn-context>")) return text;
  const end = text.indexOf(TURN_CONTEXT_CLOSE);
  return end < 0 ? text : text.slice(end + TURN_CONTEXT_CLOSE.length).trimStart();
}

function renderUserMessage(text) {
  text = stripTurnContext(text);
  const box = el("div", "msg-user");
  box.appendChild(el("div", "msg-user-bubble", text));
  appendBlock(box);
}

function renderContract(c) {
  const deliverables = c.deliverables || [];
  const acceptance = c.acceptance || [];
  if (!deliverables.length && !acceptance.length) return;
  const card = el("div", "contract");
  card.appendChild(el("div", "contract-label", "交付契約"));
  if (deliverables.length) {
    const sec = el("div", "contract-sec");
    sec.appendChild(el("div", "contract-sub", "交付物"));
    for (const d of deliverables) {
      const row = el("div", "contract-item");
      row.append(el("span", "contract-path", d.path || ""), el("span", "contract-desc", d.description || ""));
      sec.appendChild(row);
    }
    card.appendChild(sec);
  }
  if (acceptance.length) {
    const sec = el("div", "contract-sec");
    sec.appendChild(el("div", "contract-sub", "驗收條件"));
    for (const a of acceptance) sec.appendChild(el("div", "contract-accept", "✓ " + a));
    card.appendChild(sec);
  }
  appendBlock(card);
}

function renderPlan(items) {
  const card = el("div", "plan");
  card.appendChild(el("div", "plan-label", "計畫"));
  for (const it of items) {
    const st = (it.status || "").toLowerCase();
    const cls = st === "done" ? "done" : (st === "in_progress" || st === "doing" ? "doing" : "");
    const row = el("div", "plan-item" + (cls ? " " + cls : ""));
    const mark = st === "done" ? "✓" : (cls === "doing" ? "▸" : "○");
    row.append(el("span", "plan-mark", mark), el("span", "plan-text", it.title || it.text || ""));
    card.appendChild(row);
  }
  appendBlock(card);
}

/* ---- meter / elapsed ---- */
function updateMeter() {
  if (runningTokens <= 0) return;
  $("tokens-wrap").classList.remove("hidden");
  $("tokens").textContent = runningTokens.toLocaleString() + " tok";
  const hitRate = usage.input > 0 ? Math.round((usage.cacheRead / (usage.input + usage.cacheRead)) * 100) : 0;
  $("tokens-wrap").title =
    "輸入 " + usage.input.toLocaleString() +
    " · 輸出 " + usage.output.toLocaleString() +
    " · 快取讀 " + usage.cacheRead.toLocaleString() + " (命中 " + hitRate + "%)" +
    " · 快取寫 " + usage.cacheWrite.toLocaleString() +
    (usage.reasoning ? " · 推理 " + usage.reasoning.toLocaleString() : "");
  const frac = Math.min(1, runningTokens / contextWindow);
  const fill = $("meter-fill");
  fill.style.width = (frac * 100).toFixed(1) + "%";
  fill.className = "meter-fill" + (frac > 0.9 ? " danger" : frac > 0.7 ? " warn" : "");
}
function startElapsed() {
  elapsedStart = Date.now();
  $("elapsed").classList.remove("hidden");
  elapsedTimer = setInterval(() => {
    const s = Math.floor((Date.now() - elapsedStart) / 1000);
    $("elapsed").textContent = s < 60 ? s + "s" : Math.floor(s / 60) + "m" + (s % 60) + "s";
  }, 1000);
}
function stopElapsed() { if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; } }

/* ---- running state ---- */
function setRunning(on) {
  running = on;
  $("start").disabled = on;
  $("goal").disabled = on;
  $("stop").classList.toggle("hidden", !on);
  $("working").classList.toggle("hidden", !on);
  if (on) { startElapsed(); } else { stopElapsed(); }
}
function setStatusBadge(status, ok) {
  const b = $("status-badge");
  b.textContent = status;
  b.className = "badge " + (ok === true ? "ok" : ok === false ? "bad" : "run");
  b.classList.remove("hidden");
}

/* ---- settings / key ---- */
async function loadDefaults() {
  try {
    const d = await invoke("defaults");
    $("model").value = d.model; $("base-url").value = d.base_url;
    $("protocol").value = d.protocol; $("autonomy").value = d.autonomy;
    $("cpus").value = d.cpus; $("ram").value = d.ram_mib;
    $("context-window").value = d.context_window; $("max-tokens").value = d.max_tokens;
  } catch (e) { /* keep html defaults */ }
  await refreshKeyStatus();
}
async function refreshKeyStatus() {
  let has = false;
  try { has = await invoke("key_status", { baseUrl: $("base-url").value.trim() }); } catch (e) {}
  const s = $("key-status"); s.textContent = has ? "已設定" : "未設定"; s.className = "dot-status " + (has ? "ok" : "bad");
  const chip = $("key-chip"); chip.textContent = has ? "金鑰 ✓" : "金鑰未設定"; chip.className = "chip-hint " + (has ? "ok" : "bad");
}
async function loadMcpServers() {
  const box = $("mcp-list");
  if (!box) return;
  let servers = [];
  try { servers = await invoke("mcp_servers"); } catch (e) {}
  box.innerHTML = "";
  if (!servers.length) { box.appendChild(el("div", "mcp-empty", "尚未設定任何 MCP 伺服器。")); return; }
  for (const s of servers) {
    const row = el("div", "mcp-item" + (s.disabled ? " off" : ""));
    row.append(
      el("span", "mcp-dot" + (s.disabled ? "" : " on")),
      el("span", "mcp-name", s.name),
      el("span", "mcp-cmd", s.command + (s.disabled ? " · 已停用" : "")),
    );
    box.appendChild(row);
  }
}

async function loadMemory() {
  const box = $("memory-list");
  if (!box) return;
  let items = [];
  try { items = await invoke("list_memory"); } catch (e) {}
  box.innerHTML = "";
  if (!items.length) { box.appendChild(el("div", "mcp-empty", "還沒有學到的教訓。")); return; }
  for (const m of items.slice(0, 50)) {
    const row = el("div", "mem-item");
    row.appendChild(el("div", "mem-cue", m.cue || ""));
    row.appendChild(el("div", "mem-lesson", m.lesson || ""));
    if (m.evidence) row.appendChild(el("div", "mem-evidence", "依據:" + m.evidence));
    box.appendChild(row);
  }
}
async function loadSkills() {
  const box = $("skill-list");
  if (!box) return;
  let items = [];
  try { items = await invoke("list_skills"); } catch (e) {}
  box.innerHTML = "";
  if (!items.length) { box.appendChild(el("div", "mcp-empty", "還沒有提案的技能。")); return; }
  for (const s of items) {
    const row = el("div", "mem-item");
    row.appendChild(el("div", "mem-cue", s.name || ""));
    row.appendChild(el("div", "mem-lesson", s.description || ""));
    box.appendChild(row);
  }
}

async function loadHooks() {
  const box = $("hook-list");
  if (!box) return;
  let items = [];
  try { items = await invoke("list_hooks"); } catch (e) {}
  box.innerHTML = "";
  if (!items.length) { box.appendChild(el("div", "mcp-empty", "尚未設定任何鉤子(~/.bulge/hooks.json)。")); return; }
  for (const h of items) {
    const row = el("div", "mcp-item");
    row.append(
      el("span", "mcp-name", h.event),
      el("span", "mcp-cmd", h.matcher + " → " + h.actions),
    );
    box.appendChild(row);
  }
}

const schedHints = {
  daily: "HH:MM(例 09:30)",
  every: "秒數(最少 60,例 3600)",
  cron: "5 欄 cron(例 0 9 * * 1-5)",
  after: "幾秒後執行一次(例 600)",
  at: "Unix 時間秒數(例 1792544400)",
  weekly: "mon,wed,fri:HH:MM",
  on_change: "要監看變更的路徑",
};
function updateScheduleHint() {
  const kind = $("sched-kind").value;
  $("sched-value").placeholder = schedHints[kind] || "";
}
async function addSchedule() {
  const goal = $("sched-goal").value.trim();
  const workspace = $("sched-workspace").value.trim();
  const value = $("sched-value").value.trim();
  if (!goal) { toast("請填寫排程目標", "err"); return; }
  if (!workspace) { toast("請填寫工作區路徑", "err"); return; }
  if (!value) { toast("請填寫排程設定值", "err"); return; }
  const btn = $("sched-add");
  btn.disabled = true;
  try {
    await invoke("add_schedule", {
      goal, workspace,
      autonomy: $("autonomy").value,
      model: $("model").value.trim(),
      baseUrl: $("base-url").value.trim(),
      protocol: $("protocol").value,
      kind: $("sched-kind").value,
      value,
      offsetMinutes: Number($("sched-offset").value) || 0,
    });
    $("sched-goal").value = "";
    $("sched-value").value = "";
    loadSchedules();
    toast("已新增排程", "ok");
  } catch (e) { toast("新增排程失敗:" + e, "err"); }
  finally { btn.disabled = false; }
}

async function loadSchedules() {
  const box = $("schedule-list");
  if (!box) return;
  let items = [];
  try { items = await invoke("list_schedules"); } catch (e) {}
  box.innerHTML = "";
  if (!items.length) { box.appendChild(el("div", "mcp-empty", "沒有排程任務。")); return; }
  for (const t of items) {
    const row = el("div", "mcp-item" + (t.enabled ? "" : " off"));
    const toggle = el("input");
    toggle.type = "checkbox"; toggle.checked = t.enabled; toggle.title = "啟用／停用";
    toggle.addEventListener("change", async () => {
      try { await invoke("set_schedule_enabled", { id: t.id, enabled: toggle.checked }); loadSchedules(); }
      catch (e) { toast("操作失敗:" + e, "err"); }
    });
    const rm = el("button", "btn btn-ghost btn-sm", "移除");
    rm.addEventListener("click", async () => {
      try { await invoke("remove_schedule", { id: t.id }); loadSchedules(); toast("已移除", "ok"); }
      catch (e) { toast("移除失敗:" + e, "err"); }
    });
    const next = t.next_run_at ? new Date(t.next_run_at * 1000).toLocaleString() : "—";
    row.append(
      toggle,
      el("span", "mcp-name", t.title),
      el("span", "mcp-cmd", t.schedule + " · 下次 " + next + " · 已跑 " + t.runs),
      rm,
    );
    box.appendChild(row);
  }
}

async function saveProfileEntryPrompt() {
  const file = (prompt("要編輯哪個檔案?(USER 或 MEMORY)", "USER") || "").trim().toUpperCase();
  if (!file) return;
  if (file !== "USER" && file !== "MEMORY") { toast("檔案必須是 USER 或 MEMORY", "err"); return; }
  const key = (prompt("章節名稱") || "").trim();
  if (!key) return;
  const body = prompt("內容") || "";
  try {
    await invoke("save_profile_entry", { file, key, body });
    loadProfile();
    toast("已儲存", "ok");
  } catch (e) { toast("儲存失敗:" + e, "err"); }
}
async function loadProfile() {
  const box = $("profile-list");
  if (!box) return;
  let items = [];
  try { items = await invoke("list_profile"); } catch (e) {}
  box.innerHTML = "";
  const add = el("button", "btn btn-primary btn-sm", "＋ 新增/編輯");
  add.addEventListener("click", saveProfileEntryPrompt);
  box.appendChild(add);
  if (!items.length) { box.appendChild(el("div", "mcp-empty", "還沒有使用者模型或環境記憶。")); return; }
  for (const p of items) {
    const row = el("div", "mem-item");
    row.appendChild(el("div", "mem-cue", "[" + p.file + "] " + (p.key || "")));
    row.appendChild(el("div", "mem-lesson", p.body || ""));
    const rm = el("button", "btn btn-ghost btn-sm", "刪除");
    rm.addEventListener("click", async () => {
      try { await invoke("remove_profile_entry", { file: p.file, key: p.key }); loadProfile(); toast("已刪除", "ok"); }
      catch (e) { toast("刪除失敗:" + e, "err"); }
    });
    row.appendChild(rm);
    box.appendChild(row);
  }
}

async function loadUsage() {
  const box = $("usage-list");
  if (!box) return;
  let items = [];
  try { items = await invoke("list_usage"); } catch (e) {}
  box.innerHTML = "";
  if (!items.length) { box.appendChild(el("div", "mcp-empty", "還沒有技能使用記錄。")); return; }
  for (const u of items) {
    const row = el("div", "mcp-item" + (u.state === "active" ? "" : " off"));
    const pin = el("button", "btn btn-ghost btn-sm", u.pinned ? "取消釘選" : "釘選");
    pin.addEventListener("click", async () => {
      try { await invoke("set_skill_pinned", { name: u.name, pinned: !u.pinned }); loadUsage(); }
      catch (e) { toast("操作失敗:" + e, "err"); }
    });
    const archive = el("button", "btn btn-ghost btn-sm", "封存");
    archive.addEventListener("click", async () => {
      try { await invoke("set_skill_state", { name: u.name, state: "archived" }); loadUsage(); }
      catch (e) { toast("封存失敗:" + e, "err"); }
    });
    const forget = el("button", "btn btn-ghost btn-sm", "移除");
    forget.addEventListener("click", async () => {
      try { await invoke("forget_skill", { name: u.name }); loadUsage(); toast("已移除", "ok"); }
      catch (e) { toast("移除失敗:" + e, "err"); }
    });
    row.append(
      el("span", "mcp-name", u.name + (u.pinned ? " 📌" : "")),
      el("span", "mcp-cmd", u.state + " · " + u.created_by + " · 用 " + u.uses + " 修 " + u.patches),
      pin, archive, forget,
    );
    box.appendChild(row);
  }
}

async function detectModels() {
  const btn = $("detect-models");
  const old = btn.textContent;
  btn.textContent = "偵測中…"; btn.disabled = true;
  try {
    const models = await invoke("detect_models", { baseUrl: $("base-url").value.trim(), protocol: $("protocol").value });
    const dl = $("model-list"); dl.innerHTML = "";
    for (const m of models) { const o = document.createElement("option"); o.value = m; dl.appendChild(o); }
    toast(models.length ? ("偵測到 " + models.length + " 個模型,點模型欄可選") : "沒有回傳模型", models.length ? "ok" : "err");
    if (models.length && !$("model").value.trim()) $("model").value = models[0];
  } catch (e) {
    toast("偵測失敗:" + e, "err");
  } finally { btn.textContent = old; btn.disabled = false; }
}

async function saveKey() {
  const key = $("api-key").value;
  const msg = $("key-msg");
  if (!key.trim()) { msg.textContent = "請先貼上金鑰"; msg.className = "inline-msg settings-msg err"; return; }
  try {
    await invoke("save_key", { baseUrl: $("base-url").value.trim(), key });
    $("api-key").value = "";
    msg.textContent = "已儲存(權限 600)。"; msg.className = "inline-msg settings-msg ok";
    await refreshKeyStatus();
  } catch (e) { msg.textContent = "儲存失敗:" + e; msg.className = "inline-msg settings-msg err"; }
}

async function applyExecSettings() {
  const msg = $("exec-msg");
  const cpus = Number($("cpus").value) || 2, ram = Number($("ram").value) || 1024, network = $("network").checked;
  if (!currentHandle) {
    msg.textContent = "目前沒有進行中的工作階段;新設定會在下一個任務自動生效。"; msg.className = "inline-msg settings-msg";
    return;
  }
  if (running) { msg.textContent = "任務執行中,請先停止或等它結束再重啟 VM。"; msg.className = "inline-msg settings-msg err"; return; }
  const btn = $("apply-exec"); const old = btn.textContent; btn.textContent = "重啟中…"; btn.disabled = true;
  msg.textContent = ""; msg.className = "inline-msg settings-msg";
  try {
    await invoke("restart_vm", { handle: currentHandle, cpus, ramMib: ram, network });
    msg.textContent = "VM 已依新設定重啟,對話保留。"; msg.className = "inline-msg settings-msg ok";
    toast("VM 已重啟(對話保留)", "ok");
  } catch (e) {
    msg.textContent = "重啟失敗:" + e; msg.className = "inline-msg settings-msg err";
    toast("重啟失敗:" + e, "err");
  } finally { btn.textContent = old; btn.disabled = false; }
}

/* ---- workspace ---- */
async function pickWorkspace() {
  try {
    const dir = await invoke("pick_workspace");
    if (dir) { workspacePath = dir; $("ws-label").textContent = dir.split("/").pop() || dir; $("pick-ws").title = dir; }
  } catch (e) { toast("選擇資料夾失敗:" + e, "err"); }
}

/* ---- sidebar job history ---- */
async function loadJobs() {
  let jobs = [];
  try { jobs = await invoke("list_jobs"); } catch (e) {}
  const list = $("job-list");
  list.innerHTML = "";
  if (!jobs.length) { list.appendChild(el("div", "side-empty", "還沒有任務")); return; }
  for (const j of jobs.slice(0, 40)) {
    const item = el("button", "job-item");
    item.dataset.id = j.id;
    const ok = j.status === "Succeeded";
    const bad = j.status === "Failed" || j.status === "Stuck";
    item.append(el("span", "ji-dot" + (ok ? " ok" : bad ? " bad" : "")), el("span", "ji-title", j.title || j.id));
    item.addEventListener("click", () => viewJob(j.id, j.title));
    list.appendChild(item);
  }
}
async function searchJobs() {
  const q = ($("job-search")?.value || "").trim();
  if (!q) { loadJobs(); return; }
  let hits = [];
  try { hits = await invoke("search_jobs", { query: q }); } catch (e) {}
  const list = $("job-list");
  list.innerHTML = "";
  if (!hits.length) { list.appendChild(el("div", "side-empty", "找不到相符的任務")); return; }
  for (const h of hits) {
    const item = el("button", "job-item");
    item.dataset.id = h.job_id;
    item.append(el("span", "ji-dot"), el("span", "ji-title", h.title || h.job_id));
    item.title = h.snippet || "";
    item.addEventListener("click", () => viewJob(h.job_id, h.title));
    list.appendChild(item);
  }
}
async function viewJob(id, title) {
  if (running) { toast("有任務執行中,無法切換", "err"); return; }
  let data;
  try { data = await invoke("load_job", { id }); } catch (e) { toast("讀取失敗:" + e, "err"); return; }
  if (currentHandle) { invoke("end_session", { handle: currentHandle }).catch(() => {}); }
  currentHandle = null;        // no live run yet; a follow-up resumes in a fresh VM
  currentJobId = id;           // but you can send a follow-up to continue this conversation
  resetTranscript();
  $("job-title").textContent = title || id;
  $("status-badge").classList.add("hidden");
  $("review").classList.add("hidden");
  for (const ln of data.jsonl.split("\n")) {
    if (!ln.trim()) continue;
    try { renderEvent(JSON.parse(ln)); } catch (e) {}
  }
  if (data.diff) showReview({ status: "(過去任務)", diff: data.diff, changes: [], readonly: true });
  document.querySelectorAll(".job-item").forEach((n) => n.classList.toggle("active", n.dataset.id === id));
}

/* ---- new task ---- */
function newTask() {
  if (running) { toast("有任務執行中", "err"); return; }
  if (currentHandle) { invoke("end_session", { handle: currentHandle }).catch(() => {}); }
  currentHandle = null;
  currentJobId = null;
  resetTranscript();
  $("review").classList.add("hidden");
  $("status-badge").classList.add("hidden");
  $("job-title").textContent = "新任務";
  $("steps").classList.add("hidden"); $("elapsed").classList.add("hidden"); $("tokens-wrap").classList.add("hidden");
  document.querySelectorAll(".job-item").forEach((n) => n.classList.remove("active"));
  $("goal").focus();
}

/* ---- start / stop ---- */
async function startJob() {
  const goal = $("goal").value.trim();
  const msg = $("start-msg"); msg.textContent = ""; msg.className = "inline-msg";
  if (!goal) { msg.textContent = "請寫下目標。"; msg.className = "inline-msg err"; return; }
  if (running) return;

  const liveSession = currentHandle;   // continue the live VM if we still have one
  const resumeJob = currentJobId;      // else resume this stored conversation
  const continuing = !!liveSession || !!resumeJob;
  const ctx = Number($("context-window").value) || 128000;
  if (!continuing) {
    resetTranscript();
    $("job-title").textContent = clip(goal.split("\n")[0], 60);
    contextWindow = ctx;
  }
  $("review").classList.add("hidden");
  renderUserMessage(goal);

  const temp = $("temperature").value.trim();
  const args = {
    session: liveSession || null,
    job_id: resumeJob || null,
    goal, workspace: workspacePath,
    model: $("model").value.trim(), base_url: $("base-url").value.trim(),
    protocol: $("protocol").value, autonomy: $("autonomy").value,
    network: $("network").checked, cpus: Number($("cpus").value) || 2, ram_mib: Number($("ram").value) || 1024,
    auto_review: $("auto-review")?.checked || false,
    temperature: temp === "" ? null : Number(temp),
    reasoning_effort: $("reasoning").value || null,
    max_tokens: Number($("max-tokens").value) || 8192,
    context_window: ctx,
    system_prompt: $("system-prompt").value.trim() || null,
  };
  try {
    currentHandle = await invoke("start_job", { args });
    setRunning(true);
    setStatusBadge("執行中", null);
    $("goal").value = ""; autoGrow();
  } catch (e) { msg.textContent = "無法開始:" + e; msg.className = "inline-msg err"; }
}
async function stopJob() {
  if (!currentHandle) return;
  try { await invoke("stop_job", { handle: currentHandle }); setStatusBadge("停止中…", null); } catch (e) {}
}

/* ---- review / apply ---- */
function kindLabel(k) { return ({ file: "檔案", deleted: "刪除", dir: "資料夾", symlink: "連結", too_large: "過大" })[k] || k; }

function showReview(ev) {
  const review = $("review");
  const changes = ev.changes || [];
  const hasDiff = ev.diff && ev.diff.trim() && ev.diff.trim() !== "(無文字 diff)";
  // Don't show an empty box for a past job that changed nothing.
  if (ev.readonly && changes.length === 0 && !hasDiff) { review.classList.add("hidden"); return; }

  review.className = "review";
  const eyebrow = review.querySelector(".review-eyebrow");
  if (eyebrow) eyebrow.textContent = ev.readonly ? "這個任務的變更" : (changes.length ? "待寫回的變更 · " + changes.length + " 項" : "沒有變更");
  const badge = $("review-status");
  badge.textContent = ev.error ? "錯誤" : ev.status;
  badge.className = "badge " + (ev.readonly ? "" : ev.status === "Succeeded" ? "ok" : "bad");

  const list = $("change-list");
  list.innerHTML = "";
  const applyBtn = $("apply");
  const hint = $("review-hint-text");
  if (ev.readonly) {
    if (hint) hint.classList.add("hidden");
    applyBtn.classList.add("hidden");
    $("select-all").classList.add("hidden"); $("select-none").classList.add("hidden");
  } else {
    if (hint) hint.classList.remove("hidden");
    applyBtn.classList.remove("hidden"); $("select-all").classList.remove("hidden"); $("select-none").classList.remove("hidden");
  }

  if (changes.length === 0) {
    list.appendChild(el("div", "review-hint", ev.error ? ("這次沒有完成改動。" + (ev.error || "")) : (ev.readonly ? "" : "這次沒有對工作區做任何改動。")));
    applyBtn.disabled = true;
  } else {
    applyBtn.disabled = false;
    for (const c of changes) {
      const row = el("label", "change" + (c.kind === "deleted" ? " del" : ""));
      const cb = el("input"); cb.type = "checkbox"; cb.checked = true; cb.dataset.path = c.path;
      if (c.kind === "too_large") { cb.disabled = true; cb.checked = false; }
      row.append(cb, el("span", "ck", kindLabel(c.kind)), el("span", "cpath", c.path), el("span", "cdetail", c.detail || ""));
      list.appendChild(row);
    }
  }
  // diff
  const diffBox = $("diff"); diffBox.innerHTML = "";
  renderDiffInto(diffBox, ev.diff || "(無文字 diff)");
  $("apply-msg").textContent = ""; $("apply-msg").className = "inline-msg";
  review.classList.remove("hidden");
}

function renderDiffInto(box, text) {
  for (const raw of String(text).split("\n")) {
    let cls = "dl-ctx";
    if (raw.startsWith("+++") || raw.startsWith("---") || raw.startsWith("@@") || raw.startsWith("diff ") ||
        raw.startsWith("new ") || raw.startsWith("deleted") || raw.startsWith("symlink") || raw.startsWith("Binary") || raw.startsWith("too large")) cls = "dl-meta";
    else if (raw.startsWith("+")) cls = "dl-add";
    else if (raw.startsWith("-")) cls = "dl-del";
    const span = el("span", cls, raw || " ");
    box.appendChild(span);
  }
}

function setAllChecks(on) {
  $("change-list").querySelectorAll("input[type=checkbox]").forEach((cb) => { if (!cb.disabled) cb.checked = on; });
}
async function applyChanges() {
  if (!currentHandle) { toast("這是過去的任務,無法再套用", "err"); return; }
  const approved = [];
  $("change-list").querySelectorAll("input[type=checkbox]").forEach((cb) => { if (cb.checked) approved.push(cb.dataset.path); });
  const msg = $("apply-msg");
  if (!approved.length) { msg.textContent = "沒有勾選任何項目。"; msg.className = "inline-msg err"; return; }
  $("apply").disabled = true;
  try {
    const report = await invoke("apply_changes", { handle: currentHandle, approved });
    let txt = "已套用 " + report.applied.length + " 項到工作區。";
    if (report.skipped.length) txt += " 略過 " + report.skipped.length + " 項:" + report.skipped.map((s) => s[0] + "(" + s[1] + ")").join("、");
    msg.textContent = txt; msg.className = "inline-msg " + (report.skipped.length ? "err" : "ok");
    toast(report.skipped.length ? "部分套用完成" : "已套用到工作區", report.skipped.length ? "err" : "ok");
  } catch (e) { msg.textContent = "套用失敗:" + e; msg.className = "inline-msg err"; }
  finally { $("apply").disabled = false; }
}

/* ---- composer auto-grow ---- */
function autoGrow() {
  const t = $("goal");
  t.style.height = "auto";
  t.style.height = Math.min(200, t.scrollHeight) + "px";
}

/* ---- settings + theme ---- */
function openSettings() { $("settings-overlay").classList.remove("hidden"); loadMcpServers(); loadMemory(); loadSkills(); loadHooks(); loadSchedules(); loadProfile(); loadUsage(); }
function closeSettings() { $("settings-overlay").classList.add("hidden"); }
function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", cur);
  try { localStorage.setItem("bulge.theme", cur); } catch (e) {}
}
function loadTheme() {
  let t = "dark";
  try { t = localStorage.getItem("bulge.theme") || "dark"; } catch (e) {}
  document.documentElement.setAttribute("data-theme", t);
}

/* ---- events from backend ---- */
listen("job-line", (e) => {
  const p = e.payload;
  if (!currentHandle || p.handle !== currentHandle) return;
  let ev; try { ev = JSON.parse(p.line); } catch { return; }
  renderEvent(ev);
});
listen("egress-ask", (e) => {
  const p = e.payload;
  if (!currentHandle || p.handle !== currentHandle) return;
  renderEgressAsk(p.id, p.host, p.port);
});
listen("job-done", (e) => {
  const p = e.payload;
  if (!currentHandle || p.handle !== currentHandle) return;
  setRunning(false);
  if (p.job_id) currentJobId = p.job_id; // enable follow-up turns on this conversation
  const ok = p.status === "Succeeded";
  setStatusBadge(p.error ? "失敗" : p.status, ok ? true : false);
  showReview(p);
  loadJobs();
});

/* ---- wire up ---- */
window.addEventListener("DOMContentLoaded", () => {
  loadTheme();
  $("new-task").addEventListener("click", newTask);
  {
    let t = null;
    const search = $("job-search");
    if (search) search.addEventListener("input", () => { clearTimeout(t); t = setTimeout(searchJobs, 250); });
  }
  $("theme-toggle").addEventListener("click", toggleTheme);
  $("open-settings").addEventListener("click", openSettings);
  $("close-settings").addEventListener("click", closeSettings);
  $("settings-overlay").addEventListener("click", (e) => { if (e.target === $("settings-overlay")) closeSettings(); });
  $("base-url").addEventListener("change", refreshKeyStatus);
  $("save-key").addEventListener("click", saveKey);
  $("detect-models").addEventListener("click", detectModels);
  $("apply-exec").addEventListener("click", applyExecSettings);
  $("pick-ws").addEventListener("click", pickWorkspace);
  $("network").addEventListener("change", () => {});
  $("sched-kind").addEventListener("change", updateScheduleHint);
  $("sched-add").addEventListener("click", addSchedule);
  updateScheduleHint();
  $("start").addEventListener("click", startJob);
  $("stop").addEventListener("click", stopJob);
  $("review-close").addEventListener("click", () => $("review").classList.add("hidden"));
  $("select-all").addEventListener("click", () => setAllChecks(true));
  $("select-none").addEventListener("click", () => setAllChecks(false));
  $("apply").addEventListener("click", applyChanges);
  $("goal").addEventListener("input", autoGrow);
  $("goal").addEventListener("keydown", (e) => {
    // Enter sends; Shift+Enter inserts a newline. `isComposing` guards IME input
    // (e.g. confirming a Chinese candidate with Enter must NOT send). Ctrl/Cmd+Enter
    // also sends, as a habit-friendly fallback.
    const composing = e.isComposing || e.keyCode === 229;
    if (e.key === "Enter" && !e.shiftKey && !composing) { e.preventDefault(); startJob(); }
  });
  loadDefaults();
  loadJobs();
});
