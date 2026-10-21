# bulge vs 參考代理——對照評估

對照對象(本輪深度 code review 的素材):**Hermes Agent**(Nous,Python,自我改進迴圈)、
**openclaw**(TS gateway + Rust 執行 crates,可信 gateway/不可信執行)、
**opencode**(TS/Effect coding agent,139 端點 HTTP API)、
**deepseek-harness / dsh**(TS,評測導向,typed hook seam + code-mode)。

評估軸:**功能、體驗、自動化、智能、安全**。以下標示 bulge 現況與各代理的對位關係。
狀態:✅ 已具備且對位或勝出;🟡 已具備基礎、可再強化;⬜ 尚未實作(列為後續)。

---

## 安全(bulge 的核心優勢)

| 機制 | bulge | 參考對位 |
|---|---|---|
| 真·隔離邊界 | ✅ libkrun **microVM**(KVM)唯讀 rootfs + sandboxd;擋主機 IP/區網/metadata | 勝出:opencode 無容器(僅策略+路徑)、deepseek 三模式政策、hermes/openclaw 用 Docker/SSH |
| 寫回審批 | ✅ 全程只在 VM;結尾出 diff 經人核准才寫回主機 | 對位 opencode 的 per-file diff 預覽審批 |
| 程式碼策略引擎 | ✅ opencode 式 last-match-wins allow/deny/ask(`permission.rs`) | 直接對位 opencode `Permission.evaluate` |
| 生命週期 hooks | ✅ **PreToolUse/PostToolUse**(deny/allow/改寫/注入,command 相容 CC exit-2,fail-closed) | 對位 hermes `pre_tool_call`、opencode `execute.before/after`、dsh hook-protocol |
| 秘密遮蔽 | ✅ `redact.rs`:token/Bearer/賦值/PEM + 註冊精確值 | 對位 hermes `redact.py` |
| 注入/外洩偵測 | ✅ `threat.rs`:持久面(記憶/技能)寫入前 Strict 掃描 | 對位 hermes `threat_patterns.py` |
| 協作式出口審批 | ✅ 非允許清單網域即時 ask | 對位 openclaw exec-approval socket |
| 出口阻擋主機自身 IP | ✅ 解析後比對主機介面 IP | bulge 自有強化 |
| LLM 二次審查閘 | ✅ 變動型工具呼叫前 LLM 二次審查(`driver.with_review`);審查者只見提案、fail-open;排程自動化預設開啟 | 對位 deepseek `auto-review` |

## 智能(學習與記憶)

| 機制 | bulge | 參考對位 |
|---|---|---|
| 越用越懂的記憶 | ✅ 證據引用 lessons + 關鍵字檢索 + 自動注入 | 對位 hermes experience memory |
| 反自我污染護欄 | ✅ `DO_NOT_CAPTURE`(禁環境相依/負面論斷/暫時錯誤;就地修正;使用者不滿=第一級訊號) | 移植 hermes background-review 的關鍵 IP |
| 使用者模型 | ✅ **USER.md**(偏好/工作方式)自動注入、改進迴圈維護、寫入前安全把關 | 對位 hermes USER.md |
| 環境記憶 | ✅ **MEMORY.md**,事實單一路由(user vs env) | 對位 hermes MEMORY.md + routing block |
| 技能工房 | ✅ 從成功任務提煉技能(60 字描述上限,對齊索引截斷) | 對位 hermes skill_manage |
| 技能使用台帳 | ✅ `.usage.json`:作者/uses/patches/生命週期/pinned | 對位 hermes skill_usage |
| 技能策展 curator | ✅ 依閒置 active→stale→archived(pinned 豁免、只封存不刪) | 對位 hermes curator.py |
| 規劃/自審 | ✅ update_plan 工具 + self-review + 契約驗收 + loop 偵測 | 對位 hermes verify/guardrails |
| 過往任務檢索 | ✅ `recall` 關鍵字(含 CJK 分詞)+ CLI/側欄搜尋;FTS 升級為後續優化 | 對位 hermes `session_search` |
| 子代理委派 | ✅ 同步 `delegate`(父只見摘要、共用 VM 含 hooks/review、深度上限 1) | 對位 deepseek/hermes delegate |

## 自動化

| 機制 | bulge | 參考對位 |
|---|---|---|
| 排程引擎 | ✅ 六選擇器 + 5 欄位 cron(純算術,零 tz 依賴) | 對位 deepseek schedule、hermes cron |
| 排程執行 | ✅ `bulge schedule tick`:single-flight 鎖、只補最近漏跑、產出可審核 diff | 對位 hermes scheduler_tick 單飛鎖 |
| 自動化更緊信封 | ✅ 排程執行跳過學習迴圈(skip_review);autonomous + 不自動寫回 | 對位 openclaw scheduled-tool-policy(ask:always) |
| 持久/模塊化 VM 工作階段 | ✅ 一個 VM 跨回合存活,設定變更只重啟機器、保留對話 | bulge 自有 |
| MCP 外部工具 | ✅ stdio JSON-RPC client(mcp.json) | 對位三者的 MCP |
| ACP 代理伺服器 | ✅ `bulge acp`(編輯器可驅動) | 對位 hermes acp_adapter、openclaw codex harness |
| 同步子代理 delegate | ✅ 見「智能」列(自動化上可拆分批次工作) | deepseek subagent、hermes delegate |
| 事件觸發 | ✅ `OnPathChange`:監看路徑 mtime 變更即執行(`--on-change`) | 對位 openclaw cron event-source |
| 非同步 return-now 子代理 | ⬜ 後續優化(bulge 回合式 driver;同步版已涵蓋核心價值) | deepseek 非同步 |

## 體驗

| 機制 | bulge | 參考對位 |
|---|---|---|
| 桌面 App | ✅ Tauri 2,即時串流、diff 審批、計量條、多任務 | 對位 opencode TUI/console |
| 設定面板 | ✅ 模型/金鑰/取樣/人設/MCP/記憶/技能檢視 | — |
| 本地 HTTP 伺服器 | ⬜ **刻意不做**(既定約束;整合走 ACP stdio) | opencode 139 端點 HTTP API(不採) |
| hooks/排程/profile 的 UI | 🟡 後端已備,UI surfacing 進行中 | — |
| 逐回合 revert/diff | ⬜ 後續 | opencode shadow-git 快照 |
| code-mode(工具即函式批次) | ⬜ 後續(省 token) | deepseek PTC、opencode Code Mode |

---

## 本輪新增(對照素材補齊的能力)

| commit | 功能 | 主要軸 |
|---|---|---|
| hooks | 生命週期 PreToolUse/PostToolUse | 安全+自動化 |
| 學習護欄+台帳 | DO_NOT_CAPTURE + 技能 .usage.json | 智能 |
| 掃描器 | 秘密遮蔽 + 威脅偵測 | 安全 |
| 使用者模型 | USER.md/MEMORY.md + 安全把關 | 智能+安全 |
| cron 引擎 | 六選擇器 + 5 欄位 cron | 自動化 |
| curator | 技能依閒置老化 | 智能 |
| 排程執行 | schedule add/list/remove/tick | 自動化 |
| 事件觸發 | OnPathChange 監看路徑變更 | 自動化 |
| LLM 審查閘 | 變動型呼叫前二次審查 | 安全 |
| 子代理 | 同步 delegate(父只見摘要) | 智能+自動化 |
| 對話檢索 | recall 關鍵字(含 CJK) | 智能+體驗 |
| UI | 設定面板呈現上述 | 體驗 |

## 每軸裁決(對四個參考代理)

- **安全 ✅ 勝出**:唯一同時具備「真 microVM 隔離 + 寫回審批 + opencode 式程式碼策略 +
  Pre/Post hooks + 持久面威脅掃描 + 秘密遮蔽 + LLM 二次審查閘」的防禦縱深。opencode 無容器、
  deepseek 僅政策模式、hermes/openclaw 用 Docker/SSH 但無 VM 等級 + 寫回審批的組合。
- **智能 ✅ 勝出或對位**:具備 hermes 式學習迴圈**並額外**有反污染護欄、使用者模型、技能生命週期
  台帳 + curator、對話檢索、子代理委派。opencode/openclaw/deepseek 皆無持久自我學習。
- **自動化 ✅ 對位或勝出**:時間(六選擇器 + Vixie cron)**與**事件(OnPathChange)雙觸發 +
  single-flight + 自動化更緊信封(skip_review + 預設審查)+ 子代理拆分 + MCP + ACP。
- **體驗 ✅ 對位或勝出**:桌面 App + 即時串流 + diff 審批 + 持久工作階段 + 設定面板全呈現 +
  側欄過往任務檢索。較 opencode 的 TUI 在「審批式安全 UX」上更完整。
- **功能 ✅ 廣度對位**:VM 沙箱 + MCP + ACP + hooks + cron/事件 + 子代理 + recall + profile/記憶/技能。

## 後續優化(非軸線缺口,屬加分項)

1. **非同步 return-now 子代理**(deepseek 式 childId→settled 通知):bulge 回合式 driver 下同步版
   已涵蓋核心價值,async 為效率加分。— 自動化
2. **對話檢索 FTS 升級**(SQLite FTS5 四模式 + cron session 降權):現關鍵字版已可用。— 智能
3. **逐回合 shadow-git revert/diff**。— 體驗
4. **code-mode**(工具即函式,單次批次多呼叫,省 token)。— 智能/體驗

> 原則:保留 bulge「VM 為真邊界 + 寫回審批」的既有優勢;新機制一律 fail-closed/fail-open 依
> 其為「邊界」或「第二意見」而定、持久面寫入前做威脅掃描、自動化執行採更緊信封。不引入既定
> 約束排除的本地 HTTP 伺服器(整合走 ACP)。
