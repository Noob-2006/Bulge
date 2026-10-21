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
| LLM 二次審查閘 | ⬜ 後續可選 | deepseek `auto-review` |

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
| 過往對話檢索 | ⬜ 後續(需 FTS) | hermes `session_search`(FTS5 四模式) |

## 自動化

| 機制 | bulge | 參考對位 |
|---|---|---|
| 排程引擎 | ✅ 六選擇器 + 5 欄位 cron(純算術,零 tz 依賴) | 對位 deepseek schedule、hermes cron |
| 排程執行 | ✅ `bulge schedule tick`:single-flight 鎖、只補最近漏跑、產出可審核 diff | 對位 hermes scheduler_tick 單飛鎖 |
| 自動化更緊信封 | ✅ 排程執行跳過學習迴圈(skip_review);autonomous + 不自動寫回 | 對位 openclaw scheduled-tool-policy(ask:always) |
| 持久/模塊化 VM 工作階段 | ✅ 一個 VM 跨回合存活,設定變更只重啟機器、保留對話 | bulge 自有 |
| MCP 外部工具 | ✅ stdio JSON-RPC client(mcp.json) | 對位三者的 MCP |
| ACP 代理伺服器 | ✅ `bulge acp`(編輯器可驅動) | 對位 hermes acp_adapter、openclaw codex harness |
| 非同步子代理 | ⬜ 後續(回傳 childId、settled 通知、send_message) | deepseek subagent、hermes delegate |
| 事件觸發 | ⬜ 後續 | openclaw cron event-source |

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

## 後續排序(持續縮小與超越差距)

1. **非同步子代理**(deepseek 式:回傳 childId → settled 通知 → send_message 續談;parent 只見摘要、深度上限、批次並行)。— 自動化/智能
2. **UI surfacing**:hooks / 排程(建立/列表/刪除)/ USER.md·MEMORY.md / 技能台帳檢視。— 體驗
3. **過往對話檢索**(FTS;四模式;cron session 降權)。— 智能
4. **逐回合 shadow-git revert/diff**。— 體驗
5. **code-mode**(工具即函式,單次批次多呼叫,省 token)。— 智能/體驗
6. **LLM 二次審查閘**(危險動作前)。— 安全

> 原則:保留 bulge「VM 為真邊界 + 寫回審批」的既有優勢;新機制一律 fail-closed、
> 持久面寫入前做威脅掃描、自動化執行採更緊信封。不引入既定約束排除的本地 HTTP 伺服器。
