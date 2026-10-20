# Bulge — P0 參考盤點

來源縮寫：**DSH** = ~/deepseek-harness、**OC** = ~/openclaw、**OCD** = ~/opencode。
決策：**沿用**（設計照搬，以 Rust 重寫）／**改造**（取核心概念、改形）／**捨棄**／**新做**（三者皆無）。
所有程式碼皆為 MIT，只參考設計並重寫；THIRD_PARTY_NOTICES 列出三者。

---

## 1. 代理迴圈（bulge-core::loop）

| 零件 | 來源 | 決策 | 理由 |
|---|---|---|---|
| turn → step 狀態機；pre-step / request-error / turn-stopping 掛點 | DSH `packages/core/agent-loop/src/agent.ts` L298-561 | 改造 | 結構好；Cordis waterfall 換成 Rust trait 中介層鏈 |
| 「模型看得到 ⟺ 有寫入日誌」 | DSH 同上 | 沿用 | 稽核與重播的基礎 |
| 孤兒 tool call 補合成結果 | DSH `ToolCallRecovery` | 沿用 | 保持 call/result 配對 |
| concurrencySafe 平行 + 互斥屏障排程 | DSH `tool-calls.ts`（上限 10） | 沿用 | |
| 每 step 一次 stream、從持久歷史續跑；durable inbox；write-ahead 執行 claim 供當機恢復 | OCD `AGENTS.md` Session Core、`core/src/session/` | 沿用 | 簡單且可恢復 |
| **步數 / token / 牆鐘預算**為迴圈不變量 | DSH 沒有；OCD 只有 `runner/max-steps.ts` | 新做（參考 OCD max-steps：耗盡時停用工具、強制總結） | 防失控核心 |
| 緊急停止 | DSH 單一 AbortController + typed cancel cause | 沿用 | 對應 UI 停止鈕 |

## 2. 模型層（bulge-llm）

| 零件 | 來源 | 決策 | 理由 |
|---|---|---|---|
| Model 結構、「wire 協定家族 ≠ provider」分離 | OC `packages/llm-core/src/types.ts` L17-28, L807-850 | 改造 | → `trait LlmBackend { stream(ctx) -> Stream<Event> }` |
| 串流事件聯集（text/thinking/toolcall/done/error） | OC `types.ts` L611 | 沿用 | |
| 協定實作：Anthropic Messages、OpenAI chat/compatible | OCD `packages/ai/src/protocols/*` | 改造 | v1 只做這兩種（DeepSeek 走 Anthropic 相容端點） |
| DeepSeek thinking signature 重播、effort 對應、call/result 嚴格檢查 | DSH `packages/llm/llm-deepseek/src/{serialize,replay}.ts` | 沿用 | |
| DeepSeek wire extensions：`dsh_session_log`、user/session id 標頭 | DSH `docs/deepseek-llm-api-wire-extensions.md` | **捨棄** | 會把 session log 上傳給供應商，屬隱私外洩 |
| 重試：指數退避 + jitter、尊重 retry-after | DSH `llm-retry` | 沿用 | |
| 兩段式 failover（同 provider 換金鑰 → 模型備援鏈）、速率閘門 | OC `docs/concepts/model-failover.md`、`src/llm/provider-rate-limit.ts` | 沿用（v1 只做備援鏈） | |
| 本地模型 | OC `extensions/llama-cpp`（llama-server HTTP） | **捨棄其做法** | 屬本地伺服器；改用 `llama-cpp-2` 程序內 |
| 弱/本地模型的文字型 tool call 修復（JSON、`<tool_call>`、ReAct） | OC `packages/tool-call-repair/src/attempt.ts` | 沿用 | 本地 GGUF 必需 |
| models.dev 模型中繼資料（context window、價格） | OCD `core/src/models-dev.ts` | 改造 | 內建快照，不上網抓 |
| token 估算 chars/4 + 4/區塊 | DSH `token-meter/src/estimate.ts` | 沿用 | 本地模型可用真 tokenizer |

## 3. 省 token（bulge-context）

| 零件 | 來源 | 決策 | 理由 |
|---|---|---|---|
| 快取穩定規則：歷史只追加、system 變更改成追加訊息、動態資訊用 runtime-context user 訊息、工具排序固定 | DSH `core/system-prompt/src/index.ts` L176、llm-deepseek | 沿用 | 最大的省 token 來源；本地模型也因此可重用 KV 前綴 |
| 提示分「穩定區 / 快取界線 / 易變區」 | OC `src/agents/system-prompt.ts` | 沿用 | |
| 自動快取斷點（最後工具、system 首尾、訊息尾，最多 4） | OCD `ai/src/cache-policy.ts` | 沿用 | Anthropic 相容端點用 |
| 小型基礎提示 + 只為存在的工具加說明 + 各模型家族變體 | OCD `session/system-prompt.ts`、`plugin/system-prompt/*.txt` | 沿用 | 加一個「本地小模型」變體 |
| 長工具輸出 spill 到檔案、只給頭尾 + 路徑 | DSH `packages/spill/*`（12,500 tokens）；OCD `core/src/tool-output.ts`（2000 行/50 KiB） | 沿用 | spill 檔放在 **VM 內**，代理用 read/grep 取 |
| 修剪：>30% 用量 soft-trim 舊工具輸出；>50% hard-clear；不碰最後 3 輪 | OC `docs/concepts/session-pruning.md` | 沿用 | OCD v2 已移除修剪，以 OC 為準 |
| 壓縮：0.8 門檻 + overflow 反應式；先修剪再摘要；摘要呼叫重用同一前綴（吃快取） | DSH `packages/compaction/compaction-basic/*` | 沿用 | |
| 摘要模板與保留量 max(16k, 15%) | OCD `core/src/session/compaction.ts` L93-146 | 沿用 | |
| 摘要品質檢查（識別字、待辦）、逾時退回決定性摘要 | OC `src/agents/compaction.ts` | 沿用 | |
| 工具 schema 延遲載入（tool_search / describe） | OC `docs/tools/tool-search.md`；DSH `defer_loading` | 沿用 | |
| PTC（一段程式批次呼叫工具） | DSH `run_code` | 延後 | v1 之後再評估 |

## 4. 防失控與審批（bulge-guard）

| 零件 | 來源 | 決策 | 理由 |
|---|---|---|---|
| 權限規則 `{action, resource, allow/deny/ask}`、last-match-wins 萬用字元、once/always/reject、帶回饋的 reject 讓模型修正 | OCD `core/src/permission.ts` L88、`util/wildcard.ts`、`permission/saved.ts` | 沿用 | |
| shell 指令用 tree-sitter 解析成逐指令資源 | OCD `shell/parse.ts` | 沿用 | 規則才能比對到真正執行的指令 |
| **規則式風險分級**（工具 + 參數模式、碰工作區外、網路外連） | DSH auto-review 的 low/medium/high 分類只有 LLM 版 | 新做（以 DSH `REVIEW_POLICY` 分類為規則基礎；LLM 審查只當第二意見） | 決定性、可預測 |
| 審批綁定精確 argv/cwd/env + 執行檔 realpath 與 hash；`python -c` 類 inline eval 需審批 | OC `docs/tools/exec-approvals.md` L50-60 | 沿用 | |
| 一次性升權：同一呼叫帶理由重試、使用者核准 | DSH `sandbox/sandbox/src/escalation.ts` | 沿用 | |
| 審批成對記錄 `approval/asked` + `decided` | DSH | 沿用 | |
| 迴圈偵測：generic_repeat、argument_churn、ping_pong、no-progress poll、全域斷路器；結果雜湊去除易變欄位；同錯 3 次停 | OC `src/agents/tool-loop-detection.ts` L36-61 | 沿用 | |
| 重複呼叫提醒 [3,5,8] | DSH `guard/repeat-tool-reminder` | 改造 | 最高門檻改為**硬停** |
| 先讀後改 | DSH `fs-observation-policy` | 沿用 | |
| 工具逾時、bash 逾時轉背景 | DSH `guard/timeout-policy`、`jobs-local` | 沿用 | |
| 計畫模式：計畫被核准前**真的擋**寫入類工具 | DSH plan-mode（不擋）；OCD `plugin/plan.ts`（以權限集擋） | 改造（用 OCD 做法） | |
| 偏離計畫偵測（工具目標 vs 已核准計畫） | 三者皆無 | 新做 | |
| goal 輪次上限、「宣告完成前要驗證」 | DSH `goal/goal-round-driver` | 沿用 | |
| subagent 深度上限 1、總產生數上限 | DSH `subagent/depth.ts`；OCD explore/general 權限集 | 沿用 | |
| OC「不要預先拒絕」執行偏好 | OC system-prompt Execution Bias | **捨棄** | 與謹慎、先計畫相衝 |

## 5. 沙箱與 VM（bulge-vm / sandboxd）

| 零件 | 來源 | 決策 | 理由 |
|---|---|---|---|
| 隔離機制（bwrap/Landlock/Seatbelt；Docker/Podman） | DSH `sandbox-local`；OC `src/agents/sandbox/` | 捨棄 | 改用 libkrun microVM，強很多 |
| 沙箱後端介面、預設開啟 | OC `backend.types.ts` | 改造 | OC 預設關，bulge 預設開且無法關 |
| 探測失敗即拒跑（fail closed）、拒絕標記文字（叫模型別換方法繞） | DSH `sandbox-local` | 沿用 | |
| 主機↔guest 協定：長度前綴幀、magic、方向、generation、遞增序號、HMAC-SHA256、先檢上限再配置、先驗 HMAC 再解析、錯誤即毒化通道 | OC `crates/openclaw-node-host/src/sidecar_protocol.rs`、`SIDECAR_PROTOCOL.md` | 沿用 | 走 vsock；Rust 原生，最好移植 |
| guest 指令執行器：逐指令 admission、位元組/逾時/並行上限、取消 | OC `openclaw-node-host/src/runtime.rs` L29-34, L166-330 | 沿用 | 成為 sandboxd 骨幹 |
| 網路外連過濾：非公開 IP 擋（loopback、link-local、RFC1918、CGNAT、metadata、NAT64/嵌入 IPv4）、DNS 解析一次並釘住位址防 rebinding | OC `packages/net-policy/src/ip.ts`；DSH `web-fetch-http/src/network.ts` L80-125 | 沿用 | 落實「允許網路但擋主機/區網」 |
| 工作區快照與 diff：shadow git tree 擷取/差異/還原 | OCD `core/src/snapshot.ts`、`session/revert.ts`；DSH `deliverables/workspace-changes` | 改造 | 套在 overlay 上，產生審批 diff |

## 6. 工具集（在 sandboxd 內執行）

| 工具 | 來源 | 決策 |
|---|---|---|
| read（行號、offset/limit 2000）、write、glob、grep（ripgrep）| DSH `docs/tool-catalog.md`；OCD `tool/plugin/*` | 沿用 schema（模型熟悉這種風格） |
| edit：三層比對（精確 → unicode 正規化 → 行尾空白不敏感）、保留 CRLF/BOM、diff 先進審批請求 | OCD `tool/plugin/edit.ts` L49-283 | 沿用 |
| patch（`*** Begin Patch` 格式） | OCD `tool/patch.txt` | 沿用 |
| shell：timeout、背景執行完成通知（「不要輪詢」）、輸出環形緩衝 | OCD `shell.ts`；DSH `jobs-local` | 沿用 |
| web_fetch / web_search | DSH | 沿用（走 VM 網路閘門） |
| todo、question、skill、subagent | DSH / OCD | 沿用 |
| MCP client | DSH `mcp-client` | 延後（v1 之後） |

## 7. 越用越懂（bulge-memory）

| 零件 | 來源 | 決策 | 理由 |
|---|---|---|---|
| 檔案佈局：USER.md（偏好）、MEMORY.md（精選，開場注入、限預算）、每日筆記 | OC `docs/concepts/memory.md` | 沿用 | 人可讀、可手改；存主機端 |
| memory_search：SQLite FTS5 + 向量（本地 embedding） | OC `extensions/memory-core`；DSH `session-query-sqlite` | 沿用（rusqlite + sqlite-vec） | |
| **自動寫入 1**：壓縮前 flush，靜默一輪寫入今日筆記，可指定本地小模型 | OC pre-compaction flush | 沿用 | |
| **自動寫入 2**：閒置整合（dreaming），模型回傳 add/merge/supersede 操作而非散文、需引用來源行、改寫前存 preimage | OC `dreaming.md`、`src/memory-host-sdk/dreaming.ts` | 改造成閒置背景工作 | |
| 來源汙染閘：untrusted（網頁、工具輸出）來源的候選不得成為記憶 | OC deep phase taint gate | 沿用 | 防提示注入污染長期記憶 |
| skill 格式 SKILL.md + 漸進揭露（目錄 ~24 tokens/條，本文按需載入） | OC `docs/tools/skills.md`；DSH `packages/skill/*` | 沿用 | |
| **自動學 skill**：skill_workshop（create/patch/archive/restore，改前存版本保留 10 份，驗證與機密掃描）；背景審查（10 次迭代、閒置 30 秒、每次最多 1 改）；30 天未用自動封存 | OC `docs/tools/skill-workshop.md`、`self-learning.md` | 沿用 | 「越用越懂」核心 |
| 規則：事實進記憶、做法進 skill | OC | 沿用 | |
| 操作手冊 5 段式（Gather → Mutate → Repair → Prove → Report） | OC `custodian-skills/` | 沿用 | 內建 skill 的寫法 |

## 8. 儲存與稽核（bulge-store）

| 零件 | 來源 | 決策 |
|---|---|---|
| session / message 表結構、訊息聯集、tool 狀態機 | OCD `core/src/session/sql.ts` L79、`packages/schema/src/session-message.ts` | 沿用（rusqlite） |
| 只追加 JSONL 事件日誌（turn/step/tool/approval/compaction/sandbox），尾端損毀恢復，舊世代 zstd 壓縮 | DSH `session-persistence-jsonl` | 沿用：同時當稽核日誌與重播來源 |
| OpenTelemetry | DSH `telemetry/otel` | 捨棄（不外送任何資料） |

## 9. 不可複製（本地伺服器類）

- DSH：`packages/host/webserver`、`api/gateway/src/stream-server.ts`、`ssh/helper-processes.ts`、Electron `apps/desktop`、`llm-mock-server`。
- OC：`src/gateway/*`（WS 控制面 18789、`/v1/chat/completions`、`/tools/invoke`、mcp-http、control UI）、`crates/openclaw-gateway-client`、llama-server/ollama 外掛。
- OCD：`packages/server`、`protocol`、`client`、`httpapi-codegen`、`cli/src/server-process.ts`、`packages/desktop`。

bulge 一律：UI ⇄ 核心走 Tauri IPC；核心 ⇄ VM 走 vsock；本地模型程序內載入。

## 10. 需新做的部分（三者皆無）

1. 迴圈層的硬預算（步數 / token / 牆鐘）。
2. 規則式風險分級器。
3. 偏離計畫偵測。
4. libkrun VM 後端 + 網路閘門 + overlay diff 審批流程。
5. 程序內 GGUF 後端（含 KV 前綴重用）。
6. Tauri UI（對話、計畫審批、diff 審批、記憶/skill 檢視、緊急停止）。

## 建議 crate 版圖

```
bulge/
  crates/
    bulge-proto     # vsock 幀協定（主機與 guest 共用）
    bulge-llm       # LlmBackend trait、anthropic/openai 協定、llama-cpp 後端、tool-call 修復
    bulge-core      # 迴圈、預算、context/壓縮/修剪、工具註冊
    bulge-guard     # 權限規則、風險分級、迴圈偵測、計畫閘
    bulge-memory    # 記憶、skill workshop、FTS/向量
    bulge-store     # SQLite session + JSONL 事件日誌
    bulge-vm        # libkrun 啟動、virtiofs overlay、網路閘門、快照/diff
    sandboxd        # guest 常駐程式（musl 靜態），工具實作
  app/              # Tauri 2 桌面 APP
```
