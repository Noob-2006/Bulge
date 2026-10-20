# M18 — 上下文視窗管理（估算 / 修剪 / 壓縮範圍）

**目標**：`crates/bulge-core/src/context.rs` 的 `estimate_tokens`、`prune`、`compaction_range`（可加私有函式；公開型別、常數、`summary_message`、`SUMMARY_TEMPLATE` 不可變）。
**來源**：
- `~/deepseek-harness/packages/llm/token-meter/src/estimate.ts`（chars/4 + 每區塊 4 token 概念）→ `estimate_tokens`
- `~/deepseek-harness/packages/compaction/compaction-tool-result-pruner/src/index.ts`（stage-1 修剪：>8192 字留頭 4096 + 尾 1024，中間換標記）→ `prune`
- `~/openclaw/docs/concepts/session-pruning.md`（>30% 壓力才修剪、不碰最後數則、不碰系統訊息）→ `prune` 的觸發與保護
- `~/deepseek-harness/packages/compaction/compaction-basic/src/{region.ts,config.ts}`（範圍選擇：從第一個非系統訊息到保留尾端；tail = retainRatio 的預算；不切 call/result 對）→ `compaction_range`
- `~/opencode/packages/core/src/session/compaction.ts` L93-146（reserve = max(16k,15%)）→ `compaction_range` 的 reserve 概念

## 規則
- `estimate_tokens`：對每則訊息，所有 text/reasoning/tool-call 內容的字元數總和 /4，再每個區塊 +4，每則訊息角色 +4。回傳總和。
- `prune`：
  - 先 `estimate_tokens`；若 ≤ `window * pressure_ratio` → 原樣回傳（clone）。
  - 否則掃描**可修剪範圍**：跳過索引 0 的系統訊息（若 `messages[0].role == System`）、跳過最後 `keep_recent` 則、只處理 `Role::Tool` 訊息中的 text 區塊。
  - 對超過 `max_tool_result_chars` 的 tool-result text：保留前 `head_chars` + `\n[... {n} chars pruned ...]\n` + 後 `tail_chars`（n 以字元計；切片需在 char boundary）。
  - 不得移動或刪除任何訊息（只改內容），保持 call/result 配對。
- `compaction_range`：
  - 若 `estimate_tokens(messages) + reserve <= window` → `None`。
  - `start` = 第一個非系統訊息索引。
  - 從尾端往回累計 token，直到累計達 `window * retain_ratio`，該點即 `kept_from`；但不可讓 `kept_from` 落在一組 call/result 之間（若某 `Role::Tool` 訊息被保留，其對應的 assistant tool-call 訊息也要在保留側；做法：把 `kept_from` 往前移到該 assistant 訊息）。
  - 若 `kept_from <= start`（沒東西可壓縮）→ `None`。
  - 回傳 `CompactionRange { start, kept_from }`。
- 只用 bulge-llm 型別與 std，不新增依賴。

## 驗收測試
- estimate 對已知訊息給出合理值（單調：內容越多越大）。
- 低於壓力門檻 → prune 原樣返回；超過 → 只有舊的、長的 tool-result 被截，系統訊息與最後 keep_recent 則不動，assistant/user 訊息不動。
- 截斷標記含正確的省略字元數；多位元組字元不被切壞。
- compaction_range：未超量 → None；超量 → start 在系統訊息之後、kept_from 不切斷 call/result 對、保留尾端量 ≥ retain_ratio。
- `cargo test -p bulge-core`、`cargo clippy -p bulge-core --all-targets -- -D warnings` 通過。
