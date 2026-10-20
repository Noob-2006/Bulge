# M8 — 純文字 tool call 修復（本地/弱模型用）

**目標**：`crates/bulge-llm/src/repair/mod.rs`（`looks_like_tool_call`、`repair`）、`repair/grammar.rs`、`repair/payload.rs`（私有）。
**來源**（`~/openclaw/packages/tool-call-repair/src/`）：
- `grammar.ts` 全檔 → `grammar.rs`（掃描輔助、XMLish `<tool_call>` 掃描、JSON 物件掃描）
- `payload.ts` 全檔（`scanPlainTextToolCall` L299、`parseStandalonePlainTextToolCallBlocks` L450、`stripPlainTextToolCallBlocks` L513）→ `payload.rs`
- `attempt.ts` `detectToolCallShapedText` L232、`isPlainTextToolCallAttempt` L286 → `looks_like_tool_call`
- `contracts.ts` 的 protected range 概念：fenced code block（``` 與 ~~~）內一律視為保護區不修復。
- 測試參考：`attempt.test.ts`、`payload.test.ts`、`grammar.test.ts` → 移植為 Rust 測試。

## 規則
- 支援語法：JSON（`{"name":..,"arguments":{..}}`）、`<tool_call>…</tool_call>` XMLish、harmony 標記（`<|channel|>…<|message|>…<|call|>`）、`[TOOL_CALL]…[END_TOOL_REQUEST]`、ReAct `Action:` / `Action Input:`，以來源實際支援的為準。
- `allowed_tools` 為空 → 不修復任何呼叫；名稱不在名單 → 保持原文。
- payload 超過 `max_payload_bytes` → 保持原文。
- `arguments` 輸出為緊湊 JSON object 文字；非 object → 保持原文。
- **不搬** `stream-normalizer*.ts`、`promote.ts`、`protection-fast-path.ts`（串流版在 P1b 本地後端時再評估）。
- JS 字串索引是 UTF-16；Rust 一律用 byte offset，`span` 為 byte range，切片前確認在 char boundary。

## 驗收測試
- 來源三個 test 檔中屬於「standalone 解析 / 偵測 / grammar」的案例全部移植。
- fenced code 內的呼叫不被修復；不在白名單的名稱不修復；多個呼叫依序回傳且移除後文字正確。
