# M3 — Anthropic Messages 協定（DeepSeek 主力路線）

**目標**：`crates/bulge-llm/src/protocol/anthropic.rs`：實作 `encode` 與 `decoder`（回傳私有的 `AnthropicDecoder: StreamDecoder`）。`classify_error` 已委派給 M5，不要動。
**來源**（`~/deepseek-harness/packages/llm/llm-deepseek/src/`）：
- `serialize.ts` 全檔（L60-169 為主體）→ `encode`
- `translate.ts` 全檔 → `AnthropicDecoder`
- `replay.ts` → 只取概念（見下）
- `wire-types.ts` → 線上 JSON 形狀（可用私有 serde struct 或直接組 `serde_json::Value`）

## encode 規則（對照 serialize.ts）
- 輸入是 `GenerateRequest` + `EncodeContext`；`cx.model.system_prompt_update` 取代 TS 的 `inHistory`。
- 第一個 `Role::System` 訊息 → 頂層 `system`。之後的 `Role::System` 訊息：
  - `InHistory`：轉成 `{"role":"system","content":[...]}` 的歷史更新，放在前一個 user/tool-result 回合**之後**、下一個 assistant **之前**（TS 的 `flushSystemUpdates`）；沒有前置 user 回合 → `unsupported`。
  - `LeadingOnly`：文字併入頂層 `system`（以 `\n\n` 連接）。
  - `ToolAddition/ToolRemoval` 區塊 → `{"type":"tool_addition"|"tool_removal","tool":{"type":"tool_reference","name":...}}`，只允許出現在 System 訊息；出現在其他角色 → `unsupported`。
- **Replay（取代 replay.ts 的 envelope）**：assistant 的 `Reasoning{signature}` 只在 `message.source_model == Some(request.model)` 時送出 `signature`，否則只送 `thinking` 文字。
- assistant：空文字略過；`ToolCall.arguments` 解析為 JSON object，解析失敗或非 object → `{}`（同 TS `toolInput`）。
- `Role::Tool` → user 角色的 `tool_result{tool_use_id, content, is_error?}`；相鄰同角色訊息合併。
- 圖片：`Image{media_type,data}` → `{"type":"image","source":{"type":"base64",...}}`。不做 Files API。
- 送出前檢查（serialize.ts L130-150）：tool_use id 不重複；每個 assistant 的所有 tool_use 必須由**緊接**的 user 訊息全部回應；tool_result 移到該 user 訊息最前面；結尾不可有未回應的 call。違反 → `ErrorCode::InvalidRequest`。
- effort：`request.reasoning_effort` 預設 `High`（`cx.model.reasoning == false` 時預設 `Off`）；`Off` → `thinking:{type:"disabled"}` 且不送 `output_config`；其他 → `thinking:{type:"enabled"}` + `output_config:{effort}`。
- `max_tokens` = request → `cx.model.max_tokens` → `cx.default_max_tokens`。`temperature`、`stop_sequences`（非空才送）。
- tools：`{name, description, input_schema, defer_loading?}`，`defer_loading` 只在 `cx.model.deferred_tools` 為真時送，否則該 tool 照常完整宣告。**保持輸入順序**（排序由上層負責）。
- `stream: true`。

## decoder 規則（對照 translate.ts）
- 事件：`message_start`（必須第一個且只有一次，讀 usage）、`content_block_start/delta/stop`、`message_delta`（stop_reason、usage）、`message_stop`、`ping` 與未知類型忽略；`error` 事件 → `crate::error::classify_http(None, &event, None, None)` 作為錯誤回傳。
- 線上 index → 本地密集 index（第 n 個開啟的區塊）。
- 區塊：text / thinking（`signature_delta` 累加到 signature，不輸出 chunk）/ tool_use（`input_json_delta` 累加）。start 時若已有初始文字要立即輸出 delta；tool_use start 輸出一個帶 `name` 的 `ToolCallDelta`。
- stop → `BlockEnd{block}`；tool_use 的 arguments 若有累加 JSON 則用累加值，否則用 start 的 `input` 序列化。
- stop_reason：`end_turn|stop_sequence` → Stop、`tool_use` → ToolCalls、`max_tokens` → MaxTokens，其他 → malformed。
- `message_stop`：要求所有區塊已關閉且有 stop_reason；零區塊且 Stop → `EmptyResponse`；非 MaxTokens 時每個 tool call 的 arguments 必須是合法 JSON object。依序輸出 `Usage` 再 `Finish`。
- usage 對應：`input_tokens`、`output_tokens`、`cache_read_input_tokens` → cache_read、`cache_creation_input_tokens` → cache_write。
- `on_close` 在未收到 `message_stop` 時 → `ErrorCode::StreamClosed`。

## 驗收測試
- encode：in-history system 更新位置正確；LeadingOnly 合併；跨模型 signature 被移除、同模型保留；tool 配對的三種錯誤；tool_result 移到最前；effort Off/High；defer_loading 依 `deferred_tools` 切換。
- decoder：一段含 thinking+signature、text、tool_use（分多個 input_json_delta）的完整事件序列 → 正確 chunk 序列與 BlockEnd 內容；`max_tokens` 時截斷的 tool JSON 不報錯；缺 message_stop → StreamClosed；未知事件被忽略。
