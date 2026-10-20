# M6 — OpenAI Chat Completions 協定

**目標**：`crates/bulge-llm/src/protocol/openai_chat.rs`：實作 `encode` 與 `decoder`（私有 `OpenAiChatDecoder`）。`classify_error` 已委派 M5。
**來源**：`~/opencode/packages/ai/src/protocols/openai-chat.ts`
- 線上形狀：L43-292（Schema 定義）
- encode：`lowerTool` L334、`lowerToolCall` L353、`lowerUserMessage` L412、`lowerAssistantMessage` L436、`lowerToolMessages` L501、`lowerMessages` L552、`fromRequest` L773-823
- decode：`ParserState` L302、`step` L1015-1192、`finishEvents` L1193-1246、`mapFinishReason` L834、`mapUsage` L879-903、`toolIndexByID` L904、`reasoningDelta` L914

## 只搬的部分
- messages：system（**每個** System 訊息依序轉 `role:"system"`，含中途更新；`ToolAddition/Removal` → `unsupported`）、user（text / image_url data URI）、assistant（`content` 文字 + `tool_calls[{id,type:"function",function:{name,arguments}}]` + 推理文字放 `reasoning_content`，僅當 `source_model == request.model`）、tool（`role:"tool", tool_call_id, content`；多個 text 區塊以 `\n` 串接）。
- tool call/result 配對檢查同 M3（錯誤 → InvalidRequest）。
- body：`model, messages, stream:true, stream_options:{include_usage:true}, max_tokens, temperature?, stop?, tools?`（`{type:"function",function:{name,description,parameters}}`）。`defer_loading` 在此協定無對應 → 該 tool 照常宣告。
- reasoning effort：`Off` 或 `cx.model.reasoning == false` → 不送；其他 → `reasoning_effort: "low"|"high"`（Max 送 "high"）。
- decode：`data == "[DONE]"` 為結束標記；`choices[0].delta.{content, reasoning_content|reasoning, tool_calls[]}`；tool_calls 依 `index` 聚合（第一次出現帶 id/name），每個新 index 開一個 ToolCall 區塊；text 與 reasoning 各自開區塊；切換類型時先關閉前一個區塊（保持順序）。`finish_reason`：stop → Stop、tool_calls|function_call → ToolCalls、length → MaxTokens、content_filter → Stop、其他 → malformed。usage 可能在最後一個無 choices 的事件裡，`[DONE]` 時輸出 `Usage` 與 `Finish`。
- usage：`prompt_tokens` 減去快取命中（`prompt_tokens_details.cached_tokens` 或 `prompt_cache_hit_tokens`）= input；cache_read = 命中數；`completion_tokens` = output；`completion_tokens_details.reasoning_tokens` = reasoning。
- `on_close` 在未收到 `[DONE]` 時：若已有 finish_reason 則照常收尾，否則 StreamClosed。
- in-band `{"error":{...}}` 事件 → `classify_http(None, &event, None, None)`。

## 不搬（違反「不得寫死」或超出範圍）
- `detectSupportsStore`、`detectSupportsStrictMode`、`detectZaiToolStream`、`detectMaxTokensField`、OpenRouter/Kimi/Google `reasoning_details`、cache_control、tool_choice、store、seed。

## 驗收測試
- encode：中途 system 更新、跨模型 reasoning 移除、tool 配對錯誤、圖片 data URI。
- decode：reasoning→text→兩個平行 tool call（分片 arguments）→ usage 事件 → `[DONE]` 的完整序列；DeepSeek 的 `prompt_cache_hit_tokens` 正確扣除；缺 `[DONE]` 但已有 finish_reason。
