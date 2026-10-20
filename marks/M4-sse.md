# M4 — SSE 解析器

**目標**：`crates/bulge-llm/src/sse.rs` 的 `SseParser::push`（可加私有欄位）。
**來源**：`~/deepseek-harness/packages/llm/llm-deepseek/src/sse.ts`（只用了 eventsource-parser）。規則依 WHATWG HTML「event stream interpretation」：
- 以 `\n`、`\r\n`、`\r` 分行；跨 `push` 呼叫的半行、半個 UTF-8 字元要保留在緩衝。
- 空行派送事件；`data:` 多行以 `\n` 串接；`event:`；`id:`/`retry:` 讀取後忽略；冒號開頭為註解 → `comments += 1`；欄位名後第一個空白去掉。
- 只有 data 時派送；data 為空的事件不派送。不完整的最後一個事件**不**派送。
- 開頭 UTF-8 BOM 去除。
- JSON 解析與 `[DONE]` 判斷**不在這裡**做（屬於各協定的 decoder）。

## 驗收測試
- 一次餵完整串流；逐 byte 餵入結果相同；`\r\n` 與 `\r`；多行 data；註解計數；中文字元被切在兩次 push 之間；結尾沒有空行的事件不出現。
