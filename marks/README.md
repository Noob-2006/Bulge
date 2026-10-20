# 轉寫標記（P1）

流程：Claude code review 參考原始碼 → 在此標記 → dsh 轉寫成 Rust → Claude 用預先定義的接口組裝、測試。

## 共同規則（每個標記都適用）
1. **只改標記指定的目標檔案。** 不要改 `types.rs`、`error.rs`（M5 的函式本體除外）、`backend.rs`、`protocol/mod.rs`、`http.rs`、`assemble.rs`、`Cargo.toml`。
   需要新依賴時，不要自己加，在回報裡列出來。
2. **公開簽名不得變更。** stub 裡的 `pub` 型別、函式簽名就是接口；`todo!()` 換成實作即可，可加私有輔助函式與私有型別。
3. **不得寫死。** 模型名稱、URL、金鑰、特定供應商的特例不可出現在協定碼裡；需要的值一律從參數（`EncodeContext`、`ModelInfo`、`RetryPolicy`…）取。
4. **不得默默丟資料。** 無法表示的內容回傳 `LlmError::unsupported(...)`，不可略過。
5. 參考原始碼是設計來源，不是逐字翻譯：TS 的 plugin/hook/Effect 機制全部省略，只保留演算法與檢查。
6. 每個標記附 `#[cfg(test)] mod tests`，至少涵蓋「驗收測試」列出的情境。
7. 完成條件：`cargo test -p <crate>` 與 `cargo clippy -p <crate> -- -D warnings` 皆通過。
8. 禁止 `unsafe`、禁止 `unwrap()` 於非測試碼（用 `?` 或明確錯誤）。

## 標記一覽
| ID | 目標 | 來源 |
|---|---|---|
| M1 | crates/bulge-proto/src/frame.rs | openclaw sidecar_protocol.rs |
| M2 | crates/bulge-proto/src/handshake.rs | openclaw sidecar_handshake.rs |
| M3 | crates/bulge-llm/src/protocol/anthropic.rs | DSH llm-deepseek serialize/translate/replay |
| M4 | crates/bulge-llm/src/sse.rs | DSH sse.ts（eventsource 規則） |
| M5 | crates/bulge-llm/src/error.rs `classify_http` | DSH transport.ts |
| M6 | crates/bulge-llm/src/protocol/openai_chat.rs | opencode openai-chat.ts |
| M7 | crates/bulge-llm/src/retry.rs | DSH llm-retry |
| M8 | crates/bulge-llm/src/repair/* | openclaw tool-call-repair |
