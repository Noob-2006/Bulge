# M5 — 錯誤分類

**目標**：`crates/bulge-llm/src/error.rs` 的 `classify_http` 函式本體（只改這個函式，可在同檔加私有輔助函式）。
**來源**：`~/deepseek-harness/packages/llm/llm-deepseek/src/transport.ts` `providerError`（L20-44）；`isQuotaExceededError` / `isContextWindowExceededError` 在 `~/deepseek-harness/packages/llm/llm/src/` 內（請 grep 找出其比對規則並一併移植為私有函式）。

## 規則
- 只讀 `body.error.{type, code, message}`（string 才採用）；其他欄位一律不信任。
- 分類順序與 TS 相同：401/403 或 authentication_error/permission_error → Auth；quota 文字或 402 → Quota；429 或 rate_limit_error → RateLimit；context window 文字 → ContextWindowExceeded；400/413 或 invalid_request_error → InvalidRequest；≥500 或 api_error/overloaded_error → Server；其餘有 status → `Http(status)`，無 status → Server。
- `retry_after`：純數字（可含小數）= 秒 → 毫秒；否則當 HTTP-date 解析，減去現在時間；≤0 或解析失敗 → None。HTTP-date 解析用標準庫手寫（IMF-fixdate 格式即可），不要加依賴。
- message 缺省：`"request failed (<status or 'stream error'>)"`。

## 驗收測試
- 每個分類分支各一；retry-after 秒數、小數、過去日期、垃圾字串；body 為 null 或非 object。
