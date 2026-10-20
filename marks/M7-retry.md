# M7 — 重試延遲

**目標**：`crates/bulge-llm/src/retry.rs` 的 `RetryPolicy::delay_for`。
**來源**：`~/deepseek-harness/packages/llm/llm-retry/src/index.ts` `localDelay`（L46-51）與 provider retry-after 的處理（同檔，搜尋 `providerRetryAfterMs`）。

## 規則
- `!error.code.retryable()` 或 `retry > max_retries` 或 `retry == 0` → None。
- 本地延遲 = min(initial × 2^(retry-1), max) × (1 - j + 2j·random)，再 min(max)；指數上限防溢位。
- 若 `error.retry_after_ms` 存在：用 max(本地延遲, retry_after)，但不超過 `max_delay`；若 retry_after 大於 `max_delay` → None（不要等太久，交給上層）。請對照 TS 確認此行為，若 TS 不同以 TS 為準並在回報說明。

## 驗收測試
- 不可重試的 code；超過次數；random=0/0.5/近1 的邊界；retry_after 小於/大於本地延遲；retry_after 超過 max。
