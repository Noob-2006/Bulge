# M16 — 單步內的工具呼叫排程

**目標**：`crates/bulge-core/src/schedule.rs` 的 `run_tool_calls`（可加私有函式；公開型別、簽名、常數不可變）。
**來源**：`~/deepseek-harness/packages/core/agent-loop/src/tool-calls.ts`（`executeToolCalls` L60-104、`parseArguments` L105-121、`runGroup` L122-249、skipped 處理 L250-262）、`constants.ts`（`DEFAULT_MAX_PARALLEL_TOOL_CALLS = 10`）、`docs/tool-execution-pipeline.md`（`~/deepseek-harness/docs/`）。

## 規則
- 回傳 `Vec<CallResult>`：**每個輸入呼叫恰好一筆**，順序與輸入相同（不論完成順序）。
- 分組：連續的 `concurrency_safe == true` 呼叫為一組並行執行（同時最多 `max_parallel`，0 視為 1）；`concurrency_safe == false` 的呼叫自成一組、單獨執行。組與組依序。
- 參數解析：`raw_arguments` 空字串視為 `{}`；必須是 JSON object，否則 `InvalidArguments(說明)` 且**不呼叫** `on_start`、不執行。
- 取消：每個呼叫開始前檢查 `cancel`；已取消 → `Skipped`（不呼叫 `on_start`）。已在執行的呼叫等它結束（executor 自己會看 token）。
- `on_start(call, &args)` 在該呼叫真正開始執行前同步呼叫一次（給上層寫 write-ahead 紀錄用）。
- executor 的 panic 不需處理（上層 executor 不 panic）；不要 spawn 到別的 runtime thread（用 `futures` 的 `join_all` / `FuturesUnordered` + 數量限制即可，保持在呼叫者的 task 內）。
- 只用 bulge-core/Cargo.toml 已列的依賴。

## 驗收測試
- 結果順序與輸入一致（即使後面的先完成）。
- 3 個 safe 呼叫真的並行（用計數器量到同時在跑 ≥2）；max_parallel=1 時同時只跑 1 個。
- unsafe 呼叫是屏障：它執行時沒有任何其他呼叫在跑；它前後的 safe 組不重疊。
- 非 object 參數 → InvalidArguments、未執行、未 on_start；空字串 → `{}` 正常執行。
- 執行到一半 cancel → 後續未開始的呼叫 Skipped，已開始的有結果。
- `on_start` 被呼叫的次數 = 實際執行的呼叫數，且先於該呼叫執行。
- `cargo test -p bulge-core`、`cargo clippy -p bulge-core --all-targets -- -D warnings` 通過（其他模組若尚未完成可只跑 schedule 測試，並註明）。
