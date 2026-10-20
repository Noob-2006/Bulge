# M17 — 回圈偵測

**目標**：`crates/bulge-guard/src/loop_detect.rs` 的 `LoopDetector::check` 與 `observe`（可加私有欄位、型別、函式）。公開型別、簽名、常數不可變。
**來源**：`~/openclaw/src/agents/tool-loop-detection.ts`（全檔）、`tool-loop-thresholds.ts`（`TOOL_LOOP_WARNING_THRESHOLD = 10`）。只取演算法，省略 openclaw 特有工具（memory_search、computer、progress_card、send-like）的特例與 incognito/log。

## 規則（對照來源）
- `observe` 把一筆 `Observation` 推進固定長度 `HISTORY_SIZE`(30) 的環形歷史。每筆存：tool、**canonical 參數雜湊**（object 鍵排序後序列化再雜湊，陣列順序保留）、**outcome 雜湊**、`no_progress`（來源 `hashToolOutcome`：error、或 write 未變更、或相同輸出等）。雜湊用 `std` 的 hasher（`DefaultHasher`），**去除易變欄位**：對 `result` 遞迴移除常見易變鍵（`timestamp`、`time`、`duration`、`durationMs`、`elapsed`、`pid`、`requestId`、`id` 當值像隨機、`startedAt`、`finishedAt`、`at_ms`），再雜湊。
- `check(tool, arguments, unknown_tool)` 針對「即將執行」的呼叫，用目前歷史算各偵測器的 streak，依序判斷（與來源 `detectToolCallLoop` 相同順序）：
  1. **unknown_tool_repeat**：連續對同一個未知工具（`unknown_tool==true`）的呼叫數 ≥ `UNKNOWN_TOOL_THRESHOLD`(10) → critical。
  2. **global_circuit_breaker**：同一 (tool, 參數雜湊, 相同 outcome 且 no_progress) 連續 ≥ `GLOBAL_CIRCUIT_BREAKER_THRESHOLD`(30) → critical。
  3. **no_progress_poll**：同上 streak ≥ `WARNING_THRESHOLD`(10) → warning；≥ `CRITICAL_THRESHOLD`(20) → critical。
  4. **argument_churn**：同一 tool、**參數一直變**但 outcome 一直 no_progress，streak ≥ `WARNING_THRESHOLD` → warning。
  5. **ping_pong**：A,B,A,B… 兩種簽名交替，count ≥ `WARNING_THRESHOLD` → warning；≥ `CRITICAL_THRESHOLD` 且有 no_progress 證據 → critical。
  6. **generic_repeat**：同一 (tool,參數,outcome) 連續重複，低於上述門檻但 ≥ 某合理值時可併入 no_progress_poll；不需獨立回報。
  - **bulge 追加**：同一 (tool,參數) 連續**錯誤** ≥ `IDENTICAL_ERROR_STOP`(3) → critical（`Detector::GenericRepeat`），訊息請模型換一個有界的替代方案或回報失敗。
- `message` 要具體：指出哪個工具卡住、重複幾次、建議「換一個有界的替代方案並設停止條件，或回報失敗」。
- 無任何偵測器觸發 → `None`。
- 只用 serde_json 與 std（含 `std::collections::hash_map::DefaultHasher`、`std::hash::{Hash,Hasher}`）。不新增依賴。

## 驗收測試
- 同一呼叫 + 相同 no-progress outcome 連續 3 次錯誤 → critical（IDENTICAL_ERROR_STOP）。
- 相同 no-progress 達 10 次 → warning、20 次 → critical（no_progress_poll）。
- 未知工具連續 10 次 → unknown_tool_repeat critical。
- 參數每次都不同但都 no-progress 達 10 次 → argument_churn warning。
- A/B 交替達 10 次 → ping_pong warning。
- outcome 只差易變欄位（timestamp/pid/duration）仍算相同 → 會觸發（證明有去除易變欄位）。
- 有進展（outcome 改變、no_progress=false）會重置 streak → 不觸發。
- 參數 object 鍵順序不同視為相同簽名。
- `cargo test -p bulge-guard`、`cargo clippy -p bulge-guard --all-targets -- -D warnings` 通過。
