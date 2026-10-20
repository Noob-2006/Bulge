# M11 — guest 指令執行器（sandboxd 骨幹）

**目標**：`crates/sandboxd/src/runtime.rs`：把所有 `todo!("M11")` 換成實作；可加私有欄位、私有型別、私有函式。**公開型別與簽名不可變**。
**來源**：`~/openclaw/crates/openclaw-node-host/src/runtime.rs`（已是 Rust）
- 常數 L29-35；`CancellationToken` L45-80；`InvocationContext` L83；`HandlerError` L105；`RuntimeBuildError` L122；`CommandRuntimeBuilder` L166-373；`RuntimeInner` / `CommandRuntime` L375-430；評估流程 `evaluate_with_scope`、`Evaluation`、`ActiveInvocation(s)` L1139-1305；`failure`、`nonzero_duration`、`LimitWriter`、`serialized_json_within_limit` L1306-1345。
- 測試：同檔 `#[cfg(test)]` 區塊中與 builder 限制、admission、timeout、cancel、panic、輸入/輸出上限、overload 相關的案例。

## 移除（與 Gateway / NodeSession 綁定，bulge 不需要）
`NodeSession`、`NodeConnectOptions`、`activate`、`dispatch`、`run`、`SessionScope`、duplex（`duplex_command`、`system_duplex_command`、`InvocationDuplex`、`InvocationIo`、heartbeat）、capability、`system.*` 保留命名空間、`ClientError`、`RuntimeError`、`route_invocation_control`、delivery/overload permits 的 session 部分。

## 保留（語意不可放寬）
- 預設上限：並行 8、輸入 256 KiB、輸出 256 KiB、預設逾時 30 s、最大逾時 5 min；`timeout` 夾到最大值、0 視為預設（`nonzero_duration`）。
- 指令名稱文法 `[A-Za-z0-9._-]{1,128}`、不得重複；`command_names` 依 byte 排序。
- 評估順序：未知指令 → `UNKNOWN_COMMAND`；並行已滿 → `OVERLOADED`（不排隊）；輸入 JSON 序列化超過上限 → `INPUT_TOO_LARGE`；admission 拒絕 → 其 code；handler 逾時 → 取消 token 後回 `TIMEOUT`；handler panic → `HANDLER_PANICKED`（`AssertUnwindSafe` + `catch_unwind`）；`cancel(id)` → `CANCELLED`；輸出超過上限 → `OUTPUT_TOO_LARGE`（用 `LimitWriter` 不完整物化）。成功 → `Outcome::Ok { value }`；失敗 → `Outcome::Err { code, message }`。若來源的 code 字串不同，**以來源為準**並在回報列出。
- `cancel(id)` 只影響該 id；`cancel_all()` 取消全部；同一 id 重複 invoke 時第二個直接回 `DUPLICATE_INVOCATION`。
- admission 與 handler 都能收到同一個 cancellation（admission 收 `Invocation`，可用 token 版本則保留來源行為）。

## 依賴
只用 sandboxd/Cargo.toml 已列的（bulge-proto、futures、serde、serde_json、thiserror、tokio）。需要 `futures::FutureExt::catch_unwind`。

## 驗收測試
- 來源相關測試移植（去掉 session/duplex 部分）。
- 每個錯誤 code 至少一個測試；並行上限滿時第 9 個立即 `OVERLOADED`；逾時後 handler 的 token `is_cancelled()` 為真；`cancel(id)` 只取消目標。
- `cargo test -p sandboxd`、`cargo clippy -p sandboxd --all-targets -- -D warnings` 通過。
