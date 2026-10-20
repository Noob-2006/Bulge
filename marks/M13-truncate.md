# M13 — 工具輸出截斷與 spill

**目標**：`crates/sandboxd/src/tools/truncate.rs` 的 `bound_output`（可加私有函式；公開型別不可變）。
**來源**：
- `~/deepseek-harness/packages/spill/spill-policy/src/index.ts`（L37-156：head + `[...]` + tail，各佔一半預算，tail 以二分搜尋找最大可容納長度）
- `~/deepseek-harness/packages/spill/spill-policy/src/notice.ts`（提示文字結構：省略量、位置、取回提示）
- `~/deepseek-harness/packages/spill/spill-local/src/store.ts`（spill 檔：隨機十六進位檔名前綴、owner-only、exclusive create）
- `~/opencode/packages/core/src/tool-output.ts` L13-14、L67-120（2000 行 / 50 KiB 上限與標記格式 `[showing ... of N; full output saved to PATH]`）

## 規則
- 在上限內（行數 ≤ max_lines 且 bytes ≤ max_bytes）→ 原文返回，`truncated=false`、`spill_path=None`。
- 超過：
  - 全文寫到 `spill_dir/tool-<16 hex 隨機>.txt`，`create_dir_all(spill_dir)`，檔案權限 0600，`create_new`（不可覆寫）。隨機數用 `std` 可得的來源即可（例如 `std::collections::hash_map::RandomState` + 時間），**不要新增依賴**。
  - 顯示文字 = head 行 + `\n[... N lines / M bytes omitted ...]\n` + tail 行 + 結尾 notice：`[full output (L lines, B bytes) saved to PATH — use read with offset/limit or grep on this path]`。
  - head 與 tail 各用一半預算（行數與 bytes 都要遵守）；以**整行**為單位，不切半行（單一行超過預算時才按 char boundary 切並標註）。tail 用二分搜尋找最大可容納行數。
  - 顯示文字總長（含標記）不得超過 `max_bytes + 512`。
- `total_lines` 以 `\n` 分割計，結尾換行不算額外一行（同 opencode）。

## 驗收測試
- 未超限原樣返回；行數超限；bytes 超限；單一超長行；head/tail 內容正確且不重疊；spill 檔內容等於全文、權限 0600；兩次呼叫產生不同檔名；多位元組字元不被切壞。
- `cargo test -p sandboxd`、`cargo clippy -p sandboxd --all-targets -- -D warnings` 通過。
