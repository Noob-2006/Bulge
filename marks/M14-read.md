# M14 — 分頁讀檔 / 列目錄

**目標**：`crates/sandboxd/src/tools/read.rs` 的 `read_page`（可加私有函式；公開型別與常數不可變）。
**來源**：
- `~/opencode/packages/core/src/tool/read-filesystem.ts`（402 行：文字分頁、行號格式、長行截斷、二進位判斷、目錄列出與分頁）
- `~/opencode/packages/core/src/tool/plugin/read.ts` L29-211（offset/limit 預設、`toModelContent` 的輸出格式）

## 規則
- 文字檔：offset 為 1-based（預設 1），limit 預設且上限 `DEFAULT_LIMIT`；每行輸出 `{行號}: {內容}`；超過 `MAX_LINE_CHARS` 的行截斷並加 `… [line truncated]`（以 char 計，不切壞 UTF-8）；還有剩餘行時 `next_offset = Some(下一行號)`。
- offset 超過總行數 → `OffsetPastEnd`（空檔案 offset=1 合法，回空文字）。
- 二進位判斷沿用來源規則（例如前 N bytes 含 NUL 或非文字比例過高）；圖片/PDF 不支援 → 視為 `Binary`。
- 非 UTF-8 但非二進位：以 lossy 方式解碼（來源若不同以來源為準並回報）。
- 目錄：列出直接子項，排序，目錄名加 `/`；offset/limit 同樣適用於項目；`total` 為總數。
- 不存在 → `NotFound(path)`；其他 I/O → `Io(msg)`。
- 不新增依賴。

## 驗收測試
- 來源相關測試移植。至少：小檔全讀；offset/limit 分頁與 next_offset；長行截斷；中文行；空檔；offset 越界；NUL 二進位；目錄排序與 `/` 後綴；不存在路徑。
- `cargo test -p sandboxd`、`cargo clippy -p sandboxd --all-targets -- -D warnings` 通過。
