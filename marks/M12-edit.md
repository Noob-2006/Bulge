# M12 — edit 比對與替換

**目標**：`crates/sandboxd/src/tools/edit.rs` 的 `apply_edit`（可加私有函式；`EditOutcome`、`EditError` 不可變）。
**來源**：`~/opencode/packages/core/src/tool/plugin/edit.ts`
- `normalizeForMatch` L49-54（unicode 正規化：引號、破折號、空白）
- `findOccurrences` L56、`findLineOccurrences` L66-102（逐行、忽略行尾空白）
- `lineEnding` L105、`withRegionEndings` L118、`alignLines` L131-162（以 LCS 保留每區行尾）
- `matchView` L168-189（在 LF 視圖上比對，再映射回原始 offset）
- `countBefore` L191、`Plugin` 內的替換流程 L207 起（唯一性、replace_all、BOM 保留）
- 測試參考：`~/opencode/packages/core/test/` 下與 edit 相關的測試（請 grep `edit`）。

## 規則
- 比對層級（第一個有命中的層級勝出）：精確 → unicode 正規化 → 逐行行尾空白不敏感。
- 在 LF 視圖上比對；替換後寫回時保留原檔每一區的行尾（CRLF / LF 混用時以 LCS 對齊）與開頭 BOM。
- `old` 空字串 → `EmptyOldString`；`old == new` → `NoChange`；找不到 → `NotFound`；多處命中且非 `replace_all` → `Ambiguous(n)`。
- `replace_all` 時替換該層級的所有命中，`replacements` 為次數。
- JS 字串索引是 UTF-16，Rust 一律用 byte offset，切片前確保在 char boundary。
- 不做檔案 I/O、不做 formatter、不做鎖（handler 負責）。

## 驗收測試
- 來源測試中屬於比對/替換的案例全部移植。
- 至少：精確單一命中；多處命中回 Ambiguous；replace_all；彎引號 vs 直引號命中第二層；行尾多空白命中第三層；CRLF 檔案替換後仍為 CRLF；混合行尾保留；BOM 保留；中文內容 offset 正確。
- `cargo test -p sandboxd`、`cargo clippy -p sandboxd --all-targets -- -D warnings` 通過。
