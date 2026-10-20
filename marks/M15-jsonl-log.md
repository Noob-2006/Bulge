# M15 — 只追加 JSONL 日誌（工作事件的持久層）

**目標**：`crates/bulge-store/src/log.rs`：把所有 `todo!("M15")` 換成實作；可加私有欄位、私有函式。公開型別、簽名、`MAX_RECORD_BYTES` 不可變。
**來源**（`~/deepseek-harness/packages/session/session-persistence-jsonl/src/`）：
- `format.ts`：`SessionLogScanner` L386-532、`scanLog` L532（逐行掃描、未終結的最後一行視為 torn tail、完整行壞掉＝corruption）
- `storage.ts`：`JsonlSessionHandle.append` L187-200 與失敗回滾、`flush`、`close`（L85-300 一帶）
- `lease.ts`：`SessionWriteLease` L58-135（單一寫入者）
- README 的 "Durability and crash semantics" 一節（`~/deepseek-harness/packages/session/session-persistence-jsonl/README.md`）
**只搬**：raw JSONL（不做 zstd、不做多代格式遷移、不做 catalog、不做 live batching、不做 win32）。

## 規則
- 檔案格式：第 1 行 header（compact JSON + `\n`），之後每行一筆 record。寫出時一律 `serde_json::to_string`（compact）+ `\n`；單筆編碼後超過 `MAX_RECORD_BYTES` → `RecordTooLarge`，且不寫任何東西。
- `create`：`OpenOptions::create_new`（已存在 → `Exists`），取得 `File::try_lock()`（Rust 標準庫，1.89+；失敗 → `Locked`），寫 header、`sync_all`，並 fsync 父目錄（`File::open(parent)?.sync_all()`）。
- `open`：以讀寫開啟，`try_lock`（被佔用 → `Locked`），掃描：
  - 空檔或第一行不完整 → `MissingHeader`。
  - 完整（以 `\n` 結尾）但不是合法 JSON 的行 → `Corrupt { line, reason }`（line 為 1-based 檔案行號）。
  - 最後一行沒有 `\n` → torn tail：記錄 bytes 數，**在回傳前**把檔案 `set_len` 截到最後一個完整行並 `sync_all`。
- `read`：唯讀、不加鎖、不修改；torn tail 只忽略並回報 bytes。
- `append`：把整批編碼成一個 buffer，一次 `write_all` + `sync_all`；任何一步失敗 → `set_len(舊長度)` + `sync_all`（盡力），回傳原錯誤；成功後更新內部長度。空 batch 是 no-op。
- 鎖：`JsonlLog` 存活期間持有鎖（File drop 時自動釋放）。同一行程內第二次 `open` 同一檔案也必須回 `Locked`。
- 不新增依賴；只用 std、serde_json、thiserror。

## 驗收測試
- create → append 多批 → drop → open：records 與 header 完全一致。
- create 已存在的路徑 → `Exists`。
- 持有寫入者時再 `open` → `Locked`；drop 後可 open。
- 手動在檔尾寫入半行（無 `\n`）→ `read` 忽略並回報 bytes；`open` 截掉並回報，之後 append 的資料能被正確讀回。
- 中間某行改成壞 JSON（含 `\n`）→ `Corrupt`，行號正確。
- 空檔 → `MissingHeader`。
- 超大 record → `RecordTooLarge` 且檔案長度不變。
- 中文與跳脫字元往返正確。
- `cargo test -p bulge-store`、`cargo clippy -p bulge-store --all-targets -- -D warnings` 通過。
