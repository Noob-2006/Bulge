# Matrix（Client-Server API）對照表

範圍：Matrix Client-Server API r0.6.1–v1.11（`/_matrix/client/v3`）、房間事件、E2EE（Olm/Megolm）。
ark 實作：`crates/ark-channel/src/matrix.rs`、`matrix_e2ee.rs`、`matrix_sas.rs`、`matrix_trust.rs`、`olm.rs`、`mls.rs`。
上游：OpenClaw `extensions/matrix/src/*`、Hermes `plugins/platforms/matrix/adapter*.py`；opencode 無 Matrix 通道（見 `README.md`）。

| 面向 | 官方規格 | OpenClaw | Hermes | ark |
|---|---|---|---|---|
| 傳輸 | `GET /sync?since=&timeout=` 長輪詢；`PUT /rooms/{id}/send/{type}/{txnId}` | matrix-js-sdk（`extensions/matrix`） | matrix-nio（`adapter.py:1-30`） | 自寫 `Http`（`matrix.rs`），`exec()` 把長輪詢放工作執行緒以免卡住 cancel（`matrix.rs:155`） |
| 認證 | access token（`Authorization: Bearer …`）或 password login | access token | password / token | password、access token；token 可放 `{{secret:…}}`（`config.rs`） |
| 房間加入 | `POST /join/{roomIdOrAlias}`；invite 在 `/sync` 的 `rooms.invite` | 自動 | 自動，DM invite 記錄到 `m.direct`（`adapter.py:2854`） | `auto_join`（預設開）；DM invite 寫回 `m.direct`（`matrix.rs:810`） |
| DM 判定 | 規格只有 `m.direct` account data（與 invite 的 `is_direct`） | 以 `m.direct` 為主 | 只用 `m.direct`（`_refresh_dm_cache`，`adapter.py:2844`） | `m.direct` 或「無名稱的 ≤2 人房間」；**具名房間不算 DM**（`matrix.rs:832`，本輪修正，原本任何 ≤2 人房間都算 DM） |
| 訊息格式 | `m.room.message`（`m.text`/`m.notice`/`m.image`/`m.file`/`m.audio`/`m.video`/`m.emote`） | 同 | 同 | 同 + `msgtype` 由 `MediaKind` 映射（`matrix.rs:246`） |
| 編輯 | `m.replace`（`m.relates_to.rel_type = "m.replace"`） | 有 | 有 | 有（`matrix.rs` edit） |
| 討論串 | `m.thread`（`rel_type = "m.thread"`，`is_falling_back`） | 有 | 有（`_thread_root`，`adapter.py:551`） | 有（`ChatType::Thread`） |
| 反應 | `m.reaction` + `m.annotation` | 有 | 有 | 有（`event_inbound` 只收 `m.annotation`） |
| 長度上限 | 無硬上限（事件 ≤64 KiB） | 由 SDK | `MATRIX_MAX_MESSAGE_LENGTH` = 15000 **UTF-8 bytes**（`adapter.py:14`） | 4000 **字元**（`matrix.rs:47`），`chunk::split` 分段 |
| 速率限制 | 429 `M_LIMIT_EXCEEDED` + `retry_after_ms` | SDK 重試 | 有 | `classify()` 轉 `RateLimited`，`retry_after` 超過上限就上拋 |
| 重連 | 長輪詢自然重連；`since` 續接 | SDK | 有（曾有 timeout 卡死 sync 的事故，`adapter.py:227-231`） | `since` 存 state，斷線重試並沿用 |
| E2EE | Olm/Megolm、cross-signing、SAS、key backup | 有（SDK） | 有（`adapter_crypto.py`） | 自寫 Olm/Megolm、SAS、cross-signing、key backup（`matrix_e2ee.rs`、`matrix_sas.rs`、`matrix_trust.rs`）；未加密房間收到加密事件時發一次提示（`matrix.rs:48`） |
| 已讀 | `POST /rooms/{id}/receipt/m.read/{eventId}` | 有 | 有 | `read_receipts`（預設開） |
| presence | `PUT /presence/{userId}/status` | 有 | — | `presence = online`（`matrix.rs:1341`） |

## ark 的選擇與差異

1. **DM 判定比上游寬，本輪收斂**：原本「≤2 人即 DM」會把兩人的具名群組房間當成 1:1（不再要求 @ 提及），與 Hermes/規格不一致；現在只有 `m.direct` 或**無名稱**的兩人房才算 DM。
2. **長度以字元而非 UTF-8 bytes 計**（4000 字 vs Hermes 15000 bytes）：中文訊息 ark 送得比較保守，不會超過事件大小限制。
3. **E2EE 是自寫實作**（`olm.rs`/`mls.rs`），沒有用 vodozemac；本輪只驗證未加密流程（見下）。
4. 沒有 `MATRIX_ALLOWED_ROOMS` 這類房間白名單；存取控制交給 `allow` / `dm_policy`（`config.rs`）。

## 實測（本輪真的跑起來的）

Synapse 1.x（podman，sqlite，`tests/real/run.sh`）＋兩個真實帳號：

- `crates/ark-channel/tests/real_matrix.rs`
  - `joins_and_receives_on_real_synapse`：建房間 → 邀請 bot → bot 用 `/sync` 自動加入 → 房間訊息變成 `Inbound`（`chat` = room id、`message_id` = `$event`、`chat_type` = Group）。**這個測試就是發現 DM 誤判的地方。**
  - `sends_to_real_synapse`：`send()` → `PUT /rooms/{id}/send/m.room.message/{txn}` → 對端 `GET /rooms/{id}/messages` 看得到。
- 未涵蓋：E2EE（Synapse 預設房間未加密）、SAS 驗證、key backup、`m.replace` 編輯的實際送達（只有單元測試覆蓋）。
