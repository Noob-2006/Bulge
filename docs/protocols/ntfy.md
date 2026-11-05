# ntfy 對照表

ark 實作：`crates/ark-channel/src/ntfy.rs`（移植自 Hermes）。上游：Hermes `plugins/platforms/ntfy/adapter.py`（384 行）；**OpenClaw 沒有 ntfy**（`extensions/` 無此目錄）；opencode 無。

| 面向 | 官方規格（ntfy server / ntfy.sh） | OpenClaw | Hermes | ark |
|---|---|---|---|---|
| 收訊 | `GET /<topic>/json`（`poll=false` 串流，每行一個 JSON 事件；`open`/`keepalive`/`poll_request` 控制事件） | — | `adapter.py:204-206`：`GET …?poll=false` 串流 | 同（`ntfy.rs` 串流執行緒），忽略非 `message` 事件，另有 90 秒閒置就重連（ntfy 預設 55 秒 keepalive） |
| 續接 | `since=<message id>` / `since=<timestamp>` / `since=all` | — | 有 | state 檔存最後 id，重連或重啟用 `since=<id>`；**下一次 poll 才提交**（at-least-once） |
| 發訊 | `POST /<topic>`，body 為純文字；標頭 `X-Title`、`X-Priority`、`X-Tags`、`X-Markdown`、`X-Actions`、`X-Attach` | — | `adapter.py:75`：`X-Tags` 帶回音標記 | 同 + `X-Filename`/`X-Message`/`PUT` 檔案上傳（`ntfy.rs:534-570`） |
| 身分 | ntfy 沒有使用者身分：一個 topic 就是一個聊天 | — | `title` 是發佈者控制，**不當身分**（`adapter.py:8`） | 同：`sender = chat = topic`（`ntfy.rs:120`），`title` 不用於身分 |
| 認證 | `Authorization: Bearer <token>` 或 Basic（`user:pass`） | — | 有 | `auth_header()`：含 `:` 走 Basic，否則 Bearer（`ntfy.rs:81`） |
| 回音防護 | — | — | `X-Tags: ark-agent` | 兩層：`X-Tags` 標記 + 最近 500 個自己發出的 id（`shared.sent`） |
| 長度 | 單訊息 body 上限 4096 bytes（伺服器可調） | — | — | `MAX_MESSAGE = 4096` **字元**（`ntfy.rs:32`）分段；超過伺服器上限時會被 ntfy 以 413 拒絕 |
| 速率限制 | 每訪客每日訊息數（ntfy.sh 免費額度），超量 429 | — | 有 | `classify()` → `RateLimited{retry_after}`，`retry_after > max_wait` 直接上拋，否則重試 3 次（`ntfy.rs:399-430`） |
| 錯誤 | 401/403 認證、404 topic 不存在、429 額度、5xx | — | 有 | 401/403 → `Auth`、404 → `NotFound`（都不重試）；5xx/網路 → 退避重連 2/5/10/30/60 秒（`ntfy.rs:35`） |
| 附件 | `X-Attach: <url>` 或 `PUT /<topic>` 上傳（回傳 JSON 帶 attachment url） | — | 部分 | 有；下載時只在自家 server 才帶認證（`ntfy.rs` `fetch_media`） |
| 動作按鈕 | `X-Actions: view, <label>, <url>` | — | — | 有（URL 按鈕轉 `view` action） |
| 非 ASCII 標頭 | 建議 RFC 2047 編碼字 | — | 有 | `header_value()` 非 ASCII 轉 `=?UTF-8?B?…?=`（`ntfy.rs:88`） |

## ark 的選擇與差異

1. **`Inbound` 沒有真正的寄件者**：`sender` 與 `chat` 都是 topic，存取控制只能靠 topic 本身的秘密性（`ntfy` 沒有使用者層）。這點三家一致，但值得在文件裡講清楚。
2. **長度以字元計**（4096 字元），ntfy 伺服器限制的是 body bytes；中文訊息可能被伺服器以 413 拒絕——目前沒有按 bytes 分段。
3. **回音防護多一層 id 佇列**（比 Hermes 只靠 tag 更穩），但 id 佇列只在記憶體，重啟後靠 tag。
4. 有 `PUT` 檔案上傳（Hermes 只有 `X-Attach` 連結）。

## 實測（本輪真的跑起來的）

ntfy 2.37.2（podman `binwiederhier/ntfy`，`tests/real/run.sh`）：

- `crates/ark-channel/tests/real_ntfy.rs`
  - `receives_message_published_by_a_real_ntfy_server`：真伺服器發佈 → ark 串流收到，`sender == chat == topic`、`message_id` == 伺服器事件 id。
  - `sends_and_does_not_echo_through_a_real_ntfy_server`：`send()` 之後用 `?poll=1&since=all` 讀回伺服器存的內容，驗證 `X-Title`/`X-Priority`（high→4）/`X-Markdown`→`content_type: text/markdown`、回音 tag、回傳 id == 伺服器 id；自己的訊息不會回流成 `Inbound`。
  - `resumes_from_the_persisted_id_on_a_real_ntfy_server`：重啟後用 `since` 只收到新訊息，不重播舊的。
- 未涵蓋：Bearer token 認證（測試 server 沒開認證）、附件上傳、429 額度。
