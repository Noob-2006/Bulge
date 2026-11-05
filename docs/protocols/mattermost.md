# Mattermost（API v4）對照表

SE Agent 實作：`crates/seagent-channel/src/mattermost.rs`。上游：OpenClaw `extensions/mattermost/src/*`、Hermes `plugins/platforms/mattermost/adapter.py`（772 行）；opencode 無。
**本輪已對真的 Mattermost 實測**：podman 起 `docker.io/mattermost/mattermost-team-edition:latest`（**Mattermost 12.0.1**，2026-11 的 `latest`，image `c1c9a86f98a6`，730 MB）+ `postgres:16-alpine`，由 `tests/real/mattermost_up.sh` 建管理員／團隊／公開頻道／兩個 bot 與個人存取權杖，`crates/seagent-channel/tests/real_mattermost.rs` 的 7 個測試全綠（`cargo test -p seagent-channel --test real_mattermost`）。下表 SE Agent 欄是本輪在真伺服器上確認後的行為，最後一欄是證據。

| 面向 | 官方規格（API v4） | OpenClaw | Hermes | SE Agent | 實測 |
|---|---|---|---|---|---|
| 收訊 | `GET /api/v4/websocket`：連上先送 `{"seq":1,"action":"authentication_challenge","data":{"token":"…"}}`，之後收 `posted`/`post_edited`/`post_deleted`/`reaction_added`/`typing`/`status_change` 事件 | WS + REST（`extensions/mattermost`） | WS（`adapter.py:476` 把 http→ws 接上 `/api/v4/websocket`） | WS + 心跳、重連退避、驗證 challenge（模組註解 + `mattermost.rs` 的 WS 區段）；`posted` 的 `data.post` 是 **JSON 字串**，`data.channel_type`/`sender_name`/`channel_display_name`/`team_id`/`mentions` 都在 | ✅ `receives_peer_posts_on_real_mattermost`、`websocket_pings_and_authenticates_on_real_mattermost` |
| 認證 | `Authorization: Bearer <bot token>`（個人存取權杖或 bot 帳號） | bot token | bot token | `token`（`{{secret:…}}`）；`GET /users/me` 401 → `Auth` | ✅ `maps_auth_and_missing_channel_errors_on_real_mattermost` |
| 發訊 | `POST /api/v4/posts`（`channel_id`、`message`、`root_id`、`props`、`file_ids`） | REST | REST（`adapter.py:640`） | REST（`mattermost.rs:728`），長文自動分段 | ✅ `sends_edits_and_threads_on_real_mattermost` |
| 編輯／刪除 | `PUT /api/v4/posts/{id}/patch`、`DELETE /api/v4/posts/{id}` | 有 | 有 | 有；入站的 `post_edited` 以 `{id}:e{edit_at}` 當 `message_id` 且 `edited = true` | ✅ `sends_edits_and_threads_on_real_mattermost`、`receives_peer_posts_on_real_mattermost` |
| 討論串 | `root_id` / `post.root_id` | 有 | 有 | 有（`thread` = root id）；`reply_to` 指到「回覆」時會用 REST 往上找 root；`root_id` 指到回覆時伺服器回 400，SE Agent 改成頂層貼文 | ✅ `sends_edits_and_threads_on_real_mattermost`（含 stale root 退回頂層） |
| 頻道類型 | `D`（direct）、`G`（group）、`O`（public）、`P`（private） | 有 | 有 | `D` → `Direct`、其餘 → `Group`、有 root → `Thread`（`D` 的討論串仍是 `Direct`） | ✅ `receives_peer_posts_on_real_mattermost`（O/Thread）、`direct_messages_uploads_and_deletes_on_real_mattermost`（D） |
| 提及 | `@username`（`mentions` 陣列在 metadata） | 有 | 有 | `@提及` + 回覆 bot 視為 addressed；`@seagentbot2` 不會誤認成 `@seagentbot` | ✅ `receives_peer_posts_on_real_mattermost` |
| 長度 | `MaxPostSize`（**實機 12.0.1 回報 262144**，舊版預設 16383） | 16383 | 16383 | `MAX_MESSAGE = 16383`（`mattermost.rs:30`）分段——保守但安全，真伺服器全部接受 | ✅ `sends_edits_and_threads_on_real_mattermost`（>16383 字切成多則，逐則驗證） |
| 檔案 | `POST /api/v4/files`（multipart，`channel_id`）→ 取得 `file_ids` 再貼文 | 有 | 有（`adapter.py:222`） | 有，每則訊息最多 5 個檔（`MAX_FILES`，`mattermost.rs:32`）；只有檔案沒有文字也可以；下載帶 Bearer | ✅ `direct_messages_uploads_and_deletes_on_real_mattermost` |
| 反應 | `POST /api/v4/reactions`（回 **200**，不是 201） | 有 | 有 | 有；`👍`→`+1` 由伺服器接受；`reaction_events` 開啟時入站事件轉成 `:{emoji}: reaction added` | ✅ `bot_posts_and_reaction_events_on_real_mattermost` |
| 輸入中 | WS `user_typing` | 有 | 有 | WS typing（斷線時退回 `POST /users/me/typing`） | ✅ `typing_over_the_websocket_reaches_the_peer_on_real_mattermost`（對方真的收到 `typing` 事件） |
| 互動按鈕 | 官方沒有原生按鈕；社群做法是 message attachment 的 `actions`（integration URL + `context`），Mattermost 會 POST 到該 URL | 有（slash + actions） | 部分 | 有：HMAC 簽章的 callback（需 `listen` + `callback_url`，否則退回編號選項），並在 `PUT /posts/{id}/patch` 更新原訊息 | ⛔ 未實測（要容器連得到 host 的 callback URL） |
| Slash command | 由 server 設定 `POST <callback>`，帶 `token` 驗證 | 有 | — | 有：註冊 slash command 並驗證 `token` | ⛔ 未實測（同上） |
| 速率限制 | 429 + `X-Ratelimit-*` 標頭 | 有 | 有 | `mm_error()` 轉 `RateLimited`，尊重 `retry_after` | ⛔ 未實測（測試 server 預設沒開限流） |
| 錯誤碼 | 401/403 權限、404 頻道/訊息不存在、400 參數錯 | 部分 | 部分 | 401 → `Auth`；**403/404/410 → `NotFound`（不重試）**；400 → `Protocol`；5xx/網路 → `Network` 退避重試 | ✅ `maps_auth_and_missing_channel_errors_on_real_mattermost` |
| WS 心跳 | 伺服器要回 pong | — | — | 每 `ping_every`（30 秒）送 ping frame，沒 pong 就重連 | ✅ `websocket_pings_and_authenticates_on_real_mattermost` |

## SE Agent 的選擇與差異

1. **互動按鈕自製 HMAC callback**：Mattermost 沒有像 Slack 的 block actions，SE Agent 用簽章過的 callback URL 模擬，`listen` 沒開就降級成「回覆數字選項」——這個降級路徑在官方規格裡不存在，是 SE Agent 的取捨。
2. **`user:` / `@name` 直接開 DM**：靠 `/api/v4/channels/direct` 建 D 頻道，上游也這樣做。實測：這個端點是**冪等**的（重打回同一個頻道），而 `GET /api/v4/channels/direct/{a}/{b}` 在 12.0.1 **不存在**（404），要拿既有 DM 只能再 POST 一次。
3. 未實作 `/api/v4/commands` 的完整管理介面（只註冊四個 slash command）。`POST /posts/ephemeral` 有實作（`ack_callback`），但本輪沒有 callback URL 可測。

## 實測（本輪真的跑起來的）

Mattermost 12.0.1 team edition（podman，`tests/real/mattermost_up.sh`），Postgres 16，兩個 bot + 一個真人帳號：

- `crates/seagent-channel/tests/real_mattermost.rs`
  - `receives_peer_posts_on_real_mattermost`：真人用 REST 貼文 → SE Agent 收到 `Inbound`（`chat` = 頻道 id、`sender` = 真人 user id、`message_id` = 伺服器 post id、`chat_type` = `Group`、`chat_name` = `SE Agent E2E`、`account` = team id、`ts` 是秒、`sender_name` 去掉 `@`）；執行緒回覆 → `thread` = root、`chat_type` = `Thread`、`reply.id` = root；`@seagentbot` → `mentioned`；`@seagentbot2` → 不誤認；真人編輯 → `edited` + `message_id = {id}:e{edit_at}`；執行緒內的回覆被編輯仍留在原討論串；回覆 bot 自己的貼文 → `reply.is_own` 且 `addressed()`；bot 自己貼的文不會回流成 `Inbound`。
  - `sends_edits_and_threads_on_real_mattermost`：`send()` 後用 `GET /posts/{id}` 讀回**逐字相同**的文字與 `user_id`；`edit()` → patch 生效；`reply_to`（root 或回覆）→ `root_id` 正確；`thread` 指到回覆 → 伺服器 400 `api.post.create_post.root_id.app_error`，SE Agent 退回頂層貼文而不是失敗；`👍` 反應 → 伺服器存成 `+1`，移除也生效；>16383 字 → 多則，每則 ≤ 16383 字，開頭、結尾與 16,500 個「長」都還在。
  - `direct_messages_uploads_and_deletes_on_real_mattermost`：`user:<id>` 與 `@seagentpeer` 都送到同一個 D 頻道；對方在 DM 貼文 → `chat_type` = `Direct`；multipart 上傳 → `file_ids`、`metadata.files`（`note.txt`、大小、`text/plain; charset=utf-8`）；`fetch_media()` 帶 bot token 讀回原位元組；只有檔案的貼文 `message` 是空字串；`delete()` 後 `GET /posts/{id}` 404。
  - `bot_posts_and_reaction_events_on_real_mattermost`：另一個 bot 的貼文 → `is_bot = true`；WS typing frame 不會弄斷連線；真人加 `:eyes:` → 入站 `:eyes: reaction added`，`message_id = r:{post}:{user}:eyes:+`，`reply.id` = 被反應的貼文。
  - `websocket_pings_and_authenticates_on_real_mattermost`：challenge 後**沒有 `seq_reply` 框**（只送 `hello`，之後是 `status_change`），測試用一則 `posted` 事件證明已認證；送 ping frame 收到 pong；壞 token 的連線由伺服器直接關掉（實測是沒有 Close 框的 EOF）。
  - `typing_over_the_websocket_reaches_the_peer_on_real_mattermost`：另一個成員的 WS 真的收到 `{"event":"typing","data":{"user_id":<bot>}}`。
  - `maps_auth_and_missing_channel_errors_on_real_mattermost`：壞 token → `Auth`（<10 秒，不是無盡輪詢）；不存在的頻道 → `NotFound`（<3 秒，沒有 0.5/1/2/4 秒的重試風暴）。
- 未涵蓋：互動按鈕與 slash command 的 callback（要容器連得到 host）、429 限流、私密頻道（`P`）與 group DM（`G`）、一封貼文 >5 個檔、執行中 token 被撤銷。

## 實測抓到的問題與修正

程式碼本身在 12.0.1 上**沒有抓到缺陷**（上面 7 個測試第一次跑就全綠）；抓到的是文件與實機不符，以及一個只在真實伺服器上才看得到的行為：

1. **`MaxPostSize` 不是 16383**：12.0.1 的 `GET /api/v4/config/client` 回報 `262144`。文件原本寫「預設 16383」是舊版的數字。SE Agent 仍以 16383 分段（舊版安全值），所以不用改程式，但表格已改成實測值。
2. **錯誤碼對照寫錯**：文件寫「401/403 → `Auth`」，程式其實是 `403 → NotFound`（只有 `id` 含 session/token 的 403 才是 `Auth`）。實測也證明不存在的頻道 id 回的是 **403 `api.context.permissions.app_error`**，不是 404——所以 `403 → NotFound` 才是對的，文件已修正。
3. **WS challenge 沒有 `seq_reply`**：文件以為 challenge 會回 `{"seq_reply":1,"status":"OK"}`；12.0.1 只送 `hello`，之後是 `status_change`，完全沒有 `seq_reply`。SE Agent 的 `run_ws()` 兩個訊號都認（`hello` 也算 healthy），所以行為正確；文件已改成實機形狀。
4. **`posts/ephemeral` 不是「未實作」**：`ack_callback()` 有實作，文件原本列在缺口裡，已更正（本輪仍無 callback URL 可測）。
5. **壞 token 的 WS 行為（未改程式，記錄下來）**：`GET /api/v4/websocket` 對壞 token **照樣 upgrade**，然後在 challenge 後直接把連線關掉（可能是沒有 Close 框的 EOF）。所以 `run_ws()` 那個「handshake 回 401 就 `Fatal(Auth)`」的分支在真伺服器上永遠不會觸發；SE Agent 對壞 token 的 `Auth` 判定實際來自 REST `GET /users/me`（第一次 `me()` 就會 401）。連線途中才被撤銷的 token 因此只會在「下一次 REST 呼叫」時被發現，`poll()` 不會自己回 `Auth`——這是已知限制，沒有改程式：測試沒辦法叫伺服器關掉既有連線，改了就是沒有測試護著的行為變動。
6. 測試輔助發現：`GET /api/v4/channels/direct/{a}/{b}` 在 12.0.1 是 404，`POST /channels/direct` 才是冪等的取得方式（文件已註明）。

## 缺口與待驗

- 互動按鈕、slash command 的 callback：需要 Mattermost 容器能連到 host（`--add-host host.containers.internal`），本輪沒做。
- 429：測試 server 沒開限流（`RateLimitSettings.Enable`），`retry_after` 的行為只有單元測試。
- 執行中撤銷 token（見上）、私密頻道 `P`、group DM `G`、一封 >5 檔、`post_deleted` 事件。
