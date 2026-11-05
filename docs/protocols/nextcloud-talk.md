# Nextcloud Talk（OCS Talk API v1/v4 + Bot API）對照表

ark 實作：`crates/ark-channel/src/nextcloud_talk.rs`。上游：OpenClaw `extensions/nextcloud-talk/src/*`（`send.ts`、`signature.ts`、`inbound.ts`、`outbound-media.ts`、`message-actions.ts`、`webhook-spool.ts`、`room-info.ts`、`bot-preflight.ts`）；Hermes **沒有內建 Talk 平台**（`plugins/platforms/` 27 個目錄裡沒有 nextcloud，`grep -rli nextcloud --include=*.py` 只命中 `tests/tools/test_ssh_environment.py`），只有社群外掛目錄條目 `plugin-catalog/nextcloud-talk.yaml`（指向 `github.com/Cliff3c/hermes-nextcloud-talk`，`known_issues` 自承「純文字、無附件／反應／回覆脈絡」、「去重只在記憶體」、「OCS 只回空確認，沒有 message id」）。

**本輪已對真的 Nextcloud 實測**：podman 起 `docker.io/library/nextcloud:29.0.7-apache`（SQLite，1.24 GB pulled，image tag `29.0.7-apache`）+ Talk `spreed 19.0.9`（app store 對 NC 29 的版本，release tarball 42 MB，因為 `occ app:install spreed` 在這台機器上 app store 只有 ~44 KB/s 且不可續傳），`tests/real/nextcloud_up.sh` 建管理員／真人 `arkpeer`／API 使用者 `arkbot`（含 app password）／公開對話／`talk:bot:install` 的機器人並在對話裡啟用，`crates/ark-channel/tests/real_nextcloud_talk.rs` 的 12 個測試全綠（`cargo test -p ark-channel --test real_nextcloud_talk`，乾淨狀態下 27 秒）。

**怎麼讀「實測」欄**：✅ = 這輪真的在 29.0.7 + 19.0.9 上跑過（附測試名）；📖 = 只讀官方規格／Talk 19.0.9 原始碼（`lib/Controller/BotController.php`、`lib/Service/BotService.php`、`lib/Chat/ChatManager.php`），沒有實測；⛔ = 本輪未驗。

| 面向 | 官方規格 / 實機行為（Talk 19.0.9） | OpenClaw | Hermes | ark | 實測 |
|---|---|---|---|---|---|
| 收訊機制 | 只有 **bot** 會收到 webhook：`BotService::afterChatMessageSent()` 對 `FEATURE_WEBHOOK` 的 bot POST ActivityStreams JSON；`ChatMessageSentEvent` 對 bot 自己送出的訊息直接 return（`if (!$attendee instanceof Attendee) // No bots for bots`） | webhook（`inbound.ts`、`webhook-route.ts`） | 社群外掛：自架 HTTP listener（預設 `0.0.0.0:8788`） | `listen` 上的 HTTP server（`nextcloud_talk.rs:120-172`），POST + `Content-Type: application/json`，`type=Create` / `object.type=Note` 才收（`nextcloud_talk.rs:447-460`） | ✅ `inbound_message_from_a_real_conversation`、`works_in_a_conversation_created_through_ocs`（機器人自己的訊息不回送，也是 `outbound_message_is_readable_by_a_second_client` 證明的） |
| 簽章 | `X-Nextcloud-Talk-Signature = hex(HMAC-SHA256(secret, X-Nextcloud-Talk-Random + body))`，random 是 `generate(64)`；`BotService.php:165` | `signature.ts` 同式（`random + body`） | 外掛自稱 HMAC 驗證 | `sign()`/`verify()`（`nextcloud_talk.rs:99-107`），hex 不分大小寫、constant-time 比較 | ✅ `the_listener_rejects_a_wrongly_signed_webhook`（真的 401，偽造訊息不會進 `poll()`） |
| 重放 | 規格沒講；random 每次不同 | 有**持久化**去重（`webhook-spool.ts`、`persistent-dedupe`） | 只在記憶體（`known_issues`） | 記憶體 `Replay`（`REPLAY_CAP = 4096`，`nextcloud_talk.rs:72-94`），重放回 200 但不投遞 | ✅ `webhook_signature_good_bad_missing_replay_and_backend`（單元）；重啟後會忘掉（📖 已知限制） |
| Backend 釘選 | `X-Nextcloud-Talk-Backend` = `overwrite.cli.url` + `/`（`BotService.php:170`） | `signature.ts` 解析後交給 policy | 外掛沒提 | `allowed_backends`，兩邊都 trim 結尾 `/`（`nextcloud_talk.rs:128-135`） | ✅ `allowed_backends_is_enforced_by_the_real_sender`（錯的 backend → 403，伺服器 log 記 `backend not allowed`，同一則訊息換成對的 backend 就送到） |
| 認證（讀房間／WebDAV） | OCS Basic：`user:app-password`（`occ user:add-app-password --password-from-env`，`NC_PASS` 要帶登入密碼） | `api-credentials.ts` | 外掛有 Basic 房間查詢 | `api_user`/`api_password`（`nextcloud_talk.rs:203-213`），`OCS-APIRequest: true` + `Accept: application/json` | ✅ 整輪測試都用 `arkbot` 的 app password（`downloads_a_file_the_peer_shared`、`uploads_a_file_and_shares_it_into_the_conversation`） |
| 發訊 | `POST /ocs/v2.php/apps/spreed/api/v1/bot/{token}/message`，JSON `{message, referenceId, replyTo?, silent?}`，簽章 **只簽 message 文字**（`BotController.php:148` `getBotFromHeaders($token, $message)`）；回 **201 + 空 data**，沒有 message id | `send.ts:79-95`，註解明寫「Talk signs the extracted message/reaction value」 | 外掛：純文字回覆 | `post_message()`（`nextcloud_talk.rs:319-331`）+ `bot()`（`:220-247`，5xx/短 429 退避重試、`max_wait` 上限） | ✅ `outbound_message_is_readable_by_a_second_client`（以第二個 client 讀回**逐字相同**的文字，`actorType = bots`、`actorDisplayName = "Ark (Bot)"`、只出現一次） |
| 送出的 message id | 回傳空 `data`，**沒有 id** | 同（沒有 id 可用） | 外掛 `known_issues` 也這樣寫 | `Sent.ids` 為空（`post_message` 的 `id_str(&v["ocs"]["data"]["id"])` 永遠是 `None`）；`share:` 形式只有檔案分享有 | ✅ `outbound_message_is_readable_by_a_second_client` 直接斷言 `sent.ids.is_empty()` |
| 編輯／刪除 | Bot API 只有 `message`、`reaction`、`reaction DELETE`（`routesBotController.php:46-58`），沒有 edit/delete；人類的 `/chat/{token}/{id}` PUT/DELETE 需要使用者 session | `message-actions.ts` 只做反應 | 外掛沒有 | `caps().edit/delete = false`，`edit()`/`delete()` 回 `Unsupported`（trait 預設，`nextcloud_talk.rs:548-552`） | ✅ `reactions_add_and_remove_through_the_bot_api` 斷言 `Unsupported`，也斷言 `caps` 其餘欄位 |
| 反應 | `POST|DELETE /ocs/v2.php/apps/spreed/api/v1/bot/{token}/reaction/{messageId}`，JSON `{reaction}`，簽章簽**emoji 本身**（`getBotFromHeaders($token, $reaction)`）；需要 `response` feature；201/200/404 | `message-actions.ts:81`：**只能加、移除未實作** | 外掛：無反應 | `react()`（`nextcloud_talk.rs:612-615`）加與移除都走同一支，`caps().reactions = 8` | ✅ `reactions_add_and_remove_through_the_bot_api`（加 → 訊息上出現 1 個 👍；移除 → 回到 0；對方讀回看到 `actorType=bots`、`actorDisplayName="Ark (Bot)"`） |
| 長度上限 | `ChatManager::MAX_CHAT_LENGTH = 32000`（`lib/Chat/ChatManager.php:79`，`setMessage(..., MAX_CHAT_LENGTH)`，PHP `mb_strlen` 以字元計） | `channel.ts:493-499`：`textChunkLimit: 4000`（保守） | 外掛沒寫 | `MAX_MESSAGE = 32000`（`nextcloud_talk.rs:34`）+ `chunk::split` 依字元切，**實際切點 31992**（`chunk.rs:34` 留 8 字元給 code fence 收尾） | ✅ `long_messages_are_split_at_the_real_server_limit`（40000 字 → 31992 + 8008，兩則都被伺服器接受，接起來與原文逐字相同） |
| 檔案上傳 | 不是 Talk API：WebDAV `PUT /remote.php/dav/files/{uid}/…` + `POST /ocs/v2.php/apps/files_sharing/api/v1/shares`（`shareType=10`、`shareWith={token}`、`talkMetaData`{caption,replyTo,silent}） | `outbound-media.ts`、`webdav.ts` | 外掛沒有 | `upload_share()`（`nextcloud_talk.rs:278-317`），`/Ark/ark-<hex>/`、`if-none-match: *`、單檔時 caption 跟著檔案走（`send()`，`:586-604`） | ✅ `uploads_a_file_and_shares_it_into_the_conversation`（對方讀回 `messageParameters.file`：名稱、`text/plain`、caption 就是訊息文字；`Sent.ids = ["share:<id>"]`，不再另送一則純文字） |
| 檔案下載 | webhook 帶 `{file}` 參數（`id`、`name`、`size`、`mimetype`、`link`=`/s/<token>`、`path`）；`GET /chat/{token}/{msgId}/context` 才拿得到檔案路徑 | `inbound-media.ts`（含語音訊息） | 外掛沒有 | `fetch_media()`（`nextcloud_talk.rs:617-641`）：先用 context 的 `messageParameters.file.path` 以 API 使用者身分走 WebDAV，失敗才退回公開分享 `/s/<tok>/download` | ✅ `downloads_a_file_the_peer_shared`（對方上傳 `Talk/<name>` 並分享進對話 → `media.name`/`mime`/`size` 正確 → `fetch_media()` 取回**逐位元相同**的內容） |
| 房間類型 | `GET /ocs/v2.php/apps/spreed/api/v4/room/{token}` 的 `type`：1=1:1、2=群組、3=公開、5=前 1:1、6=自己 | `room-info.ts:34`：`1/5/6 → direct`，其餘 group | 外掛沒有 | `room_kind()`（`nextcloud_talk.rs:249-261`）同規則，快取 300 秒／失敗 30 秒 | ✅ 公開對話（type 3）→ `ChatType::Group`；📖 1:1（type 1）只讀原始碼，本輪沒開 1:1 對話 |
| 提及 | 富文本 `content` 是 `{"message":"{mention-user1} …","parameters":{…}}`；bot **不在**提及選單裡，所以只能靠純文字 `@名字` | `inbound-media.mentions.test.ts` | 外掛沒有 | `decode_content()` + `render_rich()`（`nextcloud_talk.rs:380-435`）把參數還原成 `@名字`；`mentions()`（`:437-445`）比對純文字 `@Ark` 且後面不能接字母 | ✅ `inbound_message_from_a_real_conversation`（`@Ark ping` → `mentioned` 且 `addressed()`） |
| silent / replyTo | `silent`、`replyTo` 是 bot message 的參數 | 有 | 沒有 | `Outbound.silent`、`Outbound.reply_to` → `post_message()` 的 JSON | ⛔ 未實測（19.0.9 的聊天列表不回 `parentId`，讀不回「這是回覆」，只有單元測試） |
| `inReplyTo` 解讀 | **19.0.9 的 webhook 不帶 `inReplyTo`**（`BotService.php:90-112` 只有 type/actor/object/target） | 無 | 無 | 有實作（`nextcloud_talk.rs:497-505`），對 19.0.9 是死路徑 | 📖 只讀原始碼＋單元測試；實機 webhook 沒有這個欄位 |
| 費率限制 | 一般 OCS 沒有公開的 Talk 限流數字；**bot 端點有 brute-force 保護**（`#[BruteForceProtection(action: 'bot')]`），失敗會延遲，上限 25 秒 | 有 `failure` 處理 | 外掛沒有 | 429 + `Retry-After` → `RateLimited`，`max_wait` 內重試（`nextcloud_talk.rs:232-243`） | 📖 429 未實測；**實測到的是 brute-force 延遲**（見下） |
| 錯誤碼 | 400 參數錯／message 空、401 簽章錯或 bot 不在房間、404 房間不存在、413 訊息太長（`BotController.php:131-146`） | 有分類 | 外掛只說「空確認＝送達」 | 401 → `Auth`、403/404 → `NotFound`、其餘交給 `classify`（`nextcloud_talk.rs:365-374`） | ✅ `a_wrong_bot_secret_is_rejected_by_the_server`（錯的 secret → `Auth`，且訊息真的沒貼出去） |
| Bot 安裝／啟用 | `occ talk:bot:install -f webhook -f response <名字> <密鑰 40..128> <url>`（`secret` 至少 40 字元）＋用 moderator 身分 `POST /ocs/v2.php/apps/spreed/api/v1/bot/{token}/{botId}` 在對話裡啟用（`BotController::enableBot`，bot 的全域 state 必須是 1） | `bot-preflight.ts:76`（`GET /bot/admin`） | 外掛沒有 | ark **不管理** bot 註冊（由管理員用 occ 做），只用 `bot_secret` 簽章 | ✅ `tests/real/nextcloud_up.sh` 就是這樣裝的；`works_in_a_conversation_created_through_ocs` 用 OCS 建新對話、加人、啟用 bot，ark 不用重啟就能在裡面雙向收送 |

## ark 的選擇與差異

1. **只有 webhook，沒有輪詢**：Talk 的 bot 收訊只有 webhook 一條路（沒有「讀取新訊息」的 bot 端點），所以 `poll()` 只是把 webhook handler 的佇列抽乾（`nextcloud_talk.rs:563-577`）。這代表 **ark 的 `listen` 必須讓 Nextcloud 容器連得到**；本輪用 `http://host.containers.internal:28091/nextcloud-talk-webhook`。OpenClaw 同樣是 webhook，但多了持久化 spool 與去重（`webhook-spool.ts`），ark 的重放表只在記憶體、重啟就忘。
2. **檔案一定要 `api_user`**：Talk 的 bot API 不能傳檔，只能走「WebDAV 上傳 + files_sharing 分享」，所以 `caps().media` 取决于有沒有 API 憑證（`nextcloud_talk.rs:543-560`）。這也是 Hermes 外掛「純文字」的根因。
3. **bot 訊息沒有 id**：三個實作都一樣（ark 的 `Sent.ids` 空、OpenClaw 不指望、Hermes 外掛寫進 known_issues）。ark 的 `reply_to` 因此只能回覆「人類訊息」的 id。
4. **分段保守**：OpenClaw 用 4000 字，ark 用 32000-8；實測 31992 一則被 19.0.9 完整接受，所以 ark 的設定是對的（也更省訊息數）。
5. **反應移除**：OpenClaw 明確不做（`message-actions.ts:81` 直接回「not supported yet」），ark 做（DELETE），實測有效。

## 實測抓到的問題與修正

1. **ark 會把自己的檔案分享當成入站訊息（已修）**：`send()` 上傳檔案後，Talk 會把「分享到對話」的結果以 **API 使用者** 的身分回送 webhook（實測 `actorType=users`、`actorId=arkbot`、`messageParameters.file.path = "Talk/<name>"`、`link = /s/<token>`）。原本的自我過濾只認 `name.starts_with("ark-")` 或 url 含 `/Ark/`，兩個都不成立（檔名是使用者給的、連結是公開分享），於是這個回聲被當成新訊息投遞 → 在有自動回覆的 daemon 裡就是自我迴圈。修法：`upload_share()` 把剛分享的檔名記進 `uploads`（`UPLOAD_TTL = 900s`，`nextcloud_talk.rs:315`），`is_own_share()`（`:334-342`）在寄件者是 API 使用者且**所有**附件都是自己剛上傳的檔名時丟棄。測試：`our_own_file_share_is_not_echoed_as_inbound`（負向斷言之前先確認那則分享真的在對話裡，避免空測），單元測試 `own_file_share_echo_from_the_api_user_is_dropped`。
2. **bot 端點的 brute-force 延遲（未改程式，改了 harness 與文件）**：`POST /bot/{token}/message` 連續被拒幾次後，每個請求都會被 Nextcloud 的 brute-force 節流**延後到 25 秒**（伺服器 log：`"message":"Reached maximum delay"`，`Throttler::MAX_DELAY`）。第一輪測試 86 秒、重複跑到 243 秒就是這樣來的；`occ security:bruteforce:reset <gateway>` 後同一個請求 0.05 秒。這對 ark 的意義：`bot_secret` 設錯時 `send()` 會**卡 25 秒才回 `Auth`**，而且 `max_retries` 的重試會讓它更慢（ark 對 401 不重試，這點是對的）。harness 在交棒前清掉計數器（`nextcloud_up.sh` 的 `security:bruteforce:reset`），文件也寫明。
3. **「切在 32000」是錯的，實際是 31992（只改測試與文件）**：`chunk::split` 留 8 字元給 code fence（`chunk.rs:34`）。測試原本斷言 32000/8000 而失敗，實測 31992/8008；程式正確，錯的是我的預期與文件描述。
4. **bot 的顯示名稱是 `Ark (Bot)`（只改測試）**：Talk 對 `actorType=bots` 的訊息在顯示名後加 ` (Bot)`。ark 用它做「自己訊息」判斷的地方（`parse()` 的 `actor.type == Application` + 名字比對，`nextcloud_talk.rs:470-474`）在 19.0.9 上不會誤判（bot 訊息根本不會回送 webhook），但**若未來版本改了「bot 不轉發給自己」的規則，這個比對會失手**（`"Ark (Bot)" != "Ark"`）。本輪不改：改了是沒有測試護著的行為變動，先記在缺口。
5. **反應在 19.0.9 只回「數量」不是「誰」**：對話列表的 `reactions` 是 `{"👍": 1}`（陣列形式是較新版本），所以測試用「加之前 0、加之後 1、移除之後 0」驗證，而不是比對 actor。
6. **`occ user:add-app-password` 的介面**：需要 `NC_PASS` 環境變數（不是 `OC_PASS`），且要用 `-u www-data` 執行，否則 Nextcloud 直接拒絕「Console has to be executed with the user that owns the file config/config.php」。這是 harness 的坑，寫進 `nextcloud_up.sh`。
7. **`http::Http::call` 不支援 MKCOL（只影響測試，未改）**：未知方法會退回 POST（`http.rs:176-180`），所以測試原本的「`call("MKCOL", …)` 建 `Talk/`」其實送的是 `POST`，Nextcloud 回 404，接下來對不存在資料夾的 `PUT` 得到 500，而資料夾被別的路徑建好後又會過——典型的順序性 flaky。`nextcloud_talk.rs` 自己走 `raw()`（access log 確認真的送出 `MKCOL … 405/201`），所以程式的上傳路徑沒問題；測試改成直接傳到使用者 DAV 根目錄再分享（不需要建資料夾）。
8. **`occ talk:bot:install --feature reaction`**：Talk 19 只有 `webhook` 與 `response` 兩個 feature，`reaction` 不報錯但被忽略（`talk:bot:list` 顯示 `webhook, response`）；反應能力屬於 `response`。

## 缺口與待驗

- **回覆（`replyTo`）**：ark 會送，但 19.0.9 的 `GET /chat/{token}` 不回 `parentId`／`parent`，這一輪讀不回來，所以只算「送得出去」，⛔ 未證明伺服器端有掛上。
- **`silent`**：同上，沒有可觀察的差異（需要通知才有感）。
- **`inReplyTo`（入站引用）**：19.0.9 的 webhook 根本不帶，ark 的解析是為較新格式準備的，目前是死路徑。
- **1:1 對話（type 1）→ `Direct`**：只讀原始碼（`room_kind()` 與 OpenClaw `room-info.ts:34` 同規則），本輪只開了 type 3。
- **429／`Retry-After`**：沒有在真伺服器上製造過限流（Talk 的 bot 端點走 brute-force 而不是 429），只有單元測試。
- **webhook 重試**：Talk 送 webhook 失敗只記 `error_count`（`BotService.php:188-201`），不重送；ark 的 `webhook-spool` 對應物不存在，斷線期間的訊息就是掉了。這是設計差異，不是 bug。
- **語音訊息（`messageType=voice-message`）**：`upload_share()` 會標，但沒有真的用 `audio/mpeg` 上傳測過。
- **`Ark` 資料夾位置**：上傳到 `/Ark/ark-<hex>/` 後，Talk 會把它複製到對話的 `Talk/<name>`；ark 靠檔名認自己的回聲（見上），若兩個使用者在 15 分鐘內分享同名檔案，理論上會誤丟一則（實務上可接受，已寫在上面的修法裡）。

## 重跑方式

```bash
export TMPDIR=/home/noob/.cache/ark-build/r6-be/nc   # 或任何可寫目錄
export CARGO_INCREMENTAL=0 ARK_HOME=$TMPDIR/ark-home
eval "$(./tests/real/nextcloud_up.sh --keep)"        # image 已快取：實測 19–25 秒
time cargo test -p ark-channel --test real_nextcloud_talk  # 12 tests，乾淨狀態 28 秒
./tests/real/nextcloud_up.sh --down                  # 只移除 ark-test-nc-*
```

`nextcloud_up.sh` 只碰 `ark-test-nc-web`（容器）、`ark-test-nc-data`（volume）、`ark-test-nc`（network）；不帶 `--keep` 時它跑完自我檢查就自己收掉（smoke test 模式）。
