# Telegram Bot API：官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ ark

> **驗證狀態：ark 未對真實 Telegram 服務驗證。** 沒有 bot token、沒有公開 webhook URL；ark 行為僅由原始碼與 `FakeServer` 錄製測試向量佐證（`telegram.rs` 的 `#[cfg(test)]`，`:608-869`，覆蓋長輪詢、HTML 送出、UTF-16 分段、429 retry_after、409 衝突、webhook secret）。真實環境的 flood 懲罰、20 MB 媒體邊界、rich entity 解析未測。
> 比較來源：`core.telegram.org/bots/api`（含 `bots/api/methods/sendmessage.md`、`getupdates.md`、`getfile.md`、`bots/api/types/update.md`、`bots/faq`，本次以官方 markdown 版本逐條核對）＋ 上游原始碼。
> 圖例：❓ = 未確認；`—` = 該專案無此通道。

**opencode**：無此通道。`/home/noob/.cache/ark-build/r5-e/opencode` 的 36 個 `packages/` 全是 coding-agent 元件，全 repo 搜 `api.telegram.org`、`getUpdates` 皆 0 命中；`telegram` 只出現在 README 社群徽章（`README.md:12`）。下表 opencode 欄一律 `—`。

## 對照表

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | opencode | ark |
|---|---|---|---|---|---|
| 傳輸與端點 | `https://api.telegram.org/bot<token>/<method>`；`getUpdates` 長輪詢或 `setWebhook` 推播 | grammY `Bot`，`apiRoot` 可覆寫（`extensions/telegram/src/accounts.ts:46`）；預設長輪詢、可切 webhook（`src/monitor.ts:57`）；同 token 有 polling lease 擋第二個 poller（`src/polling-lease.ts:8-25`） | python-telegram-bot `Application`，預設 `start_polling()`（`telegram/adapter.py:439-451`），支援 webhook（`:600`、`:1890`） | — | 自寫 `ureq` HTTP：`getUpdates`（`telegram.rs:455-476`）或自架 webhook listener（`:91-120`）；`base_url` 可覆寫（`:26`、`:578`） |
| 認證 | bot token 置於 URL path，無 Authorization 標頭 | token 取 config／secret 檔（`src/token.ts`） | `TELEGRAM_BOT_TOKEN`／config | — | `ctx.secret("token")`（`telegram.rs:597`）；空 token 建構期即 `Err`（`:64-66`）；錯誤字串 redact（`:211`） |
| 入站訊息事件 | `Update` 共 28 種，含 `message_reaction`、`edited_channel_post`、business/guest 系列（`types/update.md`） | grammY 預設集合 + `message_reaction`、`channel_post`，刻意扣掉 `stopped_message_generation`（`src/allowed-updates.ts:5-19`） | 由 PTB handler 註冊決定（文字／媒體／編輯／指令） | — | 只訂 4 種 `message`、`edited_message`、`channel_post`、`callback_query`（`telegram.rs:227`；`getUpdates` `:470`、`setWebhook` `:116`）；無 reaction 入站 |
| 出站訊息格式 | `parse_mode` = HTML／MarkdownV2／Markdown | HTML（`src/bot/delivery.replies.ts:293`），由 `markdownToTelegramChunks` 轉換（`src/format.ts:658`） | `ParseMode` HTML（`adapter.py:124`、`:369`）；另有 Bot API 10.1 `sendRichMessage`（`:527`、`:1293`） | — | Markdown → HTML（`Markup::TelegramHtml`，`telegram.rs:384`）：`<b>/<i>/<s>/<a>/<pre><code class=language-x>/<blockquote>`（`markup.rs:100-152`、`:166`） |
| 長度上限與分段 | `text` 1–4096 字元（entities 解析後，`methods/sendmessage.md`）；caption 1024；`getFile` 上限 20 MB（`methods/getfile.md`） | 4096，HTML-aware 切分並補未閉合標籤（`src/format.ts:575-658`） | `MAX_MESSAGE_LENGTH = 4096`（`adapter.py:524`）；rich 上限 32768（`:527`） | — | 4096 且**以 UTF-16 code unit 計**（`telegram.rs:28`、`:450`；`chunk.rs:7-13`）；`chunk::split` 段落→換行→空白斷點並重開 ``` 圍籬（`chunk.rs:34-71`）；媒體 caption 1024 UTF-16（`:491`） |
| 速率限制 | 單聊天約 1 msg/s、群發約 30/s，超額 429 + `retry_after`（`bots/faq`） | 每 token 一把 flood limiter、預算 5 分鐘，stream preview／typing 可替換請求讓位（`src/account-throttler.ts:24-30`）+ grammY `apiThrottler`（`:10`） | 只處理單次 `RetryAfter`：短的睡完重送、長的失敗（`adapter.py:193`、`:212`），無全域配額 | — | 429 → `RateLimited`（`telegram.rs:218-221`）；≤60s 就地等待重試、>60s 上拋（`:184-186`，測試 `:772-779`）；無主動節流 |
| 重連與重試 | 長輪詢失敗即重試；offset 以「下一次更高 offset 呼叫」確認（`getupdates.md`） | polling watchdog + 重啟策略（`src/polling-session.ts`、`polling-session-restart-policy.ts`），指數退避 | 自建 reconnect ladder + stall watchdog，以 `getUpdates` 心跳量測（`adapter.py:648-683`、`:2033`） | — | 指數退避 500ms×2、最多 4 次（`telegram.rs:78-80`、`:186`）；offset 只在下次 poll 前落地（`:195-202`）→ at-least-once |
| 錯誤碼處理 | 401 token 失效；409 有另一個 poller 或 webhook 生效；429 flood control | grammY `ApiError` + 集中分類（`src/error-policy.ts`） | 401 觸發 suspend/backoff（`src/sendchataction-401-backoff.ts`）、409 走 conflict recovery（`adapter.py:1210`、`:652`） | — | 401/404→`Auth`；403 與 chat not found／bot kicked／user deactivated→`NotFound`；409→`Fatal`；429→`RateLimited`；5xx→`Network`（`telegram.rs:206-225`，測試 `:781-792`） |
| 簽章/驗證 | `secret_token`（1–256 字元、`A-Za-z0-9_-`）以 `X-Telegram-Bot-Api-Secret-Token` 回送（`bots/api`） | 驗該 header（`src/webhook.ts:128`）、註冊帶 `secret_token`（`:473`）、body 上限 1 MiB（`:58`） | webhook 模式比對 `secret_token`（`adapter.py:3128`） | — | 要求 ≥16 字元且限 `A-Za-z0-9_-`（更嚴，`telegram.rs:92-93`），`ct_eq` 常數時間比較（`:103`）；錯 secret 401、錯路徑 404（`:99-113`，測試 `:849-869`） |
| 媒體 | `getFile` → `/file/bot<token>/<file_path>`，上限 20 MB、連結有效 ≥1 小時 | `getFile` + 串流下載，上限 ❓（`src/bot/delivery.resolve-media.ts` 無對應常數） | 20 MB（公共 API）／2 GB（自架 `base_url`）（`adapter.py:708-709`） | — | `getFile` 後 `get_bytes` 硬上限 20 MiB（`telegram.rs:553-558`）；上傳 multipart（`:156-165`、`:415-419`）；`photo` 取最大尺寸（`:243-247`） |
| 互動元件 | InlineKeyboard + `callback_query` + `answerCallbackQuery`；`setMyCommands`；無模態 | inline keyboard（`src/send.ts` `buildInlineKeyboard`）、native commands（`src/bot-native-commands.*`） | `InlineKeyboardMarkup`（`adapter.py:116`、`:363`）+ slash handler | — | inline keyboard（`telegram.rs:351-360`），按鈕只掛最後一段（`:509-511`）；`answerCallbackQuery`（`:545-551`）；`setMyCommands` 選配（`:137-153`、`:592`）；無模態 |
| 已知差異 | — | 訂閱面最廣、傳輸交給 grammY | 唯一支援 Bot API 10.1 rich message／draft | 無此協定 | 最小可用集合（4 種 update、無 reaction 入站、無 business/guest）；HTML 輸出與 UTF-16 分段自寫 |

## ark 的選擇與差異

- **只訂 4 種 update。** `ALLOWED_UPDATES = ["message","edited_message","channel_post","callback_query"]`（`telegram.rs:227`）對照官方 28 種（`types/update.md`）。使用者加 ❤ 這類回饋永遠不會變成 `Inbound`，只有出站 `react`（`:540-543`）。
- **分段單位刻意用 UTF-16。** `MAX_MESSAGE=4096` + `LenUnit::Utf16`（`telegram.rs:28`、`:450`），因為實體 offset 與長度都算 UTF-16；`utf16_slice` 也是為此存在（`:345-349`）。OC 在 HTML chunker 內處理同一問題（`src/format.ts:575`）。
- **offset 語意偏 at-least-once。** 只有下一次 `poll` 才把 pending offset 寫檔（`telegram.rs:195-202`、`:469-475`），崩潰後必定重投；官方語意是「以更高 offset 呼叫即確認」（`getupdates.md`）。去重推給 router（模組註解 `:10-11`）。
- **webhook secret 比官方更嚴。** 官方允許 1–256 字元，ark 要求 ≥16 且限 `A-Za-z0-9_-`（`telegram.rs:92-93`），並用 `ark_net::crypto::ct_eq`（`:103`）；OC 只驗存在與相等（`webhook.ts:128`）。
- **flood 控制只有被動等待。** `retry_after ≤ 60s` 就地睡、`>60s` 上拋 `RateLimited`（`telegram.rs:184-186`）；沒有 OC 的 5 分鐘 token 預算與「可替換請求讓位」（`account-throttler.ts:24-30`），也沒有任何主動節流。
- **多重 poller 只靠 409 偵測。** ark 把 409 當 `Fatal` 並提示「另一個 poller 或 webhook 正在跑」（`telegram.rs:217`）；OC 先用 token fingerprint 租約排除（`polling-lease.ts:8-25`），HE 有 conflict-recovery 迴圈（`adapter.py:1210-1240`）。
- **forum topic 的假回覆被剔除。** `is_topic_message && reply_to_message.forum_topic_created` 不算 reply（`telegram.rs:304-307`），否則每個 topic 訊息都會被當成回覆串。
- **編輯以 `message_id` 加後綴去重。** `"<id>:e<edit_date>"`（`telegram.rs:325-326`）：編輯視為新訊息，但共用原 id；`message is not modified` 直接視為成功（`:523`），避免串流編輯空轉報錯。
- **沒有 history API。** `read` 只讀 poll 期間的記憶體快取（`telegram_actions.rs:7-11`、`:26`），上限 5000 訊息／10000 貼圖（`:29-30`），與 OC `history-read.ts` 同策略但額度自訂。
- **未測真實服務。** 以上全部由 `FakeServer` 向量覆蓋（`telegram.rs:759-869`）；20 MB 媒體邊界、flood 懲罰曲線、rich entity 解析仍屬未驗證。

## 抓取備註與證據

- 官方 `bots/api` 的 HTML 版超過抓取上限（100 KB 後被截斷），因此改用官方機器可讀版：`bots/api.md` 只是索引，逐方法頁面在 `bots/api/methods/<name>.md`（例：`sendmessage.md`、`getupdates.md`、`getfile.md`）。4096 字元、`offset` 語意、20 MB 都出自這幾頁。
- `types/update.md` 共列 28 種 update 型別；`setWebhook` 的 `allowed_updates` 若不給會沿用上一次設定，ark 每次都顯式帶（`telegram.rs:116`、`:470`）。
- `bots/faq` 的速率數字：單聊天「避免超過 1 則/秒」、群發「約 30 則/秒」，付費廣播可到 1000 則/秒——ark 完全沒有對應的批次節流，只有 429 之後的等待。
- `getFile` 明載「bot 目前最多下載 20 MB」「連結至少有效 1 小時」，ark 的 20 MiB 限制（`telegram.rs:557`）與此一致，但沒有處理連結過期重取。
- 官方沒有列出「edit 只能在 48 小時內」之類的明文限制於本次抓到的頁面 ❓，ark 的 `edit()` 也沒做時間檢查（`telegram.rs:518-526`）。
- OC 的 `markdownToTelegramChunks` 會輸出 HTML 並處理 entity/標籤邊界（`src/format.ts:575-658`）；ark 走 `chunk::split` 先切純文字再轉 HTML（`telegram.rs:500-511`），因此 ``` 圍籬是唯一被特別平衡的結構（`chunk.rs:68-71`），粗體/連結仍可能被切斷。
- HE 的 rich message 需要 `rich_messages` 額外設定且只在最終訊息啟用（`adapter.py:608`、`:1293-1352`），預設關閉——所以三家預設行為其實都落在 4096 字元的 legacy 路徑。
- ark 的 `needs_me` 優化只在群組或回覆時才呼叫 `getMe`（`telegram.rs:478-483`），私人訊息完全不快取 bot 身分，這是三家都沒有的省呼叫設計。

## 尚未驗證

- 真實 flood control 的懲罰曲線與 `retry_after` 上限（ark 以 60s 為界，超過就上拋）。
- 20 MB 以上檔案的 `getFile` 失敗碼，以及連結過期後的重新取用。
- HTML 送出時 entity 邊界被 `chunk::split` 切斷的實際渲染結果（未對真實客戶端比對）。
- webhook 模式在 Telegram 重送（非 200 回應）下的去重表現：ark 直接 200，無 `update_id` 去重紀錄。
- `setMyCommands` 的權限/範圍（`scope`、`language_code`）未使用，只送全域清單（`telegram.rs:143-151`）。

## ark 的 caps() 宣告

- `chat_types = [Direct, Group, Channel, Thread]`（`telegram.rs:437`）：Telegram 的 `channel_post` 是真的頻道貼文，ark 因此把 `Channel` 列為一等型別（OC/Hermes 的對應分類未逐一核對 ❓）。
- `reactions = 1`（`Caps` 定義：`1 = one per message per user`，`lib.rs:301-302`，即每個訊息每個使用者一個 reaction）、`polls = false`（送出端未實作投票）、`native_commands = true`、`streaming = Edit`（`telegram.rs:441-448`）。
- `max_len = 4096`、`len_unit = Utf16`、`markup = TelegramHtml`（`telegram.rs:449-451`）——host 直接用這三個值切分，所以 `send()` 內再一次 `chunk::split` 只是防呆（`:500`）。
- `topic-create`/`topic-edit` 等論壇操作只在 `message` tool 的 action 層（`telegram_actions.rs:26`），不在 `caps()` 內。
