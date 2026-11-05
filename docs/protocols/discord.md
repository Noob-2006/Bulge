# Discord API：官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ ark

> **驗證狀態：ark 未對真實 Discord 驗證。** 沒有 bot token、沒有測試 guild；ark 行為僅由原始碼與 scripted gateway／`FakeServer` 測試佐證（`discord.rs` 的 `#[cfg(test)]`，`:2226` 起，覆蓋 identify、心跳 zombie、resume、4004 fatal、zlib 解壓、REST 429）。真實 close code 分佈與 rate-limit 標頭未測。
> 比較來源：`discord.com/developers/docs/reference`、`.../resources/channel`、`.../topics/gateway`（站台為 JS 渲染，本次只取到含內文的 HTML；未取到的細節標 ❓）＋ 上游原始碼。
> 圖例：❓ = 未確認；`—` = 該專案無此通道。

**opencode**：無此通道。`/home/noob/.cache/ark-build/r5-e/opencode` 的 36 個 `packages/` 皆為 coding-agent 元件，全 repo 搜 `discord.com/api`、`gateway/bot` 0 命中；`discord` 只出現在 README 社群徽章（`README.md:12`）。下表 opencode 欄一律 `—`。

## 對照表

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | opencode | ark |
|---|---|---|---|---|---|
| 傳輸與端點 | REST `https://discord.com/api/v{version}`；Gateway `wss://gateway.discord.gg/?v=10&encoding=json`，可選 `compress=zlib-stream`／`zstd-stream`（`topics/gateway`） | 自寫 gateway client，預設 `wss://gateway.discord.gg/`（`src/internal/gateway.ts:47`）；REST 經 `src/internal/rest.ts` + 佇列排程（`rest-scheduler.ts:36-39`） | discord.py `commands.Bot`（`adapter.py:1249`），gateway 由套件管理 | — | REST v10（`discord.rs:59`）；Gateway 手寫 WebSocket（`:842`），URL 取自 `GET /gateway/bot`（`:589-598`）；只支援 `zlib-stream`（`:738-748`），zstd ❓ 未實作 |
| 認證 | `Authorization: Bot <token>`（`reference`） | 同（`src/internal/rest.ts`） | bot token 交 discord.py | — | `format!("Bot {}", token)`（`discord.rs:516`）；token 來自 `ctx.secret`（`:2172`）；錯誤不含 token |
| 入站訊息事件 | Gateway dispatch（`MESSAGE_CREATE`、`MESSAGE_UPDATE`、`INTERACTION_CREATE`…），可見性由 intents 決定 | intents = Guilds∣GuildExpressions∣GuildMessages∣DirectMessages∣GuildMessageReactions∣DirectMessageReactions + MessageContent（`src/monitor/gateway-plugin.ts:124-152`） | `Intents.default()` + `message_content`、`dm_messages`、`guild_messages`、`voice_states`，members 依需求（`adapter.py:1466-1474`） | — | intents = 0/9/12/15/24/25（`discord.rs:63`）；處理 `MESSAGE_CREATE/UPDATE`、`INTERACTION_CREATE`、poll 投票、`GUILD_CREATE`／`THREAD_*` 快取（`:1022-1050`） |
| 出站訊息格式 | `content` 用 Discord markdown；另有 `embeds`（≤10 個、合計 6000 字）與 `components`（`resources/channel`） | 自有 chunker + `allowed_mentions`（`src/send.shared.ts:37`、`outbound-text.ts:26`） | `content` 直送（`adapter.py:1225-1235`），`supports_code_blocks = True` | — | **完全直通不改寫**：`Markup::DiscordMarkdown` 時 `convert()` 原樣回傳（`markup.rs:131-134`）；`allowed_mentions` 由 `Mentions::allowed` 產生（`discord.rs:136-150`、`:2001`） |
| 長度上限與分段 | `content` ≤2000 字元；單次訊息請求上限 25 MiB（`resources/channel`） | 2000（`src/send.shared.ts:37`；`outbound-text.ts:26` 再夾一次） | 2000、切點 1900、最多 8 段，超過改提示（`adapter.py:1225-1235`） | — | 2000 且以**字元**計（`discord.rs:60`、`:1924`、`:1982`；`chunk::split` 同處）；`edit()` 只 `truncate_chars(…,2000)` 不切段（`:2040`） |
| 速率限制 | 每路由 bucket、`X-RateLimit-*`、429 帶 `retry_after`、可能為全域（`topics/rate-limits`，本次未取到正文 ❓） | gateway 送出自限 120/60s、佇列上限 120 丟最舊（`src/internal/gateway-rate-limit.ts:1-3`）；REST 4 worker／佇列 1000／每請求重試 ≤3（`rest-scheduler.ts:36-39`） | 交 discord.py／http 套件，無自管配額 | — | REST 以 `"METHOD path"` 為 bucket（`discord.rs:515`），讀 `x-ratelimit-remaining==0` + `reset-after`（`:581-587`）；429 回填 bucket、`global:true` 記在 `"*"`（`:543-545`）；等超過 `max_wait` 回 `RateLimited`（`:563-580`）。Gateway 無自限 |
| 重連與重試 | Hello(10)→Heartbeat(1)/ACK(11)；未收 ACK 應關閉並 Resume；另有 Resume(6)、Reconnect(7)、Invalid Session(9)、`resume_gateway_url` | `GatewayReconnectReason` 狀態機、resume 失敗門檻 3、identify limiter（`src/internal/gateway.ts:34-58`、`gateway-identify-limiter.ts`） | discord.py 內建 + 自建 liveness 探測，連續不健康強制重連（`adapter.py:1988-2036`） | — | `gateway_loop` 指數退避 ×2（上限 5 次）、`resume_failures>=3` 丟 session 重 identify（`discord.rs:787-836`）；首心跳 jitter（`:926-927`）；未 ACK 視為 zombie 主動關閉（`:860-863`）；op 7/9 分支（`:954-966`） |
| 錯誤碼處理 | close 4013 = intents 無效、4014 = 特權 intent 未啟用（`topics/gateway`，已核對）；其餘 close code ❓ | `isFatalGatewayCloseCode` 區分可 resume／致命（`src/internal/gateway.ts:14`、`gateway-close-codes.ts`） | 4014 特別提示去開 privileged intents（`adapter.py:417-433`） | — | REST 401→`Auth`；403/404 與 code 10003/10008/10013/50001/50007→`NotFound`；408/5xx→`Network`（`discord.rs:487-505`）；close 4004→`Auth`、4011/4010/4012/4013/4014→`Fatal`、4003/4005/4007/4009→重新 identify（`:906-916`） |
| 簽章/驗證 | HTTP Interactions 需驗 `X-Signature-Ed25519` + timestamp（官方 interactions 文件，本次未取 ❓） | 只走 gateway，`src` 無 ed25519／signature 驗證（全檔搜尋無命中） | discord.py 只走 gateway，無 HTTP 互動端點 | — | **只走 gateway、不實作 HTTP interactions 端點**，故無簽章需求（`discord.rs` 全檔無 ed25519/signature；模組註解 `:4-19` 只描述 gateway 入站） |
| 媒體 | multipart `files[n]` + `attachments` metadata，單請求 25 MiB（`resources/channel`） | `payload_json` + `files[n]`（`src/internal/rest-body.ts`） | `plugins/platforms/discord/adapter_media.py`（459 行，含縮放與 voice message） | — | 本機檔 → multipart（`discord.rs:438-452`、`:1970`）；圖片 URL → `embeds[].image.url`（≤10，`:1972`），其他 URL 併入文字（`:1977`）；每訊息 ≤10 附件（`:1984-1988`、`:2018`）；下載上限 100 MiB（`:2074-2077`） |
| 互動元件 | components（action row ≤5、合計 25）、select menu、modal（type 9 + `MODAL_SUBMIT`）、poll；interaction 需 3 秒內回應（type 4／6） | 元件／select／模態（`src/internal/components.message.ts`、`components.modal.ts`、`modal-fields.ts`）；slash 部署（`command-deploy.ts`） | `discord.ui` View／Select／Modal（`adapter.py:5710-5860`）、slash 同步（`:86`） | — | 按鈕列 >5 顆降級成 string select（`discord.rs:1496-1600`、`:1718-1736`）；modals 以 `arkm:` 前綴（`:1338`、`:1631`、`:1780-1792`）；select 值 `arkv:`（`:1339`、`:1607`）；poll 送出／結束／選民（`:1681`、`:1794-1823`）；slash `/new /stop /status /help`（`:676-704`）；ack 用 type 6 或 type 4+EPHEMERAL（`:2061-2072`） |
| 已知差異 | — | 元件最完整（modal field 對應、command deploy），另有 gateway 自限流 | 依賴 discord.py 生態，語音／DAVE 另建模組 | 無此協定 | 自寫 gateway（shard、zlib、voice 另檔 `discord_voice.rs`／`dave.rs`）；無 HTTP interactions、無 zstd |

## ark 的選擇與差異

- **入站只做 Gateway。** `discord.rs` 沒有 Ed25519／`X-Signature-Ed25519` 驗證，模組註解也只描述 gateway（`:4-19`）；代價是無法在純 HTTP 環境提供 slash 端點。OC 與 HE 同樣是 gateway-only，但 ark 是唯一自寫 WebSocket 的。
- **intents 寫死預設、可用 `intents` 覆寫。** `DEFAULT_INTENTS` = 0/9/12/15/24/25（`discord.rs:63`、`:2179`），刻意不含 GuildExpressions／Presence／Members；OC 預設多帶 GuildExpressions（`monitor/gateway-plugin.ts:127-136`），HE 用 `Intents.default()`（`adapter.py:1466`）。
- **close code 策略偏保守。** 4013/4014 直接 fatal，且錯誤訊息直接叫人去開發者後台開 MESSAGE CONTENT INTENT（`discord.rs:913`）；OC 只回 fatal 分類（`gateway-close-codes.ts`）。
- **Resume 中毒重設。** `sess.resume_failures >= 3` 即 `sess.reset()` 改走 identify（`discord.rs:822-825`），避免無限 resume 迴圈；OC 的門檻常數同樣是 3（`internal/gateway.ts:58`）。
- **REST 限流自管 bucket。** 只認 `remaining==0` 與 `reset-after`（`discord.rs:581-587`），沒有 OC 的 4 worker／1000 佇列／優先級 lane（`rest-scheduler.ts:36-39`）；超過 `max_wait` 直接回 `RateLimited` 而非無限等（`:567-575`）。
- **編輯不切段。** `edit()` 直接 `truncate_chars(text, 2000)`（`discord.rs:2040`）；`send()` 才走 `chunk::split` 並保留 ``` 圍籬（`:1982`、`chunk.rs:34-71`）。HE 的 `MAX_SPLIT_MESSAGES = 8` 上限（`adapter.py:1231`）ark 沒有。
- **Discord markdown 完全不轉換。** `markup.rs:132-134` 直接回傳原文，連跳脫都不做；只有 Telegram／Slack 有轉換器。好處是 `**粗體**`、`> 引用` 原樣可用，壞處是模型輸出 HTML 時不會被修正。
- **forum 頻道自動開新帖。** 送到 forum 時第一段改走 `forum_post()`，並把回傳的新 thread id 當後續目標（`discord.rs:2020-2025`、`:1843-1865`）。
- **按鈕列太長自動變 select。** >5 顆就換成 string select（`discord.rs:1496-1600`），與 Slack 同一條自訂規則（`slack.rs:810-838`），非官方要求。
- **未測真實服務。** gateway 行為全由 scripted WS server 覆蓋（`discord.rs:2226` 起）；真實 close code 分佈、shard `max_concurrency` 與 rate-limit 標頭仍屬未驗證。

## 抓取備註與證據

- 官方三個頁面都是 JS 渲染的 SPA：`web_fetch` 取得的是導覽外殼 + 內嵌 JSX，可讀段落有限。已核對的具體數字只有：`content` ≤2000 字元、單次訊息請求 ≤25 MiB、`embeds` ≤10 個且合計 6000 字元、close 4013/4014 的含義（`resources/channel`、`topics/gateway`）。
- Gateway 生命週期已逐條核對：Hello(10) 帶 `heartbeat_interval`、Heartbeat(1)/ACK(11)、收不到 ACK 要主動關閉並 Resume、`READY.resume_gateway_url`、`compress` 可為 `zlib-stream` 或 `zstd-stream`（`topics/gateway`）。ark 只實作 zlib。
- `topics/rate-limits` 的正文（bucket 標頭名稱、全域限流語意）本次沒取到 ❓；ark 的實作是照 `X-RateLimit-Remaining/Reset-After` 與 429 body 的 `retry_after`/`global` 寫的（`discord.rs:543-544`、`:581-587`），與 OC 的 `rest-routes.ts` 假設一致。
- ark 的 intents 沒有 `GUILD_EXPRESSIONS`（bit 7），OC 預設有（`gateway-plugin.ts:127`）；若貼圖/表情事件是需求，ark 會收不到。
- ark 的 `MESSAGE_UPDATE` 也走 `inbound_of`（`discord.rs:1022-1026`），編輯會被當成新訊息（靠 `message_id` 去重），與 Telegram 的 `:e<edit_date>` 後綴策略不同——Discord 沒有 `edit_date` 可用。
- ark 的 shard 邏輯會依 guild 把出站 gateway 訊息分派到對應 shard（`discord.rs:874-884`、`:630-634`），OC 則用 `sharedGatewayIdentifyLimiter` 控 identify 併發（`gateway-identify-limiter.ts`）。
- 語音（`voice = true`）在 ark 是獨立模組（`discord_voice.rs`、`dave.rs`，含 DAVE 簽章金鑰持久化 `discord.rs:2140-2215`），OC 與 HE 各自有 voice 實作，本表未逐項比較。

## 尚未驗證

- 真實 close code 分佈（4004/4009/4011 等）與 ark 對照表是否完全正確。
- `zstd-stream` 是否已成為預設協商值（若 Discord 端改預設，ark 會解不開）。
- shard `max_concurrency` 在大型 bot 下的 identify 節流（ark 每 5s 一個 bucket，`:226-247`）。
- 互動元件的 25 個上限：ark 的 `components()` 沒有截斷（`discord.rs:1718-1736`），超過上限的真實錯誤碼未測。

## ark 的 caps() 宣告

- `chat_types = [Direct, Group, Channel, Thread]`（`discord.rs:1911`）：Discord 的 guild 文字頻道是真的 `Channel`，thread 另立一型。
- `reactions = 20`（Discord 每個訊息可有大量 reaction）、`polls = true`、`native_commands = cfg.commands`（需設定才註冊 slash）、`streaming = Edit`（`discord.rs:1915-1922`）。
- `max_len = 2000`、`len_unit = Chars`、`markup = DiscordMarkdown`（`discord.rs:1923-1925`）——與 Telegram 的 UTF-16 不同，這裡的 2000 就是字元數。
- 語音不進 `caps()`，而是獨立 channel 綁定（`discord_voice.rs`），`/voice join` 由 gateway 訊息攔截處理（`discord.rs:1057-1077`）。
