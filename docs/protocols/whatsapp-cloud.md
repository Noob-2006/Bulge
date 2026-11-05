# WhatsApp Cloud API：官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ SE Agent

> **驗證狀態：SE Agent 未對真實 WhatsApp Cloud API 驗證。** 本文件沒有帳號、沒有 WABA、沒有 token，全部 SE Agent 行為只由原始碼與其內建 `FakeServer` 單元測試佐證；與 Meta 實際部署的差異（API 版本、新互動型別、吞吐量實測）未經證實。
> 比較來源：官方文件（`/docs/whatsapp/cloud-api/overview`、`/webhooks/payload-examples`、`/guides/send-messages`，2026-11 讀取）＋ 上游原始碼靜態閱讀。
> 圖例：❓ = 官方文件或原始碼未確認；`—` = 該專案沒有這個通道。

## 對照表

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | opencode | SE Agent |
|---|---|---|---|---|---|
| 傳輸與端點 | 出站 `POST https://graph.facebook.com/v{ver}/{phone_number_id}/messages`；入站 HTTPS webhook（須公開可達、TLS）；訂閱握手 `GET ?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…` | —（無 Cloud 模組；只有 WhatsApp Web/Baileys） | `plugins/platforms/whatsapp_cloud/adapter.py:63` `GRAPH_API_BASE`、`:58` `v20.0`、`:62` `/whatsapp/webhook`、aiohttp 內建 server | —（無此通道） | `crates/seagent-channel/src/whatsapp_cloud.rs:27` `DEFAULT_GRAPH`、`:28` `v20.0`、`:522` 內建 HTTP server（body 上限 3 MiB） |
| 認證 | 出站：`Authorization: Bearer <access token>`（system user / 臨時 token）；入站：不是 OAuth，靠 app secret 的 HMAC 簽章 | 不適用 | Bearer token 由 env 注入（`WHATSAPP_CLOUD_*`） | — | Bearer token；`:480` 啟動時強制要求 `phone_number_id`、`access_token`、`app_secret`、`verify_token` 四者齊備 |
| 入站事件 | `entry[].changes[field=messages].value.{messages[],statuses[],errors[]}`；`messages[].type` = text / image / audio / video / document / sticker / location / contacts / interactive / button / reaction / system / order…；`statuses` 是「已送達/已讀」回條 | — | `adapter.py:92` `_INBOUND_MEDIA_KINDS`、`:96` `_CONTENTLESS_KINDS`（system/reaction/unsupported/unknown 丟棄）、`:67` wamid 去重 5000 筆 | — | `:7-10` 只取 `field=messages` 且 `phone_number_id` 相符者，WABA id 選配（`:514`、`:510`）；接受 text/媒體/位置/聯絡人/`button_reply`/`list_reply`/模板 `button`；`:151` 明確丟棄 reaction/system/order |
| 出站格式 | `{messaging_product:"whatsapp", recipient_type, to, type, <type>:{…}}`；文字 `text.body` + `preview_url`；引用回覆用 `context.message_id` | — | `adapter.py:375-377` 同樣組 `text` + `preview_url`，只有第一段帶 quote | — | `:414` `{"body":…, "preview_url": true}`；`:267` 統一 `post_message`；`:425` typing 用 `status:read` + `typing_indicator`（新 API） |
| 長度上限與分段 | `text.body` 4096 字元；interactive `body.text` 1024；按鈕標題 20；caption 1024 | — | `adapter.py:373` `truncate_message(self._outgoing_chunk_limit())`；`:442-443` 按鈕 body 截到 1024 | — | `:29` `MAX_MESSAGE=4096`（以 char 計）；`:398` 用 `chunk::split` 分段；`:389` 單一媒體 + 文字 ≤1024 且無按鈕時改用 caption，否則另送文字 |
| 速率限制 | 以電話號碼為單位的吞吐量（每秒訊息數，預設 80 mps，可升到 1000）；配對速率限制（pair rate limit）；超限回 130429 / 131056 | — | 只做單次重試與錯誤分類，無本地 token bucket ❓ | — | 無本地限流；靠 `Retry-After` 與錯誤分類退回上層（`:81-105`） |
| 重連與重試 | 無長連線；Meta 對非 2xx 的 webhook **重送數天**（指數退避） | — | webhook 快速回 200，dedup 防重（`:67`、`:208`） | — | `:519` 簽章通過後**一律回 200**（含「非本站號碼」的 payload），就是為了斷開 Meta 的重送迴圈；`:501` 簽章失敗回 401、`:504` 壞 JSON 回 400 |
| 錯誤碼處理 | Graph 錯誤在 `error.{message,code,error_subcode,error_data.details}`；131047 = 超過 24 小時客服視窗；190/102 = token；130429 = 速率 | — | `:276` 只標 fatal/retryable，`:1096` 以字串提示 24h | — | `:88-101` 逐碼分類：131047 → Protocol（附白話說明「超過 24 小時」）、190/10/200/102 → Auth、4/80007/130429/131056/131048 → RateLimited、131026/131030/131021 → NotFound、133010 → Fatal |
| 簽章/驗證 | `X-Hub-Signature-256: sha256=<hex HMAC-SHA256(app secret, raw body)>`；握手 token 需自行常數時間比對 | — | `adapter.py:737-756` `hmac.compare_digest`，`sha256=` 前綴 | — | `:71-78` `strip_prefix("sha256=")` + `ct_eq`，大小寫不敏感（測試 `:602`）；握手 `:491` 也是 `ct_eq` |
| 媒體 | 上傳 `POST /{phone_id}/media` → media id；送出可帶 `link` 或 `id`；下載先 `GET /{media_id}` 取 `url` 再帶 Bearer；各型別有大小上限（image 5MB / video 16MB / audio 16MB / document 100MB / sticker 100KB ❓ 依官方 media 文件） | — | `adapter.py:72-75` 帶了同一組上限，用於入站檢查 | — | `:285` 上傳、`:294` 依 link/id 送出、`:434-440` 兩段式下載（上限 100 MiB）；`:107-117` 型別對映含 voice/sticker |
| 互動元件 | 回覆按鈕 ≤3、清單列 ≤10、CTA URL 按鈕、Flows；皆需 `interactive` 型別 | — | `:436` 按鈕標籤截 20；清單/按鈕 fallback 成編號文字 | — | `:190-210` 3 個以內 → reply buttons、5~10 → list（row title 24、description 72）、單一 URL → CTA；>10 或放不下 → 「1. 2. 3.」編號純文字（`:211`） |
| 已知差異 | Cloud API 本體是 1:1 對話（群組是較新功能）；24h 視窗內才能送自由格式，之外只能送審核過的模板 | **OC 完全沒有 Cloud API**：`extensions/whatsapp/package.json:13` 是 `baileys 7.0.0-rc14`，也就是 WhatsApp Web 個人帳號多裝置協定（QR 配對、端對端加密），沒有模板、沒有 24h 視窗、沒有 WABA | 有 Cloud + Web 兩套；Cloud 走 aiohttp | 無任何聊天通道（見下） | 兩套並存：`whatsapp_cloud.rs`（原生 Rust Graph client）與 `whatsapp.rs`（Baileys bridge）。**SE Agent 的 Cloud 實作不送模板、不改用模板繞過 131047**，直接報錯給使用者 |

### opencode 的證據（無此通道）

opencode 是「The open source AI coding agent」（`README.md:20`）；`packages/` 只有 `ai / app / cli / client / codemod / console / core / desktop / … / tui / web`，沒有任何 channel 目錄。
`grep -rIl --include=*.ts -iE "whatsapp|telegram" packages/*/src` → **0 命中**；把 `slack|discord` 一併納入也只命中 `packages/app/src/runtime/i18n/*.ts`（社群連結字串）。
結論：**沒有入站訊息通道可比**，本表 opencode 欄一律 `—`。

## SE Agent 的選擇與差異

- **不用模板繞 24 小時視窗。** 131047 被歸為 `Protocol` 並回一句人話（`whatsapp_cloud.rs:89`），而不是自動改送審核過的模板訊息 — 這一點比 Hermes 的純字串提示更明確，但兩者都不實作模板流程。
- **分段與引用綁定。** 4096 字元切成多段，只有第一段帶 `context.message_id`（`:413-414`），避免每段都變成獨立的引用回覆。
- **按鈕是最後一招。** 按鈕只能寄生在最後一段、且該段 body ≤1024，否則整組按鈕退化為「1. 2. 3.」純文字（`:399-411`、`:211`）——因為 WhatsApp 的 interactive body 硬上限就是 1024。
- **webhook 一定回 200。** 簽章過但內容與本站號碼無關也回 200（`:506`、`:519`），只有簽章錯才 401；這是刻意的取捨：Meta 會重送數天，錯誤碼換不到正確行為。
- **入站嚴格 1:1。** 帶 `group_id` / `chat` 或 sender 等於自己的訊息一律丟棄（`:124`），與 Hermes 一致；SE Agent 沒有群組支援。
- **已讀 + 打字是同一個 API。** `typing()` 送 `status:"read"` 加 `typing_indicator`（`:425`），沒有 inbound wamid 時直接 no-op（`:424`）。
- **媒體下載走 100 MiB 上限**（`:439`），與 Hermes 的分型別上限不同：SE Agent 不按型別擋，只在 HTTP 層設總量上限。
- **啟動即失敗，而非執行期才炸。** `open()` 要求四個欄位齊備才肯建通道（`:480-482`）；Hermes 只強制 `phone_number_id` + `access_token`，`app_secret` 缺了照樣啟動、等到 webhook 進來才回 503（`adapter.py:6-7`、`:736`）。SE Agent 選擇在設定階段就把問題擋掉。

## 上游實作位置

- OpenClaw：`extensions/whatsapp/`（`package.json:13` = `baileys 7.0.0-rc14`）；**沒有 Cloud API 模組**，`grep -rIl "graph.facebook.com" src extensions packages` 在 OC 樹內零命中。
- Hermes：`plugins/platforms/whatsapp_cloud/adapter.py`（1533 行，aiohttp webhook server）＋ `plugins/platforms/whatsapp/`（Baileys bridge 版）。
- SE Agent：`crates/seagent-channel/src/whatsapp_cloud.rs`（754 行，含 `#[cfg(test)]`）；Baileys 版在 `whatsapp.rs`（1054 行）。
- SE Agent 共用：`chunk.rs`（分段，保留 ``` 圍籬）、`deliver.rs`（指數退避、`retry_after` 上限 60 秒）、`http.rs`（`classify`）。

## SE Agent 的測試覆蓋（全部離線）

- `:586` `handshake_and_signature_checks`：握手 200/403、簽章大小寫不敏感、別家 `phone_number_id` 被 ACK 但丟棄。
- `:611` `parses_every_message_kind`：文字、媒體、位置、聯絡人、互動回覆、模板按鈕、引用。
- `:655` `send_shapes_text_buttons_media_and_reactions`：按鈕→清單→編號文字的三段降級、CTA URL、分段、媒體上傳。
- `:702` `error_mapping`：Graph 錯誤碼分類（含 131047）。
- `:724` `fetch_media_resolves_url_then_downloads_with_bearer`：兩段式媒體下載。
- 以上全部走 `FakeServer`，沒有一個請求離開本機。

## 未驗證清單

- 沒有 WABA、沒有 `verify_token`：24 小時客服視窗與「只能送模板」的真實行為未實跑。
- 未實作模板訊息，因此「視窗外送模板」與模板審核流程完全空白。
- 未實作 Flows、位置要求、影音素材輪播等新互動型別。
- 各型別媒體大小上限（image 5 MB 等）只寫在文件中，SE Agent 端不檢查，實際超限錯誤路徑未知。
- 吞吐量（預設 80 mps）與 130429 的實際退避行為未測；`statuses` 回條被忽略，送達/已讀不會回饋到上層。
- API 版本寫死 `v20.0`（`:28`），Meta 後續版本的行為差異未知。
