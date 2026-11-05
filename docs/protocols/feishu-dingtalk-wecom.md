# 飛書 / 釘釘 / 企業微信：官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ ark

> **驗證狀態：ark 未對真實飛書、釘釘、企業微信驗證。** 沒有企業自建應用、沒有 app secret、沒有機器人；ark 行為僅由原始碼與 `FakeServer`／假 WebSocket 測試佐證。長連線（飛書 protobuf、釘釘 Stream、WeCom openws）在真實網路上是否會被中間設備重置，完全未測。
> 比較來源：`open.feishu.cn/document/server-docs/event-subscription-guide/overview`、`open.dingtalk.com/document/orgapp/stream`（這兩頁為 JS 渲染，`web_fetch` 只取到空殼，故協定細節以原始碼與公開規格為準，未能核對者標 ❓）＋ 上游原始碼。
> 圖例：❓ = 未確認；`—` = 該專案無此通道。

**opencode**：三個平台都沒有對應實作。`/home/noob/.cache/ark-build/r5-e/opencode` 的 `packages/` 無任何 channel / bot / webhook 模組，`README.md:20` 自述為 "The open source AI coding agent"；`grep -rIl -iE "feishu|dingtalk|wecom|larksuite" packages/*/src` → **0 命中**（`webhook` 只命中 `elevenlabs-transcription.ts`）。以下三表 opencode 欄一律 `—`。

## 一、飛書 / Lark（`feishu`、`lark`）

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | ark |
|---|---|---|---|---|
| 傳輸與端點 | 事件訂閱兩種：Webhook（HTTPS POST，需 `url_verification` 握手）或長連線 WebSocket（SDK 內建）；出站 `POST /open-apis/im/v1/messages?receive_id_type=`、`…/messages/{id}/reply` | `@larksuiteoapi/node-sdk 1.74.0`（`package.json`），WS 與 webhook 皆走 SDK，見 `extensions/feishu/src/client.ts:480`、`feishu-ingress.ts` | `feishu/adapter.py`，`websockets` + aiohttp，兩者其一 | **自寫 protobuf WS**：`feishu.rs:6-8` `POST /callback/ws/endpoint` 換 `wss://`，二進位 `Frame`（`sum`/`seq` 分片、回應 `{"code":200}`）；`:10-13` 另支援 webhook |
| 認證 | `tenant_access_token`（`auth/v3/tenant_access_token/internal`，約 2 小時）；lark 域名為 `open.larksuite.com` | SDK 快取 | SDK 快取 | `:291-293` 自己換 token，`:22` 快取至到期前並在「token invalid」時刷新 |
| 入站事件 | schema 2.0：`{"header":{"event_type":"im.message.receive_v1"},"event":{…}}`；`card.action.trigger` 為卡片按鈕 | `monitor.message-handler.ts`、`card-interaction.ts` | `feishu/adapter.py`（text/post/image/file/audio/media/sticker） | `:15-18` `im.message.receive_v1`（含 post、sticker、forward 佔位）與 `card.action.trigger`（`:722`）；`thread_id` 主題、`parent_id` 回覆 |
| 出站格式 | `msg_type`: text / post（富文本）/ interactive（卡片）/ image / file / audio / media；`content` 是**JSON 字串** | `outbound.ts`、`markdown.ts`（Markdown → post） | `adapter.py:109-131` 同套 Markdown→post 轉換與 fence 修補 | `:19-21` `im/v1/messages`、`…/reply`（含 `reply_in_thread`）、卡片、上傳後送 |
| 長度上限與分段 | 單則訊息內容上限 ❓（可讀頁面未確認；社群常見 150 KB 說法） | `outbound.ts:73` `FEISHU_TEXT_CHUNK_LIMIT=4000` | `truncate_message` 預設 | `:53` `MAX_MESSAGE=4000`（字元）、`:1385` `chunk::split` |
| 速率限制 | 應用層頻率限制；錯誤碼 99991400（頻率限制）、230020、11232 | SDK 重試 | ❓ | `:62` `RATE_CODES=[99991400, 230020, 11232]` → `RateLimited`，交 `deliver.rs` 全域退避 |
| 重連與重試 | WS 斷線由客戶端重連（`ping`/`pong`） | SDK 內建 | SDK 內建 | `:6-8` 自己維護 ping/pong 與重連；`:1163-1166` 重新取 endpoint |
| 錯誤碼處理 | `code=0` 成功；99991661/99991663/99991668 = token；10003/10014 = 權限 | SDK 拋錯 | ❓ | `:59` `AUTH_CODES` 9 碼、`:61` `TOKEN_CODES` 3 碼（先刷新再重試）、`:62` 速率 3 碼 |
| 簽章/驗證 | `X-Lark-Signature = sha256(timestamp + nonce + encrypt_key + body)`，有時間窗；`{"encrypt":…}` 為 AES-256-CBC（key = sha256(encrypt_key)、iv = 前 16 bytes） | SDK | `adapter.py`（verification token / encrypt key） | `:10-13` 簽章 + 新鮮度窗（`:55` `MAX_SKEW_SECS=3600`）、AES-256-CBC 解密 |
| 媒體 | `im/v1/images`、`im/v1/files` 上傳取 `image_key`/`file_key`；下載 `…/messages/{id}/resources/{key}` | `media.ts`、`media-download.ts` | `adapter.py:133-139` 以副檔名分類 | `:56` `MAX_MEDIA=30 MB`；上傳後送、resource 下載 |
| 互動元件 | interactive 卡片 + `card.action.trigger` 回呼 | `presentation-card.ts`、`card-action.ts` | `dashboard_card.py` | 卡片按鈕 → `Callback`；`:18`；`caps()` `buttons: true`（`:1295`） |
| 已知差異 | 飛書**沒有 typing indicator API** | ❓ | ❓ | `:28-29` 明確註記無 typing API，`caps()` `typing: false`（`:1294`）；串流用 `Streaming::Edit`（`:1298`）改訊息而非原生 token 串流 |

## 二、釘釘（`dingtalk`，Stream Mode）

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | ark |
|---|---|---|---|---|
| 傳輸與端點 | `POST /v1.0/gateway/connections/open`（clientId/clientSecret + subscriptions）→ WebSocket endpoint + 一次性 ticket；frame `{specVersion, type, headers, data}`，以 `messageId` ACK | —（無 DingTalk 通道；`src/channels/bundled-channel-ids.generated.ts` 無此 id） | `dingtalk/adapter.py`，`dingtalk-stream` SDK | `:4-9` 自己開 WS、自己 ACK；`:43` `BOT_TOPIC=/v1.0/im/bot/messages/get`；`:317-322` 開連線 |
| 認證 | clientId（AppKey）+ clientSecret → ticket；OpenAPI 另用 `oauth2/accessToken` | — | SDK | 同上，`:317` 直接帶 secret 換 ticket |
| 入站事件 | `CALLBACK` frames：text / richText / picture / file / audio / video / 卡片；`SYSTEM` ping、`disconnect` | — | SDK + `inbound.py:9` 型別對映 | `:9-10` 六種訊息型別 + `isInAtList` → `mentioned`；群組 gating 交給 host |
| 出站格式 | 首選回 `sessionWebhook`（markdown/text），有效期見 `sessionWebhookExpiredTime`；失效則走 OpenAPI `robot/oToMessages/batchSend`（單聊）/ `robot/groupMessages/send`（群） | — | 同（sessionWebhook 為主） | `:11-13` 同策略，`:12` 留 5 分鐘安全邊際；`:429` sessionWebhook POST |
| 長度上限與分段 | 文字/markdown 上限 ❓（ark 與 HE 都用 20000 字元） | — | `adapter.py:64` `MAX_MESSAGE_LENGTH=20000` | `:45` `MAX_MESSAGE=20000`、`:953` `chunk::split` |
| 速率限制 | 機器人每分鐘訊息數上限 ❓（常見說法 20 則/分鐘）；超限 errcode 130101 | — | ❓ | `:174` `130101/130102/90018/90002` → `RateLimited`；無本地配額 |
| 重連與重試 | `disconnect` frame 或連線中斷後重連 | — | `adapter.py:65` `RECONNECT_BACKOFF=[2,5,10,30,60]`、`:66-67` 連續 5 次相同錯誤 → 斷路器 300 秒 | 同 backoff（`:47` `BACKOFF=[2,5,10,30,60]`、`:64`）；無斷路器 ❓ |
| 錯誤碼處理 | `{code,message}`（OpenAPI）或 `{errcode,errmsg}`（oapi/webhook） | — | SDK 拋錯 | `:162-187` 兩種格式都解析；`:174` 限流、其餘 `Protocol`；`:187` 非 JSON 交 `classify()` |
| 簽章/驗證 | Stream 模式**沒有 HMAC 簽章**，靠 ticket + TLS；sessionWebhook 自帶 session token | — | 同 | 同；`:257-259` `webhook_ok()` 要求 `sessionWebhook` 必須以設定的 `api_base`/`oapi_base` 開頭且後接 `/`（測試 `:1422`：`http://127.0.0.1:9.evil.com` 與 `https://evil.example` 都被拒） |
| 媒體 | `oapi media/upload` → `media_id` 送 image/file；下載 `robot/messageFiles/download` | — | `adapter.py:132` sessionWebhook 不支援本地檔上傳（需 OpenAPI） | `:13` 本地檔上傳後送；`:14` 附件用 `robot/messageFiles/download` |
| 互動元件 | 互動卡片（需先建卡片模板）與 `card_template_id`；回呼 topic `/v1.0/card/instances/callback` | — | ❓ | `:16-18` AI Card（create → deliver → `card/streaming`）、`:26` 按鈕回呼 → `Callback`；`:44` `CARD_TOPIC`；沒有模板時按鈕退化成編號選項（`:26`） |
| 已知差異 | 釘釘沒有 typing API；表情回應（emotion）是替代品 | — | `adapter.py:126` 用 emotion 模擬 | `:21-22` 進站先用「🤔思考中」emotion、回覆後換「🥳完成」 |

## 三、企業微信（`wecom` 智能機器人 / `wecom_callback` 自建應用）

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | ark |
|---|---|---|---|---|
| 傳輸與端點 | 智能機器人：`wss://openws.work.weixin.qq.com`，`aibot_subscribe` 訂閱、`ping` 心跳；自建應用：`GET/POST` 回呼 URL（XML） | —（無 WeCom 通道） | `wecom/adapter.py:50` `DEFAULT_WS_URL`、`:52-56` `aibot_*` 指令；`callback_adapter.py` | `wecom.rs:5-7` 背景執行緒持有 socket、`ping` 30 秒（`:102`）；`wecom_callback.rs:4-11` XML 回呼 |
| 認證 | 自建應用：`gettoken(corpid, corpsecret)` → `access_token`；機器人：`bot_id` + `secret` + `device_id` | — | 同 | `wecom.rs:4` `aibot_subscribe(bot_id/secret/device_id)`；`wecom_callback.rs:14` `gettoken` 快取，40001/42001 刷新 |
| 入站事件 | 機器人：`aibot_msg_callback`（text/image/mixed/voice/file/video/appmsg/quote）、`aibot_event_callback`（`template_card_event`）；應用：XML 明文或 `Encrypt` | — | `adapter.py:53-59` 指令集合 | `wecom.rs:13-14` 同；群組只有被 @ 才收得到，會自動剝掉開頭 `@Bot`；`wecom_callback.rs:12` 簽章先驗再解密 |
| 出站格式 | 機器人：`aibot_respond_msg`（被動）、`aibot_send_msg`（主動）、`msgtype: stream`；應用：`message/send`（text/markdown/image/voice/video/file） | — | `streaming.py`、`send_queue.py` | `wecom.rs:18-22` 被動優先（群組必須），主動 fallback；`:22` 原生 `stream` 幀；`wecom_callback.rs:14` 五種型別 |
| 長度上限與分段 | 應用圖文訊息 2048 bytes；機器人 markdown ❓（ark 與 HE 都用 4000 字元） | — | `adapter.py:61` `MAX_MESSAGE_LENGTH=4000` | `wecom.rs:46` 4000 字元、`:48` `MAX_STREAM_BYTES=20480`、`:49` 中間幀上限 85；`wecom_callback.rs:36` **2048 bytes**（`:542` `len_unit: Bytes`） |
| 速率限制 | 每對話每分鐘訊息數上限（errcode 846607） | — | `send_queue.py` 對應 | `wecom.rs:23-25` 30 則/分鐘切成「一般池 24 + 控制池 6」（`:62` `ERR_RATE_LIMIT`、`:105` `rate_per_min`），核准提示與串流收尾走控制池 |
| 重連與重試 | 斷線重連；`disconnected_event`（被別人接管）應停止重連 | — | `adapter.py:65` backoff `[2,5,10,30,60]` | `wecom.rs:6` 同 backoff（`:103`）、`:7` `disconnected_event` 停止重連；`:8` 以 `headers.req_id` 對應請求 |
| 錯誤碼處理 | 40001/42001 = token；846607 = 速率；45009 = API 頻率 | — | ❓ | `wecom_callback.rs:14` 40001/42001 刷新 token；`wecom.rs:62` 846607 → 本地配額；其餘交 `classify()` |
| 簽章/驗證 | 應用回呼：`msg_signature = sha1(sort(token, timestamp, nonce, echostr))`；內文 WXBizMsgCrypt（AES-256-CBC，key = base64(EncodingAESKey+"=")，`random16 + len(4) + xml + corpid`） | — | `wecom_crypto.py` | `wecom_callback.rs:59` `sha1(parts.concat())`、`:85-86` `ct_eq` 比對、`:12` corp id 必相符、`:12` 拒絕過期時間戳、`:13` 重送回包只 ACK 一次 |
| 媒體 | `media/upload` → `media_id`；`media/get` 下載；機器人分塊上傳 | — | `media.py` | `wecom.rs:20` `aibot_upload_media_init/chunk/finish`（512 KiB base64 分塊 + md5）；`:16` 媒體 URL 用每則訊息的 `aeskey` 解密（AES-256-CBC、PKCS#7 to 32） |
| 互動元件 | 模板卡片 `template_card` / `button_interaction`；事件 `template_card_event` | — | `adapter.py` 卡片 | `wecom.rs:21` 按鈕 = `button_interaction` 模板卡；`wecom_callback.rs:541` `buttons: false`（自建應用的回呼模式不支援按鈕） |
| 已知差異 | 自建應用的被動回覆必須快速回 `success`（官方為 5 秒 ❓ 未在可讀頁面核對），實際內容要另外主動送 | — | 同 | `wecom_callback.rs:13` 一律立刻回 `success`，之後用主動 API 送；`wecom.rs:18-19` 群組一定要用被動 `aibot_respond_msg`（綁最近一則入站 `req_id`） |

## ark 的選擇與差異

- **三套長連線全部自己寫，不用 SDK。** 飛書 protobuf 幀（`feishu.rs:6-9`）、釘釘 ticket + frame ACK（`dingtalk.rs:4-9`）、WeCom openws（`wecom.rs:5-9`）都是手刻；HE 三者都靠官方 SDK（`lark`、`dingtalk-stream`），OC 只做飛書且靠 `@larksuiteoapi/node-sdk`。代價是協定細節（分片、心跳、`disconnected_event`）要自己維護，好處是零 Python/Node 執行期依賴。
- **飛書同時支援 WS 與 webhook，且兩條路餵同一個佇列**（`feishu.rs:5`）；OC 與 HE 多半二選一。
- **WeCom 有雙實作。** `wecom.rs`（智能機器人 WS）與 `wecom_callback.rs`（自建應用 XML 回呼）並存，且 callback 版支援多應用共用一個 listener（`wecom_callback.rs:16-18`，chat id 變成 `<app>:<user>`）；上游只有 Hermes 兩者都有。
- **WeCom 的 30 則/分鐘被做成顯式雙池配額**（`wecom.rs:23-25`、`:898`），不是被動接 846607 再重試——這是 ark 相對 HE `send_queue.py` 最實質的差異：核准提示永遠送得出去。
- **長度單位不一致是刻意的。** 飛書/釘釘/WeCom 機器人用「字元」（4000/20000/4000），WeCom 自建應用用「bytes」（2048，`wecom_callback.rs:36`、`:542`），因為 WeCom 應用 API 就是以 byte 計。
- **釘釘不做模板就沒有真按鈕。** 沒有 `button_template_id` 時 `caps().buttons=false`（`dingtalk.rs:848`），按鈕退化成「1. 2. 3.」文字；同理沒有 `card_template_id` 就沒有串流（`:851`）。這點 ark 直接反映在能力宣告上，而不是假裝支援。
- **釘釘 typing 是假的。** 用 emotion 回應模擬「思考中/完成」（`dingtalk.rs:21-22`），飛書則直接宣告 `typing:false`（`feishu.rs:1294`）——官方都沒有 typing API。

## 上游實作位置

- OpenClaw：只有 `extensions/feishu/`（`@larksuiteoapi/node-sdk 1.74.0`）；**沒有 DingTalk / WeCom 通道** —— `src/channels/bundled-channel-ids.generated.ts` 的 28 個 id 中不含 `dingtalk`、`wecom`、`weixin`。
- Hermes：`plugins/platforms/feishu/`（5684 行）、`plugins/platforms/dingtalk/`（1061 行，`dingtalk-stream` SDK）、`plugins/platforms/wecom/`（2171 行，含 `callback_adapter.py`、`wecom_crypto.py`、`send_queue.py`）。
- ark：`feishu.rs`（2531 行，另有 `feishu/` 子目錄：`approval.rs`、`comment.rs`、`meeting.rs`、`onboard.rs`、`tools.rs`）、`dingtalk.rs`（1602 行）、`wecom.rs`（1961 行）、`wecom_callback.rs`（1040 行）。

## ark 的測試覆蓋（全部離線，無真實長連線）

- 飛書：`:1628` 七種訊息 + mention + thread + 卡片回呼；`:1682` 加解密已知答案；`:1718`/`:1992` webhook 明文與加密簽章；`:1751` 名稱快取；`:1803` 核准卡一次性。
- 釘釘：`:1216` 每幀 ACK、ping 回聲、斷線重連；`:1317` 卡片回呼走 Stream；`:1372` sessionWebhook → OpenAPI fallback；`:1422` 外站 webhook 被拒；`:1479` AI Card 三段生命週期。
- WeCom：`:1576` 被動回覆後主動送；`:1634` errcode 分類；`:1662` 本地限流回 `retry_after`；`:1710` 分塊上傳；`:1754` 原生串流 seed/中間/收尾。
- WeCom callback：`wecom_callback.rs` 的測試涵蓋 SHA1 簽章、AES 解密、重送回包與多應用路由。

## 未驗證清單

- 飛書：沒有企業自建應用，`tenant_access_token` 從未真的換過；WS `Frame` 用假 server 模擬，真實 protobuf 分片（`sum`/`seq`）行為未驗。
- 飛書：`MAX_SKEW_SECS=3600`（`feishu.rs:55`）的時間窗是否與官方一致 ❓；卡片 `card.action.trigger` 的 payload 變體未全覆蓋。
- 釘釘：沒有 AppKey/AppSecret，`gateway/connections/open` 的 ticket 流程從未對釘釘跑過；20 則/分鐘的實際限流未觀察。
- 釘釘：AI Card（`card_template_id`）與按鈕模板（`button_template_id`）都需要先在釘釘後台建模板，ark 從未用真實模板 ID 跑過。
- WeCom：沒有 `bot_id`/`secret`，`aibot_subscribe` 未實跑；30 則/分鐘的雙池配額只用假時鐘驗證（`wecom.rs:1662`）。
- WeCom callback：`corpid`、`EncodingAESKey` 都是測試值，WXBizMsgCrypt 的真實互通（含 corp id 不符的拒絕路徑）未驗。
