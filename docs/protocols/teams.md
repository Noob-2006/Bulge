# Microsoft Teams / Bot Framework：官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ SE Agent

> **驗證狀態：SE Agent 未對真實 Teams 租戶驗證。** 沒有 Azure Bot 註冊、沒有 app id / secret / tenant id，SE Agent 行為僅由原始碼與 `FakeServer` 測試佐證。JWT 驗證、FileConsentCard 上傳、原生 `streaminfo` 串流這三項尤其沒有對真實 Bot Connector 跑過。
> 比較來源：`learn.microsoft.com/microsoftteams/platform/bots/how-to/conversations/conversation-messages`（已讀：訊息大小上限 100 KB / 建議 ≤80 KB / 超限回 413 `MessageSizeTooBig`）、`azure/bot-service/rest-api/bot-framework-rest-connector-authentication`（已讀：OpenID metadata、`issuer=https://api.botframework.com`、`RS256`、client-credentials 換 token）＋ 上游原始碼。
> 圖例：❓ = 未確認；`—` = 該專案無此通道。

## 對照表

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | opencode | SE Agent |
|---|---|---|---|---|---|
| 傳輸與端點 | 入站：Bot Connector 對 bot 的 HTTPS 端點 POST Activity（慣例 `/api/messages`）；出站：`POST {serviceUrl}v3/conversations/{conversationId}/activities`、回覆 `…/activities/{activityId}`、更新 `PUT …/activities/{id}` | express 5.3 webhook，`msteams/src/accounts.ts:271` 預設 `/api/messages`；SDK 為 `@microsoft/teams.apps 2.1.0`（`package.json`） | aiohttp 內建 server，`teams/adapter.py:71` port 3978、`:76` `/api/messages`、`:78` 預設 serviceUrl `smba.trafficmanager.net/teams/`；SDK `microsoft-teams-apps` | —（無此通道） | 內建 HTTP server（`msteams.rs:918`），`DEFAULT_SERVICE_URL` 同官方（`:39`），路徑可設 |
| 認證 | 入站：`Authorization: Bearer <JWT>`，RS256，金鑰由 OpenID metadata 的 `jwks_uri` 取得；驗 `iss`(api.botframework.com)、`aud`(app id)、`exp/nbf`。出站：client-credentials，`POST https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token`，`scope=https://api.botframework.com/.default` | 交給 `@microsoft/teams.apps` 的 app 框架處理 | SDK 處理（`TEAMS_APP_ID`/`TEAMS_APP_PASSWORD`/tenant） | — | 自己實作：`msteams.rs:5-9` JWKS 快取、未知 `kid` 重抓、`iss`/`aud`/`exp`/`nbf`（300 秒容差，`:44` `SKEW`）、金鑰 `endorsements`、`serviceUrl` claim（`:938-945`）；`:571` token 快取 |
| 入站事件 | `Activity` 物件：`type=message / messageUpdate / messageDelete / conversationUpdate / messageReaction / invoke / typing`；`text`、`attachments`、`entities`、`channelData`、`conversation.id`、`serviceUrl` | `msteams/src/monitor-handler.ts`、`inbound.ts` | `teams/adapter.py:321` `_CHAT_TYPES`（personal→dm、groupChat、channel）、`:423` AdaptiveCardInvoke | — | `:12-14` 接受 message、edit(`messageUpdate`)、@mention、附件、回覆、channel thread、`Action.Submit`／`Action.Execute`（invoke）；`:22` `messageReaction` |
| 出站格式 | Activity JSON（`{type:"message", text, attachments, entities}`）；Markdown 僅支援子集；卡片用 attachment `contentType: application/vnd.microsoft.card.adaptive` | `msteams/src/send.ts`、`presentation.ts` | `teams/adapter.py:604` `_send_card`（AdaptiveCard 物件）、`format_message` | — | `:13-14` 同一 connector 路徑；`:679` 群組拒絕 threaded reply 時退回普通送出 |
| 長度上限與分段 | **訊息大小上限 100 KB**（含 @mention 與 reactions，UTF-16 計），官方建議 ≤80 KB；超限 `413 MessageSizeTooBig` | `msteams/src/outbound-config.ts:5` 4000 字元、`messenger.ts:113` `Math.min(limit, 4000)` | `teams/adapter.py:335` `_truncate`、`:356` `splits_long_messages` | — | `:42` `MAX_MESSAGE=4000`（字元），`:1140` `chunk::split`；SE Agent 用 4000 而非 100 KB，等於自願取保守值 |
| 速率限制 | Connector 會節流，超限回 `429` 並帶 `Retry-After`（各流量配額見官方 throttling 說明 ❓ 具體 mps） | SDK 內建重試 | ❓（未見本地限流） | — | 無本地 token bucket；純靠 `Retry-After`（`:666-668`），超過 `max_wait` 直接放棄 |
| 重連與重試 | 無長連線；bot 端點需在時限內回應（官方建議快速回 200，之後用 proactive 送）❓ 具體逾時秒數未確認 | SDK 重試 | `per_request_timeout` 15 秒（`:218`） | — | `:571` `Retry(500ms, 3 次, 上限 60s)`；`:644-676` 指數退避、429 依 `Retry-After`、401 先刷新 token 再試一次（`:653-657`） |
| 錯誤碼處理 | 401/403 = token 無效；413 `MessageSizeTooBig`；429 = 節流；5xx = 服務端 | 由 SDK 拋出 | ❓ | — | `:864-871` `teams_error()` 解析 `error.code/message` 後交 `classify()`：401/403→Auth、413→Protocol、429→RateLimited、5xx→Network |
| 簽章/驗證 | 沒有 HMAC 簽章，只有 JWT；`serviceUrl` 必須在白名單（防 SSRF / token 洩漏） | SDK | `teams/adapter.py:81` `_ALLOWED_TEAMS_SERVICE_HOSTS` 只允許 `smba.trafficmanager.net` 與 GCC High | — | `:938-945` 比對 JWT 中的 `serviceurl` claim 與 activity 的 `serviceUrl`；`:11` 另有金鑰 `endorsements` 檢查 |
| 媒體 | `attachments[]`（`contentType`、`contentUrl`、`name`）；個人聊天上傳檔案要走 FileConsentCard（`fileConsent/invoke` → PUT 到 uploadUrl → 回 file info card） | `msteams/src/attachments.ts`、`pending-uploads.ts` | `teams/adapter.py:582` 以 content-type 推副檔名 | — | `:17-18` 個人聊天非小圖一律 FileConsentCard；URL 參照或本地檔轉 data URI |
| 互動元件 | Adaptive Cards：`Action.Submit`（回 message + `value`）、`Action.Execute`（`invoke adaptiveCard/action`）、task module、dialogs | `approval-card.ts`、`adaptive-card-submit.ts` | `:423-424` `AdaptiveCardInvokeActivity` | — | `:15` 兩種都支援；`:1083-1090` 個人聊天原生串流（typing + `streaminfo`，`streamType: final` 收尾），其他場景退回 edit-in-place |
| 已知差異 | 需 Azure Bot 註冊 + Teams app manifest 上架；三種 scope（personal / groupChat / channel）能力不同；channel 內回覆必須是 thread | 用新版 Teams AI library（`@microsoft/teams.apps`），並非舊 `botbuilder` | 用 `microsoft-teams-apps` Python SDK，授權/活動處理大部分交給 SDK | 無任何聊天通道（`packages/` 無 channel 模組，`README.md:20` 自述為 coding agent） | 不用 SDK，自己寫 JWT + connector；`caps()` 宣告 `reactions: 0`（`:1066`）與 `threads: true`（`:1065`），即使官方有 `messageReaction` 事件 |

### opencode 的證據（無此通道）

`$HOME/.cache/seagent-build/r5-e/opencode` 的 `packages/` 為 `ai / app / cli / client / codemod / console / core / desktop / effect-drizzle-sqlite / function / gui-plugins / httpapi-codegen / identity / latex / merman / patchmark / plugin / plugin-browser / posts / process-daemon / protocol / schema / script / sdk / server / session-ui / simulation / stats / stories / theme / tui / ui / util / web`，沒有 bot / webhook / channel 模組；`grep -rIl -iE "webhook|bot framework|messaging api" packages/*/src` 只命中 `elevenlabs-transcription.ts`（音訊轉錄）與一個 UI stories 檔，`grep -rIl -iE "msteams|botbuilder|bot framework"` 為 0 命中。故本表 opencode 欄一律 `—`。

## SE Agent 的選擇與差異

- **不用 SDK，自己驗 JWT。** 這是 SE Agent 與 OC/HE 最大的分歧：OC 交給 `@microsoft/teams.apps`、HE 交給 `microsoft-teams-apps`，SE Agent 自己抓 OpenID metadata、快取 JWKS、遇未知 `kid` 重抓（`msteams.rs:5-9`、`:145-186`）。好處是零 Node/Python 依賴，代價是 endorsement 與 claim 檢查得自己維護。
- **`serviceUrl` 雙重檢查。** 不只白名單主機（HE 的做法，`teams/adapter.py:81`），SE Agent 還比對 JWT 內的 `serviceurl` claim 與 activity 的 `serviceUrl`（`:938-945`），把「token 被拿去別處用」的路徑封掉。
- **4000 字元 vs 官方 100 KB。** SE Agent 的 `MAX_MESSAGE=4000`（`:42`）遠低於官方上限，等於自願切得細；OC 也是 4000（`outbound-config.ts:5`），HE 則用 `truncate_message` 的預設。三家都沒用到 100 KB 的額度。
- **重試參數固定。** `Retry(500ms, 3, 60s)`（`:571`）寫死，`Retry-After` 超過 60 秒就放棄；401 只刷新 token 重試一次（`:653-657`），不無限循環。
- **reactions 宣告為 0。** `caps()` 寫 `reactions: 0`（`:1066`），但入站仍會收 `messageReaction` 事件（`:20`）；也就是「讀得到、送不出」。
- **串流只在個人聊天。** `stream_begin` 要求 `native_streaming` 且 `is_personal` 且無 thread（`:1083-1085`），其餘場景一律 edit-in-place；這與官方 `streaminfo` 的可用範圍一致。
- **群組 thread 的 fallback。** 群組回覆被拒（Protocol 錯誤）時自動改送非 thread 訊息（`:679`），避免整則訊息失敗。

## 上游實作位置

- OpenClaw：`extensions/msteams/`（`@microsoft/teams.apps 2.1.0` + `express 5.3.0`）；另有 `extensions/teams-meetings/` 處理會議。
- Hermes：`plugins/platforms/teams/adapter.py`（1024 行）＋ `summary_writer.py`；SDK 為 `microsoft-teams-apps`。
- SE Agent：`crates/seagent-channel/src/msteams.rs`（1753 行，含 `#[cfg(test)]`），JWT/JWKS helper 與 Google Chat 共用（`:25`）。
- SE Agent 共用：`chunk.rs`（分段）、`http.rs`（`classify`）、`deliver.rs`（上層重試）。

## SE Agent 的測試覆蓋（全部離線）

- `:1401` `inbound_requires_a_valid_bot_framework_jwt`：自簽 RS256 金鑰、`iss`/`aud`/`exp`/`kid` 各項拒絕路徑。
- `:1438` `parses_dm_group_channel_threads_mentions_edits_cards_and_attachments`：三種 scope + thread + @mention + edit + 卡片 + 附件。
- `:1503` `send_shapes_replies_cards_media_and_actions`：回覆、卡片、媒體、invoke 動作。
- `:1552` `errors_map_and_retry`：429 `Retry-After`、5xx 退避、401 刷新。
- `:1616` `file_consent_flow_in_personal_chats`：FileConsentCard 三段流程。
- `:1660` `proactive_conversations_reactions_and_streaming`：持久化 serviceUrl、`user:<id>` 開個人對話、`streaminfo` 串流。
- `:1707` `sso_token_exchange_verify_state_and_signin_card`：SSO 交換與 OAuthCard。

## 未驗證清單

- 沒有 Azure Bot 註冊：JWT 是測試金鑰自簽，從未對 `login.botframework.com/v1/.well-known/keys` 實抓。
- `serviceUrl` claim 比對只在測試向量上驗過；真實 Teams 是否每次都帶該 claim ❓。
- 100 KB 訊息上限：SE Agent 用 4000 字元，實務上碰不到 413，`MessageSizeTooBig` 的處理路徑等於沒被走過。
- Teams app manifest 上架、channel scope 的權限申請、`@mention` 於 channel 的必要格式皆未實跑。
- FileConsentCard 的 `PUT` 到 SharePoint uploadUrl 從未執行。
- 各 scope 的節流配額（每秒/每租戶）未知，`Retry-After` 的實際數值範圍未觀察。
