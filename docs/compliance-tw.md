# SE Agent 台灣法遵對照（研究日 2026-11-02）

> 本文件由網路研究整理，未經律師審閱，不構成法律意見。【拘束】現行有效；【待施行】已公布未生效或待子法；【指引】無強制力；【未證實】未能以一手來源確認。

## 1. 人工智慧基本法
- 2025-12-23 三讀，**2026-01-14 公布（華總一義字第 11500001671 號）並施行**，全文 20 條，主管機關國科會。來源：總統府公報 7837 號 https://www.president.gov.tw/File/Doc/d961e5b2-f8c4-424b-8993-4a52702ae8c7
- 第 4 條七原則：永續福祉、人類自主（允許人類監督）、隱私與資料治理（最小化）、資安與安全、透明可解釋（適當揭露或標記）、公平不歧視、問責。
- 第 5 條：經認定為高風險之 AI 應標示注意事項或警語；數發部提供評估驗證工具。
- 第 14 條：privacy by default / by design。第 16 條：數發部風險分類框架，各目的事業主管機關訂管理規範。第 17 條：高風險責任、救濟、保險另定（研發階段除外）。第 18 條：兩年內（約 2028-01）完成法規調整。第 19 條：政府使用 AI 應風險評估。
- 判斷：義務主語多為政府，**對民間開發者尚無附罰則的直接義務**【拘束：政府／待施行：民間】。
- 數發部《人工智慧風險分類框架》v1.0（2026-07-07）https://www-api.moda.gov.tw/File/Get/moda/zh-tw/UieEfux5Yv0iJuR ：3 大類 20 子類；與 SE Agent 相關 A1 安全漏洞、A5 隱私、A8 錯誤訊息、B1 過度依賴、B3 違法內容、B5 網攻、**B6 AI 自主代理授權外行為**【指引】。

## 2. 個人資料保護法（https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=I0050021）
- 2025-11-11 公布大修（第 12、18、21 條修正；增 20-1、21-1～21-5、51-1；刪 27），**施行日由行政院另定（未定）**。
- 現行有效：第 51 條個人或家庭活動除外；第 8、9 條告知義務（含間接蒐集）；第 19、20 條特定目的與合法事由；第 3、11 條當事人權利；第 27 條安全措施；第 12 條事故通知當事人；第 21 條跨境傳輸原則允許、例外限制（產業限制令另查【未證實】）。
- 新法施行後：事故須通報個資會、安全維護辦法由個資會訂、罰鍰上限 1,500 萬、國際傳輸限制權歸個資會【待施行】。
- 法遵主體主要是**部署 SE Agent 的使用者**；SE Agent 應提供讓其合規的功能。

## 3. 資通安全管理法
- 2025-09-24 修正公布、2025-12-01 施行，主管機關數發部。只適用公務機關與特定非公務機關（關鍵基礎設施等）。**對 SE Agent 不直接適用**，被上述機關採用時間接適用。
- 行政院 2025-02 禁止公務機關使用 DeepSeek（新聞報導，函文【未證實】）。

## 4. 其他
- 數發部 AIEC 評測十項：安全、可解釋、彈性、公平、準確、透明、當責、可靠、隱私、資安【指引】。
- 行政院及所屬機關使用生成式 AI 參考指引（2023-08-31）：機密文書禁用、不得揭露未公開公務資訊與個資、結果須人工判斷【指引：公部門】。
- 詐欺犯罪危害防制條例：義務主體為網路廣告平臺業者，SE Agent 不直接適用。
- 一般聊天機器人輸出目前無強制 AI 標示義務（廣告、選舉另有規定【未證實】）。

## 5. 平台條款（契約）
- WhatsApp Business Solution Terms：2026-01-15 起禁止以 Business API 提供通用型 AI 助理（報導，原文【未證實】）。
- Telegram Bot Developer ToS：每個 bot 須有隱私權政策、資料最小化 https://telegram.org/tos/bot-developers
- LINE User Data Policy / Developers Agreement https://developers.line.biz/en/terms-and-policies/ 【細節未證實】

## 6. SE Agent 合規檢查清單

| # | 要求 | 依據 | SE Agent 實作 | 優先 | 狀態 |
|---|---|---|---|---|---|
| 1 | 對頻道使用者告知 | 個資法 8、9 條 | 每頻道首次互動告知訊息、隱私政策 URL；告知範本 | P0 | ✅ `privacy_notice`（每位新使用者首次回覆前送出）；範例見 config-example.toml |
| 2 | 平台隱私政策 | Telegram ToS、LINE | `privacy_policy_url` 設定，缺少時啟動警告 | P0 | ✅ 對陌生人開放的 channel 未設 `privacy_notice` 時啟動警告 |
| 3 | 跨境傳輸透明可控 | 個資法 21 條、基本法 4 條 | provider 標示資料目的國；allow/deny；敏感 session 只走本地；送出前遮罩 | P0 | 部分（outbound 閘門已遮罩秘密） |
| 4 | 公部門禁用特定產品 | 行政院禁令、資安法 | `government` 模式：停用 DeepSeek 與中國境內端點 | P1 | ✅ `[compliance] profile = "government"`：拒絕中國境內 provider 設定、主機加入 egress_deny |
| 5 | 資料安全維護 | 個資法 27 條／新 20-1 條 | 檔案 0600、秘密 vault、log 加密選項 | P0 | 部分（0600、vault 已有） |
| 6 | 最小化與保存期限 | 基本法 4、14 條 | log／記憶保存天數自動清除；預設最小化 | P0 | ✅ `retention_days`（daemon 每小時清除）；長期記憶需人工檢視 |
| 7 | 當事人權利 | 個資法 3、11 條 | `seagent data export/delete --user`；頻道 `/forget` | P1 | ✅ `seagent data export|delete <channel> <sender>`（session、路由、配對、附件）；頻道內 `/forget` 待做 |
| 8 | 事故處理 | 個資法 12 條 | 稽核紀錄、`seagent incident report`、SOP | P1 | 部分（事件 log、閘門紀錄已有） |
| 9 | 人類監督、Agent 授權外行為 | 基本法 4 條、框架 B6 | sudo／外送閘門、每頻道工具 allowlist、步數與費用上限、kill switch、子代理深度限制 | P0 | 大部分已有（閘門、預算、/stop） |
| 10 | AI 產出揭露 | 基本法 4 條第 5 款 | 頻道回覆可設 AI 標示，預設開 | P1 | ✅ `ai_label`；`profile = "government"` 時預設開（「— 本訊息由 AI 生成」，`ai_label = ""` 關閉），其他情況需設定 |
| 11 | 違法內容與網攻防範 | 框架 B3、B5 | 輸出審核 hook、危險指令規則、AUP | P2 | 部分（hooks、gate 規則） |
| 12 | WhatsApp 用途限制 | WhatsApp Terms | 文件與啟動警示 | P1 | ✅ whatsapp_cloud 啟動警示 |
| 13 | 公部門機密 | 行政院指引、基本法 19 條 | 機密 session 禁止外送 | P2 | 待做 |
| 14 | 風險自評 | 數發部框架、AIEC | `docs/risk-assessment.md` 逐子類對應 | P2 | ✅ 20 子類逐項對照 |
| 15 | 追蹤待施行法規 | 個資法施行日、子法 | 本文件每季更新 | P2 | 持續 |

## 7. 本輪（round 5 F 段）新增設計的合規影響

F 段做的是「接別人的生態、送資料出去」，這幾項直接碰到跨境傳輸、最小化與人類監督，補列如下。

| # | 要求 | 依據 | SE Agent 實作 | 優先 | 狀態 |
|---|---|---|---|---|---|
| 16 | **追蹤資料出境要揭露、可關、可最小化** | 個資法 21 條（跨境）、8/9 條（告知）、基本法 4 條（隱私與資料治理） | `[telemetry]` 預設關閉；開啟後只送三種**無內容**事件（`gateway_health`、`gateway_diagnostic`、`cron_execution`），每個字串都先遮罩（秘密、email、UUID、電話）並限長 500；`seagent telemetry status` 顯示 endpoint 與 header 名稱（值不顯示）。指向 LangSmith／任何 SaaS collector 等於出境，應在隱私政策中列為「委外處理者」 | P0 | ✅（本輪補上 LangSmith profile；文件 `docs/ecosystem/langsmith.md`） |
| 17 | **代理人不得做授權外行為（B6）** | 數發部框架 B6、基本法 4 條人類自主 | 流程（`graph-flow`）與 `lobster` 在執行前宣告完整 `Effect`，由閘門一次判斷；流程內部的 `gate` 節點才會問人；每個 superstep 都有 checkpoint，可從任一舊點分支重跑（可回復 → 不需要事先詢問，見 GAPS 第 0 段） | P0 | ✅（本輪新增，`docs/ecosystem/graph-flows.md` §7） |
| 18 | **第三方程式碼的來源與能力** | 基本法 4 條資安、框架 A1 | OpenClaw／Hermes 外掛匯入後仍受 `[plugins.<id>] trust` 與能力核准（`seagent security plugins accept`）管制；`hermes_shim.py`／`openclaw_shim.mjs` 在**獨立行程**內執行原外掛，hook 失敗一律回 allow 並記 stderr（不阻塞 agent、也不假冒授權）；外掛需要的金鑰以 `{{secret:NAME}}` 參照，不寫進 config | P0 | 🚧（能力核准與 trust 已有；簽章與版本鎖定屬 A13，未做） |
| 19 | **流程狀態的保存期限與當事人權利** | 個資法 3、11 條、27 條 | 流程 checkpoint 存於 `<data>/surfaces/graph/threads/<thread>/`，只含流程作者定義的狀態（建議不要放個資）；`seagent data export/delete` 尚未涵蓋此目錄 | P1 | 🚧（待納入 `seagent data` 與 `retention_days`） |
| 20 | **對外 agent 互通的身分與界線** | 基本法 4 條問責、框架 B5 | A2A 用 bearer（app token 或 peer token）＋可選 HMAC 推播簽章；MCP 對外 server 走同一組閘門；ACP 的寫入／執行請求在 `approve-reads` 下會問人，無人可答時拒絕 | P1 | ✅（既有；本輪文件化） |
| 21 | **告知「這是 AI」與「這是代理人」** | 基本法 4 條第 5 款 | 同第 10 列；與外部 agent 互通時，A2A agent card 的 `name`/`description` 應寫明是 AI agent | P2 | 🚧（`ai_label` 已有；agent card 文案靠使用者填） |

### 7-1 風險自評要補的三句話

1. 開啟 `[telemetry]` 就是**資料出境**：內容已最小化與遮罩，但「什麼時候送、送到哪」必須在隱私政策揭露，且預設關閉。
2. 外掛／技能是**第三方程式碼**：SE Agent 的閘門管的是它對外宣稱的 hook/tool/command，不是它行程內部的行為；不可信來源請用 `trust = "untrusted"`。
3. 流程的 checkpoint 是**新的資料存放點**：目前不在 `seagent data export/delete` 與保存期限之內，這一項要在下一輪補上（第 19 列）。
