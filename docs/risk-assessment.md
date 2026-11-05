# SE Agent 風險自評（依數發部《人工智慧風險分類框架》v1.0）

框架：數位發展部《人工智慧風險分類框架》v1.0（中華民國 115 年 7 月 7 日，依《人工智慧基本法》第 16 條訂定），表 1「AI 風險類型表」3 大類 20 子類。來源：https://www-api.moda.gov.tw/File/Get/moda/zh-tw/UieEfux5Yv0iJuR
（子類名稱由 PDF 抽取後重組，標點以原檔為準。）

**定位**：SE Agent 是自架的 agent 執行環境，不訓練模型、不提供模型。
- **開發者**（SE Agent）提供控制機制。
- **部署者**（安裝 SE Agent 的人或組織）決定接哪個模型、開放給誰、做什麼用途。
- 下表的「責任」欄標示主要由誰負責。

評等：
- **高**：直接相關，已實作控制
- **中**：部分相關，或有控制但需部署者設定
- **低**：主要屬於模型或社會層面，SE Agent 無法實質控制

## A：AI 系統本身之技術設計缺陷

| 代碼 | 子類 | 相關 | SE Agent 的控制措施 | 責任 | 殘餘風險／部署者應做 |
|---|---|---|---|---|---|
| A1 | AI 系統的安全漏洞與攻擊 | 高 | **權限與閘門**：四級風險分類（tier 0–3，`seagent_security::risk`）＋不可覆寫的底線（tier 3 一律詢問，任何模式關不掉）；tier 0/1 靠 VM 與快照直接放行、只記錄；提權與外送兩道閘門；`NoNewPrivileges`；工具輸出與 MCP 描述的 prompt injection 掃描；untrusted MCP 需核准。**不宣稱「模型無法繞過閘門」**：閘門擋的是動作（依工具宣告的 effects 與指令文字判定），模型仍可能改用其他工具或把動作拆小；這是分層防線與稽核紀錄要處理的殘餘風險。<br>**對外介面**：webhook／channel 驗簽章（常數時間比對）；app token、per-peer A2A token；裝置 Ed25519 簽章＋配對。<br>**本機防護**：CSP、Origin 檢查、0600 檔案權限；HTTP 伺服器有大小與時間限制，防慢速連線。 | 開發者 | 保持更新；不要把 App Server 綁到公網而不經反向代理與 TLS。 |
| A2 | 缺乏透明性或可解釋性 | 中 | 每個 session 有完整、不可省略的事件紀錄（工具呼叫、參數、結果、閘門判定、成本）；ACP／Web UI 即時顯示工具與 diff；`seagent session show`。 | 雙方 | 模型本身的推理仍是黑箱；需要時保存紀錄供稽核。 |
| A3 | AI 行為偏離人類意圖與社會價值 | 中 | goal／budget／max_steps 上限；卡住偵測；`/stop` 與中斷；hooks 可以阻擋或改寫工具呼叫。 | 雙方 | 撰寫明確的 identity 與指示；用 hooks 加上組織政策。 |
| A4 | AI 具有危險的能力 | 中 | 能力受工具集限制，可停用工具（`[tools] disabled`）；shell 經閘門；子 agent 有深度與預算限制；node 指令由裝置端政策決定。 | 雙方 | 只開需要的工具與 channel；node 的 `system.run` 預設為 `deny`。 |
| A5 | 影響隱私與違反個人資料保護法規 | 高 | 外送閘門擋下秘密與個資；`privacy_notice`；`retention_days`；`seagent data export/delete`；DM 預設拒絕陌生人；秘密放 vault，不進紀錄。 | 部署者為主 | 依個資法告知、限定目的；評估跨境傳輸（見 compliance-tw.md）。 |
| A6 | 侵害智慧財產權疑慮 | 低 | 無特定控制（SE Agent 不訓練模型）；web_fetch 會標示來源 URL。 | 部署者 | 注意生成內容與引用來源的授權。 |
| A7 | 不公平的歧視或偏見 | 低 | 屬於模型特性；可切換或多模型備援。 | 部署者 | 高影響決策不要只依賴模型。 |
| A8 | 錯誤或誤導訊息 | 中 | `ai_label` 標示 AI 生成；工具結果與來源可追溯；回覆可附註停止原因（預算、步數）。 | 雙方 | 在對外 channel 開啟 `ai_label`，並提醒使用者查證。 |

## B：部署後操作及人機互動問題

| 代碼 | 子類 | 相關 | SE Agent 的控制措施 | 責任 | 殘餘風險／部署者應做 |
|---|---|---|---|---|---|
| B1 | 過度依賴與不安全使用 | 中 | 閘門在高影響動作時要求人確認；ask_user 讓 agent 主動提問；不確定時要求說明假設。 | 部署者 | 醫療、法律、財務情境需人工複核。 |
| B2 | 喪失人類自主性 | 中 | 只有 tier 2/3 會停下來問人（tier 0/1 直接執行）；未回應時改走安全替代方案並把待辦列進摘要（不是整個任務失敗）；任務信封可一次核准範圍與期限；永遠可以設為 `deny`；所有自動化（cron、goal、channel）都能 `/stop`、`seagent daemon stop`；核准紀錄可追溯。 | 部署者 | 決定哪些工作可以全自動。 |
| B3 | 生成違法內容 | 中 | hooks（pre_tool／post_tool）可接內容審核；channel 可限制使用者與群組。 | 部署者 | 對公眾開放時加上輸出審核 hook 與使用規範（AUP）。 |
| B4 | 詐欺與深偽技術濫用 | 低 | SE Agent 不內建語音或影像合成；對外訊息都經 channel 身分送出，且可加 AI 標示。 | 部署者 | 不要用 SE Agent 冒充他人。 |
| B5 | 用於網路攻擊 | 中 | shell 經閘門（提權、外送）；hooks 可封鎖特定指令；egress_deny 清單。 | 雙方 | 共用主機上不要開放 `group_policy = "open"` 加上 shell 工具。 |
| B6 | AI 自主代理之授權外行為 | 高 | 四級風險分類＋tier 3 硬底線（不受 yolo／mode=off／allow-always 影響）＋任務信封（範圍、期限、上限）＋授權到期（`approvals.grant_ttl_days`）＋不可信內容進入上下文後 tier 2/3 降權（A7）；untrusted MCP；成本與步數上限；子 agent 深度限制；A2A 對方訊息標記為「非操作者指令」；node 指令由裝置端白名單決定；專案設定未受信任時不載入 hooks／MCP／channels；kill switch：`/stop`、`seagent daemon stop`、systemd stop。 | 開發者 | 定期檢視 session 紀錄與閘門紀錄。 |

## C：社會結構與環境衝擊

| 代碼 | 子類 | 相關 | SE Agent 的作法 |
|---|---|---|---|
| C1 | 企業及國家間競爭秩序失衡 | 低 | 不適用於單一工具；SE Agent 有完整的自動測試與實測紀錄後才發佈。 |
| C2 | 權力集中與利益分配不公平 | 低 | 自架、開源（MIT）、可接任何供應商或本地模型，降低單一廠商依賴。 |
| C3 | 不平等加劇、就業品質下降 | 低 | 屬於部署者的組織決策。 |
| C4 | 人類在經濟與文化上之創作價值受損 | 低 | 屬於部署者的用途決策。 |
| C5 | 環境傷害 | 低 | 省 token 設計（漸進揭露、快取、壓縮）降低用量；可改用小模型做輔助工作。 |
| C6 | 認知作戰與資訊主權 | 中 | `profile = "government"` 拒絕中國境內的模型與主機；所有資料留在部署者自己的機器。 |

## 追蹤

- 數發部會定期增修框架（第 3.2.3 點）；各目的事業主管機關依基本法第 16 條訂定的管理規範（期限約 2028-01）公布後，要更新本表。
- 法規面的檢查清單見 [compliance-tw.md](compliance-tw.md)。

---

# 威脅模型：假設、分層與殘餘風險（第 5 輪重寫）

## 1. 對手與假設

| # | 假設 | 為什麼 |
|---|---|---|
| T1 | 模型本身可能被投毒（間接注入、供應鏈改寫系統提示） | Amazon Q 擴充被合併清除提示、GitHub MCP 的 issue 注入 |
| T2 | 技能、外掛、MCP server 都可能是惡意的 | ClawHub 上數百個惡意技能、MCP tool poisoning |
| T3 | 工具輸出（網頁、issue、email）是資料，不是指令 | toxic agent flow |
| T4 | agent 執行環境裡的憑證已經外洩 | 只要 agent 能讀到，就當它會送出去 |
| T5 | 使用者會按「允許」按到手軟 | 核准疲勞 → 防線必須預設不問，只問真正不可逆的 |

**因此：** 任何只靠「模型判斷」的防線都不算防線；每一類事故至少兩層，且至少一層是資料驅動（政策檔／effects 分類器／網路層／OS 隔離），不經過模型。

## 2. 四級風險與處理方式

由 `crates/seagent-security/src/risk.rs` 的 `assess()` 分類，輸入只有工具宣告的 effects（exec 指令、寫入路徑、目的地主機、外送內容、金額），輸入不含模型輸出。

| 等級 | 例子 | 處理 | 實作 |
|---|---|---|---|
| 0 sandboxed | 工作區讀寫、跑測試、裝依賴、刪 VM 內暫存 | 直接放行、只記錄 | `Preset::disposition` |
| 1 recoverable | 允許清單主機、自己的分支 commit、唯讀抓取 | 放行＋稽核 | 同上（standard 為 `RunAndAudit`） |
| 2 impactful | 推送共用分支、新主機的**外送**、寄信、花錢 | 任務信封內放行；否則詢問 | `envelope::Envelope::covers` |
| 3 irreversible | 刪正式資料／備份、雲端刪除、force push、外送秘密、改權限、轉帳 | **一律詢問**；無人時進佇列並改走替代方案 | `risk::destructive_command`、`secgate` 的 hard floor |

`[approvals] preset = "relaxed" | "standard" | "strict"` 只調整 tier 1/2 的問法；tier 3 與公網暴露的雙層防護不受任何 preset 影響。

## 3. 任務信封與授權期限

- 長任務（排程、goal、channel 機器人）開工前用 `envelope::create` 一次核准：可寫路徑 glob、可連主機、可用指令前綴、花費上限、時限（最長 30 天）。
- 信封**永遠不能**授權 tier 3（`max_tier` 建立時就被夾在 2 以下）。
- `allow always` 授權到期（`approvals.grant_ttl_days`，預設 7 天）；`ap::grants()` 會濾掉過期的。沒有永久的全域放行。
- 卡住只卡那一條：需要人核准的呼叫進 `approvals::defer` 佇列（`seagent approvals queue`），agent 先把可回復的部分做完並在摘要標記；owner 之後 `seagent approvals queue allow <id>` 就放行那一個呼叫。

- 先預覽、再批次核准（gen2-409）：`seagent approvals queue preview` 把同工具＋同等級＋同理由的待核准呼叫合成一組並列出各自影響，`seagent approvals queue allow|deny --group N` 一次回答整組；**等級 3 永不批次放行**，必須逐筆。
- 依信任等級分流（gen2-412）：`[approvals] trust_presets = { owner = "…", channel = "…", stranger = "…" }`。owner＝CLI／TUI／排程或 `approvals.forward.owners` 裡的聊天帳號；stranger＝webhook、email 等不可信入站通道與機器 API；其餘聊天參與者是 channel。未設定時 owner／channel 用 `preset`、stranger 預設 `strict`。
- 核准疲勞監測（gen2-413）：每次真的問人都記一筆（`<data>/approvals/asks.jsonl`：工具、閘門、等級、結果、等待毫秒，不含輸入）。`seagent doctor` 的 `approval load` 與 `seagent approvals status` 顯示近 7 天每日詢問數、拒絕率、逾時數、平均等待；超過 `approvals.fatigue_daily_asks`（預設 30）時警告，並點名「幾乎每次都被允許」的理由，建議改成預先授權。

## 3.1 新防線的設計審查準則（GAPS-next 0-3，gen2-422）

新增或預設開啟任何一道防線之前，設計審查必須寫下兩個答案，寫在 PR 說明或該防線的模組註解：

1. **它會讓長時間無人看管的任務多停幾次？** 估計一個典型的夜間任務（排程、goal、channel 機器人）會因為這道防線多出幾次詢問或阻擋；答案不能是「不知道」。
2. **有沒有「隔離或回復」的替代做法，能達到同樣的安全效果而不需要詢問？** 例如改在 VM／bwrap 內執行、改成快照或 git 分支可回復、改成任務信封預先授權、改成降權（只停用等級 2／3）而不是停擺。

答不出來的防線**不准預設開啟**；只能以設定開關提供，預設關。等級 3 硬底線與公網暴露的雙層防護不受此限（它們本來就是「無法隔離也無法回復」才存在）。

審查時的參考做法：

| 情境 | 優先選擇 | 最後才選 |
|---|---|---|
| agent 可能動到主機檔案 | 預設隔離（microVM → bwrap／Landlock，見 srv-015） | 每次寫檔都問 |
| 可回復的大範圍修改 | checkpoint／VM 快照＋事後稽核 | 事前詢問 |
| 同類請求大量出現 | 預覽＋批次核准、任務信封 | 逐筆詢問 |
| 陌生人觸發的任務 | 依信任等級套較嚴 preset、降權 | 全體一律最嚴 |
| 發檔／外送 | 來源限制在工作區（srv-012）＋外送掃描 | 只靠出口核准 |

## 4. 邊界

| 邊界 | 誰強制 | 說明 |
|---|---|---|
| VM（B 段） | 核心／hypervisor | agent 的工具執行在 microVM 內；裡面的破壞靠快照回復 |
| 特權指令 | broker（A2） | VM 內沒有 root：只能送 argv 到 `broker.sock`，由 daemon 依允許清單與 tier 決定執行或排隊（`crates/seagent-security/src/broker.rs`、`audit/round5/AB-interface.md`） |
| 出口 | egress proxy ＋ broker（A3） | 主機允許清單、SSRF／私有位址、網站黑名單；憑證只在 daemon 注入，不外流；外送內容掃秘密（vault 值與金鑰樣式） |
| 秘密 | vault（A4） | 金鑰只在 daemon；子行程環境 scrub；`payload_exfil`／`vault.leaks` 擋外送 |
| 對外暴露 | app server（A8–A12） | 預設 loopback；非 loopback 需 TLS（或 `behind_proxy`）＋強認證＋Origin 限制＋速率限制，缺一層就拒絕啟動 |
| 模型上下文 | 注入防線（A7、H8） | 外部內容加邊界標記；偵測到不可信內容後 tier 2/3 需人，tier 0/1 照常（降權不是停擺） |

## 5. 已知事故對照（H 段）

| 事故 | 防線（A 側） | 重現的測試 |
|---|---|---|
| H1 刪庫／刪備份 | tier 3 分類（`DatabaseWipe`/`CloudDelete`/`ProdAndBackup`/`MassDelete`）、tier 3 硬底線、核准顯示影響、憑證不在執行環境 | `seagent-kernel/tests/security.rs::h1_prod_data_and_backups_need_a_human_under_any_mode`、`risk::tests::the_pocketos_incident_is_tier_three` |
| H2 間接注入（toxic agent flow） | 不可信標記＋taint 降權、出口強制、信封 | `h2_untrusted_issue_text_demotes_high_risk_tools_only` |
| H3 MCP 工具投毒 | 描述掃描、能力變更重新確認（A13，部分） | `plugin_guard` 既有測試 |
| H4 技能市集投毒 | skills guard、agent 建立技能一律掃描 | `agent_created_skills_are_scanned` |
| H5 供應鏈把 CLI 當武器 | 沒有全域 skip-permissions；yolo 仍受 tier 3 限制；VM 內無金鑰 | `h1_...`（yolo 段落）、`floors_are_not_bypassable` |
| H6 系統提示被改 | 內建提示與技能完整性（A13/A18，部分） | — |
| H7 網關被接管 | 預設 loopback、雙層防護、Origin／CSP、`seagent security audit` | `seagent_app::server::tests::cross_origin_and_url_tokens_are_refused_a11` |
| H8 記憶投毒 | 寫入掃描＋讀取時再掃、來源標記 | `path_floors_threats_and_output_wrapping` |
| H9 權限繞過模式 | 自動核准只能放寬 tier 0/1；tier 3 無法關閉 | `h1_...`（`--yolo` 下仍詢問） |
| H10 多 agent 連鎖 | 子代理不繼承更大權限（C 段）、A2A 訊息非操作者指令 | C 段 |
| H11 秘密外洩 | vault、envscrub、broker 外送掃描、log 遮罩 | `broker::egress_injects_secrets_and_refuses_them_on_the_way_out` |
| H12 框架對照 | 見下表 | — |

## 6. OWASP Top 10 for Agentic Applications 2026（ASI01–ASI10）對照

| 代碼 | 風險 | SE Agent 的防線 | 殘餘風險 |
|---|---|---|---|
| ASI01 Agent Goal Hijack | 注入改寫目標 | A7 不可信標記＋taint 降權；tier 3 硬底線 | 模型仍可能被說服去做 tier 0/1 的錯事 |
| ASI02 Tool Misuse | 工具被濫用 | 四級分類、信封範圍、broker 允許清單 | 新工具要有正確的 effects 宣告（A5 未完成） |
| ASI03 Identity & Privilege Abuse | 權限冒用 | VM 內無金鑰、broker 代執行、token 分級（A10） | 同機的 owner 行程仍可讀 vault |
| ASI04 Agentic Supply Chain | 供應鏈 | OSV、plugin/skill 掃描、A13（部分） | 缺簽章與可重現建置（A18 🚧） |
| ASI05 Unexpected Code Execution | 非預期執行 | 沙箱、`strict_inline_eval`、interp 分析 | 靜態分析不是證明 |
| ASI06 Memory & Context Poisoning | 記憶投毒 | 寫入／讀取掃描、來源信任等級 | 語意型投毒靠掃描抓不到 |
| ASI07 Insecure Inter-Agent Comms | agent 間通訊 | A2A 對等 token、訊息標記非操作者 | C5 通道未完成 |
| ASI08 Cascading Failures | 連鎖失敗 | 卡住只卡分支、逾時安全替代、資源上限 | 多 agent 全域協調仍在 C 段 |
| ASI09 Human-Agent Trust | 信任／核准疲勞 | 預設不問、只問 tier 3、批次核准、`seagent doctor` 監測 | 使用者仍可能一直按允許 |
| ASI10 Rogue Agents | 失控 agent | kill switch、estop、tier 3 硬底線、broker 稽核 | daemon 本身的權限等於使用者 |

## 7. 明確不成立的主張（過去文件寫錯的）

- ~~「模型繞不過閘門」~~：閘門判定的是 effects 與指令文字；模型可以換工具、拆步驟、或用未被 effects 描述的路徑。防線的價值在於**分層＋稽核＋可回復**，不是數學上的不可繞過。
- ~~「有兩道閘門就夠」~~：舊版只有提權與外送兩道，刪資料只需要一次普通 `rm`。現在由 tier 3 分類器覆蓋資料庫、雲端、備份、force push、權限與外送秘密。
- ~~「核准越多越安全」~~：核准疲勞是已知的失效模式；預設只問 tier 3，其餘靠隔離與回復。
