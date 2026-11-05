# 資安問卷預填（CAIQ v4／SIG Lite 風格）

使用方式：把你們的問卷題目對到下面的領域，直接引用「回答」與「證據」。回答欄用語：

- **是**：已實作，證據欄指出位置。
- **部分**：有實作但有明講的限制。
- **否**：沒有。
- **客戶**：SE Agent 是自行部署的軟體，這項屬部署者責任（SE Agent 沒有供應商端雲服務）。

> 這是供應商自評，沒有第三方稽核或認證可附。證據欄的路徑都在原始碼庫內，可被審閱。

## A. 治理與供應商資訊（GRC／AIS）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| A1 | 產品形式？ | 說明 | 自行部署的單一 Linux 執行檔與容器映像；無託管服務 |
| A2 | 供應商是否處理客戶資料？ | 否 | 資料只在客戶主機；唯一外送是客戶設定的端點（白皮書 §6）|
| A3 | 是否有書面安全開發流程？ | 部分 | 依賴審查流程 `packaging/release/DEPENDENCY-REVIEW.md`；新防線設計審查準則 `docs/risk-assessment.md` §3.1；CI 含 clippy、`cargo deny`、秘密掃描、測試 |
| A4 | 是否有威脅模型？ | 是 | `docs/risk-assessment.md` §1–§6 |
| A5 | 是否做過第三方滲透測試？ | 否 | 無報告可附；有自評與 OWASP Agentic Top 10 對照（`docs/risk-assessment.md` §6）|
| A6 | 是否取得 SOC 2／ISO 27001？ | 否 | 對照見 [compliance-mapping.md](compliance-mapping.md)，非認證 |
| A7 | 是否有 AI 風險評估？ | 是 | 依數發部《人工智慧風險分類框架》逐子類自評：`docs/risk-assessment.md`；法規對照 `docs/compliance-tw.md`（無律師審閱）|
| A8 | 是否有漏洞回報管道？ | 部分 | `docs/SECURITY.md` §7（回報指引）；沒有賞金計畫或 SLA |
| A9 | 變更是否有審查與可追溯性？ | 部分 | git 歷史、CI；單一維護團隊，無獨立變更委員會 |
| A10 | AI 輸出是否可標示？ | 是 | `ai_label`（聊天回覆標示「由 AI 生成」，`government` 模式預設開）|

## B. 資料安全與隱私（DSP／DCS）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| B1 | 資料靜態加密？ | 部分 | 金鑰庫 ChaCha20-Poly1305（`secrets.enc`）。對話與稽核檔本身不加密，依賴磁碟／檔案系統加密（客戶）|
| B2 | 金鑰儲存？ | 是 | 登入 keyring／TPM（root 服務）／密語檔／`SEAGENT_VAULT_KEY`；無來源時降為 0600 明文並明說，可用 `SEAGENT_VAULT_REQUIRE_ENCRYPTION=1` 禁止降級 |
| B3 | 傳輸加密？ | 部分 | 對模型與聊天平台為 TLS（rustls）。app server 非 loopback 必須 TLS 或在 TLS 代理後，否則拒絕啟動；內網 `http://` 模型端點由客戶負責 |
| B4 | 是否使用客戶資料訓練模型？ | 客戶 | SE Agent 不訓練模型；模型供應商的條款由客戶選擇與簽署 |
| B5 | 個資遮罩？ | 是 | `[compliance.pii]`：email、電話、Luhn 卡號、SSN、台灣身分證、IPv4；寫入前遮罩、匯出預設遮罩。daemon stderr log 未遮罩 |
| B6 | 資料保留與刪除？ | 是 | `[compliance.retention]` 各類天數；`seagent data export|delete <channel> <sender>`；法律保全 `seagent retention hold` |
| B7 | 當事人權利（查閱、刪除）？ | 部分 | `seagent data export|delete`（session、路由、配對、附件）；流程 checkpoint 目錄尚未納入（`docs/compliance-tw.md` 第 19 列）|
| B8 | 資料分級？ | 是 | `[compliance] data_class` ＋ `[compliance.classes]` 限制可用模型，未定義類別 fail closed |
| B9 | 資料地理位置？ | 客戶 | 資料在客戶主機；模型端點地區由客戶選；`government` 模式拒絕中國境內端點 |
| B10 | 資料外流清單？ | 是 | 白皮書 §6、部署架構「資料外流清單」|
| B11 | 電子取證？ | 是 | `seagent ediscovery export|verify`（遮罩、雜湊、保管鏈）|
| B12 | 備份與還原？ | 客戶 | `/var/lib/seagent`；`seagent update` 前自動備份 config＋data 並可回滾；企業備份流程屬客戶 |
| B13 | 隱私告知？ | 是 | 每位新聊天使用者首次回覆前送出 `privacy_notice`；對陌生人開放而未設時啟動警告 |
| B14 | 遙測？ | 是 | 預設關閉；開啟後僅三種無內容事件並遮罩 |

## C. 身分與存取（IAM）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| C1 | 是否支援 SSO／OIDC？ | 是 | `self_hosted` OIDC，群組→角色（`[app.rbac]`）；舊式前端（Kerberos／`mod_auth_gssapi`、WAM、mTLS 代理）以受信代理身分標頭登入（`[app.exposure.proxy_auth]`，只採信列出的代理位址）|
| C2 | 是否支援 MFA？ | 客戶 | 由 IdP 提供；SE Agent 不自行實作 MFA |
| C3 | RBAC？ | 是 | admin／user／operator／auditor；多角色取聯集；內容方法對 operator、auditor 關閉（白皮書 §4）|
| C4 | 最小權限？ | 是 | 工具預設隔離；政策鎖定；任務信封；服務帳號按角色 |
| C5 | 服務帳號與憑證輪替？ | 是 | `seagent accounts issue|rotate|revoke|expiring`，預設 90 天，輪替有寬限期，只存 SHA-256 |
| C6 | 特權帳號管理？ | 部分 | `admin` 角色與本機 OS 使用者（unix socket）。高風險動作可要求雙人覆核（`[approvals.dual_control]`：N 位不同且非申請者的核准者、角色限定、到期，可連動 ServiceNow／Jira 變更單）。沒有 JIT 提權；擁有 daemon 的本機帳號可繞過雙人覆核（等同系統管理員）|
| C7 | 使用者停用／離職？ | 是 | `seagent users disable`，登入與聊天立即失效 |
| C8 | 工作階段管理？ | 是 | 角色在登入時決定並簽進 cookie；個人 token TTL 不超過 session |
| C9 | 核准者可否被冒充？ | 否（防住）| 伺服器端以認證後 principal 寫入核准者，用戶端 `_by` 被剝除 |
| C10 | 暴力破解防護？ | 是 | app server 速率限制（`seagent_http_rate_limited_total` 指標）；非 loopback 必設 |
| C11 | 來源 IP 判定？ | 是 | `[app.exposure] trusted_proxies`；只有受信代理的 XFF 被採信 |

## D. 日誌與監控（LOG）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| D1 | 稽核日誌涵蓋？ | 是 | 請求決策、登入、token、設定變更、核准、gate、使用者異動、保留、匯出、預算（白皮書 §5）|
| D2 | 日誌防竄改？ | 部分 | SHA-256 雜湊鏈、封存段 0400＋seal；seal 可用 Ed25519 簽章並取 RFC 3161 時戳（`[audit] seal_key`、`tsa_url`；`seagent audit verify --pubkey … --require-signed`）。同 uid 仍可重寫尚未輪替簽章的部分；簽章金鑰須放在被稽核主機之外，並外送 SIEM 以 `--anchor` 比對 |
| D3 | 日誌保存？ | 是 | `[compliance.retention] audit_days`，不刪法律保全範圍 |
| D4 | SIEM 整合？ | 是 | syslog（UDP、TCP RFC 6587、TLS RFC 5425）訊息可為 JSON、CEF（ArcSight）或 LEEF（QRadar），可設多個具名 sink；Splunk HEC、OTLP logs；各 sink 獨立游標、至少一次 |
| D5 | 指標與健康檢查？ | 是 | `/metrics`（Prometheus）、`/ready`、`seagent health --ready`、`seagent health --nagios`（Nagios／Icinga 外掛格式）、`[alerts]` 的 `snmp://` 目標（SNMPv2c trap，需 `snmptrap`）|
| D6 | 時鐘同步？ | 客戶 | 使用主機時間；NTP 屬客戶 |
| D7 | 日誌是否含秘密？ | 否（遮罩）| 稽核自由文字遮罩；工具輸出遮罩金鑰樣式 |
| D8 | 重啟風暴／異常偵測？ | 是 | 10 分鐘內 3 次啟動警告（`seagent doctor`、`seagent service audit`）|
| D9 | 費用／用量告警？ | 是 | `[alerts]` 推送、`[quotas]` 滿額停止 |
| D10 | 給稽核人員的彙整報告？ | 是 | `seagent audit report --from --to --format md\|html\|json`（ARP `audit.report`）：登入、權限異動、核准與核准者、被拒動作、設定變更、session 覆核，附整條鏈驗證結果與 head hash |
| D11 | 對話的人工覆核？ | 是 | `seagent session review <id> reviewed\|flagged\|cleared --note …`、ARP `session.review.*`；擁有者不能覆核自己的 session，auditor 唯讀；每次標記寫稽核 |
| D12 | 稽核涵蓋是否有機制保證？ | 部分 | 測試逐一列舉 app server 所有會改變狀態的 ARP 方法與 `seagent users`／`tenancy`／`accounts` 子命令，斷言每個都寫稽核（允許與拒絕兩條路徑）；其他 CLI 命令沒有同等的自動檢查 |

## E. 應用程式與介面安全（AIS）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| E1 | 預設是否對網路開放？ | 否 | app server 預設關閉；開啟預設 loopback；容器預設無監聽 |
| E2 | 非 loopback 暴露的要求？ | 是 | token＋強認證＋Origin 限制＋速率限制＋TLS，缺一不啟動 |
| E3 | SSRF 防護？ | 是 | 單一分類表；轉址每跳再判；連線時再判（擋 DNS rebinding）|
| E4 | CSRF／跨來源？ | 是 | Origin／CSP；URL token 被拒（測試 `cross_origin_and_url_tokens_are_refused_a11`）|
| E5 | 提示注入防護？ | 部分 | 不可信內容標記＋降權、第 3 級硬底線、出口閘門；語意型攻擊無法完全偵測（白皮書 §9）|
| E6 | 輸出是否被當成指令？ | 否 | 工具輸出視為資料；外部內容加邊界標記 |
| E7 | 沙箱／隔離？ | 是 | microVM → bwrap → Landlock；無隔離時 `NOT ISOLATED` 警告 |
| E8 | 檔案外送限制？ | 是 | 來源限制在工作區／artifact，排除金鑰檔 |
| E9 | 輸入驗證與記憶體安全？ | 部分 | Rust 實作（`unsafe` 用於 libc 呼叫等系統邊界）；無獨立模糊測試或記憶體安全審計報告 |
| E10 | 破壞性操作保護？ | 是 | 四級分類；第 3 級一律詢問，不可批次、不可 Allow Always |
| E11 | 核准疲勞對策？ | 是 | 預設只問第 3 級；批次預覽；信任等級分流；`seagent doctor` 監測 |
| E12 | 緊急停止？ | 是 | `seagent pause`（`<data>/ESTOP`，fail safe）、步數與費用上限 |
| E13 | 子代理權限？ | 是 | 子代理不繼承更大權限；深度限制 |

## F. 供應鏈與漏洞管理（STA／TVM／CCC）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| F1 | 是否提供 SBOM？ | 是 | SPDX 2.3 JSON，隨發佈；僅 Rust crate |
| F2 | 發佈物簽章？ | 是 | `SHA256SUMS` 的 Ed25519 簽章；套件庫 GPG；映像 cosign keyless；GitHub attestation |
| F3 | 可重現建置？ | 是 | `repro-check.sh` 兩路徑比對（CI repro job）|
| F4 | 依賴管理與授權？ | 是 | `cargo deny`、`THIRD_PARTY_NOTICES.md`、依賴預算、審查流程 |
| F5 | 已知漏洞掃描？ | 是 | `seagent security audit --supply-chain`、`cargo deny check advisories`（OSV／RUSTSEC）|
| F6 | 程式碼中的秘密掃描？ | 是 | `tools/secret-scan.py` 掃工作樹與全歷史（CI）|
| F7 | 外掛／技能來源驗證？ | 是 | Ed25519 簽章、內容 digest、版本鎖定、能力變更重新同意；預設不強制簽章，可設 `require_signature` |
| F8 | MCP 工具投毒防護？ | 是 | 工具釘選，變動需人工 `accept` |
| F9 | 更新機制安全？ | 是 | 驗 `SHA256SUMS`；設 `[update] verify_key` 後強制驗簽；更新前自動備份、可回滾；套件安裝不自我更新 |
| F10 | 修補時程承諾？ | 否 | 無 SLA |
| F11 | 作業系統支援矩陣？ | 是 | 套件與 tarball 在 Amazon Linux 2／2023、Rocky 8／9、AlmaLinux 10、Fedora、Ubuntu 20.04–24.04、Debian 11–13、Alpine 實測；CentOS 7、openSUSE Leap 15 為盡力支援 |

## G. 營運韌性與事故（BCR／SEF）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| G1 | 高可用？ | 部分 | `[ha]`：多個 `seagentd` 共用資料目錄，以租約＋fencing token 選出 leader，standby 自動接手（`seagent ha status\|stepdown`）；`[workers]` 分派回合（`seagent workers`）；`seagent cluster` 是多節點主控台並以簽章下發受管政策。依賴共享儲存本身的可用性，沒有內建資料複寫或跨資料中心叢集 |
| G2 | 備份？ | 客戶 | `/var/lib/seagent`；金鑰來源（keyring、TPM、密語）要另外備份 |
| G3 | 災難復原？ | 客戶 | 無內建；還原 `/var/lib/seagent` 後 `seagent doctor` |
| G4 | 事故處理流程？ | 部分 | `seagent doctor --bundle`（去識別除錯包，不上傳）；稽核與電子取證；正式事故通報流程屬客戶 |
| G5 | 重大變更通知？ | 部分 | release notes；無主動通知服務 |
| G6 | 服務降級行為？ | 是 | 無 microVM 退 bwrap／Landlock；無 keyring 退明文（會明說）；每次降級都有警告 |

## H. 基礎設施與端點（IVS／UEM）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| H1 | 服務是否最小權限？ | 是 | 專用帳號 `seagent`、`NoNewPrivileges`、`ProtectSystem=full`、`UMask=0077`…（`ops/service.rs`）|
| H2 | 容器映像加固？ | 是 | 多階段、非 root、唯讀根檔案系統（Helm）、`seagent docker check` 六項規則 |
| H3 | Kubernetes 安全設定？ | 是 | Helm chart 符合 `restricted` PSS，NetworkPolicy，無 SA token |
| H4 | 網路分段？ | 客戶 | 建議出口只放 443 與必要端點（Helm／Terraform 範例已示範）|
| H5 | 主機加固基準？ | 客戶 | 無內建 CIS 檢查 |
| H6 | 實體安全？ | 客戶 | 自行部署 |

## I. 人員（HRS）

| ID | 問題 | 回答 | 說明與證據 |
|---|---|---|---|
| I1 | 供應商人員背景調查、資安訓練？ | 否 | 開源專案，無此項承諾 |
| I2 | 程式碼存取控制？ | 部分 | 依儲存庫權限；簽章金鑰存 CI secret（建議改離線／HSM）|

## 附：回答範本中的「限制」彙整

模型可能做錯事（tier 0／1 放行，靠回復）、同 uid 程序等同擁有者、金鑰庫降級、無隔離主機、語意型攻擊、HA 依賴共享儲存（無內建資料複寫）、擁有 daemon 的本機帳號可繞過雙人覆核、無第三方滲透測試、無 SLA。詳見白皮書 §9。
