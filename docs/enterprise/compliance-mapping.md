# SOC 2 與 ISO/IEC 27001 控制項對照

**這不是認證。** ark 沒有 SOC 2 報告或 ISO 27001 驗證。ark 是你組織內部署的軟體，只能協助你的組織滿足控制項中「技術控制」的部分；治理、人員、實體、供應商管理、風險評鑑流程等屬於組織本身，ark 不能代替。

欄位：**ark 提供**＝程式已實作的功能與入口；**證據**＝稽核時可以拿出什麼（指令輸出、檔案、設定）；**客戶補足**＝部署者還必須做的事或 ark 的已知缺口。「—」表示 ark 沒有相關功能。

## 1. SOC 2 信任服務準則（2017，2022 修訂關注點）

範圍假設：安全性（CC）為必選；可用性（A）、機密性（C）、處理完整性（PI）、隱私（P）視組織選擇。

### 1.1 共同準則 CC

| 準則 | 主題 | ark 提供 | 證據 | 客戶補足 |
|---|---|---|---|---|
| CC1 | 控制環境 | — | — | 全部屬組織治理、道德規範、人員（ark 無）|
| CC2.1–2.3 | 資訊與溝通 | 稽核事件流；`ark doctor` 報告；文件 `docs/enterprise/` | `ark audit events`、`ark doctor` | 內部溝通、對外承諾 |
| CC3 | 風險評鑑 | 威脅模型與風險自評、OWASP Agentic 對照 | `docs/risk-assessment.md` | 組織自己的風險登錄與接受 |
| CC4 | 監控活動 | `ark audit verify`（鏈完整性）、`ark security audit`、`ark service audit`、`/metrics`、`/ready`、用量告警 | 命令輸出、Prometheus 指標 | 定期執行與審閱的流程；SIEM 告警規則 |
| CC5 | 控制活動 | 政策鎖定（`/etc/ark/managed.toml`）、四級風險分類與核准、任務信封 | `ark config managed`、`ark approvals status` | 把控制納入政策文件與例外流程 |
| CC6.1 | 邏輯存取：保護資產 | 隔離層（microVM／bwrap／Landlock）、vault 靜態加密、出口閘門、app server 暴露防線 | `ark sandbox explain`、`ark secrets backend` | 主機加固、磁碟加密 |
| CC6.2 | 註冊與授權使用者 | `ark users`（角色、團隊、停用）、OIDC 群組→角色、服務帳號 | `ark users list`、`ark accounts list` | 人員異動流程接上 IdP |
| CC6.3 | 角色型存取、最小權限、職責分離 | admin／user／operator／auditor；operator 與 auditor 不可讀對話內容；核准者身分記錄 | 稽核 `auth.denied`、`approval.answer` | 角色指派審查（定期 recertification）|
| CC6.4 | 實體存取 | — | — | 全部客戶 |
| CC6.5 | 資產處置 | `ark data delete`、保留清除、`ark uninstall`（`--purge` 有防呆）| `ark retention status` | 儲存媒體銷毀 |
| CC6.6 | 邊界防護 | 預設不監聽；出口主機允許清單；SSRF 單一分類表；非 loopback 全套要求 | `gate.egress_allow`、`ark security check-url` | 網路防火牆、WAF、分段 |
| CC6.7 | 傳輸與移動中資料 | TLS（rustls）、Origin 限制、發檔來源限制、外送掃描 | `[app.exposure]` | 憑證管理、行動媒體 |
| CC6.8 | 防範惡意軟體 | 技能／外掛掃描、簽章、MCP 釘選、提示注入降權 | `ark mcp pins`、`ark security plugins` | 端點防護（EDR）|
| CC7.1 | 偵測組態變更與弱點 | `ark config` 變更入稽核；`ark service audit` 偵測單元漂移；`ark security audit` | 稽核 `config.change` | 弱點掃描、組態基準 |
| CC7.2 | 監控異常 | 稽核流＋SIEM 匯出；`auth.failed`、`gate.decision`；核准疲勞與重啟風暴偵測 | SIEM 內事件、`ark doctor` | 告警規則與 24x7 回應 |
| CC7.3–7.5 | 事故評估、回應、復原 | `ark pause`（緊急停止）、電子取證匯出、保管鏈、`ark doctor --bundle`（去識別）、checkpoint 回復 | `ark ediscovery verify` | 事故回應計畫、通報、演練 |
| CC8.1 | 變更管理 | 套件與映像簽章、SBOM、可重現建置、更新前備份與回滾、受管設定 | `verify-release.sh`、`ark update --rollback` | 你自己的變更核准流程（CAB、測試環境）|
| CC9.1 | 業務中斷風險 | 服務自動重啟、重啟風暴偵測 | `Restart=on-failure` | BCP／DRP |
| CC9.2 | 供應商與夥伴風險 | 模型端點可限制（`model.allow`、`data_class`）；SBOM 揭露依賴 | `ark config managed` | 對模型供應商的盡職調查與合約 |

### 1.2 可用性 A

| 準則 | ark 提供 | 證據 | 客戶補足 |
|---|---|---|---|
| A1.1 容量 | `[limits]`、`[quotas]`、`/metrics` | 指標 | 容量規劃；ark 無負載基準數據 |
| A1.2 環境保護、備份、復原基礎設施 | 套件／離線包可重複安裝；`update` 備份與回滾 | 備份檔 `pre-update-*.tar.gz` | 備份排程、異地、還原演練。**ark 無高可用機制** |
| A1.3 復原測試 | — | — | 客戶 |

### 1.3 機密性 C

| 準則 | ark 提供 | 證據 | 客戶補足 |
|---|---|---|---|
| C1.1 識別與維護機密資訊 | `data_class` 與可用模型對應；PII 遮罩 | `[compliance.classes]` | 資料分類方案本身 |
| C1.2 機密資訊處置 | 保留期限、法律保全、`ark data delete` | `ark retention status` | 模型供應商端的刪除（合約）|

### 1.4 處理完整性 PI

| 準則 | ark 提供 | 證據 | 客戶補足 |
|---|---|---|---|
| PI1.x | 稽核鏈（不可竄改偵測）、核准紀錄、checkpoint | `ark audit verify` | **模型輸出的正確性 ark 不保證**；對業務結果的覆核由客戶負責 |

### 1.5 隱私 P

| 準則 | ark 提供 | 證據 | 客戶補足 |
|---|---|---|---|
| P1 告知 | 聊天首次互動 `privacy_notice`、`privacy_policy_url` | 設定檔 | 隱私政策本文 |
| P2 選擇與同意 | — | — | 客戶 |
| P3–P4 蒐集、使用、保留與處置 | 最小化、PII 遮罩、保留期限、`ark data export|delete` | `[compliance.pii]`、`ark retention` | 目的限定、合法事由 |
| P5 存取 | `ark data export` | — | 受理流程 |
| P6 揭露與通知 | 資料外流清單（白皮書 §6）；遙測預設關 | — | 委外處理者清冊（模型供應商、聊天平台）|
| P7 品質 | — | — | 客戶 |
| P8 監控與強制執行 | 稽核與 SIEM | — | 客訴與違規處理 |

## 2. ISO/IEC 27001:2022 附錄 A

涵蓋率說明：技術類（A.8）ark 有直接貢獻；組織類（A.5）多數屬流程，ark 提供證據來源；人員（A.6）與實體（A.7）屬客戶。

### 2.1 A.5 組織控制

| 控制 | 名稱 | ark 提供／證據 | 客戶補足 |
|---|---|---|---|
| A.5.1 | 資安政策 | 受管設定可把技術政策落成機器可執行（`/etc/ark/managed.toml`）| 政策文件 |
| A.5.2–5.4 | 角色責任、職責分離、管理階層責任 | 四種角色，operator／auditor 不可讀內容 | 角色指派與責任書 |
| A.5.5–5.6 | 與主管機關、特殊利害團體聯繫 | — | 客戶 |
| A.5.7 | 威脅情資 | `ark security audit --supply-chain`（OSV／RUSTSEC）| 情資訂閱 |
| A.5.8 | 專案管理中的資安 | 新防線設計審查準則 | 客戶專案流程 |
| A.5.9–5.11 | 資產清冊、可接受使用、資產歸還 | SBOM；`ark users` 登記；`ark uninstall` | 資產清冊本身 |
| A.5.12–5.13 | 資訊分類與標示 | `data_class`／`classes` | 分類方案 |
| A.5.14 | 資訊傳送 | 出口閘門、發檔來源限制、外送掃描 | 傳輸政策 |
| A.5.15–5.18 | 存取控制、身分管理、鑑別資訊、存取權 | OIDC、RBAC、服務帳號輪替、使用者停用、稽核 | 權限審查週期、IdP 設定 |
| A.5.19–5.22 | 供應商關係、供應商協議、ICT 供應鏈、供應商服務監控 | SBOM、簽章、依賴審查流程；模型端點限制 | 對模型供應商的合約與審查 |
| A.5.23 | 雲端服務資安 | 模型端點、聊天平台的外送清單 | 雲端服務協議 |
| A.5.24–5.28 | 事故管理規劃、評估、回應、學習、蒐證 | 稽核流、`ark ediscovery`、保管鏈、`ark doctor --bundle` | 事故流程與通報 |
| A.5.29–5.30 | 中斷期間資安、ICT 營運持續準備 | 服務自動重啟；降級行為有警告 | BCP／DR |
| A.5.31 | 法律、法規、契約要求 | `docs/compliance-tw.md`（無律師審閱）| 法遵判斷 |
| A.5.32 | 智慧財產權 | `THIRD_PARTY_NOTICES.md`、SBOM 授權欄位 | — |
| A.5.33 | 紀錄保護 | 雜湊鏈、封存段唯讀、保留與保全 | 外部副本與存取控制 |
| A.5.34 | 隱私與 PII 保護 | PII 遮罩、保留、`ark data export|delete`、告知訊息 | 隱私管理制度 |
| A.5.35–5.36 | 資安獨立審查、遵循 | 稽核匯出供審查；`ark audit verify` | 內外部稽核 |
| A.5.37 | 文件化作業程序 | `docs/MANUAL.md`、本目錄 | 組織 SOP |

### 2.2 A.6 人員控制與 A.7 實體控制

| 控制 | ark 提供 | 客戶補足 |
|---|---|---|
| A.6.1–6.8（篩選、聘僱條款、意識、懲處、離職、保密、遠端工作、事件通報） | 離職：`ark users disable`、服務帳號撤銷；事件通報：稽核與除錯包 | 其餘全部 |
| A.7.1–7.14（實體邊界、進出、機房、監控、設備放置、離場設備、儲存媒體、支援設施、佈線、維護、處置） | — | 全部客戶 |

### 2.3 A.8 技術控制

| 控制 | 名稱 | ark 提供 | 證據 | 客戶補足／缺口 |
|---|---|---|---|---|
| A.8.1 | 使用者終端設備 | CLI 走 unix socket（OS 使用者）；app 走認證 | — | 終端管理 |
| A.8.2 | 特權存取權 | admin 角色；第 3 級一律需人；broker 代執行特權指令 | 稽核 | 特權帳號管理（PAM）|
| A.8.3 | 資訊存取限制 | RBAC、工具 allow／deny、工作區限制、發檔限制 | `tools.deny`、`ark sandbox explain` | — |
| A.8.4 | 原始碼存取 | — | — | 客戶 |
| A.8.5 | 安全鑑別 | OIDC、token 雜湊儲存、常數時間比對、過期與撤銷 | `ark accounts` | MFA 由 IdP |
| A.8.6 | 容量管理 | 限制與配額 | `/metrics` | 規劃 |
| A.8.7 | 防範惡意軟體 | 技能／外掛掃描、簽章、MCP 釘選、注入降權 | — | 端點防護 |
| A.8.8 | 技術弱點管理 | OSV／RUSTSEC 檢查、`cargo deny`、SBOM | CI | 修補時程（ark 無 SLA）|
| A.8.9 | 組態管理 | 受管設定鎖定、`ark config managed`、單元漂移稽核、組態變更入稽核 | `config.change` | 基準與漂移審查 |
| A.8.10 | 資訊刪除 | 保留清除、`ark data delete`、保全例外 | — | 備份中的副本 |
| A.8.11 | 資料遮蔽 | PII 遮罩、秘密遮罩、`{{secret:…}}` 佔位符 | `[compliance.pii]` | — |
| A.8.12 | 資料外洩防護 | 出口閘門、外送內容掃描 vault 值與金鑰樣式、發檔限制、資料分級限制模型 | `gate.*` | 企業 DLP（ark 不是 DLP 產品）|
| A.8.13 | 資訊備份 | `ark update` 前自動備份 | — | 例行備份與異地 |
| A.8.14 | 資訊處理設施備援 | 服務自動重啟 | — | **ark 無 HA** |
| A.8.15 | 日誌 | 統一稽核流、雜湊鏈、輪替、保留 | `ark audit events|verify` | 日誌保存政策、存取控制 |
| A.8.16 | 監控活動 | `/metrics`、`/ready`、SIEM 匯出、告警 | Prometheus、SIEM | 偵測規則與回應 |
| A.8.17 | 時鐘同步 | — | — | 客戶（NTP）|
| A.8.18 | 特權公用程式 | 沙箱內無 root；broker 允許清單 | — | — |
| A.8.19 | 軟體安裝管制 | 簽章套件庫、技能／外掛簽章與鎖定 | `require_signature` | 變更核准 |
| A.8.20 | 網路安全 | 預設不監聽、出口允許清單、NetworkPolicy 範例 | Helm | 網路架構 |
| A.8.21 | 網路服務安全 | TLS 要求、Origin、速率限制 | `[app.exposure]` | — |
| A.8.22 | 網路區隔 | 部署參考架構（出口代理、隔離網路）| `deployment-architecture.md` | 實際分段 |
| A.8.23 | 網頁過濾 | 出口主機清單、SSRF 分類、網站黑名單 | `gate.egress_*` | — |
| A.8.24 | 密碼學使用 | ChaCha20-Poly1305、PBKDF2（≥ 100k）、Ed25519、SHA-256、TLS 1.2+ | `ark secrets backend` | 金鑰管理流程 |
| A.8.25 | 安全開發生命週期 | CI（clippy、測試、secret scan、cargo deny）、設計審查準則 | `.github/workflows` | — |
| A.8.26 | 應用程式安全要求 | 威脅模型、OWASP Agentic 對照 | `docs/risk-assessment.md` | — |
| A.8.27 | 安全系統架構 | 分層 crate 依賴由測試強制 | `arch_lint` | — |
| A.8.28 | 安全編碼 | Rust；Clippy `-D warnings` | CI | — |
| A.8.29 | 開發與驗收中的安全測試 | 單元／整合／e2e 測試；發行版矩陣冒煙；**無第三方滲透測試** | `packaging/matrix` | 客戶 PoC 與滲透測試 |
| A.8.30 | 委外開發 | — | — | 客戶 |
| A.8.31 | 開發、測試與營運環境分離 | 測試使用拋棄式 `ARK_HOME` | — | 客戶環境分離 |
| A.8.32 | 變更管理 | 簽章發佈、回滾、受管設定 | — | 客戶變更流程 |
| A.8.33 | 測試資訊 | 測試用假模型伺服器，不使用真實資料 | `tests/e2e/fake_provider.py` | — |
| A.8.34 | 稽核期間資訊系統保護 | 稽核角色唯讀、看不到對話內容 | `auditor` 角色 | — |

## 3. 如何使用這份對照

1. 從你的控制矩陣挑出受稽核的控制項，在「ark 提供」欄找對應的指令。
2. 稽核證據的取得方式：`ark config managed`、`ark audit verify`、`ark audit events --json`、`ark sandbox explain`、`ark approvals status`、`ark users list`、`ark accounts list`、`ark retention status`、SIEM 內的事件、`ark doctor`。
3. 「客戶補足」欄是你自己的控制；若被稽核員問到 ark 的限制，引用白皮書 §9。
4. 覆蓋範圍會隨版本改變；用安裝的版本對照 `docs/MANUAL.md`，不要只信這份文件。
