# ark 安全白皮書（對外版）

適用版本：0.1.x。範圍：ark 執行檔（CLI、背景程式 `arkd`、app server、聊天通道、工具與沙箱）。
本文是 [../SECURITY.md](../SECURITY.md)（操作者版）與 [../risk-assessment.md](../risk-assessment.md)（威脅模型）的對外整理；細節以那兩份與程式碼為準。

## 1. 產品與責任邊界

ark 是一個讓大型語言模型（LLM）在你的機器上讀寫檔案、執行指令、瀏覽網頁、透過聊天通道與人互動的 agent 執行環境。

| 項目 | 事實 |
|---|---|
| 交付形式 | 單一靜態 Linux 執行檔（x86_64／aarch64，musl）＋ `/usr/share/ark`（技能、角色、目錄）。deb／rpm、tarball、OCI 映像（debian／UBI／distroless）、Helm chart。沒有雲端服務。 |
| 資料位置 | 全部在部署者的主機：系統服務為 `/var/lib/ark`（`ARK_HOME`），個人安裝為 `~/.local/share/ark` 與 `~/.config/ark`。 |
| 對外連線 | 只有部署者設定的：模型供應商 API、聊天平台、（選配）SIEM／OTLP／webhook、（選配）`ark update` 檢查發佈來源。遙測（`[telemetry]`）預設關閉。 |
| 平台 | 僅 Linux。 |
| 責任分工 | ark 提供防線與紀錄；主機加固、網路分段、IdP、備份、模型供應商的合約與資料處理條款，是部署者的責任（見 §10）。 |

## 2. 威脅模型（我們假設什麼）

取自 `docs/risk-assessment.md` §1，不是願望，是設計前提：

| # | 假設 |
|---|---|
| T1 | 模型本身可能被投毒（間接提示注入、被改寫的系統提示）。 |
| T2 | 技能、外掛、MCP server 都可能是惡意的。 |
| T3 | 工具輸出（網頁、issue、email）是資料，不是指令。 |
| T4 | agent 執行環境裡讀得到的憑證，就當作已經外洩。 |
| T5 | 使用者會按「允許」按到手軟（核准疲勞）。防線必須預設不問，只問真正不可逆的事。 |

**由此得到的原則：** 任何只靠「模型判斷」的防線都不算防線；每一類事故至少兩層，且至少一層是資料驅動（政策檔、effects 分類器、網路層、OS 隔離），不經過模型。我們**不主張**模型繞不過閘門；防線的價值在分層、稽核與可回復。

## 3. 防線總覽

| 層 | 做什麼 | 位置／入口 |
|---|---|---|
| 隔離執行 | agent 的工具執行在 microVM（Firecracker／QEMU-KVM）；沒有 microVM 時所有 session（含擁有者）退到 bwrap，再退 Landlock，家目錄與金鑰不掛入。連 namespace 沙箱都沒有才在主機執行，並以 `NOT ISOLATED` 警告。 | `ark sandbox explain`、`ark doctor`；`[exec] backend` |
| 四級風險分類 | 依工具宣告的 effects（指令、寫入路徑、目的主機、外送內容、金額）分 0–3 級；分類器的輸入不含模型輸出。0–1 直接放行並記錄；2 在任務信封內放行否則詢問；3（不可逆：刪正式資料／備份、force push、外送秘密、改權限、轉帳）一律詢問。`approvals.preset` 不影響第 3 級。 | `ark_security::risk`、`ark approvals status` |
| 核准機制 | 第 3 級在聊天中只有「允許一次／拒絕」、二次確認、限 owner、記錄核准者、逾時通知；不能批次放行；無人在場的呼叫進佇列，可先預覽再分組核准。依信任等級（owner／channel／stranger）套用不同 preset。 | `ark approvals queue preview|allow|deny`、`[approvals] trust_presets` |
| 任務信封 | 長任務開工前一次授權可寫路徑、可連主機、指令前綴、花費上限、時限（最長 30 天）；信封永遠不能授權第 3 級。`allow always` 預設 7 天到期。 | `approvals.grant_ttl_days` |
| 出口控制 | 主機允許清單、SSRF／私有位址判定（單一分類表）、連線時再判定位址以擋 DNS rebinding、外送內容掃描 vault 值與金鑰樣式。 | `gate.egress_allow`／`egress_deny`、`ark security check-url` |
| 金鑰庫 | ChaCha20-Poly1305 靜態加密（AAD 綁定 KDF 參數），解鎖來源：登入 keyring、TPM（僅 root 服務自動選用）、密語檔、`ARK_VAULT_KEY`。VM 與 broker 看到的只有 `{{secret:NAME}}` 佔位符，替換在 daemon 側。 | `ark secrets backend`、`ARK_VAULT_REQUIRE_ENCRYPTION=1` |
| 輸入防線 | 外部內容加邊界標記；偵測到不可信內容後第 2／3 級需人（降權，不是停擺）。記憶寫入與讀取時各掃描一次。聊天回覆移除記憶圍欄標記並遮罩金鑰樣式字串。工具輸出進入上下文前遮罩金鑰樣式字串。 | 自動；`[security] mask_output_secrets` |
| 發檔限制 | channel 動作讀主機檔案前，路徑（解析 symlink）必須在工作區或 artifact 目錄內，且不是金鑰類檔案（`.ssh`、`.aws`、`id_*`、`secrets.*`…）。 | `message` 工具、`ARK_SEND_ROOTS` |
| 外掛／技能／MCP | 技能與外掛 manifest 可用 Ed25519 簽章（trust store，可設 `require_signature = true`）；內容 digest 與版本鎖定；能力變多的更新需重新同意；MCP 工具首次載入即取 SHA-256 釘選，描述或 schema 變動後不給模型直到人工 `ark mcp pins accept`；內建提示與技能有完整性清單。 | `ark mcp pins`、`ark security plugins` |
| 對外暴露 | app server 預設關閉、綁 loopback。要綁非 loopback 必須同時具備：token、強認證、Origin 限制、速率限制、TLS（或確認在 TLS 反向代理後）。缺一層就拒絕啟動。 | `[app.exposure]`、`packaging/docker/config.public.toml` |
| 緊急停止 | `ark pause` 寫入 `<data>/ESTOP`（讀不到時視為已暫停，fail safe），停排程、goal、通道進來的工作與派工，不殺正在跑的互動工作；步數、費用上限。 | `ark pause`、`[limits]`（見 MANUAL） |

## 4. 身分、權限與組織政策

| 能力 | 說明 | 入口 |
|---|---|---|
| 四種角色 | `admin`（全部）、`user`（聊天、核准、讀）、`operator`（唯讀中繼資料＋daemon／通道／節點維運，**不得**讀對話內容）、`auditor`（唯讀中繼資料＋稽核，**不得**讀對話內容）。所有 ARP 呼叫（HTTP、WebSocket、外掛路由）經同一個 `permits()`。 | `[app] tokens` 的 `scope`；ARP `whoami`、聊天 `/whoami` |
| OIDC | `self_hosted` 登入可對接 IdP；角色決定順序：`ark users` 登記 → `rbac.users`（email／sub）→ `groups_claim` 對 `rbac.groups` → `default_role`（`none` 表示拒絕登入）。登入成功與拒絕都寫稽核。 | `[app.rbac]`、`ark users` |
| 服務帳號 | `ark accounts issue|list|rotate|revoke|expiring`；token 只顯示一次，檔案只存 SHA-256，預設 90 天到期，輪替有寬限期。 | `ark accounts` |
| 核准者身分 | 每個核准都記錄是誰、從哪個通道、哪個等級與工具；app server 由認證後的 principal 與其角色注入，用戶端自帶的 `_by`／`_by_role` 會被剝除。 | 稽核 `approval.answer` |
| 雙人覆核（four-eyes） | `[approvals.dual_control]` 依工具名、gate 種類、規則文字或風險等級選出高風險動作，要求 N 位**不同**、且**不是該 session 擁有者**的核准者；可限定角色或名單、設到期；auditor 永遠不能投票；`/yolo`、持久授權、任務信封、smart 審查都不會讓它安靜通過。每次申請、每一票（含被拒的票與理由）、結果、逾期都寫稽核。可選擇同時在 ServiceNow／Jira 開變更單，變更單核准算一票、駁回即拒絕。 | `ark gate list|answer|policy`、ARP `gate.pending`／`gate.answer`，詳見 [review-and-legacy-integration.md](review-and-legacy-integration.md) |
| Session 覆核 | 覆核者把 session 標記 `reviewed`／`flagged`／`cleared` 並附註；擁有者不能覆核自己的 session，auditor 不能標記。標記本身與稽核記錄（不含註記內文，只含其雜湊）分開保存。 | `ark session review`、ARP `session.review.*` |
| 舊式 SSO 前端 | `[app.exposure.proxy_auth]`：Apache `mod_auth_gssapi`（Kerberos SPNEGO）、WAM、mTLS 終結代理把使用者與群組放進標頭；**只有 TCP 對端位於 `proxies` 清單時**才採信，再經同一套 `[app.rbac]` 對應角色。 | 白皮書本節、`review-and-legacy-integration.md` |
| 系統層受管設定 | `/etc/ark/managed.toml` 與 `managed.d/*.toml` 是使用者設定之下的預設層；`[managed] locked` 列出的鍵在 user、project、`--set` 之後被強制回系統值。檔案須 root 擁有且 group／other 不可寫，否則拒絕載入。可鎖：風險 preset、允許模型、工具政策、出口主機、稽核、法遵。 | `ark config managed` |
| 資料分級 | `[compliance] data_class` 搭配 `[compliance.classes]` 限制可用模型（類別未定義時 fail closed）。 | `Config::validate` |

## 5. 稽核與可觀測性

- **統一事件流**：`<data>/audit/events.jsonl`，每筆含 `seq、ts、kind、actor{kind,name,role,ip}、target、outcome、session、detail、prev、hash`。涵蓋 app 請求決策、登入、token 發行／輪替／撤銷、設定變更、核准、gate 決策、使用者登記異動、保留與保全、匯出、預算告警。
- **防竄改**：SHA-256 雜湊鏈、`flock` 序列化多程序寫入、超過 `[audit] rotate_mb`（預設 64）自動輪替並將封存段改為 0400 加 `.seal`。`ark audit verify [--anchor HASH]` 能偵測改欄位、刪行、重排、截尾、封存段被改、seal 缺失。**限制**：能以相同 uid 執行的程序可以整條重寫；對策是匯出到外部 SIEM（每筆帶 hash）並用 `--anchor` 比對。
- **簽章封存**：設 `[audit] seal_key`（`ark audit seal-key` 產生 Ed25519 種子）後，每個輪替段的 seal 都會被簽章（`.sig`）；設 `[audit] tsa_url` 時再向 RFC 3161 時戳機構取得時戳權杖。稽核人員只需公鑰（`[audit] seal_pubkey` 或 `ark audit verify --pubkey … --require-signed`）。**限制**：簽章金鑰若放在被稽核的主機上，能讀到它的人也能偽造簽章——金鑰應放在另一個帳號或 HSM 簽章服務；ark 檢查時戳權杖的狀態、訊息摘要與 nonce，但不驗證 TSA 的 CMS 憑證鏈（請以 `openssl ts -verify` 驗證）。
- **匯出**：syslog（RFC 5424；UDP、TCP octet counting〔RFC 6587〕、TLS〔RFC 5425，可指定私有 CA〕、unix socket），訊息格式可選 JSON（rfc5424）、CEF（ArcSight）、LEEF 1.0（QRadar），可同時設多個具名 syslog sink；Splunk HEC、OTLP/HTTP logs。各 sink 獨立游標，至少一次，斷線不丟。
- **稽核報告**：`ark audit report --from --to --format md|html|json`（ARP `audit.report`）把一段期間的登入、權限與身分異動、核准（含核准者與申請者）、被拒動作、設定變更、session 覆核整理成一份文件，附整條鏈的驗證結果與 head hash。產生報告本身也寫稽核。
- **指標與就緒**：`/metrics`（Prometheus）、`/ready`、`ark health --ready`、`ark health --nagios`（Nagios／Icinga 外掛格式與 exit code）；`[alerts] targets` 可加 `snmp://community@nms` 送 SNMPv2c trap 給舊式 NMS。
- **個資**：`[compliance.pii]` 可在寫入前遮罩 email、電話、Luhn 驗證的卡號、美國 SSN、台灣身分證、（選配）IPv4；匯出預設遮罩。稽核記錄的自由文字一律遮罩，身分欄位不遮。daemon 自身 stderr log 未遮罩。
- **保留與保全**：`[compliance.retention]` 分別設 sessions、audit、broker、logs、exports 天數；daemon 每小時執行；`ark retention hold add` 建立法律保全，保全範圍不被清除；稽核只刪最舊的封存段，鏈保持可驗證。
- **電子取證**：`ark ediscovery export` 產生遮罩後的 session JSON、`manifest.json`（每檔 sha256、查詢條件、當下稽核 head）與保管鏈；`ark ediscovery verify` 重算。
- **用量**：`ark usage --by user|team`、`[quotas]`（滿額結束該回合）、`[alerts]` 推送到聊天或 webhook。

## 6. 資料流（什麼會離開主機）

| 資料 | 去哪 | 由誰決定 | 如何限制 |
|---|---|---|---|
| 提示、檔案內容、工具輸出（送給模型的上下文） | 你設定的模型供應商端點 | `[model]`、`[providers.*]` | `model.allow`（可被 `/etc/ark` 鎖定）、`data_class`、`base_url` 指向內網模型、`government` 模式拒絕中國境內端點 |
| 聊天訊息 | 你啟用的聊天平台 | `[channels.*]` | 隱私告知訊息 `privacy_notice`、AI 標示 `ai_label`、通道使用者登記與角色 |
| 稽核事件 | 你設定的 syslog／Splunk／OTLP | `[audit.export.*]` | 秘密以 `{{secret:…}}` 引用，未解析不送出 |
| 版本檢查／更新 | 發佈來源（預設 GitHub release） | `ark update` | 驗 `SHA256SUMS`，設 `[update] verify_key` 後強制驗 Ed25519 簽章；套件安裝的 ark 不自我更新 |
| 遙測 | 你設定的 collector | `[telemetry]`，預設**關閉** | 開啟後只有三種無內容事件，字串先遮罩並限長 |
| 除錯包 | **不上傳**；`ark doctor --bundle` 只產生本機 tar.gz | 使用者 | 去識別（主機名、帳號、路徑、IP、MAC、email）；`ARK_DEBUG_SHARE=off`、`/etc/ark/no-debug-upload` 可禁止貼上傳 |

## 7. 供應鏈與發佈

| 項目 | 做法 |
|---|---|
| 二進位 | musl 靜態連結（CI 以 `check-binary.sh` 斷言）；gnu 版 glibc ≥ 2.28 即可。 |
| 完整性 | 發佈目錄含 `SHA256SUMS` 與 Ed25519 簽章 `SHA256SUMS.sig`（金鑰為 CI secret）；`verify-release.sh` 依序驗簽章、逐檔雜湊、無額外檔案、SBOM 合法。簽章金鑰須由使用者以**帶外**方式取得，隨發佈附的公鑰只能偵測損毀。 |
| SBOM | SPDX 2.3 JSON，來源為 `Cargo.lock`，可重現（固定時間戳、排序）。範圍僅 Rust crate，不含瀏覽器擴充或 npm 工具。 |
| 可重現建置 | `repro-check.sh` 兩個不同路徑建置並比對雜湊；正式程式不內嵌建置目錄。 |
| 來源證明 | GitHub build attestation（SLSA provenance），`gh attestation verify`。 |
| 套件 | `.deb`／`.rpm` 由同一份二進位以 nfpm 產生，納入 `SHA256SUMS`；apt／yum 套件庫以 GPG 簽章（套件與中繼資料）；離線包含整個已簽章的發佈目錄。 |
| 容器映像 | debian、UBI 9、distroless 三種基底，amd64／arm64 原生建置，BuildKit SBOM 與 max provenance，cosign keyless 簽章（以 digest）。 |
| 依賴治理 | `cargo deny`、`DEPENDENCY-REVIEW.md` 流程；工作樹與全歷史秘密掃描（`tools/secret-scan.py`）。 |

## 8. 服務加固（系統服務）

單元檔由 `ops/service.rs::render_unit` 產生，包含：專用帳號 `ark`、`StateDirectory=ark`、`UMask=0077`、`NoNewPrivileges`、`RestrictSUIDSGID`、`LockPersonality`、`SystemCallArchitectures=native`、`RestrictRealtime`、`PrivateTmp`、`ProtectSystem=full`、`ProtectKernelTunables/Modules/Logs`、`ProtectControlGroups`、`ProtectClock`、`KillMode=mixed`、重啟風暴偵測。**刻意不設**：`MemoryDenyWriteExecute`（會弄壞 Node/V8 bridge）、`ProtectHome`、`RestrictNamespaces`（ark 啟動的沙箱需要）。舊 systemd（RHEL／CentOS 7 的 219）會自動降級：不認得的指令被省略，`StartLimit*` 移到 `[Service]`；CentOS 7 容器實測 `systemd-analyze verify` 無警告。

## 9. 已知限制（請務必讀）

1. **模型可能做錯事。** 防線針對的是危害，不是正確性；tier 0／1 的錯誤（例如在沙箱內改錯檔）會被放行並記錄，靠 checkpoint 與快照回復。
2. **同 uid 的程序等同擁有者。** 能以 `ark` 帳號執行程式的人，可讀 vault 解密後的記憶體、重寫稽核檔（鏈可驗但無法阻止整條重寫）。外部 SIEM 副本與放在別處的封存簽章金鑰是解法。同理，雙人覆核防的是網路上的使用者（SSO、token、聊天身分）；擁有 daemon 的本機帳號可以透過 unix socket 以任意名義作答，等同系統管理員。
3. **金鑰庫的降級。** 沒有 keyring、TPM、密語或 `ARK_VAULT_KEY` 時，退回 0600 的明文 `secrets.toml`（`ark secrets backend` 會明說）。系統服務請設 `ARK_VAULT_KEY`（systemd `LoadCredential`）或密語檔，並可用 `ARK_VAULT_REQUIRE_ENCRYPTION=1` 讓它在無金鑰來源時直接失敗。
4. **沒有 microVM 也沒有 namespace 沙箱的主機**（例如不允許 user namespace 的容器）：agent 在主機上執行，會明確標示 `NOT ISOLATED`。在 Kubernetes 上請改用 microVM 節點或把 pod 本身當隔離邊界。
5. **語意型攻擊**（記憶或文件裡的誘導文字）無法靠掃描完全抓到；以降權與稽核降低影響。
6. **靜態分析不是證明。** 指令與 effects 分類器可能漏判新式寫法；因此有第二層（沙箱、出口、核准）。
7. **範圍。** 高可用與集中管理有，但有前提：`[ha]` 讓多個 `arkd` 共用一個資料目錄（NFS、共享磁碟），以租約＋fencing token 選出唯一 leader，其餘為 standby（`ark ha status|stepdown`）；`[workers]` 把回合分派到 worker 程序（`ark workers status|dispatch`）；`ark cluster` 是多節點主控台（節點登錄、全節點檢視、以 Ed25519 簽章下發受管政策，節點只接受 `[managed] cluster_key` 驗得過且版本較新的政策）。**限制**：HA 依賴共享儲存本身的可用性與一致性（沒有內建複寫、沒有跨資料中心的多叢集）；不共用儲存的節點要由管理員登錄 URL 與讀取 token；沒有內建 DLP 產品；`/etc/ark` 以外的主機組態仍需你的組態管理（Ansible、Helm 已提供範例）。
8. **文件性質。** 沒有第三方滲透測試報告或認證可附；`docs/risk-assessment.md` 為自評。

## 10. 部署者責任

主機作業系統更新與 CIS 類加固、網路分段與出口代理、IdP 與 MFA、TLS 憑證、備份與還原演練（`/var/lib/ark`）、模型供應商的資料處理協議（是否用於訓練、保存期限、地區）、聊天平台的條款、SIEM 的保存與存取控制、對使用者的隱私告知。

## 11. 回報漏洞

見 [../SECURITY.md](../SECURITY.md) §7。請附 `ark doctor --bundle` 產生的去識別除錯包與重現步驟；不要貼任何 `{{secret:…}}` 的實際值。
