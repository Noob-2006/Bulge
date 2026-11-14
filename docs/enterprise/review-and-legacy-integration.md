# 審查、稽核紀錄與舊系統整合

給資安、稽核與 IT 整合人員：雙人覆核、session 覆核、auditor 角色、稽核報告與簽章封存，以及和企業既有系統（舊式 SIEM、Kerberos 前端、SQL Server／Oracle／ODBC、Nagios／SNMP、ServiceNow／Jira）的接法。每一節最後都有「限制」。

## 1. 雙人覆核（four-eyes）

```toml
[approvals.dual_control]
enabled = true
min_approvals = 2                   # 需要幾位「不同的人」
tools = ["shell", "sql_query"]      # 工具名（fnmatch）
gates = ["privilege"]               # gate 種類：privilege | egress | exec | write
rules = ["*sudo*", "*DROP*"]        # 對 gate 規則／理由文字的 glob
min_tier = 3                        # 風險等級 ≥ 此值一律適用（0 = 不用）
approver_roles = ["admin"]          # 可投票的角色（空 = 任何可核准的人）
approvers = ["sso:ciso@corp.example"]  # 額外列名可投票者
expiry_secs = 3600                  # 期限內未達票數 = 拒絕
```

- 任一選擇條件命中，該呼叫就跳過所有「安靜放行」路徑（持久授權、`/yolo`、`mode = "off"`、session 記住、任務信封、smart／auto 審查），等待 `min_approvals` 位**不同**核准者。
- **申請者不能核准自己**：申請者是該 session 的擁有者（建立它的 principal、聊天來源或本機使用者）；同一位登記使用者的 SSO 帳號與聊天身分視為同一人（`seagent users link`）。
- auditor 永遠不能投票；一位合格者按「拒絕」即結束。「always／permanent」只算這一次的一票，不會留下持久授權。
- 稽核：`approval.request`（申請者、所需票數、期限）、每張 `approval.vote`（含被拒的票與理由，例如「申請者不能核准」）、`approval.answer`（全部核准者）、`approval.expired`。
- 入口：`seagent gate list [--json]`（顯示進度、已核准者、申請者、期限）、`seagent gate answer <id> once|deny …`、`seagent gate policy`。ARP：見 §8。

**變更單連動**（選用）：

```toml
[approvals.dual_control.change_control]
system = "servicenow"               # 或 jira
url = "https://itsm.corp.example"
user = "seagent-integration"
token = "{{secret:ITSM_TOKEN}}"
poll_secs = 30
# Jira: project = "CHG"、issue_type = "Change"、approved = ["Approved"]、rejected = ["Declined"]
```

每個雙人覆核申請會在 ServiceNow `change_request`（或 Jira 專案）開一張單；輪詢到核准時以 `change:servicenow:CHG…` 的身分投一票（CAB 的票），駁回即拒絕。開單失敗不會擋住申請（人仍可投票），失敗寫 `change.request` 錯誤紀錄。

**限制**：擁有 daemon 的本機 OS 帳號可經 unix socket 以任意名義作答——雙人覆核防的是網路上的使用者，不是系統管理員。等待中的申請只存在 daemon 記憶體，daemon 重啟即視為拒絕。變更單以輪詢判斷（沒有 webhook），延遲最多 `poll_secs`。

## 2. Session 覆核

`seagent session review <id> reviewed|flagged|cleared --note "…"`、`seagent session review list [--status flagged]`、`seagent session review show <id>`。標記以附加方式存在 `<data>/reviews/reviews.jsonl`（最新一筆為現況，`cleared` 撤銷），每次標記寫 `session.review` 稽核（只含註記的 SHA-256，不含內文）。擁有者不能覆核自己的 session；auditor 只能讀。

## 3. auditor 角色

`auditor` 只能呼叫 `read` 等級的方法（不含對話內容）與 `audit.query`、`audit.verify`、`audit.report`、`audit.export`；任何寫入、核准、session 標記、設定或未知方法一律拒絕。測試 `auditor_never_writes_or_approves` 逐一檢查所有已知方法。

## 4. 稽核報告與簽章封存

- `seagent audit report --from 30d [--to 2026-11-01] --format md|html|json [--out FILE] [--pubkey …]`：登入、權限與身分異動、核准（核准者與申請者）、被拒動作、設定變更、session 覆核、匯出與保留；附整條鏈驗證結果與 head hash（HTML 無外部資源、可直接存檔列印）。
- `seagent audit export --format bundle|jsonl|csv|cef|leef [--from 30d] [--to …] [--kind …] [--actor …] [--outcome …] --out FILE`（ARP `audit.export`；主控台「稽核紀錄 → 匯出」）：可帶走查核的匯出。`jsonl` 是每筆紀錄原文（含 seq / prev / hash）；`bundle` 是證據包 ZIP：`records.jsonl`、同期間的 `report.html`、免安裝的 `verify.py`、`README.txt` 與 `manifest.json`（各檔 SHA-256、匯出當下整條鏈的驗證結果與鏈頭、期間、產生器版本、離線驗證步驟）。離線驗證：`python3 verify.py` 或 `seagent audit verify --file records.jsonl`。匯出本身寫一筆 `audit.export`（含檔案 SHA-256）。單次最多 64 MB 紀錄，超過時標示 `truncated` 與續接時間 `next_from_ms`。
- 稽核量：主控台輪詢的讀取（儀表板、裝置清單、即時畫面 frame…）同一身分、同一來源、同一對象每 10 分鐘只寫第一筆（`detail.coalesced` 記上一個視窗合併掉的次數，`detail.subject` 記看了什麼）；寫入與拒絕一律逐筆記錄；`[audit] log_reads = true` 則逐筆記錄所有讀取。
- `seagent audit seal-key [--out FILE]` 產生 Ed25519 種子；設定 `[audit] seal_key = "<檔案或 {{secret:…}}>"`、`seal_pubkey = "ed25519:…"`，daemon 會簽輪替後的每個 seal（`seagent audit seal` 可手動執行）；`[audit] tsa_url` 另向 RFC 3161 時戳機構取得權杖。`seagent audit verify --pubkey ed25519:… --require-signed` 只需公鑰。
- **限制**：金鑰若放在被稽核主機上，取得它的人也能偽造；請放在另一個帳號或 HSM 簽章服務。SE Agent 檢查時戳權杖狀態、訊息摘要與 nonce，不驗 CMS 憑證鏈——請用 `openssl ts -verify -in tsr.der -digest <sha256> -CAfile tsa-ca.pem`（`tsr` 為 `.sig` 檔中的 base64）。

## 5. 舊式 SIEM

```toml
[audit.export.syslog_sinks.arcsight]
address = "tls://arcsight.corp:6514"   # RFC 5425
format = "cef"
ca_file = "/etc/pki/siem-ca.pem"
[audit.export.syslog_sinks.qradar]
address = "tcp://qradar.corp:514"      # RFC 6587 octet counting
format = "leef"
```

CEF：`cs1`=hash、`cs2`=prev、`externalId`=seq、`suser`、`src`、`act`；LEEF 1.0（tab 分隔）：`usrName`、`src`、`cat`、`seagentSeq`、`seagentHash`。兩者都放在 RFC 5424 標頭之後。每個 sink 有自己的游標。**限制**：只有 TLS 伺服器驗證，沒有對 SIEM 的 mTLS 用戶端憑證。

## 6. 舊式 SSO 前端

```toml
[app.exposure.proxy_auth]
enabled = true
proxies = ["10.20.0.5/32"]          # 只有這些 TCP 對端的標頭會被採信（不看 X-Forwarded-For）
user_header = "X-Remote-User"       # Apache：RequestHeader set X-Remote-User %{REMOTE_USER}s
groups_header = "X-Remote-Groups"   # 以 , 或 ; 分隔，經 [app.rbac] groups 對應角色
strip_realm = true                  # alice@CORP.EXAMPLE → alice
```

**限制**：SE Agent 不自己做 Kerberos／SPNEGO（沒有 GSSAPI 函式庫）；實務做法是由 Apache `mod_auth_gssapi`、WAM 或 mTLS 終結代理驗證後轉交。代理必須**覆寫**（不是附加）該標頭，否則用戶端可自帶；`proxies` 不接受任意位址。

## 7. 企業內部資料庫、網路與監控

- **SQL**：`sql_query`／`sql_schema` 新增 `sqlserver`（`sqlcmd`，密碼走 `SQLCMDPASSWORD`，無使用者時用 Kerberos `-E`，`-K ReadOnly` 並在交易中 `ROLLBACK`）、`oracle`（`sqlplus`，帳密在 stdin 的 `CONNECT`，`SET TRANSACTION READ ONLY`）、`odbc`（unixODBC `isql -b`）。敘述檢查拒絕寫入、`WAITFOR`、`EXEC`、`OPENROWSET`、`UTL_HTTP`、`DBMS_PIPE` 等。**限制**：ODBC 沒有通用的唯讀開關（只有 DSN 的 `ReadOnly` 屬性與唯讀帳號）；ODBC 若在連線字串給帳密，會成為 `isql` 參數（同機其他使用者可在行程列表看到），請把帳密放在 DSN 或用 Kerberos；SQL Server 的連結伺服器（四段式名稱）無法由敘述檢查辨識，請用最小權限帳號。
- **企業 Proxy**：`[network] proxy`（含 `http://user:pass@proxy:3128` 的 Basic 認證）、`no_proxy`、`ca_file`（TLS 攔截代理的 CA）早已套用到所有對外 HTTP 用戶端與原始 TLS 連線（`http_client_lint` 測試強制）。**限制**：沒有 NTLM／Negotiate 代理認證；請在本機跑 `cntlm` 或 `px` 轉成無認證的本機代理。
- **監控**：`seagent health --nagios [--warn-pending N]` 輸出 `SEAGENT OK|WARNING|CRITICAL|UNKNOWN - … | perfdata`，exit code 0／1／2／3，可直接當 Nagios、Icinga 或 Zabbix 外部檢查。`[alerts] targets = ["snmp://community@nms.corp"]` 透過 `snmptrap` 送 SNMPv2c trap（OID `1.3.6.1.4.1.32473.1.0.1`，`.1.1` 告警鍵、`.1.2` 文字；`[alerts] snmptrap` 可指定執行檔）。Prometheus 見 `/metrics`。
- **尚未提供**：SMB／CIFS、SFTP／FTPS 檔案工具，SOAP／WSDL 呼叫工具，MQTT／AMQP／Kafka 佇列工具。

## 8. 給 Web UI 的 ARP 方法

| 方法 | 參數 | 回傳 | 權限 |
|---|---|---|---|
| `gate.pending` | — | 陣列；核准項多了 `tier` 與 `dual_control: {required, approvals[], votes[{by,role,approve,at_ms,via}], requester, approver_roles[], approvers[], expires_ms, change_ticket}` | read |
| `gate.answer` | `id`, `answer` | `{ok, final:true}` 或 `{ok, final:false, approvals, required}`；票被拒時錯誤碼 `-32003` 附理由 | approve |
| `gate.policy.show` | — | `{dual_control: …設定…}` | read |
| `session.review.set` | `id`, `status`, `note` | `{session, status, note, by, at_ms}` | approve |
| `session.review.list` | `status?`, `limit?` | 各 session 的現況陣列（新到舊） | read |
| `session.review.get` | `id` | `{session, current, history[]}` | read |
| `audit.report` | `from_ms?`, `to_ms?`, `format?: json\|md\|html` | JSON 報告，或 `{format, text}` | admin、auditor |
