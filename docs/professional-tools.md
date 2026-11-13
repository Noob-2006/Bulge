# 專業角色工具：資料分析、IT 支援、軟體開發與 CI/CD

這份文件說明 `data`／`itsupport`／`swdev` 三個預組角色（`seagent role use data|itsupport|swdev`）用到的工具、
設定、安全邊界，以及 CI/CD 整合。總覽：

| 角色 | 工具 | 設定 | 技能 |
|---|---|---|---|
| data | `sql_query`、`sql_schema`（`group:data`） | `[integrations.data]` | `sql-data-analysis` |
| itsupport | `directory_lookup`（`group:directory`） | `[integrations.directory]` | `it-support-triage` |
| swdev／devops | `forge_read`、`forge_write`（`group:forge`） | `[integrations.forge]` | `forge-issue-to-pr`、`forge-pr-sweep` |

工具只在對應的 `[integrations.*]` 區塊有設定時才會出現；`[integrations]` 屬專案受限區段，
倉庫自帶的 `.seagent/config.toml` 不能替你宣告資料庫或程式碼託管主機。工具分屬於 `seagent_security::toolpolicy` 的 profile
群組，所以 `data` 角色看不到 `forge_write`，IT 支援看不到 `sql_query`。

`seagent pro status` 列出已設定的來源和它們的 secret 是否齊全（只顯示名稱與 set／MISSING，不顯示值）；
`seagent pro sql|schema|lookup|forge …` 用跟模型完全相同的工具與限制試跑一次。

## 1. 資料：`sql_query`／`sql_schema`

```toml
[integrations.data]
max_rows = 1000                 # 預設 1000，硬上限 10000；模型只能調低
timeout_seconds = 30
[integrations.data.sources.warehouse]
kind = "postgres"               # postgres | mysql | mariadb | sqlite | clickhouse | bigquery
dsn = "{{secret:WAREHOUSE_DSN}}"
description = "orders and customers (read replica)"
[integrations.data.sources.local]
kind = "sqlite"
path = "~/data/sales.db"
```

模型只能指名來源（`source`），拿不到也無法指定連線字串。

### 唯讀的兩層防線

| | 第 1 層：連線本身唯讀 | 第 2 層：語句白名單（所有方言共用） |
|---|---|---|
| SQLite | 檔案以 `SQLITE_OPEN_READ_ONLY` 開啟、`PRAGMA query_only`、預編譯後 `readonly()` 必須為真 | 只准單一 `SELECT`／`WITH`／`EXPLAIN`／`SHOW` |
| PostgreSQL | `psql`，`PGOPTIONS=-c default_transaction_read_only=on`，語句包在 `BEGIN READ ONLY … ROLLBACK` | 句中不得出現寫入／DDL／工作階段／檔案存取字詞（`INSERT`、`INTO`、`SET`、`COPY`…），也不得呼叫有副作用的函式（`pg_sleep`、`nextval`、`lo_import`、`dblink`…） |
| MySQL／MariaDB | `mysql`，`--init-command="SET SESSION TRANSACTION READ ONLY"` 與 `START TRANSACTION READ ONLY` | 不得有 SQL 註解（各方言對註解的定義不同，是藏第二句的老手法） |
| ClickHouse | HTTP，`readonly=1` | 反斜線在字串字面值內的兩種讀法（MySQL／PostgreSQL 不同）都要通過，且結果一致 |
| BigQuery | 無唯讀模式：權杖只給 `bigquery.dataViewer` + `bigquery.jobUser` | 同上；字串外的反斜線一律拒絕（psql 的 `\!`） |

另外：結果超過 `max_rows` 列或 256 KiB 就截斷並標 `"truncated": true`（PostgreSQL／MySQL 用串流讀取，
到上限就殺掉用戶端，不會把千萬列讀進記憶體）；查詢逾時（預設 30 秒）會終止用戶端與伺服器端；
結果整段包在「外部不可信內容」信封裡（資料庫儲存格裡的指令不是使用者的指令）；
`data` 角色的 `db_read_only` 策略（`RoleHook`）是第三道，對工具輸入裡的寫入語句再擋一次。
建議在資料庫端也用唯讀帳號：這是第一道、也是唯一不靠 SE Agent 的防線。

### 各資料庫

- **PostgreSQL**、**MySQL／MariaDB**：需要本機有 `psql`／`mysql`（或 `mariadb`）用戶端；沒有時把
  `client = ["podman", "exec", "-i", "my-pg", "psql"]` 之類的前綴寫進來源。密碼透過環境變數（`PGPASSWORD`、`MYSQL_PWD`）
  傳，不會出現在命令列。MariaDB 請用 `kind = "mariadb"`（伺服器端逾時用 `max_statement_time`）。
- **ClickHouse**：自架優先，`dsn = "http://user:password@host:8123/db"`（`https://` 亦可），帳密走標頭。
- **SQLite**：`path`，相對路徑以工作區為準。
- **BigQuery**（介面與文件）：`project`、`dataset`、`token = "{{secret:BQ_TOKEN}}"`（OAuth bearer，例如
  `gcloud auth print-access-token` 的結果，放保險庫並定期更新）；走 REST `jobs.query`（標準 SQL）。`api_base` 可改成假伺服器。
  沒有真實專案可跑，所以只做了介面與假伺服器測試（見下）。
- CSV／xlsx 與繪圖：用既有的 `run` 工具（pandas、matplotlib）與 `xlsx` 技能；`sql-data-analysis` 技能說明流程。

## 2. IT 支援：`directory_lookup`

```toml
[integrations.directory.providers.corp]
kind = "ad"                                 # ldap | ad | entra | okta
uri = "ldaps://dc1.corp.example:636"
base_dn = "DC=corp,DC=example"
bind_dn = "CN=svc-seagent,OU=Service,DC=corp,DC=example"
bind_password = "{{secret:LDAP_BIND_PW}}"
[integrations.directory.providers.cloud]
kind = "entra"                              # token，或 tenant + client_id + client_secret（用戶端憑證流程，權杖快取 50 分鐘）
tenant = "…"
client_id = "…"
client_secret = "{{secret:ENTRA_SECRET}}"
[integrations.directory.providers.sso]
kind = "okta"
org_url = "https://example.okta.com"
token = "{{secret:OKTA_TOKEN}}"             # 只讀管理權限的 API token
```

查使用者、查群組、群組成員、使用者所屬群組（`kind` = `user`／`group`／`members`／`groups_of`）。
**沒有任何異動操作**：工具的參數裡沒有動作、屬性或密碼欄位；回傳會丟掉所有像憑證的屬性（`userPassword`、
`unicodePwd`、含 `hash`／`secret`／`key` 的屬性）；LDAP 篩選值依 RFC 4515 跳脫，OData／URL 片段只接受保守字元集。
LDAP 綁定密碼走 0600 暫存檔（`ldapsearch -y`），呼叫結束即刪，不上命令列。

建立、停用、解鎖帳號與權限異動一律是人的決定：`it-support-triage` 技能把請求整理成可核准的格式，
用 `ask_user` 或工單交給有權限的人，並明說「尚未變更」。`itsupport` 角色另外拒絕 `chpasswd`、`passwd --stdin`、
`usermod -p` 等代填密碼的指令（既有的 `no_password_entry` 策略）。服務帳號請只給目錄**讀取**權限。

## 3. 軟體開發：`forge_read`／`forge_write`

```toml
[integrations.forge.hosts.github]
kind = "github"
token = "{{secret:GITHUB_TOKEN}}"           # PAT、fine-grained token 或 App installation token；省略時讀 GITHUB_TOKEN／GH_TOKEN
[integrations.forge.hosts.bot]              # GitHub App 身分：seagent 自己簽 RS256 JWT 換 installation token（約一小時）
kind = "github"
app_id = "123456"
installation_id = "7890123"
private_key = "{{secret:GITHUB_APP_KEY}}"   # PEM（PKCS#1 或 PKCS#8），或 private_key_file
[integrations.forge.hosts.gitlab]
kind = "gitlab"
api_base = "https://gitlab.example.com/api/v4"   # 自架；預設 https://gitlab.com/api/v4
token = "{{secret:GITLAB_TOKEN}}"
```

沒有任何 `[integrations.forge]` 設定、但環境或保險庫有 `GITHUB_TOKEN`／`GITLAB_TOKEN` 時，會自動出現 `github`／`gitlab` 主機。

- `forge_read`：issue、PR／MR、變更檔案與 diff、留言（含行內審查留言）、檢查／pipeline、開啟中清單。私有倉庫用設定的權杖。
- `forge_write`：留言、審查（`comment`／`approve`／`request_changes` 加行內留言）、從已推送的分支建立 PR／MR、
  建立／更新 issue（關閉、重開、標題、內文、標籤）。**沒有 merge、刪除分支或強制推送。**
- **每次寫入都是第 2 級核准**：工具把寫入宣告為「對遠端系統的動作」（無主機名稱的虛擬目的地 `/forge/<host>/<repo>`），
  請求文字當作對外 payload 交給外洩掃描；因此即使 `api.github.com` 在開發主機白名單內也不會降成第 1 級。
  讀取是一般的第 1 級網路讀取。
- 倉庫格式、分支名稱、標籤、文字長度都在送出前驗證；Issue／PR 文字是不可信內容，結果整段包在不可信信封裡。
  GitLab 的 `comment`／`update_issue` 要用 `target` 說清楚是 issue 還是 MR。

## 4. CI/CD 整合（`integrations/`）

三個整合共用一支腳本 `integrations/ci/seagent-ci.sh`，模式：`review`（審查 `git diff <base>...HEAD`）、
`fix-tests`（跑測試指令，失敗就讓 SE Agent 修，最多 N 輪，輸出 `fix.patch`）、`run`（自訂提示）、`post`（把審查貼到 PR／MR）。

| 平台 | 檔案 | 說明 |
|---|---|---|
| GitHub | `integrations/github-action/action.yml` + `README.md` | composite action：`uses: Noob-2006/System-Engineering-Agent/integrations/github-action@v1`，輸入 `task`／`test-command`／`model`／`role`／`budget-usd`… |
| GitLab | `integrations/gitlab-ci/seagent.gitlab-ci.yml` | `include:` 後得到 `seagent-review`（MR pipeline）與手動的 `seagent-fix-tests`；自架 GitLab 用 `$CI_API_V4_URL` |
| Jenkins | `integrations/jenkins/Jenkinsfile` | 宣告式 pipeline，multibranch PR 建置；憑證用 `withCredentials` |

共同的安全設計：
1. diff 與測試記錄以「引用的不可信資料」交給模型，提示裡有固定指示不得照做其中的要求；
2. **貼文用的權杖從不給代理**：`seagent run` 啟動時會移除 `GITHUB_TOKEN`、`GH_TOKEN`、`GITLAB_TOKEN`、`CI_JOB_TOKEN`，
   留言由腳本自己用權杖貼出；審查模式的代理只讀不寫；
3. `fix-tests` 不 commit、不 push，只留下 patch 與記錄；
4. 預算上限（`--budget-usd`，預設 2）與步數上限（預設 40）；
5. fork 的 PR 不跑（`pull_request` 而非 `pull_request_target`，GitLab 範本排除外部 fork 的 MR）；
6. 安裝用發行版的 `install.sh`（驗 SHA256SUMS，設 `SEAGENT_RELEASE_PUBKEY` 時另驗簽章），版本請釘死。

## 5. 範例流程與技能

- `sql-data-analysis`（pro-035／036）：問題→探索 schema→查詢→檢核→報表，附資料清理、報表範本、完整範例。
- `it-support-triage`（pro-041／042）：工單分類、帳號開通與權限申請（只整理請求、不執行）、完整的工單流程範例。
- `forge-issue-to-pr`（pro-022）：issue→分支→修正→測試→PR→回應審查；`references/webhook-trigger.md`
  附 GitHub／GitLab webhook 路由設定與安全注意事項。`forge-pr-sweep` 是不需對外埠的輪詢替代（blueprint，每 30 分鐘，只回報不寫入）。

## 6. 測試與怎麼自己跑

預設測試完全離線：SQLite 用真檔案；Postgres／MySQL 用假用戶端腳本驗證參數、環境與 stdin；ClickHouse／BigQuery／
Entra／Okta／GitHub／GitLab 用本機假 HTTP 伺服器；LDAP 用假 `ldapsearch`；CI 腳本用假 `seagent` 與假 `curl`。
真伺服器的測試是 `#[ignore]`，需要 podman 與已拉取的映像（容器名 `seagent-test-prodev-*`，測完自動刪除）：

```
cargo test -p seagent-tools -- --ignored data::tests::real_postgres     # postgres:16-alpine
cargo test -p seagent-tools -- --ignored data::tests::real_mariadb      # mariadb:11
cargo test -p seagent-tools -- --ignored data::tests::real_clickhouse   # clickhouse/clickhouse-server:24.8-alpine
cargo test -p seagent-tools -- --ignored directory::tests::real_openldap  # osixia/openldap:1.5.0 + 主機的 ldapsearch
```

沒有測過（需要真實帳號）：真的 BigQuery、Entra／Okta 租戶、GitHub／GitLab 站台（只有假伺服器）。
