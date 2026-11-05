# 架構：分層、登記點與「不要拆得太細」的規則

這份文件說明 ark 的 crate 依賴方向、功能如何自我登記，以及為了避免程式碼劣化而**由測試強制**的幾條規則。
它對應缺口名單 D 段（D1 登記點集中、D2 依賴方向、D3 反過度細碎、D7 風格）。規則不是願望清單：每一條都由
`cargo test -p ark --test arch_lint` 或 `cargo test -p ark --test test_hygiene` 檢查，違反就會讓測試失敗。

- 建置與 feature flag（精簡執行檔、實測大小）：[BUILD.md](BUILD.md)
- 與上游（Hermes / OpenClaw / opencode）的對照：[parity.md](parity.md)
- 協定（ARP）：[arp.md](arp.md)；通道設定：[channel-guide.md](channel-guide.md)；外掛：[plugins.md](plugins.md)

---

## 1. 分層與依賴方向（D2）

每一層只能依賴**嚴格更低**的層。這條規則讓循環依賴不可能出現，也讓「跨 crate 直接改人家內部」變成編譯期
就得解釋的事。表格的權威版本在 `crates/ark/tests/arch_lint.rs` 的 `LAYERS`；新增一條邊要同時改那裡和這裡。

| 層 | crate | 可以依賴 | 職責 |
|---|---|---|---|
| 0 | `ark-core` | （無） | 介面層：`Tool`、`Provider`、`ExecBackend`、訊息型別、`registry`、`tmp`、`imageevict` |
| 0 | `ark-net` | （無） | 傳輸原語：HTTP/TLS/WebSocket、事件迴圈 |
| 1 | `ark-security` | （無） | 政策：核准、硬底線、URL/SSRF、環境變數清洗、技能掃描 |
| 1 | `ark-vm` | `ark-net` | microVM：供應商偵測、guest 映像、vsock、快照。刻意不連 `ark-tools`／kernel，guest agent 才能很小 |
| 2 | `ark-model` | core, net, security | 供應商實作（Anthropic、OpenAI 相容、Bedrock…）、模型清單、登入 |
| 2 | `ark-tools` | core, net, security, vm | 內建工具（檔案、shell、web、exec 後端） |
| 2 | `ark-browser` | core, net, security | 瀏覽器：CDP 客戶端、設定檔、雲端後端 |
| 2 | `ark-media` | core, net, security | 媒體：影像／影片／音樂生成、TTS/STT、附件理解 |
| 3 | `ark-channel` | core, net, media, security | 聊天平台。對 `ark-media` 的依賴是單向的（附件理解）；`ark-media` 不會提到任何通道。`security` 只有一個用途：通道抓圖／上傳前的位址分類走 `url_safety`（A14），不再自己維護一份私有位址表 |
| 3 | `ark-kernel` | core, model, security | 核心：session、回合執行、閘門、壓縮、子代理 |
| 4 | `ark-plugin` | core, kernel, net, security | MCP／外掛宿主、生命週期 |
| 5 | `ark-skills` | core, kernel, tools, security, plugin | 技能、hub、curator |
| 5 | `ark-memory` | core, kernel, security, tools | 記憶、wiki、向量回想（召回時以 `ark_security::threat` 重新掃描，H8） |
| 6 | `ark-app` | 上面全部（除了 binary 專屬） | 應用層：TUI、surfaces、computer use、cron、節點 |
| 7 | `ark` | 全部 | 執行檔：參數分派、`build`/`build_agent` 組裝、各命令家族模組 |

三條推論，寫下來是為了避免下次又被打破：

1. **`ark-core` 沒有內部依賴**（測試會檢查）。它是唯一的共用語言；把它變成「什麼都放一點」的倉庫，分層就結束了。
2. **跨 crate 的呼叫要有介面**：trait（`Tool`、`Provider`、`ExecBackend`、`ExecChild`）、事件（`EventKind`）或
   純資料型別。需要「繞過介面讀人家的內部狀態」時，正確做法是把狀態搬到較低的 crate，而不是加一條反向依賴。
3. **不連 kernel 的 crate 也讀不到 `Config`**。它們的工具登記改用「binary 內的薄適配層」（例如 `web_cli::register`
   把 `[web]` 表交給 `ark_tools::web`），而不是為了讀一段設定把 kernel 拉進來。

## 2. 登記點：功能自己宣告，核心只收集（D1）

以前每一個新功能都要改 `main.rs`（命令分派）、`ext.rs`、`kernel.rs`、`config.rs`——六個人同時加功能就六次衝突。
現在每個功能在自己的檔案裡宣告，`ark_core::registry` 只負責收集：

| 登記種類 | 宣告方式 | 收集者 | 範例 |
|---|---|---|---|
| 模型工具 | `register_tool_provider(name, order, factory)` | `wire::tools` → `collect_tools` | `ark_skills::host::register`（100）、`ark_memory::host::register`（110）、`web_cli::register`（300/310）、`ark_kernel::kanban::register`（500） |
| CLI 命令家族 | `register_command_route(names, owns, run)` | `main.rs` 的 `dispatch`（一次呼叫） | `ark meet …`（`meetings::register_route`）、`ark browser|screen|computer-use`（`control_cli`）、`ark message …`、`ark kanban …` |
| 設定段驗證 | `register_config_validator("kanban", f)` | `Config::validate` | `[kanban]` 的 `dispatch_interval_secs` / `claim_ttl_secs` / `failure_limit` |
| 生命週期 hook | `ark_kernel::hooks::register_provider(name, order, f)` | `wire::attach` → `hooks::install_all` | Google Meet 的 session-end 掛斷（`meet::register_hooks`） |

規則：

- **登記必須是幂等的**：同一個名字重複登記就是覆蓋。因此 `dispatch()` 和 `wire::tools()` 都可以呼叫
  `registry_init::register()`，測試也不必擔心兩次初始化會讓工具重複出現。
- **`crates/ark/src/registry_init.rs` 是唯一清單，而且一行一個 crate**（不是一行一個功能）。新增工具、命令或
  設定檢查**不該**動到那個檔案；只有「這個 binary 要包含一個新 crate」才需要加一行。
- **一個 provider 失敗不等於工具全失**：`collect_tools` 把錯誤收成警告（`ark: warning: web: …`），其他子系統照常
  登記。這是缺口名單 0 段「不要讓一道防線的失守吃掉整體自主性」在工程層的對應。
- **為什麼不用 link-time 登記（`inventory` 之類）**：它要多一個依賴和 unsafe 的 linker section，只為了省掉一行
  清單；本專案的依賴預算（`Cargo.toml` 裡每條依賴都寫了理由）優先。

## 3. 反過度細碎（D3）

Hermes 光 `hermes_state_*` 就拆成約 70 個檔案：讀一個流程要跳十幾個檔案，改一個行為要開五個視窗。ark 的規則是
**依職責切，不依函式切**：

| 規則 | 數值 | 強制方式 |
|---|---|---|
| 單檔上限 | 3,000 行 | 超過就必須列在 `crates/ark/tests/arch_baseline.txt`，並註明「要拆成什麼」；拆完必須刪掉那一行，否則測試失敗 |
| 單檔目標 | 300–1,500 行 | 文件慣例（review 時看） |
| 一個職責的檔案數 | ≤ 5 個，除非每個檔案平均 ≥ 150 行 | `arch_lint::no_responsibility_is_split_into_tiny_files`：目錄下超過 5 個 `.rs` 且平均不到 150 行就失敗 |
| 太小的檔案 | 少於 100 行且只被一處使用者要併回母模組 | review 慣例；上一条的平均值規則會抓到成群的碎檔 |

目前的例外（都寫在 baseline 裡，附上要拆成的形狀）：`ark-channel/src/email.rs`、`ark-channel/src/yuanbao.rs`。
`main.rs` 在這一輪從 3,289 行降到 3,000 行以下：`ark session …` 搬去 `session_cli.rs`、`ark mcp …` 搬去 `mcp_cli.rs`。

## 4. 風格一致性（D7）

上百個 agent 分頭寫的程式碼需要少數機械規則，其餘靠 review。機械規則由 `arch_lint::style_is_consistent_across_crates` 檢查：

1. **每個非測試檔案在 100 行以上就要有 `//!` 開頭說明**：「這個模組是什麼、對應哪個上游」。沒有上游就寫清楚它自己的設計。
2. **正式路徑不准有 `todo!` / `unimplemented!` / `dbg!`**（`#[cfg(test)]` 之後不算）。沒做完就回傳錯誤，不要讓它上線。
3. **library crate（`crates/ark-*`）不寫 stdout**：警告用 `eprintln!("ark: …")`，資料回傳給呼叫者。既有的 `println!`
   逐檔記在 baseline，只能減少。
4. **錯誤處理**：對外 API 一律 `Result<T, String>`（或專屬錯誤型別再轉字串），在邊界（CLI、工具回傳）才轉成給人看的文字；
   不用 `anyhow`／`thiserror`（依賴預算）。
5. **命名**：工具名 `snake_case`、動詞開頭（`web_fetch`、`memory_search`）；設定鍵用上游同樣的字（`allow_private_urls`、
   `busy_mode`），方便對照 `docs/parity.md`；內部函式用完整的字，不用縮寫（`resolve_redirect` 而不是 `rr`）。
6. **註解寫「為什麼」**：程式碼已經說了做什麼；註解要說為什麼這樣取捨（上游怪行為、平台限制、法規），並在適當時附上
   上游檔案名。

## 5. 測試衛生（D5）

- 測試自己建的暫存目錄用 `ark_core::tmp::TempDir`（`Drop` 會遞迴刪除），不要手寫 `std::env::temp_dir().join(…)`。
  `cargo test -p ark --test test_hygiene` 會擋下新的裸用法；既有的列在 `crates/ark/tests/test_hygiene_allow.txt`
  （只能縮短）。
- 測試不得殺／送訊號給不是它自己啟動的行程，不得讀寫真實的 `$HOME`／`$ARK_HOME`，不得寫 `/tmp`（用 `TMPDIR`）。
- 留下來的暫存目錄可以手動清：`ark system temp-clean --older-than 24`（預設 dry-run，`--yes` 才真的刪，
  只認 ark 測試的檔名前綴、只動 `TMPDIR` 的直接子項、跳過符號連結）。

## 6. 檔案在哪裡

| 想改什麼 | 去哪裡 |
|---|---|
| 新增一個模型工具 | 該子系統的模組（加一個 provider）＋（若是新 crate）`registry_init.rs` 一行 |
| 新增一個 CLI 命令家族 | 該家族自己的模組（`register_command_route`），不要在 `main.rs` 加 `if` |
| 新增一個設定段 | 段落在哪個 crate 就在那裡 `register_config_validator`，並在 `docs/config-example.toml` 寫範例 |
| 新增一個 crate | `Cargo.toml` members ＋ `arch_lint.rs` 的 `LAYERS` ＋ 本文件第 1 節的表格（附理由） |
| 精簡執行檔 | [BUILD.md](BUILD.md)：`--no-default-features` 與 per-platform feature |
| 發佈（SBOM／簽章／重現建置／依賴審查） | [../packaging/release/README.md](../packaging/release/README.md)（檢查清單）與同目錄的腳本 |

## 7. 高可用、共用儲存、worker 擴充與集中管理台（ent-095／096／097／062）

### 7.1 不變的兩件事

1. **每個 session 的 `sessions/<id>/events.jsonl` 仍是唯一真實來源。** HA 不引入第二份 session 狀態：主機、備機、
   worker 都直接讀寫同一個（共用的）資料目錄裡的同一份 JSONL；接手時靠既有的 `Kernel::run → recover()`
   （懸空的工具呼叫、未結束的回合）與 `Daemon::resume()` 續跑，和單機當機重啟走同一條路。
2. **SQLite（`index.db`）只是可重建索引。** 它從 JSONL 衍生，所以每個節點可以有自己的一份：`[ha] index_dir`
   把索引搬到節點本機磁碟（SQLite 的 WAL 需要共享記憶體，放在 NFS 上不安全）。節點換手後索引照游標增量追上，
   壞了就 `ark index rebuild`。

### 7.2 主備＋共用儲存（ent-095、ent-096）

部署形狀：N 個 `arkd` 指向同一個資料目錄（NFS／共用磁碟，或把 `data/` 符號連結到掛載點），各自有本機的
`config/` 與 `run/`（unix socket）。同一時間只有一台是 **leader**：只有它跑排程、目標、通道輪詢、續跑與 worker 池；
其他是 **standby**，只回答唯讀 ARP（`ping`、`session.list/history/view`、`ha.status`、`cluster.*` 的查詢），
會改狀態的方法回 `-32010 standby`，錯誤裡帶 leader 的 `advertise` 位址讓客戶端／負載平衡器改送。

**租約（`crates/ark-kernel/src/ha.rs`）**

- 介面 `LeaseStore { read, swap(expect, new) }`：比較後交換（CAS）。內建 `FsLease`：每個任期一個檔
  `<ha_dir>/term-<epoch>.json`，目前租約＝編號最大的那個。**刻意不用鎖檔**：持鎖的程序若被暫停（SIGSTOP、GC、
  網路分割），所有 standby 都會被它卡死（整合測試一開始就踩到）。搶新任期用 `link(tmp, term-<N>)`——已存在就
  `EEXIST`，是 NFS 上安全的排他建立，等於對 N 做 CAS；續約／釋放只有任期 N 的持有者會改寫 `term-<N>.json`
  （tmp＋fsync＋rename），被罷黜的舊主就算改寫自己的舊任期也無害，因為讀者只看最大編號。物件儲存（S3
  `If-None-Match`／`If-Match`、GCS generation）可以用同一個 trait 實作。
- 租約內容：`node`、`epoch`（**fencing token**，每次換主 +1）、`renewed`（續約計數）、`lease_ms`、`advertise`、
  `host`、`pid`。
- **不依賴跨機時鐘**：standby 不看對方寫的到期時間，而是用自己的單調時鐘觀察 `(node, epoch, renewed)` 有沒有變；
  連續 `lease_secs` 沒變才以 `epoch+1` 搶租約。leader 每 `renew_secs`（預設 lease/3）續約；本機單調時鐘超過
  `lease_secs` 沒續約成功（共用儲存斷線、程序被暫停）就**自行下台**，先於任何 standby 可能接手的時間點。
- 同一台主機上前一個化身（同 node、同 host、pid 已不存在）留下的租約可立即接手，重啟不必等一個租期。
- `ark ha stepdown`（ARP `ha.stepdown`）把租約標成釋放，standby 下一個 tick 就接手（計畫性維護）。

**Fencing**

- `Store::set_fence(f)`：設定後，`SessionLog::append`（以及開啟寫入）每次都先呼叫 `f`；`f` 重新讀共用儲存上的
  租約，`node`／`epoch` 不是自己就回 `StoreError::Fenced`，那一筆**不會寫入**，回合以錯誤結束、釋放 session 鎖。
  因此一台被暫停（SIGSTOP、GC、網路分割）後醒來的舊主機，即使手上還有進行中的模型回應，也寫不進 JSONL。
- 第二道防線是既有的每 session `flock`：本機檔案系統與 NFSv4 都會讓同一 session 同時只有一個寫者；租約
  fencing 處理的是鎖被伺服器回收後（NFS lease 過期）的情形。兩道都在，任何一道失守都不會雙寫。
- worker 程序繼承 leader 的 `ARK_HA_NODE`／`ARK_HA_EPOCH`／`ARK_HA_DIR`，裝上同一個 fence：舊 leader 派出去的
  worker 在換主後同樣寫不進去。

**接手流程**：standby 取得租約 → 安裝 leader 服務（排程、通道、備份、報表、worker 池）→ `resume()` 掃描未完成
的 session，先寫一筆 `Notice`（「ha: node B (epoch N) resumed this session after failover」）再啟動；session 若
仍被舊主機鎖住（`StoreError::Locked`），放入重試集合，每秒再試，直到舊主機被 fence 掉而釋放鎖。
失去租約 → 中斷所有本機執行、停掉 leader 服務與 worker、回到 standby。

**已知限制**：reaper 的程序群組登記檔在共用資料目錄裡，只有 leader 執行清掃（standby 沒有在跑的程序）；跨主機
的 pid 由 `/proc` 啟動時間比對保護，無法證明的項目一律不殺。整份 session 存到物件儲存（不經 POSIX 檔案）尚未實作；
租約層已抽象，事件紀錄的物件儲存後端是下一步。

### 7.3 水平擴充 worker（ent-097，`crates/ark-kernel/src/workers.rs`）

`[workers] count = N` 時，leader 啟動 N 個 worker 程序（預設 `ark worker --internal-worker-ipc`；`command` 可改成
`["ssh", "host2", "ark", "worker", "--internal-worker-ipc"]` 在別台機器跑，前提是同一個共用資料目錄）。沿用既有
的 worker JSONL 協定，加一種請求 `{"type":"run","turnId","sessionId"}`：在 worker 裡續跑一個既有 session（它直接
讀寫共用的 JSONL）。daemon 端：

- `dispatch = "all"`（預設）時 `session.submit`、續跑、`workers.dispatch` 都把 session 排進佇列，交給閒置的 worker；
  `"explicit"` 只派 `workers.dispatch` 指定的。
- worker 執行中的 session 再收到訊息時，daemon 先暫存，回合結束後寫入並再派一次（worker 持有 session 鎖）。
- worker 掛掉（stdout EOF／程序結束）→ 它手上的 session 寫一筆 `Notice` 後重新排隊、派給下一個 worker；worker
  依退避重生。session 本身的恢復仍是 kernel 的 `recover()`。
- 回收：worker 用 `PR_SET_PDEATHSIG` 綁在 worker 池的長壽執行緒上，stdin EOF 也會讓它取消回合並退出；`Pool`
  的 `Drop` 對每個子程序 SIGTERM→SIGKILL→`wait`。daemon 被 SIGKILL 也不會留下 worker。
- 限制：worker 用 `ark worker` 的權限模型（不給特權、不給額外出網，核准一律拒），需要互動核准的工作應留在 leader
  本機跑（`dispatch = "explicit"`）。

### 7.4 集中管理台（ent-062，`crates/ark-kernel/src/cluster.rs`）

- **節點註冊**：每個 daemon（HA 或 `[cluster] enabled`）每 5 秒把自己的快照寫到 `<data>/cluster/nodes/<node>.json`
  （角色、epoch、版本、advertise、執行中的 session、具名代理、worker 數、已套用的政策版本）。共用資料目錄的節點
  因此自動出現在彼此的管理台；不共用儲存的遠端節點由管理員 `ark cluster node add NAME URL --token-secret S` 登記，
  管理台用 `POST <url>/arp` 帶唯讀 token 呼叫對方的 `cluster.self.status`／`session.list`。
- **受管設定下發**：沿用 `/etc/ark` 的 `managed` 機制，加一層「叢集政策」：
  - `/etc/ark/managed.toml` 的 `[managed] cluster_key = "ed25519:…"` 釘住簽章公鑰（root 擁有，使用者改不了），
    可加 `cluster_required = true`（沒有有效政策就拒絕載入設定）與 `cluster_min_version`（防回滾）。
  - 管理員離線簽章：`ark cluster keygen`（種子只存在管理員的 0600 檔）、`ark cluster policy sign policy.toml --version N`
    產生 bundle（政策 TOML、版本、時間、公鑰、Ed25519 簽章，簽的是 `ark-cluster-policy\n1\n<ver>\n<ms>\n<sha256>\n`）。
  - 發佈：`cluster.policy.publish` 存到管理台；**推送** `cluster.policy.push` 用登記的節點 admin token 呼叫對方的
    `cluster.policy.apply`；**拉取**：節點設 `[cluster] console_url`／`console_token`（唯讀 token 即可）定期呼叫
    `cluster.policy.get`；共用資料目錄的節點直接讀發佈檔。不論哪條路，節點都用自己釘住的公鑰驗簽、要求版本嚴格遞增
    後才寫入 `<data>/managed/cluster.json`；載入設定時再驗一次（被竄改就當作不存在並警告，`cluster_required` 時拒絕）。
    政策內容當作 `/etc/ark` 檔案之後的一層 system 預設，`[managed] locked` 取聯集。daemon 的設定在啟動時載入，
    新政策回報 `restart_required`。
- **總覽**：`cluster.status`（節點、HA、所有節點的 session 與代理、政策版本）、`cluster.nodes.list`、
  `cluster.sessions.list`、`cluster.agents.list`；Web UI「叢集」頁；CLI `ark cluster status|nodes|sessions|agents`。
- **RBAC 與稽核**：方法名沿用既有的範圍規則（`*.status`／`*.list`／`*.get` 是唯讀，operator／auditor 可看中繼資料；
  其餘 `cluster.*`、`ha.stepdown`、`workers.dispatch` 未列名＝admin），不另開權限表。登記／移除節點、發佈／推送／
  套用政策、接手／下台都寫進統一稽核流（`cluster.*`、`ha.*` 事件）。

### 7.5 設定

```toml
[ha]
enabled = true
node_id = "arkd-a"          # 預設主機名稱
lease_secs = 10
renew_secs = 0              # 0 = lease_secs / 3
dir = ""                    # 預設 <data>/ha
advertise = "https://arkd-a.corp:8640"
index_dir = "/var/lib/ark-local/index"   # 節點本機的 SQLite 索引

[workers]
count = 4
dispatch = "all"            # 或 "explicit"
command = []                # 預設本執行檔 `worker --internal-worker-ipc`

[cluster]
enabled = true
console_url = "https://console.corp:8640"
console_token = "{{secret:ARK_CONSOLE_TOKEN}}"
pull_secs = 300
```
