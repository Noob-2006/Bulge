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
| 5 | `ark-memory` | core, kernel, tools | 記憶、wiki、向量回想 |
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
