# 跨平台改造計畫（Windows / macOS / Linux 各發行版 / Android / iOS）

目標：一套程式碼，五個平台都能用；同一區域網路的裝置能自動找到彼此並安全配對；
使用者下載一個檔、點開就裝好，設定精靈是圖形介面，不需要碰終端機。

## 不變的原則

1. **Linux 的功能與性能不變。** 既有的 Linux 程式碼路徑保留在 `cfg(unix)` / `cfg(target_os = "linux")`
   後面，行為逐位元相同；其他平台是新增的分支，不是把 Linux 改成最小公約數。
2. **缺的功能找替代品，不是拿掉。** 每個 Linux 專屬機制都要有該平台上的對應實作（見下表）。
3. **隔離等級一律明示、不靜默降級**（沿用 SECURITY 既有原則）：某平台只能提供較弱的隔離時，
   `seagent doctor`、`seagent tools explain` 與設定精靈都要說清楚。
4. **依賴預算照舊**（`packaging/release/DEPENDENCY-REVIEW.md`）。平台 API 用 `windows-sys`（只開需要的 feature）
   與既有的 `libc`；圖形外殼放在獨立 crate `seagent-desktop`，不進 agent 本體的依賴樹。
5. **分層規則照舊**（`docs/ARCHITECTURE.md`）：平台抽象放在 `seagent-core::platform`，其他 crate 只呼叫它。

## 平台對照表

| 功能 | Linux（不動） | Windows | macOS | Android | iOS |
|---|---|---|---|---|---|
| microVM 隔離 | Firecracker / QEMU+KVM | Hyper-V（HCS）或 QEMU+WHPX；VirtualBox 備援 | Virtualization.framework；QEMU+HVF 備援 | AVF（pKVM，支援的機型）；否則交給配對主機 | **不支援**（見下），以 WASM 直譯器沙盒替代 |
| 程序沙盒 | bwrap / Landlock / seccomp | AppContainer + Job Object + restricted token | Seatbelt（sandbox-exec 設定檔） | App 沙盒 + isolated process | `wasm`：wasmi 直譯 WASI 工具（App 沙盒內） |
| gVisor | gVisor | 改跑在上列 VM 內 | 同左 | 同左 | — |
| 容器 | docker / podman | Docker Desktop / Podman machine | 同左 | — | — |
| 常駐服務 | systemd / OpenRC | Windows 服務或工作排程器 | launchd（LaunchAgent） | Foreground Service | App 行程內（`seagent::embed`）前景 + BGProcessingTask |
| 本機 IPC | unix socket | named pipe（僅擁有者 ACL） | unix socket | unix socket（app 私有目錄） | 無控制 socket；App Server 綁 127.0.0.1 |
| 程序群組 / 訊號 | pgid / signal / PDEATHSIG | Job Object（KILL_ON_JOB_CLOSE）+ CtrlHandler | pgid / signal + kqueue 監看父程序 | pgid / signal | — |
| PTY | posix_openpt | ConPTY | posix_openpt | posix_openpt | — |
| shell | bash | 有 bash（Git Bash/MSYS）用 bash，否則 PowerShell | bash/zsh | `/system/bin/sh` + 內建 busybox | 內建 POSIX 式 shell 直譯器 + uutils coreutils（WASI） |
| 檔案權限 0600/0700 | chmod | 擁有者 DACL | chmod | chmod | 資料保護等級 |
| 秘密保管 | systemd-creds(TPM) / libsecret | DPAPI / Credential Manager | Keychain | Android Keystore | Keychain |
| 鍵鼠 / 螢幕 | xdotool / ydotool / Xvfb | SendInput / DXGI 擷取 | CGEvent / ScreenCaptureKit | AccessibilityService / MediaProjection | — |
| 錄音 / 通知 | pw-record / dunst | WASAPI / Toast | AVFoundation / UserNotifications | 系統 API | 系統 API |
| syslog | /dev/log | Windows Event Log | os_log / UDP syslog | logcat | os_log |

### Windows：路徑、shell 與外部程式（原生 Windows 測試後的決定）

- **給模型看的路徑**：工作區內的**相對路徑一律用 `/`**（`src/a.rs`，不是 `src\a.rs`）：glob / grep /
  read / write / edit / patch 的輸出與 patch 摘要都經 `seagent_tools::util::display_path` →
  `seagent_core::platform::layout::model_path`。模型與 patch 格式都假設 `/`，Windows 的檔案 API 也接受 `/`。
  **絕對路徑保持原生寫法**（`C:\Users\…`，例如溢出檔、工作區外的檔案），因為使用者會拿去貼上或開啟。
  Linux / macOS 上 `model_path` 就是 `p.display()`，輸出逐位元不變。同步到遠端 POSIX 沙盒的 tar 條目也一律 `/`；
  工作區外的 Windows 絕對路徑在遠端落在 `/c/…`（MSYS / WSL 慣例）。
- **交給 shell 的路徑**：`shell::path_arg` / `path_str` —— Unix 不變；Windows 去掉 `\\?\`，shell 是 bash 時改成
  `C:/…`（MSYS bash 會吃掉 `C:\…` 的反斜線）。cron 腳本、webhook 腳本、hook 命令都走它。
- **設定裡的程式名**：`layout::program_command`（MCP / LSP / ACP / 模型 runtime / link processor / ops run）——
  Unix 就是 `Command::new(name)`；Windows 走 PATHEXT（npm 的 `.cmd` shim）、`python3`/`python` 指 `py -3`
  （不是會印「Python was not found」並以 9009 結束的 Store 別名）、`sh`/`bash` 指 Git Bash（不是 WSL 的 `bash.exe`），
  PATH 上找不到的 POSIX 工具名（`cat`、`grep`、`false`…）改用 Git for Windows / MSYS2 附的 `usr\bin`。
  Git Bash 腳本裡的 `python3`：PATH 上只有 Store 別名時，`%LOCALAPPDATA%\seagent\shims` 放一個轉給 `py -3` 的
  `python3`/`python` 腳本，`shell::command` 與 `run` 工具把它放在 PATH 最前面。
- **連線**：主機名的每個解析位址依序嘗試（Windows 的 `localhost` 先給 `::1`，很多服務只聽 127.0.0.1）；
  第一個位址仍最先試，原本能連的設定行為不變。
- **交給子程序的 log 檔**：`proc::open_child_log` —— Windows 不用 append-only handle（缺 `FILE_WRITE_DATA`），
  否則 Git Bash 一啟動就以 1 結束、沒有任何輸出（detached job、AppContainer detached、seagentd 服務 log、Meet bot）。
- **AppContainer 內的 shell**：MSYS 執行階段在 AppContainer / 低完整性下無法建立 `\BaseNamedObjects\msys-*`
  （`0xC0000022`），所以主機 shell 是 Git Bash 時，沙盒命令改用 Windows PowerShell，並在 backend 說明、
  shell 工具的提示（`exec::local::shell_note`）與腳本外殼中照實反映：PowerShell 腳本沒有 `eval`/`unset`，
  缺少的命令照 bash 的格式回報（`x: command not found`、exit 127，失敗提示照常適用）；
  `SEAGENT_APPCONTAINER_SHELL` 可指定其他 shell。AppContainer 讀不到工作區的上層目錄，PowerShell 因此停在 `C:\`
  且 `Set-Location` 會被拒，所以腳本先把工作區掛成 `SeagentWs:` PSDrive 再切過去。真實測試：`SEAGENT_REAL_TESTS=1 cargo test -p seagent-tools real_backend_appcontainer -- --ignored`。
- **已知限制（MSYS 的命令列展開）**：MSYS / Cygwin 程式會自己對 Windows 命令列中「沒加引號」的參數做 glob 與
  大括號展開（不含空白的 `[{"a":1,"b":2}]` 會被拆開）。`MSYS=noglob` 不能用——它連引號處理也關掉，`bash -c '…'`
  的腳本會被拆成單字。要把這類 JSON 字面值交給 `echo` / `cat` 等 MSYS 工具，請放進 shell 腳本（`exec --shell`）。
- **MSYS 的訊號**：Git Bash 被訊號 N 結束時對 Windows 回報 `N << 8`，本機 backend 換回「signal N」，與 Unix 同義。
- **ConPTY**：PTY 的輸出要等 pseudo console 關閉才會 EOF，process registry 讀不到資料時會順便 `try_wait`。
  ConPTY 會把 bracketed-paste 標記當作輸入解讀，沒要求 bracketed paste 的程式只收到文字。

### macOS：子程序跟著 seagent 結束（選用）

macOS 沒有 PDEATHSIG。預設情況下，seagent 被 `SIGKILL` 時，綁定的子程序會留下來（正常結束或 `kill_group` 仍會收掉）。
設 `SEAGENT_MACOS_WATCHDOG=1` 可開啟替代機制：每個經 `proc::spawn_in_group` / `proc::adopt` 啟動的子程序，
都會多一個極小的看門程序 `seagent __watch-parent <ppid> <pid> <start>`（自己的 session）。
它用 kqueue `EVFILT_PROC NOTE_EXIT` 同時監看 seagent 與子程序：子程序先結束就直接退出；
seagent 先結束就對子程序的程序群組送 `SIGTERM`，2 秒後 `SIGKILL`。
啟動前會比對子程序的啟動時間，避免 pid 被重用而誤殺。
已知缺口：子程序 spawn 與看門程序就位之間若 seagent 剛好被殺，子程序仍會留下；每個子程序多一個行程。
尚未在真實 macOS 上驗證，所以預設關閉。iOS 不會 spawn 子程序，不適用。

### iOS：完整 agent 在 App 行程內執行（無伺服器）

SE Agent 的設計是無伺服器、自架：大部分功能本來就必須在本機。iOS 沒有 VM，不代表其餘部分不做。
iOS 版因此**不是純用戶端**，而是在 App 自己的行程裡跑完整的 agent：

- **行程內 agent**：`crates/seagent` 是函式庫＋一行的執行檔（`seagent::main()`）；`seagent::embed::start(home)`
  在 App 的背景執行緒上跑的，正是 `seagent daemon run` 的同一套組裝（`daemon_cli::run`）——核心、session、
  模型供應商、記憶、技能、web 抓取／搜尋、App 沙盒內的檔案工具、MCP（Streamable HTTP／SSE；沒有 stdio 伺服器，
  因為不能開子程序）、純網路的聊天平台、排程與心跳，以及綁在 127.0.0.1 的 App Server——WKWebView 照桌面版的方式
  載入主控台。唯一不同：沒有控制 socket（`Daemon::run_with(Ipc::Off)`，App 只經 App Server 跟它說話），也不用
  `daemon start`。`SEAGENT_HOME` = App 的 Application Support 目錄；vault 金鑰放在 iOS Keychain，經 plugin 以
  `SEAGENT_VAULT_KEY` 交給 agent。連結方式：`apps/desktop/plugins/seagent-mobile` 只在 `target_os = "ios"`
  依賴 `seagent` 函式庫，一起編進 App 的 staticlib；桌面與 Android 的依賴樹不變。
- **shell／VM 的替代品 = 行程內 WebAssembly 直譯器沙盒**（`exec.backend = "wasm"`，`crates/seagent-tools/src/exec/wasm/`）：
  每個外部指令是一個 `wasm32-wasip1` 模組，由 wasmi（純 Rust、**不 JIT**，App Store 允許在沙盒內直譯）執行；
  WASI preview 1 自己實作，路徑一律限制在預開的根目錄（工作區依沙盒設定讀寫或唯讀、私有 `/tmp`、`[exec.sandbox] binds`
  ——與 bwrap／Landlock／Seatbelt／AppContainer 同一份讀寫根政策），`..` 與 symlink 逃不出去；沒有 socket（preview 1
  沒有開 socket 的方法）；fuel 分段執行，逾時／中斷在一個分段內生效；記憶體上限可設。shell 本身由 App 內建的
  POSIX 式直譯器執行（dash／busybox ash 需要 `fork`/`exec`，WASI 沒有）：管線、`&&`/`||`、子 shell、
  `if`/`for`/`while`/`case`、函式、重新導向與 here-doc、`$(…)`、`$((…))`、glob。指令集是釘選版本的
  uutils coreutils（`feat_wasm`，78 個指令）、uutils sed、uutils findutils 的 `find`、`tools/wasi-grep` 的 POSIX grep
  （`apps/desktop/scripts/build-wasi-tools.sh` 以 `--locked` 建置；`xargs` 是 shell 內建，因為 WASI 版 xargs 無法啟動指令），
  以及 CPython 3.14（`build-wasi-python.sh`：python.org 原始碼＋官方 wasi-sdk 24，兩者都釘 SHA-256）。
  每個模組的 SHA-256 寫進 `tools.json`，不符或未釘選就拒絕執行；打包成 App 的 `share/wasi`。iOS 上 `auto` 自動選它；
  隔離等級如實回報為 OS 沙盒層級的「wasm interpreter sandbox」（政策由直譯器在 App 行程內執行，不是核心或 hypervisor）。
  Python 腳本與其他工具同樣只看得到工作區與 `/tmp`、沒有 socket、沒有執行緒與子程序。
- **背景**：App 在前景時 agent 照常執行；進背景時 plugin 以 BGTaskScheduler 預約 `BGProcessingTask`
  （時間 = 下一個到期的排程，至少 15 分鐘後），喚醒時 `seagent::embed::background_pass` 讓排程器補跑到期工作、
  等它們做完（最多約 4 分鐘）；回到前景時若 App Server 的 socket 已被 iOS 回收就重啟 agent。iOS 決定實際執行時間
  （通常是充電、連網、閒置時），所以排程在 iOS 上是「盡量準時」，不是保證準時。
- **配對電腦變成選用**：需要真正的 VM、原生 shell、瀏覽器自動化的工作，可以交給同一區域網路內配對的電腦
  （既有的 node／ARP 協定），也可以不用。

**iOS 上仍然沒有 VM 與原生 shell 程式（平台政策，無法繞過），這點會寫在 App 的啟動畫面、配對頁與這份文件裡。**

## 區域網路互聯

開法：設定精靈勾「允許這個網路上的裝置連線」，或 `[app.exposure] lan = true`（精靈把 listen 改成 `[::]:8640`；也可指定某個私有位址）。

- **IPv4＋IPv6 預設都收**（`seagent_net::listen`）：`[::]:<port>` 綁成**一個雙堆疊 socket**——手動建立
  （`libc::socket`／`WSASocketW`，不繼承、unix 加 `SO_REUSEADDR`），清掉 `IPV6_V6ONLY` 後再讀回確認，Windows 也一樣
  （std 預設在 Windows 是只收 IPv6）。系統不肯清（OpenBSD 類、`net.ipv6.bindv6only = 1`）就退成兩個 listener：
  `[::]`（只收 IPv6）＋`0.0.0.0`；完全沒有 IPv6 就只綁 `0.0.0.0`。LAN 模式下舊精靈寫的 `0.0.0.0:<port>` 也當成「所有
  介面、兩種位址族」改綁 `[::]:<port>`（`seagent_app::lan::dual_stack_listen`）；指定的位址（`192.168.1.5:8640`、
  `[fd00::5]:8640`）照寫的綁，LAN 模式關閉時任何 listen 都不變（預設 `127.0.0.1:8640` 照舊）。雙堆疊 socket 收到的
  IPv4 來源是 `::ffff:a.b.c.d`，伺服器一進來就換回 `a.b.c.d`，所以私有網段判斷、loopback 明文、稽核看到的都是 IPv4。

- **綁定規則**（`seagent_security::exposure`，位址分類的唯一來源，配對 URL 與探索共用）：LAN 模式允許私有網段
  （RFC1918、169.254/16、fe80::/10、fc00::/7、100.64/10；`::ffff:` 對應位址依內含的 IPv4 判斷）或 `0.0.0.0`／`::`，
  不需要 `allow_public`；全球 IPv6 來源與公網 IPv4 一樣被拒。但必須原生 TLS
  （反向代理不算——客戶端釘選的是我們的憑證）、有速率限制、origin 不得為 `*`。公網位址或主機名稱仍走完整防線
  （錯誤訊息會說明 LAN 模式只涵蓋私有位址）。
- **執行時防線**（`seagent_app::server`）：非私有網段的來源一律 403；網路上的連線**只接受已配對裝置的 token**
  （app token、`[app] tokens`、服務帳號、登入、host routes、A2A／SCIM 都只留給本機）；本機 loopback 可在同一個 port
  用明文 `http://127.0.0.1:8640`（依第一個位元組判斷，0x16＝TLS），本機主控台、桌面 App 本機模式與精靈照常使用。
  App 的本機通道送來的 `Host`／`Origin: 127.0.0.1:<port>` 在 TLS 連線上照常接受（同源判斷）。
- **身分憑證**（`seagent_net::x509`，手寫 DER，不加 crate）：第一次以 LAN 模式啟動時產生 ECDSA P-256 自簽憑證到
  `<data>/tls/lan-cert.pem`／`lan-key.pem`（僅擁有者可讀），SAN 含主機名、`<主機>.local`、目前 LAN IP、`localhost`、
  `127.0.0.1`；效期 825 天（瀏覽器的上限；釘選的 App 不看效期）。指紋＝DER 葉憑證的 SHA-256 小寫 hex；只有
  `seagent tls rotate --yes` 會換（所有裝置需重新配對）。
- **mDNS / DNS-SD**（`seagent_net::mdns`）：廣播 `_seagent._tcp.local` PTR/SRV/TXT/A/AAAA，TXT 只有 `v=seagent/2`、`id`
  （`<data>/tls/host-id`）、`fp`（指紋前 16 hex）、`name`，從不帶 token；啟動時宣告兩次、回應查詢（含 legacy unicast）、
  停止時送 TTL 0 告別。`[app] discovery = "mdns" | "off"`，預設只在 LAN 模式開。
  - **IPv4＋IPv6、所有介面**：列舉「已啟用、可多播、非 loopback」的介面（Linux／Android／macOS／iOS 用 `getifaddrs`，
    Windows 用 `GetAdaptersAddresses`），在每個介面加入 `224.0.0.251` 與 `ff02::fb`（UDP 5353；IPv6 socket 設
    `IPV6_V6ONLY`），宣告／查詢逐介面送出（`IP_MULTICAST_IF`／`IPV6_MULTICAST_IF`，TTL／hop limit 255）。回應帶
    「查詢進來的那個介面」的位址：IPv4 依查詢者所在子網、IPv6 依 link-local 來源的 scope id（否則同 /64）；判斷不出來
    就帶全部介面。每 30 秒重新列舉一次（Wi-Fi 切換、DHCP 換位址），有變就重新加入群組並再宣告。
  - **廣播哪些位址跟著 listen 走**：LAN 模式預設（`[::]:8640`，雙堆疊）發 A＋AAAA（AAAA 為 global／ULA／link-local，
    從不發 loopback）；指定私有位址就只廣播它；LAN 模式以外手寫的 `0.0.0.0:8640`（只收 IPv4）只發 A。
  - **與系統共用 5353**：socket 以 `libc::socket`／WinSock `socket` 建立，在 bind 前設 `SO_REUSEADDR`（unix 另加
    `SO_REUSEPORT`），再交給 std（`from_raw_fd`／`from_raw_socket`），所以能和 Avahi／systemd-resolved／
    mDNSResponder（Bonjour）／Windows DNS client 並存。若 5353 被獨佔：回應端改為「受限」模式——從臨時 port 每 30 秒
    宣告一次但無法回答查詢；`seagentd` 啟動時警告、`lan.status` 的 `discoveryState.state = "limited"`（含原因）、
    `seagent doctor` 出現 `lan.discovery_limited`，不會默默關掉。仍可用位址或 QR 配對。
  - **瀏覽**：`seagent nodes discover [--json]`、ARP `discovery.list`。每個介面、每個位址族都從臨時 port 送帶 QU 位元的
    查詢（legacy unicast：對方直接回給我們，所以不需要搶 5353），能共用 5353 時另送一份多播查詢。結果的 `addresses`
    列出所有位址（含 IPv6），`address`／`url` 取最好的一個：私有 IPv4 → 可路由 IPv6（global／ULA）→ 169.254 →
    IPv6 link-local。link-local 位址帶收到它的介面作 zone：CLI 寫 `[fe80::1%eth0]:8640`（Windows 為 zone index
    `%12`），URL 依 RFC 6874 寫 `https://[fe80::1%25eth0]:8640`；`seagent lan connect`、釘選 TLS 客戶端
    （`Stream::connect_pinned`、`pinned_request`）都接受兩種寫法並轉成 scope id。判斷不出 zone 的 link-local 位址會被丟掉。
- **配對**（`seagent_app::devices`，協定見 [arp.md](arp.md)）：`seagent pair code` 或主控台「裝置 → 配對裝置」產生
  ① QR／連結 `https://<ip>:8640/#setup=<setup code>`（手機相機開啟即配對；App 也接受）、② `seagent-pair://` setup code
  （`wss://` URL＋一次性 bootstrap token＋憑證指紋）、③ 8 碼配對碼（輸入後要在主機核准，雙方顯示四碼一組的短指紋）。
  每台裝置拿到專屬、可撤銷、預設 `write` 的 console token（只存加鹽雜湊）；`seagent devices list|approve|reject|revoke`。
  配對、核准、拒絕、撤銷、憑證輪替都寫入稽核流；`/pair/client` 每個位址每分鐘 30 次、10 分鐘內失敗 10 次即暫停。
  手機瀏覽器會先看到自簽憑證警告（接受一次即可；它是用 QR 裡的 bootstrap token 證明自己）。
- **裝置金鑰與周界**（[SECURITY.md §8](SECURITY.md)）：App（Windows／macOS／Linux／Android／iOS 同一份 Rust，
  `apps/desktop/src-tauri/src/devkey.rs`）與瀏覽器（WebCrypto，`ui/web/devauth.js`）配對時送出 P-256 公鑰；console
  token 之後只能在 `POST /pair/refresh` 配合新簽章換 60 分鐘的 access token。舊裝置下次啟動自動綁定。另有失敗鎖定、
  Host／DNS rebinding 檢查、tunnel 偵測、`allow_sources`、CORS 與安全標頭、`seagent devices revoke --all --yes`。
- **電腦對電腦**：`seagent nodes discover` 列出主機與可直接貼上的 `seagent lan connect <位址> --code <碼>`；配對後
  token 存入 vault（`LAN_<名稱>_TOKEN`），對方登記為叢集節點（`https://`＋釘選指紋，`seagent cluster status` 可見）。
  主控台「掃描網路 → 連線」做同樣的事。`seagent node --setup-code` 也以握手時釘選的方式連自簽主機。
- **PWA**：manifest 與 `index.html` 帶 192／512／maskable 512 PNG 與 180×180 apple-touch-icon。
- 被發現的 LAN 裝置**不會**變成 web/fetch 工具的 SSRF 例外（`url_safety` 不變），只有 node / ARP / 叢集客戶端用
  `seagent_net::stream::pinned_request` 連它們。
- `seagent security audit`／`seagent doctor`：`lan.mode_on`、`lan.discovery_on`、`lan.discovery_limited`、`lan.paired_devices`、
  `lan.certificate_age`。

## 安裝與圖形精靈

- 新 crate `seagent-desktop`（Tauri 2，`apps/desktop/`，獨立 workspace 與 Cargo.lock）：視窗、系統匣、第一次啟動時安裝並啟動背景服務、開啟既有的網頁設定精靈。
  建置與簽章見 [apps/desktop/README.md](../apps/desktop/README.md)，手機見 [apps/desktop/MOBILE.md](../apps/desktop/MOBILE.md)。
- 產出：Windows `.msi` / `.exe`、macOS `.dmg`、Linux `.AppImage` / `.deb` / `.rpm`、Android `.apk`、iOS（TestFlight / App Store）。
- 精靈第 7 步「開機自動啟動」依平台走 systemd / Windows 服務 / launchd / Android Foreground Service。
- 簽章：流程寫好、憑證留空位（CI secret）；未簽章前使用者會看到 SmartScreen / Gatekeeper 警告。

## 執行階段

1. **平台抽象層**：`seagent-core::platform`（proc、shell、fs_private、ipc、term、sysinfo、layout、random）；MSRV 升到 1.89 以使用 std 檔案鎖。
2. **逐 crate 移植**（平行）：kernel、tools、vm、binary+app+browser+channel、其餘輕量 crate。
3. **LAN 互聯、Tauri 外殼、安裝檔、CI 矩陣、手機 App**。
4. **驗證**：Linux 測試全過且效能不變；Windows / macOS / Android / iOS 目標 `cargo check` 通過；Windows 原生實機跑通。

## Bot Desktop（隔离桌面 / isolated desktop）

seagent screen 的平台替身（control/screen.rs 按 OS 分支）：

- **Linux**：TigerVNC Xvnc + Xfce（launcher.sh），无头渲染，VNC 可接入。
- **Windows**（control/screen_windows.rs）：交互 window station 上以 CreateDesktopW 建一个独立 desktop 对象，headed 浏览器经 STARTUPINFOW.lpDesktop 启动到该 desktop（launch.rs 读 SEAGENT_BD_DESKTOP，用 SetThreadDesktop 绑定派生线程，std 继承父线程 desktop）。桌面对象由本进程持有的 handle 保活（控制台进程无法在后台 desktop 初始化控制台会立即退出，故用 handle 而非常驻进程；浏览器挂在 seagent 的 Job Object 上，随 seagent 退出而退出，与其它浏览器一致）。Windows 仅渲染当前活动 desktop：agent 以 SwitchDesktop（take_over）把它变为活动 desktop 后用同一套 computer_use 工具（截图/输入）操作，switch_to_default 交还人类；浏览器的 CDP 截图不受活动与否限制，screenshot() 另经 GDI 抓该 desktop 帧缓冲（未曾活动过时为黑）。
- **macOS**（control/screen_macos.rs）：无进程级 desktop 对象；agent 浏览器跑在登录会话（其 CDP 截图与 computer_use 驱动在此可用），隔离由该会话提供，报告为「supported、already running」，不发布 SEAGENT_BD_DESKTOP。完全无头的 Mac 需虚拟显示器（私有 CGVirtualDisplay、HDMI 模拟器）或第二个 launchd GUI 会话——属主机置备，seagent 不代为安装。
- **iOS / Android**：无桌面。

即时画面（主控台 `/view/live`，`crates/seagent-app/src/live_view.rs`）各平台的来源：浏览器一律是 CDP screencast（各 OS 相同）；Bot Desktop 在 Linux 是 Xvnc display（`import`/`grim`），Windows 是 CreateDesktopW desktop 的 GDI 抓取（未建立时退回主屏幕），macOS 是登录会话（`screencapture`）；桌面 VM 是 QMP `screendump`（QEMU+KVM／WHPX／HVF 相同）。没有画面的地方（无 Bot Desktop 的服务器、iOS、只有 microVM 的主机）以即时终端机替代：shell／job 工具启动的每个命令都经 `seagent_tools::exec::live` 转送输出，涵盖 Firecracker、QEMU、VirtualBox、vfkit、AppContainer、Seatbelt、bwrap 与 iOS 的 WASM 解释器。

虚拟音频（Meet 说话）：不安装任何驱动。可选方案见下节「虚拟音频」。