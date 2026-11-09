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
| microVM 隔離 | Firecracker / QEMU+KVM | Hyper-V（HCS）或 QEMU+WHPX；VirtualBox 備援 | Virtualization.framework；QEMU+HVF 備援 | AVF（pKVM，支援的機型）；否則交給配對主機 | **不支援**（見下） |
| 程序沙盒 | bwrap / Landlock / seccomp | AppContainer + Job Object + restricted token | Seatbelt（sandbox-exec 設定檔） | App 沙盒 + isolated process | App 沙盒（本身即是） |
| gVisor | gVisor | 改跑在上列 VM 內 | 同左 | 同左 | — |
| 容器 | docker / podman | Docker Desktop / Podman machine | 同左 | — | — |
| 常駐服務 | systemd / OpenRC | Windows 服務或工作排程器 | launchd（LaunchAgent） | Foreground Service | App 前景 + BGTask |
| 本機 IPC | unix socket | named pipe（僅擁有者 ACL） | unix socket | unix socket（app 私有目錄） | app 內通道 |
| 程序群組 / 訊號 | pgid / signal / PDEATHSIG | Job Object（KILL_ON_JOB_CLOSE）+ CtrlHandler | pgid / signal + kqueue 監看父程序 | pgid / signal | — |
| PTY | posix_openpt | ConPTY | posix_openpt | posix_openpt | — |
| shell | bash | 有 bash（Git Bash/MSYS）用 bash，否則 PowerShell | bash/zsh | `/system/bin/sh` + 內建 busybox | — |
| 檔案權限 0600/0700 | chmod | 擁有者 DACL | chmod | chmod | 資料保護等級 |
| 秘密保管 | systemd-creds(TPM) / libsecret | DPAPI / Credential Manager | Keychain | Android Keystore | Keychain |
| 鍵鼠 / 螢幕 | xdotool / ydotool / Xvfb | SendInput / DXGI 擷取 | CGEvent / ScreenCaptureKit | AccessibilityService / MediaProjection | — |
| 錄音 / 通知 | pw-record / dunst | WASAPI / Toast | AVFoundation / UserNotifications | 系統 API | 系統 API |
| syslog | /dev/log | Windows Event Log | os_log / UDP syslog | logcat | os_log |

### macOS：子程序跟著 seagent 結束（選用）

macOS 沒有 PDEATHSIG。預設情況下，seagent 被 `SIGKILL` 時，綁定的子程序會留下來（正常結束或 `kill_group` 仍會收掉）。
設 `SEAGENT_MACOS_WATCHDOG=1` 可開啟替代機制：每個經 `proc::spawn_in_group` / `proc::adopt` 啟動的子程序，
都會多一個極小的看門程序 `seagent __watch-parent <ppid> <pid> <start>`（自己的 session）。
它用 kqueue `EVFILT_PROC NOTE_EXIT` 同時監看 seagent 與子程序：子程序先結束就直接退出；
seagent 先結束就對子程序的程序群組送 `SIGTERM`，2 秒後 `SIGKILL`。
啟動前會比對子程序的啟動時間，避免 pid 被重用而誤殺。
已知缺口：子程序 spawn 與看門程序就位之間若 seagent 剛好被殺，子程序仍會留下；每個子程序多一個行程。
尚未在真實 macOS 上驗證，所以預設關閉。iOS 不會 spawn 子程序，不適用。

### iOS 的限制（平台政策，無法繞過）

iOS 不允許 App 開虛擬機、執行子程序或 JIT，因此 iOS 版是**純 App**：
對話、通知、相機、定位、語音、檔案等照常提供；需要 shell、VM、瀏覽器自動化的工作，
可以交給同一區域網路內已配對的電腦執行（透過既有的 node / ARP 協定），也可以不用。
**iOS 上沒有 VM 與本機 shell，這點會寫在 App 說明與設定精靈裡。**

## 區域網路互聯

開法：設定精靈勾「允許這個網路上的裝置連線」，或 `[app.exposure] lan = true`（listen 改 `0.0.0.0:8640` 或某個私有位址）。

- **綁定規則**（`seagent_security::exposure`，位址分類的唯一來源，配對 URL 與探索共用）：LAN 模式允許私有網段
  （RFC1918、169.254/16、fe80::/10、fc00::/7、100.64/10）或 `0.0.0.0`／`::`，不需要 `allow_public`；但必須原生 TLS
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
  - **廣播哪些位址跟著 listen 走**：指定私有位址就只廣播它；`0.0.0.0:8640`（只收 IPv4）只發 A；`[::]:8640` 發 AAAA
    （global／ULA／link-local，從不發 loopback），在 `[::]` 為雙堆疊的 Linux／macOS／Android／iOS 也發 A（Windows 的
    `[::]` 只收 IPv6，所以不發 A——要兩者都通就用 `0.0.0.0` 或分別設定）。要讓裝置走 IPv6 連進來，listen 設 `[::]:8640`。
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
