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

### iOS 的限制（平台政策，無法繞過）

iOS 不允許 App 開虛擬機、執行子程序或 JIT，因此 iOS 版是**純 App**：
對話、通知、相機、定位、語音、檔案等照常提供；需要 shell、VM、瀏覽器自動化的工作，
可以交給同一區域網路內已配對的電腦執行（透過既有的 node / ARP 協定），也可以不用。
**iOS 上沒有 VM 與本機 shell，這點會寫在 App 說明與設定精靈裡。**

## 區域網路互聯

- `[app.exposure] lan = true`：允許綁定私有網段位址，但強制 TLS；公網位址仍需完整防線。
- 第一次啟動自動產生長期自簽憑證到 `<data>/tls/`，指紋即伺服器身分；配對碼一律帶 `wss://` 與指紋 pin。
- mDNS / DNS-SD 廣播 `_seagent._tcp.local`（TXT 只放協定版本、id、指紋前綴，不放任何 token），預設只在 LAN 模式開啟。
- 配對：掃 QR（帶指紋與一次性 bootstrap token）或 8 碼配對碼＋雙方顯示短指紋確認；每台裝置拿到可撤銷的專屬 token。
- 被發現的 LAN 裝置**不會**變成 web/fetch 工具的 SSRF 例外，只能透過 node / ARP 客戶端連。

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
