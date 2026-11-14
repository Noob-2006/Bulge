# 桌面 VM（Desktop VM）

SE Agent 可以開一台**有畫面的虛擬機**（Debian 13 + Xfce + Chromium），讓代理只靠「截圖 + 模擬滑鼠鍵盤」操作（computer use），人可以在網頁主控台即時觀看、隨時接手。它和工具隔離用的 microVM（`[exec.vm]`，無畫面、無網卡）是兩回事，程式在 `crates/seagent-vm/src/desktop/`。

## 預設：開機就先開好虛擬機，代理在裡面工作

從 0.2.0-alpha 起，**桌面 VM 就是代理的電腦**（`[desktop_vm] autostart = true`，預設開啟）：

1. SE Agent 一啟動，背景就檢查預設的 VM（`desk`）。第一次使用時沒有映像，會自動建置（下載 Debian 雲端映像並安裝桌面，約 5–20 分鐘，視網速而定），完成後自動開機。之後每次啟動 App 都直接開機，約 20 秒。
2. 頂列「代理電腦」標籤顯示進度：建置中（含已經過的時間）／開機中／執行中／啟動失敗（點一下重試）／已停止（點一下啟動）。執行中時點一下，會在工作區打開那台 VM 的畫面。
3. 代理的瀏覽器、computer use 都在這台 VM 裡（`[computer_use] target = "vm:desk"`），你在工作區看到的就是代理正在操作的畫面，可以隨時接手。
4. VM 意外關掉會自動重新開機；**你自己按停止**（工作區、`seagent vm desktop stop`、`view.vm.stop`）就不會被拉回來，直到你再按啟動。
5. 建置紀錄在 `<data>/vm/desktop/build.log`，狀態在 `<data>/vm/desktop/agent-vm.json`；ARP 方法 `view.vm.status` 讀狀態、`view.vm.build` 立即建置／重試。

不想自動開：`seagent config set desktop_vm.autostart false`。

## 快速開始（手動）

```sh
seagent vm desktop build          # 下載固定版本的 Debian 雲端映像（sha256 驗證）並安裝桌面，約 3–5 分鐘，可重複執行
seagent vm desktop start          # 開機（預設名稱 desk），約 20 秒後自動登入並開好 Chromium
seagent vm desktop screenshot -o desk.png
seagent vm desktop input '{"type":"click","x":640,"y":90}'
seagent vm desktop input '{"type":"type","text":"example.com\n"}'
seagent vm desktop status | list [--json]
seagent vm desktop stop           # ACPI 關機（磁碟保持一致），逾時才 quit / SIGTERM
seagent vm desktop reset          # 停機並刪除磁碟疊加層，下次開機用目前的映像
```

主機只需要 `qemu-system-x86_64`、`qemu-img`。不需要 root、ISO 工具、VNC 用戶端或 xdotool。

| 主機 | QEMU 從哪來 | 加速 |
|---|---|---|
| Windows 10／11 | **安裝包內附**（`vm\runtime\qemu`，含 `qemu-img.exe` 與韌體），不必另裝 | WHPX：在「Windows 功能」勾選 Windows Hypervisor Platform 後重開機（App 的 VM 頁面有按鈕）；Home 版也行 |
| Linux | 系統套件：`apt install qemu-system-x86 qemu-utils`、`dnf install qemu-system-x86 qemu-img`、`pacman -S qemu-desktop`（App 的 deb／rpm 會建議安裝） | KVM：使用者在 `kvm` 群組 |
| macOS | `brew install qemu` 或 `sudo port install qemu`；GUI App 的 PATH 沒有 `/opt/homebrew/bin` 也找得到 | Intel Mac 用 HVF；Apple Silicon 跑 x86_64 映像只能 TCG（慢） |

Windows 上實測（Windows 11 Home、WHPX、只用安裝包內附的 QEMU）：建立映像 247 秒（套件從交大鏡像 2.6 MB/s），`start` 1 秒內回應，之後的截圖是 Xfce 自動登入、Chromium 已開好（1280×800），`stop` 正常關機。

## 機器長相

| 項目 | 內容 |
|---|---|
| 加速 | Linux `/dev/kvm` 可讀寫時用 KVM、Windows 有 WHPX 時用 WHPX（`kernel-irqchip=off`）、Intel Mac 用 HVF；否則 TCG（很慢，狀態會帶警告） |
| 時區 | `timezone = "host"`（預設）時每次開機把主機的時區（IANA 名稱）以 SMBIOS OEM 字串 `seagent-tz=` 傳入，客體的 `seagent-display-setup` 把 `/etc/localtime` 連到該時區；Windows 的時區名稱（`Taipei Standard Time`）以 CLDR 對照表轉成 `Asia/Taipei`，表裡沒有的用目前的 UTC 偏移（`Etc/GMT-8`） |
| 顯示 | std VGA，EDID 偏好解析度 = 設定值（預設 1280×800）；畫面以 QMP `screendump` 取得 PNG |
| 輸入 | USB tablet（絕對座標）+ PS/2 鍵盤，以 QMP `input-send-event` 送出；鍵盤配置為美式。ASCII 走鍵盤事件；含中文等非 ASCII 的文字改走 virtio-serial 文字通道 `org.seagent.text`（`<runtime>/dvm/<name>/text.sock`），客體桌面工作階段裡的 `seagent-text-input` 經剪貼簿貼上（xclip + Ctrl+V，會覆蓋客體剪貼簿；終端機需要 Ctrl+Shift+V，所以對終端機請只送 ASCII）。改用剪貼簿是因為 xdotool 的 Unicode keysym 輸入在 Chromium 會出現錯字 |
| 網路 | QEMU user-mode NAT（`network = "none"` 可關閉） |
| 通訊端 | Linux／macOS：`<runtime>/dvm/<name>/qmp.sock`、`vnc.sock`（QEMU 自帶 VNC，目錄 0700）。Windows：QMP 與文字通道走只綁 127.0.0.1 的 TCP 埠，不開 VNC（`-display none`），畫面一律經 QMP 取得 |
| 磁碟 | `<data>/vm/desktop/<name>/disk.qcow2`：以佈建好的映像為底的 copy-on-write 疊加層，關機後保留 |
| 生命週期 | QEMU 以 `-daemonize` 常駐，CLI 結束後仍在跑；`pid` 存活且其命令列含本 VM 的 QMP 路徑才算執行中；`reap()` 清除殘留並停止閒置超過 `idle_timeout_secs` 的 VM |

## 映像

- 來源：`https://cloud.debian.org/images/cloud/trixie/20261026-2643/debian-13-generic-amd64-20261026-2643.qcow2`
- sha256：`7740a80114c1b5e6456c65713c76f4006e8b00eb50d8a122924ba823b9959fc5`（已對照 Debian 官方 SHA512SUMS），418 MiB。`image_url` 也可以是 `file://` 或絕對路徑（離線環境）。
- 佈建方式：SE Agent 在主機 127.0.0.1 開一次性的 HTTP 伺服器提供 cloud-init NoCloud 種子，透過 SMBIOS `ds=nocloud;s=http://10.0.2.2:PORT/` 讓客體抓取；客體裝好 `xserver-xorg-core`、LightDM（自動登入使用者 `seagent`）、Xfce（xfwm4/panel/desktop/terminal/thunar）、`chromium`、`fonts-dejavu-core`、`fonts-noto-cjk`（繁中網頁不會變成方塊）、`locales`（產生 `zh_TW.UTF-8`，介面語言維持映像預設）、`xdotool`、`xclip` 等（不裝 recommends），最後在序列埠印出 `SEAGENT_PROVISION_OK` 並關機，SE Agent 再把結果攤平成 `<cache>/desktop-vm/desktop-<recipe>.qcow2` 與同名 `.json` manifest。
- 下載：連線中斷時以 HTTP Range 從斷點續傳（有進度就持續重試，上次中斷留下的 `.part` 也會接著抓），最後一律比對固定的 sha256。
- 套件來源：`apt_mirror = "auto"`（預設）時，佈建前同時向 deb.debian.org、交大（linux.cs.nycu.edu.tw）與幾個官方國家鏡像各抓 1 MiB 測速，選最快的給客體 apt 用；apt 會驗證簽章，換鏡像不影響安全，也不改變 recipe。設成 `""` 固定用 deb.debian.org，或填一個 Debian 套件庫網址。
- recipe 雜湊涵蓋來源 sha256、cloud-config 範本與套件清單；設定不變時 `build` 直接回報「up to date」。解析度與 Chromium 起始網址每次開機經 SMBIOS OEM 字串（`seagent-res=`、`seagent-url=`）傳入，不必重建。

## 設定 `[desktop_vm]`

```toml
[desktop_vm]
enabled = true
default = "desk"
qemu = "qemu-system-x86_64"  # Windows 安裝版預設用安裝包內附的 QEMU
qemu_img = "qemu-img"         # 同上（vm\runtime\qemu\qemu-img.exe）
accel = "auto"            # auto | kvm / whpx / hvf | tcg
memory_mb = 2048
cpus = 2
width = 1280
height = 800
disk_gb = 12
network = "user"          # user | none
start_url = "about:blank"
image_url = "…"           # 預設為上面的固定版本
image_sha256 = "…"
extra_packages = []
apt_mirror = "auto"       # auto（測速選最快）| "" | Debian 套件庫網址
timezone = "host"         # host（跟著主機，每次開機）| ""（UTC）| IANA 名稱，例如 "Asia/Taipei"
build_timeout_secs = 2400
stop_timeout_secs = 30
idle_timeout_secs = 0     # 0 = 不自動停
```

## 網頁主控台（ARP / HTTP）

`crates/seagent-app/src/browser_view.rs` 模組文件是正式規格，摘要：

- `view.desktop.list` → `[{id:"host"|"vm:<name>", kind, label, running, width, height, controller, lease, accel?, imageBuilt?}]`（`GET /view/desktop/list`）
- `view.desktop.state|frame|takeover|handback` 多了可選的 `target`（預設 `host`，行為與舊版相同）。
- `view.desktop.input {viewer, target, event}`（`POST /view/desktop/input`）：事件為螢幕像素座標 `{type: move|click|dblclick|down|up|scroll|key|type|drag, x, y, button, dx, dy, key, text, toX, toY}`；只接受持有該目標租約（lease）的 viewer。
- `view.vm.start {name?}` / `view.vm.stop {name}`（`POST /view/vm/start|stop`）：admin 權限。

- **即時串流** `GET /view/live`（WebSocket，`crates/seagent-app/src/live_view.rs` 為規格）：主控台不再輪詢截圖。`kind=browser` 是分頁的 CDP `Page.startScreencast`（JPEG，ack 節流：有 viewer 取走上一張且未超過 fps 上限才 ack，慢的連線只會讓 Chrome 變慢、不會堆積）；`kind=desktop` 是 Bot Desktop／桌面 VM 的畫面（QMP `screendump`，畫面變了才送，速率自適應，不刷新 VM 的閒置計時）；`kind=terminal` 是代理正在執行的指令與輸出（所有 exec 後端，包括 microVM；以 vault 遮蔽秘密）。沒有畫面的目標回 `nodisplay`，主控台改顯示終端機。預設 30 fps、JPEG 85、依檢視區實際大小 × devicePixelRatio（最高 3840 px）送出，主控台可選到 60 fps；只有連線或檢視端跟不上時才先降畫質、再降 fps，恢復後回到所選等級。錄影（`browser record`）與檢視共用同一個 screencast，互不停止。所選 fps 是下限：串流以高出 10% 的速率送出，忙碌時仍不低於所選值。Bot Desktop 上若是代理自己的瀏覽器（常見情況），桌面串流改為「patch 模式」：整個桌面的底圖只在頁面以外有變化時才重送（每 250 ms 檢查、閒置時放慢到 1 s），頁面本身直接轉送瀏覽器的 CDP screencast JPEG（`{t:"patch", x, y, w, h}`，螢幕像素），主控台在 canvas 上合成；不需每格擷取與重新編碼，1080p 實測 30 fps 選項約 30、60 fps 選項約 52–54，閒置桌面不送任何資料。其他視窗蓋住頁面時（Windows 會檢查）改回整張擷取。底層是 Chromium 或 Electron 的 App（Edge、Chrome、VS Code、Slack…）也走同一條路：`computer` 工具的 `launch_app` 給執行檔完整路徑（加上 `args`）時，會以獨立的 user-data-dir 與只綁 127.0.0.1 的 DevTools 埠（`--remote-debugging-port=0`）把它開在 Bot Desktop 上，記為瀏覽器 `app:<name>`（不會因閒置被收掉），檢視規則、token 與租約和代理的瀏覽器相同。桌面串流挑沒被蓋住的 CDP 頁面（App 優先），被蓋住超過 1 秒就切回區域串流，頁面再露出時切回 patch 模式。Windows 以視窗疊放判斷；Xvnc／macOS 沒有疊放查詢，只有一個 CDP 視窗時視為沒被蓋住，多個時只有取得焦點的那個算。GPU 繪製、又不是 Chromium／Electron 的 App 在 Windows 隔離桌面上只能走 `PrintWindow`（約 10 fps）：Windows 只繪製顯示中的桌面，Windows.Graphics.Capture 對非顯示中的桌面不給畫面（擷取項目大小 0×0、建立工作階段回 0x8007139F），任何驅動程式都改變不了這點。所以 Windows 安裝程式內建（選用、預設勾選）開源的 IddCx 虛擬顯示器驅動程式（VirtualDrivers/Virtual-Display-Driver 25.7.23，MIT，SignPath Foundation 簽章，審查紀錄見 `packaging/release/DEPENDENCY-REVIEW.md`），由 `apps/desktop/src-tauri/windows/vdd/install-vdd.ps1` 以系統管理員安裝：一台 1920×1080@60 的虛擬螢幕放在使用者所有螢幕外框的右下角外側（只有角落相接，主螢幕與實體螢幕不變）。有它時 Bot Desktop 改「掛」在這台虛擬螢幕上（`crates/seagent-browser/src/control/vdd.rs`）：App 開在顯示中的桌面、被移到並固定在虛擬螢幕上、不出現在工作列與 Alt+Tab，即時檢視以 DXGI Desktop Duplication 擷取該螢幕（`control/dxgi_dup.rs`，螢幕更新率 60 Hz、只送變動的矩形），`computer` 工具的截圖與輸入（SendInput）也以該螢幕為準（座標加上其原點）；`launch_app` 給任何原生程式的完整路徑都可以（記事本、小畫家、檔案總管…）。代價：代理動作時真的會移動滑鼠游標、取得焦點（與接手模式相同）。沒有驅動程式（或 `SEAGENT_BOT_DISPLAY=isolated`）時維持原本的隔離桌面，主控台串流的 hello 帶 `display`（`view.display.status`）說明為什麼 fps 低，並在「設定 → 虛擬顯示器」提供安裝／修復／解除安裝（UAC）。沒人看時什麼都不擷取。輸入沿用 `view.*.input` 與租約規則，且需要可 POST 的憑證（read scope 只能看）。

每個目標有自己的接手租約：`host` 是原本的 Bot Desktop 租約，`vm:<name>` 在 `<data>/vm/desktop/<name>/bot-desktop/lease.json`。人接手某台 VM 時，代理對那台 VM 的所有動作（含截圖）都會被拒絕，主機與其他 VM 不受影響。

## 代理的 computer use

`computer_use` 工具多了 `target` 參數（`"host"` 或 `"vm:<name>"`），預設值來自 `[computer_use] target`。VM 目標：

- `capture` 回傳整個螢幕的 PNG 給模型（沒有無障礙樹、沒有元素編號）；
- `click / double_click / right_click / drag / scroll / type / key` 以截圖像素座標經 QMP 送出；
- `set_value`、`focus_app`、元素編號、點擊時的修飾鍵回傳 `unsupported_action`；
- 核准範圍獨立：`desktop:vm:<name>:<action>`（主機上的授權不會延伸到 VM）。

## 代理的瀏覽器在 VM 裡

`[computer_use] target = "vm:<name>"` 且 `[desktop_vm] enabled = true` 時，`browser` / `browser_*` 工具直接操作那台 VM 桌面上的 Chromium，主控台右側看到的就是代理正在用的那個視窗；`[browser]` 自己設了 `backend`、`cdp_url` 或 `desktop_vm` 時以它為準。

- 客體 Chromium 以 `--remote-debugging-port=9222`（只聽客體 loopback）啟動，`seagent-cdp-relay.service`（socat）把它轉到客體 9223；QEMU user 網路以 `hostfwd` 只綁主機 `127.0.0.1` 的隨機埠，寫在 `<data>/vm/desktop/<name>/cdp.url`（VM 停止時刪除）。
- 和 `cdp_url` 一樣，同一台主機上的其他本機使用者也連得到這個 loopback 埠；多人共用的主機請用 `network = "none"`（瀏覽器就不轉出）或另設 `[browser]`。
- 接手控制時，VM 的租約同時擋下 computer use 與瀏覽器工具。
- 需要 2026-11-05 以後建的映像（`IMAGE_LAYOUT = 3`）；舊映像請 `seagent vm desktop build` 後 `seagent vm desktop reset <name>`。

## 代理的 shell 在 VM 裡

桌面 VM 執行中時，操作者自己的 session（非 sandboxed）的 `shell`／`process`／`terminal` 指令預設在 VM 裡跑，和 computer use、瀏覽器是同一台機器（`crates/seagent-tools/src/exec/desktop.rs`）：

- 客體代理：同一個 `seagent-vm-guest`，以 `service` 角色由 `seagent-agent.service`（systemd）以 root 啟動；它開 virtio-serial 埠 `seagent0`、讀通道金鑰（Windows 的 loopback TCP 通道才有，fw_cfg `opt/seagent/key`），然後永久降為桌面使用者 `seagent`（uid 1000，含 audio/video/sudo 群組；免密碼 sudo 是這台桌面本來就有的）。環境：`HOME=/home/seagent`、`DISPLAY=:0`、`XAUTHORITY=~/.Xauthority`、session bus，所以指令開的 GUI 程式會出現在 工作區 的畫面上（請 `setsid -f 程式 >/dev/null 2>&1` 分離開啟）。`Shutdown` 只結束當次連線，不關機（VM 由主機以 ACPI 關）；主機斷線時它啟動的指令被結束，代理等下一個連線（KillMode=process：GUI 程式不受代理重啟影響）。
- 代理執行檔來源：microVM 客體映像 initramfs 裡的 `/sbin/init`（與 manifest 的 sha256 比對），否則執行檔旁或 `<data>/vm/` 的 `seagent-vm-guest`（開發版）；必須是 x86_64 且有 `service` 角色。`build` 時從 seed server 下載烤進映像；每次 `start` 也經 fw_cfg（`opt/seagent/agent`）交給客體並優先使用，所以升級 seagent 後不必重建映像。映像 manifest 的 `guest_agent` 記錄這些；`DesktopVms::image_has_agent()` 為 false 的舊映像請 `seagent vm desktop build --force`。從沒有代理的舊映像做出的疊加層會在下次 `start` 改名為 `disk.qcow2.prev` 保留一次，從新映像重新開始。
- 工作區：主機工作區是正本，鏡像在 VM 的 `~/workspace/<目錄名>-<雜湊>`，每個指令前推送、結束時拉回（與 SSH 後端同一套 `WorkspaceSync`）；指令預設在鏡像目錄開始，`cwd` 可給工作區內的路徑或 VM 裡的絕對路徑。VM 裡每個指令重新開始（`cd`／`export` 不跨指令保留）。
- 併發：一台 VM 一條通道，主機端多工器依 `id` 分派框架，多個 session／工具呼叫可同時跑。
- 路由：`[exec] target = "auto"`（預設，VM 執行中就用 VM）｜`"desktop"`（同上，VM 沒開時每個 session 都提示一次）｜`"backend"`（永遠用 `[exec] backend`，舊行為）。單次呼叫 `host: "vm"` 堅持用 VM（不行就回錯誤說明原因），`host: "host"`／`elevated`／`sandbox` 與 `/exec host=` 維持原本行為；sandboxed session 不會進到操作者的桌面。VM 有建但沒在跑、或代理沒回應時，指令照舊在原本的後端執行，結果開頭附一行說明。

## 內建瀏覽器

- `install.sh --with-browser`：把固定版本的 Chrome for Testing（`157.0.8103.38`，zip sha256 `8cdeb344…2a66`）驗證後解到 `<share>/browsers/chrome-linux64/`。
- 離線包：`make-offline-bundle.sh --with-browser [--browser-zip FILE]` 會帶上 `browser/chrome-linux64.zip`，`install-offline.sh` 與 `install.sh --with-browser` 會使用它。
- `seagent browser install` 預設也改成下載同一個固定版本並驗證 sha256（`--url latest` 才查 Google 的最新版索引）。
- 探索順序：`[browser] prefer_bundled = true` 時優先用內建版本；否則主機瀏覽器找不到時才退回內建版本。
- 桌面 VM 映像本身內建 Debian 的 `chromium`。

## 已知限制

- 映像是 x86_64；Apple Silicon 與 arm64 Linux 只能以 TCG 模擬執行（能用但慢）。Android、iOS 沒有桌面 VM（Android 可以用配對電腦上的）。鍵盤事件為美式配置。
- 時區在 2026-11-13（0.2.0-alpha）以前建的映像不會套用；`seagent vm desktop build` 重建後 `reset` 即可。非 ASCII 文字依賴客體內的 `seagent-text-input`（2026-11 以後建的映像才有），是「輸入文字」而不是輸入法組字。
- 主機（`target = host`）的 `view.desktop.input` 走 xdotool / ydotool，主機沒有這些工具時會回報錯誤。
- 映像重建後，舊 VM 的疊加層仍指向舊映像檔；要用新映像請執行 `seagent vm desktop reset <name>`。
