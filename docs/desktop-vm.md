# 桌面 VM（Desktop VM）

SE Agent 可以開一台**有畫面的虛擬機**（Debian 13 + Xfce + Chromium），讓代理只靠「截圖 + 模擬滑鼠鍵盤」操作（computer use），人可以在網頁主控台即時觀看、隨時接手。它和工具隔離用的 microVM（`[exec.vm]`，無畫面、無網卡）是兩回事，程式在 `crates/seagent-vm/src/desktop/`。

## 快速開始

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

## 機器長相

| 項目 | 內容 |
|---|---|
| 加速 | `/dev/kvm` 可讀寫時用 KVM，否則 TCG（很慢，狀態會帶警告） |
| 顯示 | std VGA，EDID 偏好解析度 = 設定值（預設 1280×800）；畫面以 QMP `screendump` 取得 PNG |
| 輸入 | USB tablet（絕對座標）+ PS/2 鍵盤，以 QMP `input-send-event` 送出；鍵盤配置為美式。ASCII 走鍵盤事件；含中文等非 ASCII 的文字改走 virtio-serial 文字通道 `org.seagent.text`（`<runtime>/dvm/<name>/text.sock`），客體桌面工作階段裡的 `seagent-text-input` 經剪貼簿貼上（xclip + Ctrl+V，會覆蓋客體剪貼簿；終端機需要 Ctrl+Shift+V，所以對終端機請只送 ASCII）。改用剪貼簿是因為 xdotool 的 Unicode keysym 輸入在 Chromium 會出現錯字 |
| 網路 | QEMU user-mode NAT（`network = "none"` 可關閉） |
| 通訊端 | `<runtime>/dvm/<name>/qmp.sock`、`vnc.sock`（QEMU 自帶 VNC，目錄 0700） |
| 磁碟 | `<data>/vm/desktop/<name>/disk.qcow2`：以佈建好的映像為底的 copy-on-write 疊加層，關機後保留 |
| 生命週期 | QEMU 以 `-daemonize` 常駐，CLI 結束後仍在跑；`pid` 存活且其命令列含本 VM 的 QMP 路徑才算執行中；`reap()` 清除殘留並停止閒置超過 `idle_timeout_secs` 的 VM |

## 映像

- 來源：`https://cloud.debian.org/images/cloud/trixie/20261026-2643/debian-13-generic-amd64-20261026-2643.qcow2`
- sha256：`7740a80114c1b5e6456c65713c76f4006e8b00eb50d8a122924ba823b9959fc5`（已對照 Debian 官方 SHA512SUMS），418 MiB。`image_url` 也可以是 `file://` 或絕對路徑（離線環境）。
- 佈建方式：SE Agent 在主機 127.0.0.1 開一次性的 HTTP 伺服器提供 cloud-init NoCloud 種子，透過 SMBIOS `ds=nocloud;s=http://10.0.2.2:PORT/` 讓客體抓取；客體裝好 `xserver-xorg-core`、LightDM（自動登入使用者 `seagent`）、Xfce（xfwm4/panel/desktop/terminal/thunar）、`chromium`、`fonts-dejavu-core`、`fonts-noto-cjk`（繁中網頁不會變成方塊）、`locales`（產生 `zh_TW.UTF-8`，介面語言維持映像預設）、`xdotool`、`xclip` 等（不裝 recommends），最後在序列埠印出 `SEAGENT_PROVISION_OK` 並關機，SE Agent 再把結果攤平成 `<cache>/desktop-vm/desktop-<recipe>.qcow2` 與同名 `.json` manifest。
- recipe 雜湊涵蓋來源 sha256、cloud-config 範本與套件清單；設定不變時 `build` 直接回報「up to date」。解析度與 Chromium 起始網址每次開機經 SMBIOS OEM 字串（`seagent-res=`、`seagent-url=`）傳入，不必重建。

## 設定 `[desktop_vm]`

```toml
[desktop_vm]
enabled = true
default = "desk"
qemu = "qemu-system-x86_64"
qemu_img = "qemu-img"
accel = "auto"            # auto | kvm | tcg
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

- **即時串流** `GET /view/live`（WebSocket，`crates/seagent-app/src/live_view.rs` 為規格）：主控台不再輪詢截圖。`kind=browser` 是分頁的 CDP `Page.startScreencast`（JPEG，ack 節流：有 viewer 取走上一張且未超過 fps 上限才 ack，慢的連線只會讓 Chrome 變慢、不會堆積）；`kind=desktop` 是 Bot Desktop／桌面 VM 的畫面（QMP `screendump`，畫面變了才送，速率自適應，不刷新 VM 的閒置計時）；`kind=terminal` 是代理正在執行的指令與輸出（所有 exec 後端，包括 microVM；以 vault 遮蔽秘密）。沒有畫面的目標回 `nodisplay`，主控台改顯示終端機。預設 30 fps、JPEG 85、依檢視區實際大小 × devicePixelRatio（最高 3840 px）送出，主控台可選到 60 fps；只有連線或檢視端跟不上時才先降畫質、再降 fps，恢復後回到所選等級。錄影（`browser record`）與檢視共用同一個 screencast，互不停止。所選 fps 是下限：串流以高出 10% 的速率送出，忙碌時仍不低於所選值。Bot Desktop 上若是代理自己的瀏覽器（常見情況），桌面串流改為「patch 模式」：整個桌面的底圖只在頁面以外有變化時才重送（每 250 ms 檢查、閒置時放慢到 1 s），頁面本身直接轉送瀏覽器的 CDP screencast JPEG（`{t:"patch", x, y, w, h}`，螢幕像素），主控台在 canvas 上合成；不需每格擷取與重新編碼，1080p 實測 30 fps 選項約 30、60 fps 選項約 52–54，閒置桌面不送任何資料。其他視窗蓋住頁面時（Windows 會檢查）改回整張擷取。沒人看時什麼都不擷取。輸入沿用 `view.*.input` 與租約規則，且需要可 POST 的憑證（read scope 只能看）。

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

## 內建瀏覽器

- `install.sh --with-browser`：把固定版本的 Chrome for Testing（`157.0.8103.38`，zip sha256 `8cdeb344…2a66`）驗證後解到 `<share>/browsers/chrome-linux64/`。
- 離線包：`make-offline-bundle.sh --with-browser [--browser-zip FILE]` 會帶上 `browser/chrome-linux64.zip`，`install-offline.sh` 與 `install.sh --with-browser` 會使用它。
- `seagent browser install` 預設也改成下載同一個固定版本並驗證 sha256（`--url latest` 才查 Google 的最新版索引）。
- 探索順序：`[browser] prefer_bundled = true` 時優先用內建版本；否則主機瀏覽器找不到時才退回內建版本。
- 桌面 VM 映像本身內建 Debian 的 `chromium`。

## 已知限制

- 只支援 x86_64 主機；鍵盤事件為美式配置。非 ASCII 文字依賴客體內的 `seagent-text-input`（2026-11 以後建的映像才有），是「輸入文字」而不是輸入法組字。
- 主機（`target = host`）的 `view.desktop.input` 走 xdotool / ydotool，主機沒有這些工具時會回報錯誤。
- 映像重建後，舊 VM 的疊加層仍指向舊映像檔；要用新映像請執行 `seagent vm desktop reset <name>`。
