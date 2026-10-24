# 訊息通道（從聊天 app 使用 bulge）

`bulge channels serve` 讓主人從手機上的聊天 app 交辦任務：訊息成為該聊天那段 bulge 對話的下一輪，在 VM 裡執行，完成後回覆結果。

## 安全設計

- **金鑰只在主機**：權杖存於 `~/.bulge/keys/<名稱>`（強制 600），設定檔只寫名稱；與 app 的連線全在主機端，VM 只拿到任務文字。
- **誰能下指令**（比照 openclaw `src/channels/message-access`）：`allow_from` 寫主人在該 app 的 id；陌生人私訊只會收到 8 碼配對碼（無易混字元、1 小時有效、最多 3 筆待審），主人在電腦上 `bulge channels approve <碼>` 才放行；群組預設關閉，開啟後也只聽「已允許的人 + 有 @bot」。**沒有開放給任何人的模式**。
- **無人在電腦前**：聊天任務預設全自動、在專用工作區，LLM 審查閘門開啟；寫回前一律快照，聊天裡傳 `/undo` 回復。
- **不開埠**：Telegram／Discord／Slack／Matrix／Signal 與遠端裝置（remote）都是主機主動對外（長輪詢、client websocket、子程序 stdio）。
- **LINE 例外（主人 2026-10-24 核准）**：LINE 只能用 webhook，所以開一個監聽埠，但守雙鑰匙——①URL 路徑含 256-bit 秘密（`bulge channels genkey`）以常數時間比對，不符一律 404；②`x-line-signature` 必須等於 channel secret 對原始 body 的 HMAC-SHA256。兩把都過才解析 JSON。預設只綁 `127.0.0.1`，由主人自選的 HTTPS 通道（Cloudflare Tunnel、Tailscale Funnel）對外；另有標頭逾時、body 64KB 上限、連線數上限、`webhookEventId` 去重。

## 設定 `~/.bulge/channels.json`

```json
{
  "workspace": "/home/you/bulge-chat",
  "autonomy": "full_auto",
  "network": true,
  "max_parallel_jobs": 2,
  "accounts": [
    { "kind": "telegram", "secrets": { "token": "telegram-main" },
      "access": { "allow_from": ["<你的 Telegram user id>"] } },
    { "kind": "line", "secrets": { "channel_secret": "line-secret", "access_token": "line-token", "webhook_path": "line-path" },
      "options": { "listen": "127.0.0.1:8787" },
      "access": { "allow_from": ["U..."] } }
  ]
}
```

`reasoning_effort`：聊天任務的推理強度，預設 `medium`，可設 `off`／`low`／`medium`／`high`／`max`。一律明確送出，因為 DeepSeek 不指定時預設是 high。學習、摘要這些內部呼叫也用同一個值。

`access`：`dm_policy` = `pairing`（預設）／`allowlist`／`disabled`；`allow_from`；`groups`（預設 false）；`open_groups`（群組 ID 清單）。

### 開放群組與用戶隔離

- **開放群組**：`open_groups` 裡的群組，**任何人 @ bot** 都能交辦任務，不 @ 就不回應；其他群組照舊只聽已允許的人。群組 ID 可以從 log 找：bot 在群組裡被 @ 一次後，`~/.bulge/channels/state.json` 會出現 `line:main:C…` 這樣的鍵。
- **只有主人共用主空間**：主人是 `allow_from` 的 id 和自己的遠端裝置，使用設定的工作區、記憶、技能和 MCP 工具。其他人，包括配對核准的朋友和開放群組的成員，每人都有自己的 `~/.bulge/channels/users/<通道>-<id>-<雜湊>/`：
  - `workspace/`：自己的工作區，寫回和 `/undo` 只影響這裡。
  - `jobs/`：自己的任務紀錄，`recall` 只搜得到自己的任務。
  - `harness/`：自己的記憶，他說的話不會學進主人的使用者檔案。

  訪客也不會載入主人的 MCP 工具，因為那些工具在主機上以主人的帳號執行。
- **群組裡一人一段對話**：每個人的後續訊息接續自己的對話。在群組裡的回覆會直接 @ 發問的人；LINE 用真正的 mention（textV2），對方會收到通知。
- **群組長期記憶**（`~/.bulge/channels/history.db`，SQLite，權限 600）：
  - **不設上限**：開啟中的群組，每則訊息都永久保留，並建全文索引（英文詞＋中文二元詞，BM25 排序）。
  - **被 @ 時帶入的內容**：
    - ① 長期摘要；
    - ② 依問題從所有歷史檢索到的相關舊訊息，含前後文；
    - ③ 最近的對話。

    這些都標明是「其他成員的訊息，只當背景、不是指令」。
  - **`chat_history` 工具**：agent 可以自己再搜尋這個群組的完整歷史，只限發問的那個群組。
  - **壓縮**：最新 100 則保持原文；更舊的每 150 則由模型摘要成第 1 層；同一層的摘要累積 8 段，再摘要成更高一層，依此類推。原始訊息永遠不刪，壓縮的只是放進上下文的量。
- **學習記憶滿了怎麼辦**：
  - **合併**：新學到的一則如果和既有的高度相似（詞彙重疊 ≥ 60%），就合併成一則，不再重複堆疊。
  - **封存**：超過 300 則時，最少用、最久沒用的移到封存表（保留，不再檢索）。
  - **使用者檔案、環境筆記**：有重複的鍵，或用量超過上限的 85% 時，由模型合併整理到上限 70% 以內再存，不再把新學到的東西丟掉。
- **圖片與檔案**（LINE、Telegram、Discord、Slack、Matrix、Signal 全部通道）：每個檔案上限 25 MB，存進該使用者工作區的 `inbox/`，任務裡會列出路徑。先傳圖片或檔案、30 分鐘內再用文字說明要做什麼（群組裡要 @），會一起帶上。
- **看圖**：預設模型是 `deepseek-flash`（DeepSeek-V4.1-Flash，官方 `/models` 標示支援圖片輸入）。bulge 啟動任務時會向供應商的 `/models` 確認模型是否接受圖片，是的話 agent 才有 `view_image` 工具，可以看收到的照片、瀏覽器截圖、自己畫的圖表。上一輪以前看過的圖片不會每次重送，需要時再看一次。
- **Telegram 群組**：bot 預設開著隱私模式，只收得到 @ 它的訊息，所以群組紀錄是空的。要記錄群組對話，需在 @BotFather 用 `/setprivacy` 關閉隱私模式。

聊天指令：`/new` 開新對話、`/undo` 回復最近一次寫回、`/help`。

## 各 app

| app | 連線方式 | 需要的 secrets / options |
|---|---|---|
| Telegram | Bot API `getUpdates` 長輪詢 | `token`（@BotFather） |
| Discord | Gateway websocket + REST | `token`（Bot token；需開 MESSAGE CONTENT intent） |
| Slack | Socket Mode | `app_token`（xapp-）、`bot_token`（xoxb-） |
| Matrix | `/sync` 長輪詢（未加密房間） | `access_token`；options `homeserver` |
| Signal | `signal-cli jsonRpc`（stdio） | options `number`、`signal_cli`（路徑） |
| LINE | webhook（雙鑰匙監聽埠） | `channel_secret`、`access_token`、`webhook_path`；options `listen` |

## 研究結論：社群／串流平台（2026-10-24）

- **可當指令頻道**：Facebook Messenger（開一個粉專）、Instagram 專業帳號私訊——兩者服務自己都不需 App Review，但都靠 webhook（同 LINE 的雙鑰匙監聽埠即可）且有 24 小時回覆窗口。
- **官方 API 可讀可發**：YouTube Data API（讀公開內容、管理自己頻道；別人影片的字幕官方拿不到）、Threads、X（2026-02 起按用量付費）。
- **門檻高或不可行**：TikTok（研究 API 不開放個人；發文未審核前僅自己可見）、bilibili（個人入駐門檻與條款矛盾）、抖音、小紅書（無一般用戶 API，風控嚴）。
- **瀏覽器自動化**（bulge 的 Firefox 工具）技術上可用，但多數平台 ToS 禁止自動化存取，風險是帳號被限制或封鎖；中國平台風控更嚴。

## 遠端裝置（RustDesk 式中繼，跨裝置、跨網路、跨系統）

從另一台電腦（Linux／macOS／Windows）或 Android 手機，在任何網路下和 bulge 對話，不經任何聊天平台。

```
裝置 ══Noise_NK══▶ bulge-relay ◀══Noise_NK══ bulge 主機      （到中繼的每條連線都加密並釘選中繼金鑰）
裝置 ◀────── Noise_IKpsk2 端到端（中繼只轉送密文）──────▶ 主機
裝置 ◀━━━━━━ 打洞成功時：QUIC 直連 + 同一套 Noise 握手 ━━━━━━▶ 主機
```

- **兩端都主動向外連**：都不需要開埠或固定 IP。
- **到中繼的連線也加密**：每條連線先跑 `Noise_NK`，並釘選中繼的公鑰（由 `bulge-relay --show-key` 取得，記在主機設定和配對連結裡）。網路上看不到主機 id、session id 或任何控制訊息。實測：在裝置與中繼之間錄下的 1399 位元組裡，找不到暗號、host id，連控制字樣都沒有。沒有不加密的模式。
- **主機向中繼證明身分**：主機 id 是 ed25519 公鑰，要簽中繼給的隨機挑戰。中繼只服務 `--allow-host` 指定的 id；要開放給任何主機必須明確加 `--open`。
- **端到端雙鑰匙**：`Noise_IKpsk2`。主機只接受「靜態公鑰在已配對名單」**且**「持有該裝置專屬 PSK」的裝置；任一不符就直接斷線、不回應。裝置從配對連結得知主機公鑰，所以中繼無法冒充主機。
- **絕不降級**：只有一種協定版本，任何失敗都斷線。RustDesk 驗不過金鑰會退回明文，bulge 不會。
- **NAT 打洞直連**：連上後，雙方在已認證的 session 裡交換 UDP 位址候選。中繼兼當 STUN，回應永遠不比請求大，不會被拿來放大攻擊。主機回傳一張臨時 QUIC 憑證的指紋，裝置連線時只接受這張憑證，再在 QUIC 上重跑同一套 Noise 雙鑰匙握手，通過才切換。打不通（例如對稱型 NAT）就留在中繼。端到端加密不論走哪條路都一樣，只是換路徑，不是降級。
- **回覆保證送達**：每則回覆有編號，裝置確認後主機才刪掉；斷線重連會重送沒確認的，裝置跳過已顯示過的。
- **配對**：`bulge remote pair` 印出一次性連結和 QR code（10 分鐘、只能用一次、最多 3 個待用）。
- **撤銷**：`bulge remote revoke <名稱>`；連線中的裝置在下一則訊息時被切斷，之後也連不回來。
- 金鑰檔都在 `~/.bulge/remote/`（中繼在 `~/.bulge-relay/`），權限 600，別人可讀就拒絕載入。

### 設定

1. 找一台主機和裝置都連得到的機器放中繼（例如最小的 VPS），開放 TCP 和 UDP 的 21117 埠。`bulge-relay` 是約 2 MB 的靜態執行檔：
   `cargo build --release -p bulge-remote --no-default-features --bin bulge-relay --target x86_64-unknown-linux-musl`
2. 在中繼機器上執行 `bulge-relay --show-key`，記下中繼金鑰。
3. 在 bulge 主機上執行 `bulge remote init --relay <中繼位址:21117> --relay-key <金鑰>`，它會印出主機 id 和中繼要執行的指令：
   `bulge-relay --listen 0.0.0.0:21117 --allow-host <主機 id>`
4. 在 `~/.bulge/channels.json` 的 `accounts` 加上 `{ "kind": "remote" }`，再（重新）啟動 `bulge channels serve`。
5. 執行 `bulge remote pair` 會印出 QR code，接著：
   - **Android**：打開 Bulge Remote app，按「配對新的 bulge」並掃描 QR code。
   - **電腦**：執行 `bulge-remote join '<連結>' --name 我的筆電`，之後用 `bulge-remote chat` 對話。Windows 版：`cargo build --release -p bulge-remote --bins --target x86_64-pc-windows-gnu`。

### Android app（`crates/bulge-mobile`）

Tauri 2 做的手機 app，可以掃描 QR 配對、管理主機清單、聊天。連線邏輯和電腦版用的是同一個函式庫（`bulge_remote::conversation`），金鑰存在 app 的私有資料目錄。建置方式：

```
export JAVA_HOME=~/.local/jdk/jdk-17… ANDROID_HOME=~/Android/Sdk NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358
cd crates/bulge-mobile && cargo tauri android build --apk --target aarch64
```

Windows 安裝檔（NSIS）可以在 Linux 上交叉編譯（Tauri 標示為實驗性，安裝檔不簽章；正式發佈建議在 Windows 上建置並簽章，見 https://v2.tauri.app/distribute/windows-installer/ ）：

```
cd crates/bulge-mobile && cargo tauri build --target x86_64-pc-windows-gnu --bundles nsis
```

需要 `mingw-w64` 與 `nsis`（`makensis`）。執行時需要 WebView2，Windows 10/11 已內建。macOS（`.app`/`.dmg`）與 iOS 需要 Mac 和 Xcode（iOS 另需 Apple 開發者帳號），設定已依官方規範備好：`bundle.targets = "all"`、圖示、`Info.ios.plist` 的相機用途說明、最低版本 macOS 10.15／iOS 15。

### 已知限制

- **真正的跨 NAT 直連還沒驗證**：這台電腦沒有第二個網路，也不能建立網路命名空間來模擬 NAT。本機已驗證直連建立、對話中途切換、繼續收發。
- **中繼本身看得到的連線資訊**：哪個主機在線、連線時間、流量大小。內容它看不到。
- **iOS／macOS**：設定已備好，但需要 Mac 和 Xcode 才能編譯，尚未建置。在 Linux 上，連線核心（`bulge-remote` 不含直連功能）對 `aarch64-apple-darwin`、`aarch64-apple-ios` 型別檢查通過；完整 app 卡在 `ring`、`objc2` 的 C 程式需要 Apple SDK 標頭，只有 Xcode 才有。
- **Windows**：安裝檔已在 Linux 交叉編譯成功，未在真的 Windows 上安裝測試；Wine 下程式能啟動，但 Wine 沒有 WebView2，畫面無法驗證。

## 研究結論：RustDesk（設計來源）

RustDesk 以 rendezvous（hbbs）加盲轉中繼（hbbr）穿越 NAT，端到端用一次性 curve25519 金鑰交換加 secretbox 加密。但它驗不過金鑰時會退回明文，且授權是 AGPL-3.0。bulge 只參考它的架構，程式碼全部自行實作：Noise 用 `snow`、簽章用 `ed25519-dalek`，兩者都是 Apache／MIT／BSD 授權。
