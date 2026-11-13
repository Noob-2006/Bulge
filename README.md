# ✦ SE Agent

**版本 0.2.0-alpha（Alpha 測試版）** · Windows · macOS · Linux · Android · iOS

自架的 AI 代理（agent），以 Rust 撰寫：一套程式碼跑在桌機、伺服器與手機上，單一執行檔、依賴極少，可以長時間穩定地自動化工作。名稱是 System Engineering Agent，指令是 `seagent`。

> **Alpha 是什麼意思**：功能已經齊全，可以每天使用；但設定格式、指令名稱和網頁主控台在 0.x 期間還可能調整，升級時請先看 [CHANGELOG.md](CHANGELOG.md)。安裝檔還沒有程式碼簽章，Windows SmartScreen 和 macOS Gatekeeper 會跳警告（處理方式見 [docs/install.md §0](docs/install.md#0-選擇平台與安裝檔)）。各平台的驗證狀態見下方「[平台狀態](#平台狀態)」，請勿在沒有備份的正式環境使用。

## 它能做什麼

你用自然語言交代工作，SE Agent 在**你自己的機器上**動手完成，模型只是它的「大腦」，可以隨時更換。

- **系統與維運**：跑指令、改設定檔、看日誌、巡檢主機、透過 SSH 操作遠端伺服器，cron 排程與長期目標（goal）讓它定時回報或自動修復。
- **寫程式**：讀整個專案、修 bug、跑測試、開 git worktree 平行處理，也能在 Zed／JetBrains／Neovim 裡當編輯器代理（ACP）。
- **操作網頁與桌面**：內建瀏覽器工具（CDP），以及一台有畫面的**桌面 VM**（Debian + Xfce + Chromium），代理靠截圖與模擬滑鼠鍵盤操作（computer use），你可以在主控台以 30 fps 以上的即時畫面觀看、隨時接手。
- **隔離執行**：有風險的指令放進 microVM（Firecracker／QEMU／Hyper-V／Virtualization.framework），iOS 則用 WebAssembly 沙盒；隔離等級一律明示，不會靜默降級。
- **研究與內容**：網路搜尋、深度研究報告、文件抽取、圖片／影片／音樂生成、TTS／STT 語音、會議機器人，也能把多個工具串成流程（例如自動做成投影片式影片）。
- **聊天平台與自動化**：在 Telegram、LINE、Discord、Slack、Teams、飛書、Email 等 46 條通道上回應指令，做成團隊或個人的值班助理。
- **多代理協作**：派子代理平行做事、kanban 看板、群聊房間，各代理有獨立的花費與資源上限。

- **只有兩道閘門**：提權（sudo、寫系統路徑）和資料外送（秘密、個資離開機器）。其他事情直接做，不會一直跳出確認。破壞性動作按四級風險處理：VM 內與可回復的直接放行，只有「VM 外且不可回復」才一定問人。
- **省 token**：工具採漸進揭露、固定前綴快取（壓縮與 fork 子代理都重播同一份前綴，舊工具輸出只在上下文吃緊時才裁剪）、自動壓縮，並把大型輸出溢寫到檔案；`seagent session stats --session <id>` 看每一步的快取命中率。
- **一套協議，到處都能用**：網頁、桌面、手機（PWA）、終端機 TUI、編輯器（ACP）、裝置（node）、其他 agent（A2A），以及 OpenAI 相容 API，全部講 [ARP](docs/arp.md)。
- **46 條聊天通道**：Telegram、Discord、Slack、LINE、WhatsApp、Signal、Matrix、Teams、飛書、釘釘、企業微信、QQ、Email……其中 43 個平台由 `seagent-channel` 直接內建（另有 webchat、A2A、OpenAI 相容 API 三條由 App Server 提供）；逐平台狀態見 [docs/parity.md](docs/parity.md)。
- **MCP 完整支援**：stdio、Streamable HTTP、舊版 SSE，OAuth 2.1（PKCE、動態註冊、device flow），sampling、elicitation、roots、成本上限，也可反過來當 MCP server。

## 功能總覽

| 面向 | 有什麼 |
|---|---|
| 代理核心 | 單次任務、互動對話、session 分支與搜尋、背景 daemon、cron 排程、長期 goal、heartbeat、自動化建議、kanban 多代理看板、git worktree 平行工作區 |
| 子代理艦隊 | `delegate_task`／`sessions_spawn`／`agents_wait`／`subagents`：背景派遣、中途 steer 與取消、共用公告板、點對點訊息、檔案租約（預設 1 小時、最長 7 天、過期自動釋放）、每代理與全域的花費／磁碟／程序上限（`seagent fleet`）；群聊房間（`seagent rooms`，lead／auto 分派）、Ralph 全新 context 輪次 |
| 安全 | 四級風險分類（`seagent-security` 的 `risk`）、任務信封（一次性授權路徑／主機／指令／花費／期限）、有期限的具名授權、不可關閉的硬底線、不可信內容降權、延後佇列（只卡那一條）、逐模型的 exec 上限與 `seagent tools explain`、緊急停止（`seagent pause`） |
| 執行環境 | microVM（Firecracker／QEMU）、gVisor、docker／podman、bwrap／Landlock、ssh／modal／daytona…，隔離等級一律明示、不靜默降級；VM 快照與 undo；指令 broker（只收 argv、白名單、稽核）與出口 proxy（內建 32 個開發主機） |
| 模型 | OpenAI Chat／Responses、Anthropic、Gemini／Vertex、Bedrock、OpenAI Agents API、外部 agent CLI（claude／gemini／codex、ACP、muse）、託管 llama.cpp；訂閱登入、多金鑰輪替、fallback、輔助小模型、用量與帳單（`seagent usage`） |
| 工具 | 檔案、shell、背景 job、todo、skill、memory、web 搜尋與抓取、深度研究（`deep_research`）、瀏覽器與電腦操作、圖片／影片／音樂生成、TTS／STT／語音、會議機器人、電話、排程、子代理 |
| 介面 | 終端機 TUI、網頁／PWA（App Server，同一套 ARP）、ACP（Zed／JetBrains／Neovim）、node 裝置、A2A、OpenAI 相容 API、canvas |
| 相容 | Claude 格式的技能目錄（`.claude/skills`）與 hooks、OpenClaw／Hermes 的技能 metadata、MCP、外掛 |
| 法遵 | `privacy_notice`、`ai_label`、`[compliance] retention_days`、公部門 profile、`seagent data export` / `seagent data delete` |

使用者手冊（安裝、通道、安全模型、VM、艦隊、技能與外掛）：[docs/MANUAL.md](docs/MANUAL.md)。

- 各平台安裝、套件（deb／rpm／pacman／apk／npm／Nix）與疑難排解：[docs/install.md](docs/install.md)
- 常見問題：[docs/faq.md](docs/faq.md)
- 參與開發：[CONTRIBUTING.md](CONTRIBUTING.md)（每個 commit 需 `Signed-off-by`）；回報漏洞：[SECURITY.md](SECURITY.md)（私下回報）；行為準則：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- 授權：Apache 2.0（[LICENSE](LICENSE)、[NOTICE](NOTICE)），第三方來源見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；變更紀錄：[CHANGELOG.md](CHANGELOG.md)

## 相容的生態

SE Agent 是獨立實作，不是任何專案的分支；它讀得懂下列生態的格式，搬過來不必重寫。

| 生態 | 相容到什麼程度 | 文件 |
|---|---|---|
| **Claude Code** | 技能目錄（`.claude/skills`、`SKILL.md`）、hooks（同樣的事件與 JSON）、settings、外掛市集格式；也能把 `claude` CLI 當成外部代理呼叫 | [other-ecosystems.md](docs/ecosystem/other-ecosystems.md) |
| **OpenClaw** | 技能 metadata、設定、外掛、ClawHub、node 裝置；`seagent migrate from openclaw` 匯入 | [openclaw-compat.md](docs/ecosystem/openclaw-compat.md) |
| **Hermes Agent** | 技能、設定、`plugin.yaml` 外掛、optional-mcps；`seagent migrate from hermes` 匯入 | [hermes-compat.md](docs/ecosystem/hermes-compat.md) |
| **LangChain／LangGraph** | 從 LangChain 經 OpenAI 相容 API、MCP 或 A2A 接入；`graph-flow` 工具提供 LangGraph 式的持久化流程；LangSmith 可經 OTLP 收追蹤 | [langchain-integration.md](docs/ecosystem/langchain-integration.md)、[graph-flows.md](docs/ecosystem/graph-flows.md)、[langsmith.md](docs/ecosystem/langsmith.md) |
| **MCP** | client 與 server 都支援：stdio、Streamable HTTP、SSE、OAuth 2.1 | [§MCP](#mcp) |
| **ACP／A2A／OpenAI API** | 編輯器（Zed、JetBrains、Neovim）、其他代理、任何講 OpenAI Chat Completions 的程式 | [arp.md](docs/arp.md) |
| **模型供應商** | Anthropic、OpenAI、DeepSeek、Gemini／Vertex、Bedrock、Mistral、OpenRouter、本地 llama.cpp／Ollama／vLLM 等 OpenAI 相容端點 | [MANUAL.md §9](docs/MANUAL.md#9-模型供應商與成本) |

匯入時預設**不**搬金鑰，要搬請加 `--migrate-secrets`（寫進加密保管庫）。

## 參考的上游專案

SE Agent 的功能設計逐項對照了下列開源代理專案，並把其中值得的部分以 Rust 重新實作（都是 MIT 授權，出處與版權聲明見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)）：

| 上游 | 對照版本 | 借鏡了什麼 |
|---|---|---|
| [OpenClaw](https://github.com/openclaw/openclaw)（OpenClaw Foundation） | `8a186ad` | 聊天通道與閘道、node 裝置、技能與外掛格式、瀏覽器沙盒、TTS 工具 |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent)（Nous Research） | `90d6b98` | 聊天平台轉接器、終端機介面與 slash 指令、檢查點與 `/undo`、語音模式、WhatsApp／iMessage 橋接、秘密遮蔽、安全指引外掛 |
| DeepSeek Harness（dsh） | `fcc0ad4` | 前綴快取策略（壓縮與 fork 子代理重播同一份前綴、只在上下文吃緊時裁剪）、逐步 TTFT 與快取統計、DeepSeek Messages 路由 |
| LangChain v1／LangGraph／deepagents／LangSmith | — | 代理迴圈、checkpoint 與 interrupt（人類介入）、持久化流程、追蹤格式；見 [langchain-internals.md](docs/ecosystem/langchain-internals.md) |

逐項落差報告在 [docs/parity-agent/](docs/parity-agent/)（含 `upstream-2026-11-06/` 這一輪同步），平台與功能對照在 [docs/parity.md](docs/parity.md)。上游預設會把工作階段紀錄上傳到模型供應商的功能（例如 dsh 的 `dsh_session_log`）**刻意沒有**移植。

## 怎麼做出來的

SE Agent 主要由 AI 程式代理在人類的指揮與審查下寫成：

- **DeepSeek Harness**：前期的核心、工具與上游對照。
- **Claude Code**（Anthropic）：跨平台移植（Windows／macOS／Android／iOS）、安裝檔與內建 VM、文件，以及在 Windows 實機上的驗證。

每個 commit 都經過測試；由代理寫成的 commit 帶有 `Co-Authored-By` 標記。產生的程式碼一樣以 Apache 2.0 授權發布。

## 平台狀態

0.2.0-alpha 在各平台的驗證程度（「實機」是在真的裝置上安裝並操作過；「建置」是安裝檔能產出、內容檢查過，但還沒在該平台上操作）：

| 平台 | 安裝檔 | 驗證程度 | 內建 VM | 備註 |
|---|---|---|---|---|
| Windows 10／11 x64 | `SE Agent_0.2.0-alpha_x64-setup.exe`、`.msi`（英／繁中／簡中） | **實機**（Windows 11 Home） | QEMU + WHPX（安裝包內附）；Hyper-V／VirtualBox 備援 | 附虛擬顯示器驅動；未簽章 |
| Linux x86_64 | `.AppImage`、`.deb`、`.rpm`；CLI 另有 musl 靜態執行檔與 deb／rpm／pacman／apk | **實機**（WSL2 Ubuntu）；原生桌面發行版待測 | Firecracker（內附）；桌面 VM 用系統的 QEMU | 主要開發平台 |
| macOS 11+（Apple Silicon／Intel） | `.dmg` | 程式碼可編譯；**安裝檔尚未產出**（需要 Mac 的 CI） | vfkit／Virtualization.framework；桌面 VM 用 Homebrew 的 QEMU | 等 CI 與 Apple 憑證 |
| Android 8+（arm64） | `.apk`（目前是 debug 簽章） | **建置** | AVF（支援的機型） | 也能連到區域網路裡的電腦 |
| iOS／iPadOS | App Store／TestFlight | 程式碼可編譯；**尚未產出**（需要 Mac 的 CI） | 無（平台禁止），改用 WASM 沙盒 | 完整代理在 App 行程內執行 |

## 安裝

各平台、各版本的完整步驟、升級與疑難排解在 [docs/install.md](docs/install.md)。最短的路：

| 你用的是 | 下載 | 然後 |
|---|---|---|
| Windows | `SE Agent_<版本>_x64-setup.exe` | 點兩下 → 「其他資訊 → 仍要執行」（未簽章） → 安裝完自動開設定精靈 |
| macOS | `SE Agent_<版本>_universal.dmg`（Apple Silicon 與 Intel 共用） | 拖進「應用程式」→ 第一次右鍵「打開」（未公證） |
| Linux 桌面 | `.AppImage`（任何發行版）或 `.deb`／`.rpm` | `chmod +x` 後執行；或 `sudo apt install ./SE-Agent_*.deb` |
| Linux 伺服器 | 一個指令（下方） | 照印出的連結開設定精靈 |
| Android | `.apk` | 允許「安裝不明應用程式」後安裝 |
| iOS | TestFlight 連結（上架後） | — |

升級：Windows／macOS／Linux App 直接裝新版即可，設定與資料保留（從 0.1.0 升級要注意的事見 [docs/install.md §10](docs/install.md#10-版本與升級)）。

### Linux／伺服器：一個指令

一個指令：安裝、啟動背景服務與網頁主控台，最後印出（並在桌面環境自動開啟）一次性的設定精靈連結。

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/Noob-2006/SE-Agent/releases/latest/download/install.sh | sh                 # 個人安裝，不需 sudo
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/Noob-2006/SE-Agent/releases/latest/download/install.sh | sudo sh -s -- --system  # 系統服務
```

在瀏覽器的設定精靈選模型供應商、貼金鑰（只存進保管庫）、挑預設模型、管理者登入方式（本機權杖或 OIDC）、工作目錄、安全模式、聊天平台；完成後精靈自動鎖定，SE Agent 以新設定重啟並帶你進主控台。設定連結 30 分鐘內有效、只能用一次；需要新的連結：`seagent setup link`。

- 重跑同一個指令即升級；`--uninstall` 解除安裝（保留設定與資料），加 `--purge` 一併清除。
- 其他選項：`--port`、`--version`、`--no-browser`、`--no-systemd`、`--local-binary PATH`、`--package FILE`（deb/rpm）、`--from-source`；`--help` 看全部。離線包解開後直接執行其中的 `install.sh`。
- 沒有瀏覽器時用終端機精靈：`seagent setup`（同一套套用邏輯）。目錄配置見 [docs/paths.md](docs/paths.md)，企業部署見 [docs/enterprise/install.md](docs/enterprise/install.md)。

從原始碼：`cargo build --release && packaging/install.sh --local-binary target/release/seagent`。也有 [Dockerfile](Dockerfile) 與 [Nix flake](flake.nix)。

指定版本：`… install.sh | sh -s -- --version v0.2.0-alpha`（不加就是最新的正式版；alpha 要明確指定）。

### 圖形安裝（App，不需終端機）

從 [Releases](https://github.com/Noob-2006/SE-Agent/releases) 下載一個檔、點兩下就裝好：Windows `SE Agent_*_x64-setup.exe`（個人安裝，不需管理員；另有 `.msi`）、macOS `.dmg`、Linux `.AppImage` / `.deb` / `.rpm`、Android `.apk`。App 第一次開啟會安裝並啟動背景服務，接著在視窗裡開同一個設定精靈；之後常駐系統匣（開啟主控台、暫停、重新啟動服務、登入時啟動、檢查更新）。原始碼與建置方式見 [apps/desktop/README.md](apps/desktop/README.md)。

**iOS 在手機上執行完整的 agent**（無伺服器，跟其他平台一樣）：agent 以函式庫形式連進 App、在 App 自己的行程裡跑——核心、session、模型供應商、記憶、技能、web 抓取／搜尋、App 沙盒內的檔案工具、MCP（Streamable HTTP／SSE）、純網路的聊天平台、排程，以及綁在 127.0.0.1 的 App Server（主控台照桌面版的方式載入）。iOS 只禁止兩件事：**虛擬機**與**原生 shell 程式**（不能開子程序、不能 JIT）。指令改在 App 內的 **WebAssembly 沙盒**執行（`exec.backend = "wasm"`：wasmi 直譯器 + 內建 POSIX shell + 釘選 SHA-256 的 uutils coreutils WASI 版，只看得到工作區與私有 `/tmp`、沒有網路）。App 在背景時，排程與心跳工作由 iOS 的 BGProcessingTask 在系統允許時執行。和區域網路中的電腦配對（Bonjour、QR／8 碼、TLS 指紋釘選）變成**選用**。詳見 [apps/desktop/MOBILE.md](apps/desktop/MOBILE.md)。

## 快速開始

```bash
seagent setup                                # 設定精靈：選供應商、填金鑰、從清單挑模型、試打一次，可順便開網頁介面與 Telegram/Discord/Slack
seagent run "整理這個資料夾的 README，列出待辦"   # 單次執行
seagent chat                                 # 互動對話
```

也可以跳過精靈：`seagent secrets set ANTHROPIC_API_KEY`（或 OPENAI / DEEPSEEK…）後直接用預設模型。設定檔位置用 `seagent config path` 查（個人安裝是 `~/.config/seagent/config.toml`，系統服務是 `/etc/seagent/config.toml`），完整範例見 [docs/config-example.toml](docs/config-example.toml)。

## 常駐服務與介面

```bash
seagent daemon start                         # 背景服務：排程、goal、channel、App Server
seagent service install                      # 開機自動啟動（systemd user unit）
seagent tui                                  # 終端機介面
seagent app token                            # 產生 App Server token 的步驟
seagent app open                             # 用瀏覽器 App 視窗開啟網頁介面
```

網頁介面也能安裝成桌面或手機 App（PWA），外觀是深緋紅漸層搭配亮金色四角星。

### 編輯器（ACP）

Zed `settings.json`：

```json
{ "agent_servers": { "seagent": { "command": "seagent", "args": ["acp"] } } }
```

### 裝置（node）

```bash
seagent node --url ws://主機:8640/node       # 在另一台機器上執行
seagent nodes approve <配對碼>               # 在主機上核准
```

裝置能執行哪些指令，由裝置自己的 `~/.config/seagent/node.toml` 決定。

### OpenAI 相容 API

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8640/v1/chat/completions \
  -d '{"model":"seagent","messages":[{"role":"user","content":"hi"}]}'
```

### 聊天平台

在設定檔加入 `[channels.<名稱>]`，並設定 `kind = "telegram"` 等。對陌生人預設拒絕；可以改成 `dm_policy = "pairing"`，讓對方取得配對碼，再由你用 `seagent pairing approve` 核准。

### MCP

```bash
seagent mcp add files -- npx -y @modelcontextprotocol/server-filesystem ~/docs
seagent mcp login github                     # OAuth（--device 給沒有瀏覽器的主機）
seagent mcp serve                            # 讓其他 agent 使用 seagent 的工具
```

## 個資與法遵

台灣法規對照與檢查清單見 [docs/compliance-tw.md](docs/compliance-tw.md)，風險自評見 [docs/risk-assessment.md](docs/risk-assessment.md)。相關功能：

- 告知訊息：`privacy_notice`
- AI 標示：`ai_label`
- 保存期限：`[compliance] retention_days`
- 公部門模式：`profile = "government"`
- 當事人權利：`seagent data export|delete`

## 架構

使用者手冊在 [docs/MANUAL.md](docs/MANUAL.md)：安裝、通道、安全模型（四級風險／信封／授權）、VM、艦隊、技能與外掛相容。

| crate | 職責 |
|---|---|
| `seagent-core` | 型別、工具與 provider 介面 |
| `seagent-kernel` | session 迴圈、閘門、事件紀錄、daemon、ARP |
| `seagent-model` | Anthropic、OpenAI、DeepSeek、Mistral、Gemini 等模型的 API 格式 |
| `seagent-tools` | 檔案、shell、job、todo、skill、memory、web、子 agent |
| `seagent-plugin` | MCP client、server、OAuth，以及外掛協議 |
| `seagent-net` | TLS、WebSocket、HTTP 伺服器、加密工具 |
| `seagent-channel` | 43 個聊天平台（56 個 kind 名稱含別名）、存取政策、配對、投遞 |
| `seagent-app` | App Server、Web UI、TUI、ACP、node、A2A、OpenAI API |
| `seagent-vm` | microVM／容器／namespace 後端、隔離等級、映像與快照 |
| `seagent-media` | 視覺、文件抽取、圖片／影片／音樂生成、TTS／STT、語音、會議 |
| `seagent-browser` | CDP 瀏覽器控制與擷取 |
| `seagent` | CLI |

分層規則、功能如何自我登記（工具／命令／設定段驗證）、以及「一個職責不要拆成十個碎檔」的實際上限（3,000 行、單一目錄 5 個檔案）
都寫在 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，並由 `cargo test -p seagent --test arch_lint` 強制。
建置選項（聊天平台與額外模型格式都能在編譯時拿掉，預設建置仍是完整版）、`[profile.slim]`、實測大小與大小預算檢查，
見 [docs/BUILD.md](docs/BUILD.md)。測試留下的暫存目錄可以清：`seagent system temp-clean --older-than 24`（預設只列出）。

## 授權

Apache License 2.0（[LICENSE](LICENSE)、[NOTICE](NOTICE)）。0.2.0-alpha 以前的版本以 MIT 發布。部分程式轉寫自 OpenClaw、Hermes Agent 與 DeepSeek Harness（皆為 MIT，其版權與授權聲明照 MIT 要求保留），見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。Windows 安裝包內附的 QEMU 是 GPL-2.0，原始碼位置寫在安裝包的 `vm\bundle.json` 與 [packaging/vm/README.md](packaging/vm/README.md)。
