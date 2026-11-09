# ✦ SE Agent

自架、Linux 優先的 AI agent，以 Rust 撰寫：單一執行檔、依賴極少，可以長時間穩定地自動化工作。

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
- 授權：MIT（[LICENSE](LICENSE)），第三方來源見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；變更紀錄：[CHANGELOG.md](CHANGELOG.md)

## 安裝

一個指令：安裝、啟動背景服務與網頁主控台，最後印出（並在桌面環境自動開啟）一次性的設定精靈連結。

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/se-agent/System-Engineering-Agent/releases/latest/download/install.sh | sh                 # 個人安裝，不需 sudo
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/se-agent/System-Engineering-Agent/releases/latest/download/install.sh | sudo sh -s -- --system  # 系統服務
```

在瀏覽器的設定精靈選模型供應商、貼金鑰（只存進保管庫）、挑預設模型、管理者登入方式（本機權杖或 OIDC）、工作目錄、安全模式、聊天平台；完成後精靈自動鎖定，SE Agent 以新設定重啟並帶你進主控台。設定連結 30 分鐘內有效、只能用一次；需要新的連結：`seagent setup link`。

- 重跑同一個指令即升級；`--uninstall` 解除安裝（保留設定與資料），加 `--purge` 一併清除。
- 其他選項：`--port`、`--version`、`--no-browser`、`--no-systemd`、`--local-binary PATH`、`--package FILE`（deb/rpm）、`--from-source`；`--help` 看全部。離線包解開後直接執行其中的 `install.sh`。
- 沒有瀏覽器時用終端機精靈：`seagent setup`（同一套套用邏輯）。目錄配置見 [docs/paths.md](docs/paths.md)，企業部署見 [docs/enterprise/install.md](docs/enterprise/install.md)。

從原始碼：`cargo build --release && packaging/install.sh --local-binary target/release/seagent`。也有 [Dockerfile](Dockerfile) 與 [Nix flake](flake.nix)。

### 圖形安裝（App，不需終端機）

從 [Releases](https://github.com/se-agent/System-Engineering-Agent/releases/latest) 下載一個檔、點兩下就裝好：Windows `SE-Agent_*_x64-setup.exe`（個人安裝，不需管理員；另有 `.msi`）、macOS `.dmg`、Linux `.AppImage` / `.deb` / `.rpm`、Android `.apk`。App 第一次開啟會安裝並啟動背景服務，接著在視窗裡開同一個設定精靈；之後常駐系統匣（開啟主控台、暫停、重新啟動服務、登入時啟動、檢查更新）。原始碼與建置方式見 [apps/desktop/README.md](apps/desktop/README.md)。

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

MIT。部分程式轉寫自 OpenClaw、Hermes Agent 與 DeepSeek Harness（皆為 MIT），見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
