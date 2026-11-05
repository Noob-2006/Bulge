# ✦ ark

自架、Linux 優先的 AI agent，以 Rust 撰寫：單一執行檔、依賴極少，可以長時間穩定地自動化工作。

- **只有兩道閘門**：提權（sudo、寫系統路徑）和資料外送（秘密、個資離開機器）。其他事情直接做，不會一直跳出確認。破壞性動作按四級風險處理：VM 內與可回復的直接放行，只有「VM 外且不可回復」才一定問人。
- **省 token**：工具採漸進揭露、固定前綴快取、自動壓縮，並把大型輸出溢寫到檔案。
- **一套協議，到處都能用**：網頁、桌面、手機（PWA）、終端機 TUI、編輯器（ACP）、裝置（node）、其他 agent（A2A），以及 OpenAI 相容 API，全部講 [ARP](docs/arp.md)。
- **46 條聊天通道**：Telegram、Discord、Slack、LINE、WhatsApp、Signal、Matrix、Teams、飛書、釘釘、企業微信、QQ、Email……其中 43 個平台由 `ark-channel` 直接內建（另有 webchat、A2A、OpenAI 相容 API 三條由 App Server 提供）；逐平台狀態見 [docs/parity.md](docs/parity.md)。
- **MCP 完整支援**：stdio、Streamable HTTP、舊版 SSE，OAuth 2.1（PKCE、動態註冊、device flow），sampling、elicitation、roots、成本上限，也可反過來當 MCP server。

## 功能總覽

| 面向 | 有什麼 |
|---|---|
| 代理核心 | 單次任務、互動對話、session 分支與搜尋、背景 daemon、cron 排程、長期 goal、heartbeat、自動化建議、kanban 多代理看板、git worktree 平行工作區 |
| 子代理艦隊 | `delegate_task`／`sessions_spawn`／`agents_wait`／`subagents`：背景派遣、中途 steer 與取消、共用公告板、點對點訊息、檔案租約（預設 1 小時、最長 7 天、過期自動釋放）、每代理與全域的花費／磁碟／程序上限（`ark fleet`） |
| 安全 | 四級風險分類（`ark-security` 的 `risk`）、任務信封（一次性授權路徑／主機／指令／花費／期限）、有期限的具名授權、不可關閉的硬底線、不可信內容降權、延後佇列（只卡那一條）、緊急停止（`ark pause`） |
| 執行環境 | microVM（Firecracker／QEMU）、gVisor、docker／podman、bwrap／Landlock、ssh／modal／daytona…，隔離等級一律明示、不靜默降級；VM 快照與 undo；指令 broker（只收 argv、白名單、稽核）與出口 proxy（內建 32 個開發主機） |
| 模型 | OpenAI Chat／Responses、Anthropic、Gemini／Vertex、Bedrock、OpenAI Agents API、外部 agent CLI（claude／gemini／codex、ACP、muse）、託管 llama.cpp；訂閱登入、多金鑰輪替、fallback、輔助小模型、用量與帳單（`ark usage`） |
| 工具 | 檔案、shell、背景 job、todo、skill、memory、web 搜尋與抓取、瀏覽器與電腦操作、圖片／影片／音樂生成、TTS／STT／語音、會議機器人、電話、排程、子代理 |
| 介面 | 終端機 TUI、網頁／PWA（App Server，同一套 ARP）、ACP（Zed／JetBrains／Neovim）、node 裝置、A2A、OpenAI 相容 API、canvas |
| 相容 | Claude 格式的技能目錄（`.claude/skills`）與 hooks、OpenClaw／Hermes 的技能 metadata、MCP、外掛 |
| 法遵 | `privacy_notice`、`ai_label`、`[compliance] retention_days`、公部門 profile、`ark data export` / `ark data delete` |

使用者手冊（安裝、通道、安全模型、VM、艦隊、技能與外掛）：[docs/MANUAL.md](docs/MANUAL.md)。

## 安裝

```bash
cargo build --release
install -m 755 target/release/ark ~/.local/bin/ark
```

或使用 [`packaging/install.sh`](packaging/install.sh)、[Dockerfile](Dockerfile)、[Nix flake](flake.nix)。

## 快速開始

```bash
ark setup                                # 設定精靈：選供應商、填金鑰、從清單挑模型、試打一次，可順便開網頁介面與 Telegram/Discord/Slack
ark run "整理這個資料夾的 README，列出待辦"   # 單次執行
ark chat                                 # 互動對話
```

也可以跳過精靈：`ark secrets set ANTHROPIC_API_KEY`（或 OPENAI / DEEPSEEK…）後直接用預設模型。設定檔放在 `~/.config/ark/config.toml`，完整範例見 [docs/config-example.toml](docs/config-example.toml)。

## 常駐服務與介面

```bash
ark daemon start                         # 背景服務：排程、goal、channel、App Server
ark service install                      # 開機自動啟動（systemd user unit）
ark tui                                  # 終端機介面
ark app token                            # 產生 App Server token 的步驟
ark app open                             # 用瀏覽器 App 視窗開啟網頁介面
```

網頁介面也能安裝成桌面或手機 App（PWA），外觀是深緋紅漸層搭配亮金色四角星。

### 編輯器（ACP）

Zed `settings.json`：

```json
{ "agent_servers": { "ark": { "command": "ark", "args": ["acp"] } } }
```

### 裝置（node）

```bash
ark node --url ws://主機:8640/node       # 在另一台機器上執行
ark nodes approve <配對碼>               # 在主機上核准
```

裝置能執行哪些指令，由裝置自己的 `~/.config/ark/node.toml` 決定。

### OpenAI 相容 API

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8640/v1/chat/completions \
  -d '{"model":"ark","messages":[{"role":"user","content":"hi"}]}'
```

### 聊天平台

在設定檔加入 `[channels.<名稱>]`，並設定 `kind = "telegram"` 等。對陌生人預設拒絕；可以改成 `dm_policy = "pairing"`，讓對方取得配對碼，再由你用 `ark pairing approve` 核准。

### MCP

```bash
ark mcp add files -- npx -y @modelcontextprotocol/server-filesystem ~/docs
ark mcp login github                     # OAuth（--device 給沒有瀏覽器的主機）
ark mcp serve                            # 讓其他 agent 使用 ark 的工具
```

## 個資與法遵

台灣法規對照與檢查清單見 [docs/compliance-tw.md](docs/compliance-tw.md)，風險自評見 [docs/risk-assessment.md](docs/risk-assessment.md)。相關功能：

- 告知訊息：`privacy_notice`
- AI 標示：`ai_label`
- 保存期限：`[compliance] retention_days`
- 公部門模式：`profile = "government"`
- 當事人權利：`ark data export|delete`

## 架構

使用者手冊在 [docs/MANUAL.md](docs/MANUAL.md)：安裝、通道、安全模型（四級風險／信封／授權）、VM、艦隊、技能與外掛相容。

| crate | 職責 |
|---|---|
| `ark-core` | 型別、工具與 provider 介面 |
| `ark-kernel` | session 迴圈、閘門、事件紀錄、daemon、ARP |
| `ark-model` | Anthropic、OpenAI、DeepSeek、Mistral、Gemini 等模型的 API 格式 |
| `ark-tools` | 檔案、shell、job、todo、skill、memory、web、子 agent |
| `ark-plugin` | MCP client、server、OAuth，以及外掛協議 |
| `ark-net` | TLS、WebSocket、HTTP 伺服器、加密工具 |
| `ark-channel` | 43 個聊天平台（56 個 kind 名稱含別名）、存取政策、配對、投遞 |
| `ark-app` | App Server、Web UI、TUI、ACP、node、A2A、OpenAI API |
| `ark-vm` | microVM／容器／namespace 後端、隔離等級、映像與快照 |
| `ark-media` | 視覺、文件抽取、圖片／影片／音樂生成、TTS／STT、語音、會議 |
| `ark-browser` | CDP 瀏覽器控制與擷取 |
| `ark` | CLI |

分層規則、功能如何自我登記（工具／命令／設定段驗證）、以及「一個職責不要拆成十個碎檔」的實際上限（3,000 行、單一目錄 5 個檔案）
都寫在 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，並由 `cargo test -p ark --test arch_lint` 強制。
建置選項（聊天平台與額外模型格式都能在編譯時拿掉，預設建置仍是完整版）、`[profile.slim]`、實測大小與大小預算檢查，
見 [docs/BUILD.md](docs/BUILD.md)。測試留下的暫存目錄可以清：`ark system temp-clean --older-than 24`（預設只列出）。

## 授權

MIT。部分程式轉寫自 OpenClaw 與 Hermes Agent（兩者皆為 MIT），見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
