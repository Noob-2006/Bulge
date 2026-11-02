# ✦ ark

自架、Linux 優先的 AI agent，以 Rust 撰寫：單一執行檔、依賴極少，可以長時間穩定地自動化工作。

- **只有兩道閘門**：提權（sudo、寫系統路徑）和資料外送（秘密、個資離開機器）。其他事情直接做，不會一直跳出確認。
- **省 token**：工具採漸進揭露、固定前綴快取、自動壓縮，並把大型輸出溢寫到檔案。
- **一套協議，到處都能用**：網頁、桌面、手機（PWA）、終端機 TUI、編輯器（ACP）、裝置（node）、其他 agent（A2A），以及 OpenAI 相容 API，全部講 [ARP](docs/arp.md)。
- **46 種聊天平台**：Telegram、Discord、Slack、LINE、WhatsApp、Signal、Matrix、Teams、飛書、釘釘、企業微信、QQ、Email……完整清單見 [docs/parity.md](docs/parity.md)。
- **MCP 完整支援**：stdio、Streamable HTTP、舊版 SSE，OAuth 2.1（PKCE、動態註冊、device flow），sampling、elicitation、roots、成本上限，也可反過來當 MCP server。

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

| crate | 職責 |
|---|---|
| `ark-core` | 型別、工具與 provider 介面 |
| `ark-kernel` | session 迴圈、閘門、事件紀錄、daemon、ARP |
| `ark-model` | Anthropic、OpenAI、DeepSeek、Mistral、Gemini 等模型的 API 格式 |
| `ark-tools` | 檔案、shell、job、todo、skill、memory、web、子 agent |
| `ark-plugin` | MCP client、server、OAuth，以及外掛協議 |
| `ark-net` | TLS、WebSocket、HTTP 伺服器、加密工具 |
| `ark-channel` | 46 種聊天平台、存取政策、配對、投遞 |
| `ark-app` | App Server、Web UI、TUI、ACP、node、A2A、OpenAI API |
| `ark` | CLI |

## 授權

MIT。部分程式轉寫自 OpenClaw 與 Hermes Agent（兩者皆為 MIT），見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
