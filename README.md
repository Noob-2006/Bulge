# Bulge — 謹慎的沙箱 AI 代理

> A cautious, sandboxed general AI agent. The agent works inside a hardware-isolated
> microVM; every change it makes is held for your review and written back to your
> machine only after you approve the diff. Rust + Tauri, Linux-first.

bulge 是一個**謹慎、越用越懂、低失控風險**的通用 AI 代理桌面 App。核心設計:
**VM 內完全自主;跨越邊界的動作(寫回主機、高風險外連)由規則閘門判斷,必要時才問人。**

## 它和別的代理有什麼不同

同一個任務跑下來,多數代理會直接改你的檔案;**bulge 把改動留在沙箱、出一份 diff 讓你審核,核准才寫回**。
完整的五方對照(bulge vs opencode / deepseek-harness / hermes / openclaw,含實跑 head-to-head、
能力矩陣、破壞性任務)見 [`docs/COMPARISON.md`](docs/COMPARISON.md)。重點:

- **安全**:唯一同時具 real microVM 隔離 + 寫回審批 + 程式碼策略引擎 + 生命週期 hooks +
  持久面威脅掃描 + 秘密遮蔽 + LLM 二次審查閘。
- **智能**:每次執行都累積可重用學習(教訓 / 使用者模型 / 技能台帳 + curator);過往任務可檢索。
- **自動化**:時間排程(六選擇器 + 5 欄位 cron)**與**事件觸發(路徑變更)、子代理委派、MCP、ACP。
- **體驗**:桌面 App + 即時串流 + diff 審批 + 響應式設定面板。

## 架構(模塊化)

Rust workspace,按職責切成獨立 crate,以 trait 當擴充縫:

| crate | 責任 |
|---|---|
| `bulge-vm` / `sandboxd` / `bulge-vmm` | libkrun microVM 沙箱 + guest 工具執行 |
| `bulge-core` | 代理步驟迴圈、工具派發(`ToolDispatcher`)、hooks、排程、子代理/檢索 handler |
| `bulge-guard` | 策略引擎(allow/deny/ask)、秘密遮蔽、威脅樣式、出口閘 |
| `bulge-harness` | 記憶(教訓)、使用者模型、技能工房 + 使用台帳 + curator |
| `bulge-store` | 只追加事件日誌(JSONL)+ 狀態 |
| `bulge-llm` / `bulge-proto` | 可插拔模型後端(OpenAI/Anthropic 相容)+ 協定 |
| `bulge-cli` | headless CLI(`run` / `eval` / `acp` / `schedule` / `recall`)+ 編排 |
| `bulge-app` | Tauri 2 桌面 App(前端 `crates/bulge-app/dist`) |

設計細節見 [`docs/CORE.md`](docs/CORE.md) 與 [`docs/PLAN.md`](docs/PLAN.md)。

## 建置與執行

需求:**Linux + KVM**(`/dev/kvm`)、Rust(見 `rust-version`)、WebKitGTK(Tauri)。

```bash
# 桌面 App
cargo run -p bulge-app            # 或 cargo build -p bulge-app --release

# headless CLI
cargo build -p bulge-cli
target/debug/bulge run --goal "讀 data.csv,算每月營收,寫成 report.md" --workspace ./work
target/debug/bulge schedule add --goal "每天摘要" --workspace ./work --daily 09:00 --offset-min 480
target/debug/bulge recall 營收
```

### 模型金鑰

金鑰**只存在本機** `~/.bulge/keys/<host>`(權限 600),不外傳、不進對話、不進 repo。
也可用環境變數 `BULGE_API_KEY`。在 App 的「設定 → API 金鑰」貼上即可(預設 DeepSeek,相容 OpenAI/Anthropic)。

### 可選設定檔(皆在 `~/.bulge/`)

- `hooks.json` — 生命週期鉤子(Pre/PostToolUse),格式見 [`docs/HOOKS.md`](docs/HOOKS.md)。
- `mcp.json` — 外部 MCP 工具伺服器。
- `schedule.json` — 排程任務(或用 `bulge schedule`)。

## 安全模型(誠實交代)

真正的邊界是 **microVM**:代理跑在 VM 裡,碰不到主機,只看得到掛進去的工作區 overlay;
改動留在 overlay,**核准 diff 才寫回**。上面再疊策略引擎、hooks、威脅掃描、秘密遮蔽、LLM 審查、
出口閘(擋主機/區網/metadata),每層 fail-closed。

**信任假設**:MCP 伺服器、command-hooks、子代理 handler 跑在**主機上(VM 外)**,等同你自己安裝的
程式——bulge 只因你把它們寫進自己的設定檔才執行。**尚未完成**:guest 二進位雜湊驗證、異常出口速率限制。

## 開發

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

能力稽核(對照參考代理):`bash scripts/capability-audit.sh`。

## 授權

MIT — 見 [`LICENSE`](LICENSE)。
