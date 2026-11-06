# SE Agent 使用手冊

對象：在自己機器上安裝、設定與長期操作 SE Agent 的人。

| 你想知道 | 看哪裡 |
|---|---|
| 某個平台／某個上游功能到底支援到什麼程度 | [docs/parity.md](parity.md) |
| crate 怎麼分層、新功能怎麼登記、程式碼風格規則 | [docs/ARCHITECTURE.md](ARCHITECTURE.md) |
| 建置、feature flags、精簡執行檔、大小預算 | [docs/BUILD.md](BUILD.md) |
| 完整設定範例（每個鍵都附說明） | [docs/config-example.toml](config-example.toml) |
| 台灣個資法規對照 | [docs/compliance-tw.md](compliance-tw.md) |

本手冊每一節結尾都列出實作位置，方便對照程式碼。最後一次逐項核對：**2026-11-06**（對應 `audit/GAPS-next.md` 第六輪，加上 OpenClaw `8a186ad`、Hermes `90d6b98`、DeepSeek Harness `fcc0ad4` 的上游同步；落差報告在 `docs/parity-agent/upstream-2026-11-06/`）。

---

## 1. 安裝與第一次啟動

### 1.1 需求

- Linux x86_64（主要目標）、macOS 可跑但未驗證；單一執行檔，不需要 root、不需要資料庫、不需要 Node。
- 需要 `git` 與一個模型供應商的金鑰（或訂閱登入）。VM 功能另外需要 `/dev/kvm`（見第 5 節）。

### 1.2 建置與安裝

```bash
cargo build --release                       # 預設：所有聊天平台與模型格式都編進去
install -m 755 target/release/seagent ~/.local/bin/seagent
```

也可以改用 `packaging/install.sh`（一個指令：安裝、啟動服務與網頁主控台、印出一次性的瀏覽器設定精靈連結；`--system` 裝成系統服務，見 README）、`Dockerfile` 或 `flake.nix`。安裝程式會先設 `umask go-w`，裝出來的檔案與目錄不會有群組／其他人的寫入權限。各模式的目錄配置見 [docs/paths.md](paths.md)。想要更小的執行檔（自架、只用自己的平台）見第 11 節與 [docs/BUILD.md](BUILD.md)。

### 1.3 `seagent setup`（設定精靈）

```bash
seagent setup            # 別名：seagent onboard
```

精靈依序做這幾件事，每一步都可以跳過：

1. 安全提示，並可匯入另一個 agent 的設定（見 2.3）。
2. 選供應商：內建 preset，或自訂 OpenAI 相容端點（base URL＋金鑰環境變數名稱）。
3. 登入或貼金鑰（金鑰寫入 `secrets.toml`，權限 0600），隨即做一次連線檢查。
4. 選預設模型，然後**真的打一次**確認可用。
5. 可選：網頁搜尋供應商。
6. 可選：開網頁介面（`[app] enabled = true`，順便產生 `APP_TOKEN`）。
7. 可選：接一個聊天平台（Telegram／Discord／Slack），token 驗證過才存，並以 `dm_policy = "pairing"` 建立（陌生人不直接進來，要先配對）。
8. 最後寫入設定、驗證；驗證失敗會回復原狀。**既有設定會先備份**成 `config.toml.bak.<hex>`。

跳過精靈也可以：`seagent secrets set ANTHROPIC_API_KEY`（或 `OPENAI_API_KEY`、`DEEPSEEK_API_KEY`…）之後直接 `seagent run "..."`。缺金鑰時的錯誤訊息會直接寫出該設的環境變數（含替代名稱、目前的 `$SEAGENT_AGENT` profile），並提示 `seagent secrets set <VAR>` 或 `seagent setup`。

### 1.4 目錄與檔案

| 位置 | 內容 |
|---|---|
| `$SEAGENT_HOME/config/config.toml`（未設 `SEAGENT_HOME` 時：`$XDG_CONFIG_HOME/seagent/config.toml`，預設 `~/.config/seagent`） | 使用者設定 |
| `$SEAGENT_HOME/config/secrets.toml` | 秘密（0600）。永遠不寫進 `config.toml`，也永遠不進模型上下文 |
| `$SEAGENT_HOME/data/sessions/`、`data/skills/`、`data/memory/`、`data/audit/` | 事件紀錄、技能、記憶、稽核 |
| `$SEAGENT_HOME/run/seagentd.sock`（或 `$XDG_RUNTIME_DIR/seagent/`） | daemon socket（0600） |
| `<工作區>/.seagent/config.toml` | 專案設定；其中 `hooks`／`mcp`／`plugins`／`channels`／`providers`／`app` 等段**只在該目錄列於 `trusted_projects` 時生效** |

`SEAGENT_HOME` 會覆蓋全部路徑（測試與多實例都用它）。相關指令：

```bash
seagent config path | show | get <key> | validate
seagent doctor                 # 一次檢查設定、金鑰、daemon、磁碟、權限
seagent version
```

`seagent config set|patch` 與網頁主控台的設定頁會拒絕把遮蔽佔位符（`***`、`[REDACTED …]`、`«redacted…»`、`__OPENCLAW_REDACTED__`）寫回設定檔，避免把畫面上被遮掉的值存成真的金鑰。

> 實作：`crates/seagent/src/setup.rs`、`crates/seagent-kernel/src/config.rs`（`Paths::from_env`）、`crates/seagent/src/ops/confcli.rs`（`redaction_placeholder`）。

---

## 2. 日常操作

```bash
seagent run "整理這個資料夾的 README，列出待辦"     # 單次任務，結束即退出
seagent run -                                     # 從 stdin 讀 prompt
seagent chat                                      # 互動對話（/help 看清單）
```

| 想做什麼 | 指令 |
|---|---|
| 看／接續過去的對話 | `seagent session list`、`session show <id>`、`session resume <id>`、`session fork`、`session search` |
| 匯出 | `seagent session export [id] --format md\|qmd\|html\|json`（預設去識別化，`--no-redact` 關閉） |
| 速度與快取統計 | `seagent session stats [--json]`；`seagent session stats --session <id> [--json]` 列出每一步的 TTFT、輸出 tok/s、model／tool 時間與 cache 命中率（`--json` 有 `step_stats` 與 `steps[]`） |
| 背景常駐 | `seagent daemon start\|stop\|status`、`seagent service install`（systemd user unit） |
| 對背景 session 下指令／跟台／打斷 | `seagent send <session> <text>`、`seagent attach <session>`、`seagent interrupt <session>` |
| 把終端對話交給聊天頻道 | `/handoff <channel>[:<chat>]`（沒給 chat 就用該 channel 的 `default_chat`；需要 `seagentd` 與已設定的 `[channels.*]`，回合進行中會拒絕；之後在該聊天回覆就延續同一對話） |
| 排程 | `seagent schedule add "0 9 * * 1-5" "每天早上整理 issue"`、`schedule list\|rm\|enable\|disable\|run`、`schedule edit <id> deliver=… failure-deliver=…` |
| 長期目標 | `seagent goal add "把測試覆蓋率拉到 80%" --rounds 5`、`goal list\|show\|run\|pause\|resume\|cancel` |
| 核准佇列 | `seagent gate list`、`seagent gate answer <id> once\|session\|permanent\|deny` |
| 緊急停止 | `seagent pause [原因]`、`seagent pause status`、`seagent pause resume` |
| 花費 | `seagent usage --days 7`、`seagent usage --billing`（需要管理金鑰） |
| 從其他 agent 匯入 | `seagent migrate`（偵測）、`seagent migrate from openclaw\|hermes\|claude\|codex --dry-run`（見 2.3） |
| 介面 | `seagent tui`、`seagent app open`（網頁／PWA）、`seagent acp`（Zed／JetBrains／Neovim） |

結束碼：`0` 完成、`1` 錯誤、`2` 用法錯誤、`3` 預算／上限／卡住、`130` 中斷。

> `seagent pause` 只停「排程、goal、heartbeat、channel 進來的工作、kanban 派工、上限重試」，**不會殺掉正在跑的工作**；互動的 `seagent run`／`seagent chat` 不受影響。sentinel 檔是 `<data>/ESTOP`，讀不到時視為「已暫停」（fail safe）。
>
> 實作：`crates/seagent/src/main.rs`、`crates/seagent-security/src/estop.rs`。

### 2.1 對話中的操作

| 想做什麼 | 怎麼做 |
|---|---|
| 退回前幾輪 | `/undo [N]`：對話倒回 N 輪（事件紀錄本身仍是 append-only）。若被倒回的最早那一輪開始時有 checkpoint，回覆會列出之後改過的檔案（新增、修改、刪除）與 checkpoint id；**倒回對話不會改檔案**，要還原檔案再下 `/undo <checkpoint id>` |
| 挑一個先前的提問重來（TUI） | 按兩下 Esc 開啟回溯清單（由新到舊；帶附件的提問不列）：↑↓ 選擇、Enter 倒回並把該提問放回輸入框編輯重送、`f` 從那裡分支 |
| 大型貼上（TUI） | 超過 4 000 字或 40 行的貼上在輸入框與對話紀錄都折疊成一個標記，送出時展開成全文；Ctrl+E 展開／收回 |
| 圖片（TUI） | 在 kitty、iTerm2／WezTerm 直接顯示圖片，其他終端機顯示文字替代 |
| 回合跑一半想開新對話（TUI） | `/new`：舊回合在背景繼續跑，結束時通知一次（`bell_on_complete` 開著會發終端通知） |
| 被模型拒答的回合 | 供應商以安全理由拒答（refusal）的那一輪會留在紀錄裡，但之後不再送給模型，以免每一輪都重新觸發同一個拒答；畫面上會有一則警告 |
| 對話被停止時是誰停的 | `/stop`、`seagent interrupt` 與主控台的停止都會寫一筆 `run.stopped` 稽核（含操作者與來源），並觸發 `run_stopped` hook；關機、failover 等內部停止不算 |

Checkpoint 不會建在 `/`、`$HOME` 或其上層目錄、瀏覽器 profile 目錄與 checkpoint 存放區本身；瀏覽器 profile 預設排除，存放區即使位在工作區內也不會被快照或被回復覆蓋。

> 實作：`crates/seagent/src/slash.rs`（`rewind_turns`）、`crates/seagent-kernel/src/checkpoint.rs`、`crates/seagent-app/src/tui/{rewind,paste,image}.rs`、`crates/seagent/src/agentcmds/handoff.rs`。

### 2.2 排程投遞與自動維運

排程輸出往哪裡送、以及 daemon 的例行清理，都在 `[automation]`。所有鍵都有安全預設，不寫就維持原行為：

```toml
[automation]
default_deliver = "slack:ops"            # 全域預設投遞
default_failure_deliver = "slack:oncall" # 全域預設失敗通知
agent = "ops"                            # 新工作記錄的擁有者 agent，對應 [automation.agents.ops]
restart_hold_seconds = 3600              # daemon 重啟時，比這個新的「已認領未完成」工作會恢復成待執行；更舊的記為 missed
scratch_ttl_hours = 24                   # <data>/tmp、scratch、art 與 session artifacts 的過期時數（0 關閉）
worktree_idle_hours = 168                # 回收乾淨且閒置的 <repo>/.worktrees/*（0 關閉）
cleanup_interval_secs = 3600             # 上面兩項清理多久跑一次
idle_session_secs = 1800                 # seagentd 把閒置 session 的記憶體狀態退場，下次使用時從事件重建（0 關閉）
plugin_auto_update_hours = 0             # 外掛無人值守更新；預設關，開了仍走掃描、簽章、install_policy 與同意

[automation.agents.ops]
deliver = "slack:C123"
failure_deliver = "slack:C999"

[automation.creators.alice]              # 以 SEAGENT_PROFILE=alice 建立的工作
deliver = "telegram:42"
```

- **投遞順序**（逐欄位，最具體的先）：工作自己的 `deliver` → 建立者（`[automation.creators.<SEAGENT_PROFILE>]`）→ 擁有者 agent（`[automation.agents.<id>]`）→ `default_deliver` → `origin`（建立工作的聊天）。
- **失敗通知**：工作的 `failure_deliver` → 工作的 `deliver` → 建立者／agent 的 `failure_deliver`（沒有就用該層的 `deliver`）→ `default_failure_deliver`／`default_deliver` → `origin`。
- **投遞到房間**：`deliver = "room:<room-id>"` 把輸出附加到 hosted room（第 6 節）的日誌，以 `cron` 身分記錄，只記下訊息裡點名的 @成員，**不會自動讓所有成員回話**。
- 清理只碰過期項目：執行中的 session 跳過、symlink 不跟隨；worktree 只回收沒有未提交變更、且最新檔案比門檻舊的。
- daemon 的 Prometheus 指標多了 `seagent_busy_arrivals_total{outcome="queued|steered|dropped"}`、`seagent_busy_chats_today`、`seagent_busy_chats_daily_peak`（只有計數，不含內容與 session id）。
- **直接呼叫工具**：ARP 方法 `tools.call`（參數 `tool`、`input`，可選 `session`、`workspace`；沒給 `session` 就新建一個）讓 script／runbook 不經模型直接呼叫一個工具（含 `mcp__<server>__<tool>`），仍走同一條 policy、hooks、閘門／核准與稽核（另寫一筆 `tool.call` 稽核）。預設需要 admin scope。

> 實作：`crates/seagent-kernel/src/cronjob/mod.rs`（`DeliveryDefaults`）、`outbound.rs`（`Target::Room`）、`automation.rs`（`recover_claims`）、`scratch.rs`、`worktree.rs`、`daemon.rs`、`crates/seagent-skills/src/hub/plugins.rs`（`run_auto_update`）、`crates/seagent-app/src/metrics.rs`。

### 2.3 從其他 agent 匯入

```bash
seagent migrate                                  # 偵測 ~/.openclaw、~/.hermes、~/.claude.json、~/.codex
seagent migrate from openclaw --dry-run          # 只看計畫
seagent migrate from hermes [--path DIR] [--overwrite]
seagent migrate from hermes --migrate-secrets    # 連同來源的金鑰／token 一起寫進 vault
```

匯入模型、MCP servers、channels、記憶檔（`SOUL.md`、`MEMORY.md`、`USER.md`…）與技能。**憑證預設不匯入**：沒有 `--migrate-secrets` 時每個略過的憑證都會印一行 `skipped credential NAME (use --migrate-secrets …)`，設定裡對應的 `{{secret:NAME}}` 會保持未設定，直到你自己 `seagent secrets set NAME`。

`seagent setup` 第一步的匯入（終端機精靈）採同一個政策：先問要不要匯入設定，再另外問要不要把金鑰匯入保管庫，預設不要。

> 實作：`crates/seagent/src/ops/migrate.rs`（`plan_opt`、`without_secrets`）、`crates/seagent/src/ops/wizard.rs`。

---

## 3. 聊天平台（channels）

一個平台就是一個 `[channels.<名稱>]` 段：

```toml
[channels.phone]
kind = "telegram"
token = "{{secret:TELEGRAM_TOKEN}}"
dm_policy = "pairing"        # allowlist（預設）| pairing | open | disabled
allow = ["123456789"]
group_policy = "allowlist"   # allowlist（預設）| open | disabled
groups = ["-1001234567890"]
require_mention = true
privacy_notice = "本服務由 AI 回覆。你的訊息會送到模型供應商處理，保存 180 天。"
ai_label = "— 由 AI 生成"
```

- 秘密一律用 `{{secret:NAME}}` 引用，值放在 `seagent secrets set NAME`；`config.toml` 裡沒有明文。
- **陌生人的預設待遇是拒絕**。`dm_policy = "pairing"` 時，未列在白名單的人會收到一組配對碼，你用 `seagent pairing approve <channel> <code>` 放行（`seagent pairing list|revoke`；8 碼、1 小時過期、只存加鹽雜湊、失敗 5 次鎖 1 小時）。
- 群組預設要 `@` 提及才回應；`require_mention = false` 可關。
- `privacy_notice`／`ai_label` 與 `[compliance] retention_days` 是法遵欄位：`dm_policy = open|pairing` 或 `group_policy = open` 卻沒設 `privacy_notice`，載入時會警告。
- **外送 HTTP 逐跳檢查轉址**：自架 channel 的設定位址（Mattermost、Matrix、Nextcloud、ClickClack…）可以在內網，但**轉址到另一個內網位址或雲端 metadata 位址會被拒絕**；跨來源轉址會丟掉授權標頭。附件下載（Discord CDN 等）只允許公開位址。
- **選擇題**：`ask_user` 可帶 `options`（2–12 個、不可重複；`multi_select = true` 可多選）。有按鈕的 channel 直接顯示按鈕（只有發問的那個聊天按了才算），其他顯示編號清單；回覆編號或選項文字都會對應回選項，也可以打自由文字。多選題目前一律用編號清單。
- **在 thread 裡分支**：支援 thread／topic 的 channel（Discord thread、Telegram topic；Slack 會先貼一則錨點訊息）用 `/fork [標題]` 會把目前對話複製到同一個聊天的新 thread，原本的聊天與 session 不受影響；不支援的 channel 退回 `/branch` 的行為。
- **交給聊天**：終端機的 `/handoff <channel>[:<chat>]` 把目前 session 綁到該聊天（見第 2 節）。

```bash
seagent channel list                       # 已設定的通道（名稱、kind、dm 政策、白名單）
seagent channel send <channel> <chat> "…"
seagent message send|edit|delete|react|poll|pin|thread|read --channel <n> --chat <id> …
seagent webhook subscribe|list|rm|test …
```

支援的平台：`config::registry()` 有 **56 個 kind 名稱**（其中 13 個是別名：`teams`、`google_chat`、`lark`、`wechat`、`twilio`、`imsg`、`imap`、`nextcloud_talk`、`synology_chat`、`urbit`、`twitter`、`qa_channel`、`home_assistant`），等於 **43 個自建平台**；再加上 App Server 提供的 webchat、A2A、OpenAI 相容 API，對照表上的 46 條通道。逐平台的傳輸方式、簽章與狀態見 [docs/parity.md](parity.md)。

精簡建置可以不含某些平台，這時在設定裡寫了它不會報錯，只會警告並跳過：
`seagent: warning: channel kind `slack` is not compiled into this build …`（見第 11 節）。

> 實作：`crates/seagent-channel/src/config.rs`（registry）、`access.rs`（政策與配對）、`http.rs`（逐跳轉址檢查）、`crates/seagent/src/ext.rs`（啟動、警告、`ask_user` 按鈕、channel `/fork`）。

---

## 4. 安全模型：四級風險、信封、授權

這一節是 SE Agent 與「什麼都問」的差別所在。設計前提：**保護不能吃掉自主性**。能「隔離」或「回復」的，就不要「詢問」；詢問只留給「影響到 VM 以外」且「無法回復」的動作。完整設計理由見 `audit/GAPS-next.md` 第 0 段。

### 4.1 四級風險

| 等級 | 例子 | 預設處理 | 實作 |
|---|---|---|---|
| 0 `sandboxed` | 工作區內讀寫、跑測試、裝開發依賴、刪 VM 內暫存檔 | **直接放行**，只記錄 | `Tier::Sandboxed` |
| 1 `recoverable` | 對白名單主機發請求、自己的分支 commit、發訊息到自己的頻道、系統動詞（`apt-get`、`systemctl`…）**在沙箱內** | 直接放行；`standard` 會加稽核紀錄 | `Tier::Recoverable` |
| 2 `impactful` | 推送共用分支、改共用設定、對外寄信、**新主機**的對外請求、`git push`、雲端寫入 | 符合預先授權範圍→放行並通知；否則問人 | `Tier::Impactful` |
| 3 `irreversible` | 刪正式資料庫、雲端資源刪除、`git push --force`、改帳號權限、外送秘密、磁碟寫入、金額 ≥ 100 | **一律問人**，任何模式都關不掉 | `Tier::Irreversible` |

分類器只看工具呼叫本身，**不看模型怎麼說**：它吃的是 `Candidate`（工具名、exec 參數、讀寫路徑、主機、payload、金額、是否在沙箱內、工作區與安全根目錄、金鑰名稱與值）。任何 destructive 命中會直接把等級拉到 3。Windows 形式也算 destructive：PowerShell 的刪除動詞（含啟動腳本內、管線後的別名、`Remove-Item -r/-fo`）、`cmd /c` 刪除、遞迴／安靜的 `del|erase|rd|rmdir`、`wmic shadowcopy delete`，以及 `Stop-Process`／`Stop-Service -Force`。

三種預設組合（`[approvals] preset`）：`relaxed`（寬鬆，T2 直接放行）、`standard`（標準，T1 加稽核）、`strict`（嚴格，T1 只有沙箱內才放行）。信封上限分別是 2／2／1 級。

`standard` 之上還有 `seagent` 的「兩道閘門」：提權（sudo、寫系統路徑）與外送（秘密、個資）由 `[gate]` 控制（`ask`／`deny`／`allow`），與上面四級是**兩層獨立防線**。

### 4.2 硬底線（等級 3 之外，不可關閉）

在問人之前，一律先過 hardline 檢查（`floors()`），它**沒有**任何設定可以關掉，`--yolo`、`approvals.mode = off`、cron 也繞不過：

- `rm -rf /`、`rm -rf` 系統目錄（`/home /root /etc /usr /var /bin /sbin /boot /lib`）或 `~`／`$HOME`
- `mkfs*`、`dd of=/dev/sd|nvme|hd|mmcblk|vd|xvd*`、`> /dev/<disk>`、`wipefs`、`shred /dev/`
- fork bomb、`kill -1`、`shutdown|reboot|halt|poweroff`、`init 0|6`、`systemctl poweroff|reboot|halt`、`telinit 0|6`
- `sudo -S` 但 vault 裡沒有 `SUDO_PASSWORD`（防止密碼猜測）
- 被 `seagent skills lock` 鎖住的技能：agent 對它的任何寫入（`skill` 工具、write／patch、shell 的重導向／`rm`／`mv`／`sed -i`／`tee`）以及 agent shell 裡的 `seagent skills unlock` 都會被擋（見 7.1）

比對前會先正規化：去 ANSI/NUL、全形轉半形、反斜線接行、`$IFS`、引號拆解、`;|&` 斷句、`bash -c`／`$(…)` 內層。解析器超過上限（128 000 字元、或 4 096 字元沒有分隔、或 ≥25 000 個分隔）**一律視為拒絕**（fail closed）。`[approvals] deny` 的操作者黑名單樣式也同樣在此比對。

> 實作：`crates/seagent-security/src/hardline.rs`、`risk.rs`（`windows_destructive`）、`crates/seagent-kernel/src/secgate.rs`。

### 4.3 任務信封（事前授權範圍）

長任務、排程、goal、channel 機器人不應該每一步都被問。信封是「一次核准這個任務可以做什麼」：

| 欄位 | 意義 |
|---|---|
| `max_tier` | 這個信封最多授權到第幾級（**上限 2**，會被 preset 上限再夾一次） |
| `paths[]` | 可寫的路徑（每次寫入都要被其中一個 match） |
| `hosts[]` | 可連的主機 |
| `commands[]` | 可執行的指令（前綴或 glob） |
| `spend_usd` | 花費上限 |
| `expires_ms` | 期限（**一定要有**，最長 30 天） |

在信封範圍內的 T2 呼叫直接放行，並在事件紀錄寫下「allow (envelope)」與通知；超出範圍才問人。等級 3 在 `covers()` 裡被結構性排除（`tier.is_irreversible()` 直接回 false），所以信封再多也授權不了不可回復的動作。

狀態：**函式庫層已完成**（`seagent_security::envelope`，存放 `<data>/envelopes.json`，原子寫入，過期／撤銷自動清），kernel 也已在每次工具呼叫前查信封並執行上限檢查。**但操作面還沒接上**：目前沒有 `seagent envelope …` 指令、沒有 chat 指令、沒有設定鍵，只有程式內 `envelope::create`（測試會用）。在那之前，長期授權請用 4.4 的具名授權。

> 實作：`crates/seagent-security/src/envelope.rs`、`crates/seagent-kernel/src/secgate.rs`（`tier <= preset.envelope_ceiling()`）。

### 4.4 有範圍、有期限的授權（不是全有全無）

「一律允許」不是永久通行證，而是**綁定樣式＋期限**的授權：

| 種類 | 綁定到 | 說明 |
|---|---|---|
| Gate 授權 | 閘門名稱＋理由字串 | 例如「只放行這個 egress 理由」 |
| 指令授權 | 完整指令或 glob | 複合指令（含 `;`、`&&`、管線）不准建立授權；指令授權只回答 exec 白名單，**不會**順便蓋過同一道指令裡另外的外送／提權發現 |
| 執行檔授權 | 執行檔名或路徑 glob | 加上安全的 shell 內建（`cd`、`pwd`、`true`…）與 stdin 安全的 `jq`、`grep`、`cut`、`sort`、`uniq`、`head`、`tail`、`tr`、`wc`。`test`／`[` 只在運算元是靜態文字時才算安全：`-v`／`-R`、`$'…'`、以及含反斜線、`$`、反引號、`* ? { } [ ]` 的運算元一律回到一般核准（bash 會重新解析這些字元，例如 `test -v 'a[$(cmd)]'` 會執行 `cmd`） |

- 期限：預設 **7 天**（`[approvals] grant_ttl_days`），讀取時才過濾（沒有背景清掃）；`seagent approvals queue allow` 這條路徑接受 0 = 永不過期。
- 存放：`<data>/approvals/allowlist.json`（目錄 0700）。
- 指令授權**永遠蓋不過等級 3**：tier-3 分支在授權檢查之前。
- 用法：`seagent approvals list`、`seagent approvals allow "<glob>" [--exec]`、`seagent approvals revoke <id|pattern>`。
- 建議來源：`seagent approvals suggest --days 7` 會從「過去被允許的閘門事件」挖出候選樣式（hardline／destructive 指令與 `rm`、`dd`、`sudo`、`chmod`、`kill`、`systemctl` 等不安全執行檔永遠不會被建議），你再用 `--apply 1,3` 套用。
- **網頁主控台**：「核准」頁列出常設授權（durable grants 可直接撤銷；設定檔裡的 allowlist 唯讀顯示）、可編輯全域 exec 政策（security／ask／ask-fallback，與 `seagent exec-policy set` 同一套驗證與回復），並以表格列出各代理的有效角色核准、exec、沙箱與工具限制。「安全」頁集中顯示每個監聽面（App Server 與 channel listener：是否 loopback、驗證、TLS、proxy、速率限制）、暴露風險發現、權杖的中繼資料（不含值）、channel 開放程度、外掛／MCP 數量與各代理能力；不認得的角色一律顯示 `unknown`，不會看起來像安全。

### 4.5 核准的模式與開關

| 開關 | 值 | 作用 | 不能覆蓋什麼 |
|---|---|---|---|
| `seagent approvals mode` | `manual`（預設）／`smart`／`auto`／`off` | `smart` 由便宜模型當監護人答 APPROVE／DENY／ESCALATE；`auto` 由審查模型答 allow／deny／ask 並附風險標籤；`off` 不問 | hardline、等級 3 |
| `seagent exec-policy preset` | `yolo`／`cautious`／`deny-all` | 一次設定 exec 的 security／ask／ask_fallback | 同上 |
| `[tools.by_provider."<provider 或 provider/model>".exec]` | `mode = "deny"｜"allowlist"｜"ask"｜"auto"｜"full"`，或直接給 `security`／`ask` | 只對該供應商或該模型的回合夾住 exec 政策；多個符合時取最嚴，只能收緊；`/yolo`、`/elevated` 也蓋不過；`seagent approvals test` 會顯示這層上限 | 等級 3、hardline |
| `--yolo`（`SEAGENT_YOLO=1`、`/yolo`） | 旗標 | 這個 process／session 跳過核准提示 | 等級 3、hardline、`deny` 規則、上面的模型 exec 上限 |
| `--allow-privilege`／`--allow-egress`／`--yes` | 旗標 | 無 TTY 時的 headless 核准者：對提權／外送直接答「一次」 | hardline；`exec` 仍走 `ask_fallback`（預設 deny） |
| `seagent pause` | 全域 | 停止新的自動工作（見第 2 節） | 已在跑的工作 |

```toml
[tools.by_provider."ollama".exec]          # 本機小模型的回合：主機指令一律要問
mode = "ask"

[tools.by_provider."openrouter/some-model".exec]
mode = "deny"
```

`smart` 在逾時或回覆無法解析時退回 ESCALATE（問人）；`auto` 退回 ASK。「沉默不是同意」：`[approvals] timeout_secs`（預設 600，daemon 啟動時套用）到期視為**拒絕**，閘門記錄寫 `deny (timeout)`，並在當初轉送核准的聊天室貼出「⏱ Approval … expired」。

**為什麼沒問就執行了**：由政策自動放行、沒有跳出提示的呼叫，工具結果末尾會附一行
`[approval] auto-approved: allow (<來源>) — <理由>`，來源例如 `allowlist`、`always`、`remembered`、`yolo`、`envelope`、`elevated full`、`elevated on`、`cron_mode`、`unattended_mode`、`smart`、`auto, <風險> risk`。模型與使用者都看得到為什麼沒有問；人工答「一次」的呼叫不加這一行。

**為什麼這個工具不見了**：`seagent tools explain <tool> [--model M] [--channel C] [--sender S]` 會依序重放 `tools.disabled`、`tools.profile/allow/deny`、`tools.by_provider`、`tools.by_channel`、`tools.by_sender`，指出卡在哪一層與要改哪個設定（沙箱與子代理工具組不是 `tools.*` 設定層，不在這裡）。

**遠端第 3 級核准（聊天軟體）：**
- 第 3 級（VM 外且不可回復）的轉送訊息標明等級、影響與「不可回復」，按鈕只有 `Review & Allow Once`／`Deny`，**沒有 Allow Always**；任何「always」回答都降為一次，不寫入記憶或授權。
- 只有 `[approvals.forward] owners`（`channel → [sender id]`；未設時用該 channel 明列、非 `*` 的 `approvers`）能回答第 3 級；`*`、被轉送的聊天對象都不算。兩者都沒設就只能在 CLI 處理。
- 第一次按下只會出現二次確認（附 `Confirm (irreversible)` 按鈕，必須同一位 owner 按）；打字則是 `/approve <id> confirm`。
- 閘門記錄與延後佇列會寫下核准者（`allow by telegram:42`、`queue.json` 的 `answered_by`）。
- cron／無人值守 session 排進延後佇列的第 2／3 級呼叫也會推到聊天：有綁定聊天室就送那裡，否則直接私訊 `owners`；id 以 `q-` 開頭，按鈕或 `/approve q-<id>`／`/deny q-<id>` 回答（第 3 級同樣只限 owner）。

```toml
[approvals.forward]
owners = { telegram = ["123456789"] }
```

> 實作：`crates/seagent-security/src/toolpolicy.rs`（`exec_ceiling`、`explain`）、`approvals.rs`、`crates/seagent-kernel/src/secgate.rs`（`note_provenance`）、`crates/seagent/src/ops/toolcfg.rs`、`crates/seagent/src/ops/ui_methods.rs`（`ui.approvals.*`、`ui.exec.policy.*`、`ui.security.status`）。

### 4.6 只卡那一條、逾時也能安全繼續

- 需要問人的呼叫進入**延後佇列**（`<data>/approvals/queue.json`，pending／allowed／denied，同 session 同工具同理由去重，上限 200 筆）。排隊只擋那一個呼叫，**分支暫停、其他工作照做**；agent 會被要求回報「待人確認」而不會空轉。
- 等級 3 被拒時，若 `[approvals] tier3_fallback`（預設 true）開啟，錯誤訊息會附上**可回復的替代做法**（例如改開 PR 而不是直接推送、改產生遷移腳本而不是直接執行）。
- 核准等待時間會從 session 的時間預算中扣除（不會因為等人而把任務判定逾時）。
- 連續被拒 3 次（`[approvals] denial_breaker_threshold`）會斷路：agent 被告知停止換寫法重試，把動作交回人手。
- 破壞性動作可以先預覽：`seagent approvals test -- <command…>` 是乾跑（結束碼 0 允許／2 要問／3 拒絕）；但它只算 floors＋閘門＋exec 政策（含模型 exec 上限），**不計算風險等級、信封與 taint**，所以「允許」不等於 T2/T3 也會過。

### 4.7 不可信內容降權（taint）

來自網頁、issue、email、channel webhook 的工具輸出會被包進 `<<<EXTERNAL_UNTRUSTED_CONTENT id=…>>>` 標記（偽造標記與 chat-template token 會被中和）。只要最近的 event 裡出現過這種輸出，該 context 就算「髒」：

- 等級 2、3 一律要人（或被排進佇列），`yolo`／授權／白名單都不能繞；
- 等級 0、1 照常，agent 仍能讀、分析、寫草稿——這是**降權，不是停擺**。

`[security.external_content]` 可調：預設包 `web_fetch`、`web_search`、`web_extract`、`browser*`、`x_search`，以及 `webhook`、`email`、`gmail`、`msgraph_webhook` 這些通道。

### 4.8 指令代理（broker）、出口與輸出遮蔽

VM 裡（或沙箱裡）的 agent 不直接碰主機的權限與網路，只能向 daemon 的 broker 請求：

- **只收 argv**：`argv` 裡任何元素含 `;`、`|`、換行、NUL、反引號、`$(` 一律拒絕；執行時用 `Command::new(argv[0]).args(...)`，不經 shell。
- **允許清單**：預設只有 `apt-get install *`、`apt-get update`、`apt update`、`dnf install *`、`systemctl restart|reload|status *`、`mount *`、`umount *`、`service * reload`。`exec_deny` 優先於 `exec_allow`；每道指令仍會再過一次風險分類，等級 3 **即使白名單也排隊**。
- 執行時洗環境、關 stdin、`timeout_secs` 到就殺。每次請求寫一行稽核到 `<data>/audit/broker.jsonl`（不含內容、不含秘密值）。
- **出口**：`[security.egress_proxy]` 的 proxy 只放行允許清單的主機，deny 與網站黑名單先檢查；`dev_hosts = true` 內建 32 個開發主機（github、crates.io、npm、pypi、debian/ubuntu 套件庫、docker registry、rustup…），這些算**操作者預先授權**的第 1 級主機，不必每次問。
- 外送秘密一律攔：payload 或 header 裡出現 vault 的秘密值、`{{secret:…}}` 佔位符、憑證檔路徑（`id_rsa`、`.ssh/`、`.aws/credentials`、`.netrc`、kubeconfig、`.env`、`secrets.toml`…）或 token 形狀（`ghp_`、`sk-ant-`、`AKIA…`、`xox*`、`AIza`、`glpat-`、JWT、PRIVATE KEY）→ 等級 3 或直接拒絕。例如 `curl -F file=@.env …` 是等級 3，授權、yolo、白名單都不能自動放行。
- **輸出遮蔽**：工具輸出（進模型、session 紀錄、聊天之前；`[security] mask_output_secrets`，預設開）、聊天回覆與強制匯出裡像憑證的字串會被換掉。除了上面的 token 形狀，還涵蓋資料庫連線字串（`postgres://user:pass@…`、ADO.NET／ODBC／JDBC 的 `Password=`／`Pwd=`、libpq `password=`）、URL 裡的帳密、`PGPASSWORD`／`MYSQL_PWD`／`SSHPASS` 與其他像秘密的環境變數賦值、PGP 私鑰、PuTTY `.ppk`、`AGE-SECRET-KEY-1…`、Azure `AccountKey`／`SharedAccessKey`、YAML／JSON 中名稱像憑證的引號值、`--password`／`--token`／`--api-key` 類旗標的值；`${DB_PASS}`、`<password>`、`--token TOKEN` 這類佔位符與說明文字保持原樣。
- 唯讀的 ARP 呼叫者（`scope:read`、`auditor` 角色）從 `session.list`、`session.view`、`schedule.list`、`goal.list` 拿不到主機上的 `workspace` 路徑。

> 實作：`crates/seagent-security/src/broker.rs`、`egress_proxy.rs`、`risk.rs`（`dev_hosts`、`command_exfil`、`mask_secrets`）、`crates/seagent-kernel/src/gate.rs`、`daemon.rs`。

### 4.9 已知落差（本輪實測）

- 信封沒有操作介面（見 4.3）。
- `--yolo` 對 `seagent tui` 沒有效果（凍結呼叫漏了 `tui`，`crates/seagent/src/main.rs`）；其他子指令正常。
- `approvals.mode = auto`／`smart` 的審查者拿不到風險等級，只看得到閘門理由，所以「自動核准」對 T3 的保護比手動弱；T3 的預設路徑仍會問人，但請把它當成第二層而非唯一一層。
- 「核准疲勞」統計（每天問幾次、被拒比例、幾乎每次都允許就建議改成預授權）**尚未實作**；`seagent approvals status` 只報規則數量，不是詢問次數。
- 主控台**不能逐代理編輯 exec 政策**：SE Agent 沒有「每個代理一份 exec 政策」的設定鍵，只有全域 `[approvals.exec]` 與角色 preset；主控台顯示各代理的有效政策、可改全域政策。
- 唯讀 ARP 呼叫者雖然拿不到 `workspace` 欄位，但 `session.history`／`session.attach` 的事件串流是對話內容，工具輸入輸出裡出現的路徑仍看得到。
- Windows 規則比對的是像指令的文字，引號內的散文也可能誤判成等級 3（寧可多問）。

---

## 5. microVM 與沙箱

### 5.1 隔離等級

SE Agent 把每個執行後端對應到一個隔離等級，並且**不會靜默降級**——降級一定在 `seagent sandbox explain` 與系統提示裡寫明原因：

| 等級 | 後端 | 擋得住什麼 |
|---|---|---|
| 4 `microVM` | Firecracker、QEMU/KVM | 自己的 kernel，硬體虛擬化 |
| 3 `app-kernel` | gVisor（`runsc`） | 使用者空間 kernel；kernel bug 被侷限 |
| 2 `container` | docker、podman | 自己的 rootfs，共用 host kernel |
| 1 `user-namespace` | bwrap、Landlock | namespace/seccomp，共用 kernel |
| 0 `host` | `local` | 沒有牆：以 SE Agent 使用者身分直接跑 |

`ssh`、`modal`、`daytona`、`vercel`、`openshell`、`singularity`／`apptainer` 也各有對應等級。`ssh` 後端在同一條 ControlMaster 連線上維持一個長駐的遠端 `bash`，工作區同步、憑證上傳、取回等內部腳本共用它（每道指令以 nonce 框住並帶回結束碼；`exit`／`cd` 不會弄壞它，逾時就重開）；模型的 `shell` 工具與需要 stdin 的呼叫仍是每次一個 ssh 程序，也沒有遠端 PTY。

```bash
seagent sandbox explain            # 這個 session 實際在哪裡跑、隔離等級、警告
seagent sandbox list [--json]      # 有沒有殘留的沙箱
seagent sandbox recreate --all     # 重建
```

### 5.2 設定

```toml
[exec]
backend = "vm"                 # 所有工具呼叫都進 microVM（預設 "local"）

[exec.vm]
provider = "auto"              # auto | firecracker | qemu | gvisor | bwrap
allow_fallback = true          # false = 寧可拒絕執行，也不要降級
vcpu = 2
memory_mb = 1024
max_processes = 512            # 客體 RLIMIT_NPROC：VM 內的 fork 炸彈死在自己家裡
workspace_access = "rw"        # rw = 靠快照回復（預設）；ro 只給明確標示的敏感目錄
workspace_max_mb = 512         # 同步上限，超過就拒絕而不是默默截斷
network = "broker"             # 客體沒有網卡，只能經 broker 向 daemon 請求
snapshots = true
snapshot_keep = 20
trust_tiers = true             # owner / stranger / untrusted 各自獨立的 VM 與工作區
deny_paths = [".ssh", ".aws", ".gnupg", ".config/gh", ".netrc", ".kube", …]

[exec.code]
run_code_only = false          # true = 模型只看得到 `run` 一個直接工具（goal 模式另加 goal_done）
```

`[exec.code] run_code_only = true` 是「只寫程式」模式：其他工具仍可在腳本內用 `seagent-call` 呼叫（同樣經過閘門），但不會出現在模型的工具清單。

### 5.3 客體映像與快照

```bash
seagent sandbox vm image build     # 下載 kernel + Alpine rootfs，放入 <data>/vm，寫 manifest.json
seagent sandbox vm image verify
seagent sandbox vm status [--json] # provider、隔離等級、每台 VM 的 pid／指令數／閒置秒數／快照數
seagent sandbox vm snapshot --reason "before refactor"
seagent sandbox vm snapshots
seagent sandbox vm undo            # 回復，且回復前先把目前狀態再快照一次
seagent sandbox vm gc              # 停掉閒置的 VM
```

VM 內沒有金鑰、沒有 daemon socket；指令透過 `seagent-vm` 的協定進出，工作區依 `workspace_access` 同步。破壞性指令在 VM backend 下會先快照——**快照取代詢問**：錯誤用 undo 撤銷，不必事前核准。

> 實作：`crates/seagent-vm/src/{isolation,config,image,snapshot,pool}.rs`、`crates/seagent-tools/src/exec/{vm,ssh}.rs`、`crates/seagent-kernel/src/coderun.rs`、`crates/seagent/src/exec_cli.rs`。

### 5.4 已知落差

- `[exec.vm.readonly]` 的逐工作區覆寫出現在文件裡但**未實作**（`readonly_patterns()` 固定回空），只有全域 `workspace_access` 有用。
- VM pool 的閒置回收／session teardown／broker 安裝有實作，但目前主要由 `seagent sandbox vm …` 與 `seagent exec` 路徑驅動，daemon 的自動回收尚未接上。
- 沒有 `/dev/kvm` 的機器會退回 bwrap 並警告；`seagent doctor` 不會顯示隔離等級，請看 `seagent sandbox explain`。
- SSH 長駐 shell 只是第一步：模型的 `shell` 工具還沒有共用它，也沒有遠端 PTY。

### 5.5 桌面 VM（給 computer use 用的圖形虛擬機）

和上面無畫面的工具隔離 microVM 不同，桌面 VM 是一台完整的 Debian 13 + Xfce + Chromium 虛擬機：代理只靠截圖與模擬滑鼠／鍵盤操作，人可以在網頁主控台觀看並接手。詳見 [desktop-vm.md](desktop-vm.md)。

```sh
seagent vm desktop build      # 下載固定版本映像（sha256 驗證）＋ cloud-init 佈建桌面，可重複執行
seagent vm desktop start [name]
seagent vm desktop screenshot [name] -o shot.png
seagent vm desktop input [name] '{"type":"click","x":640,"y":90}'
seagent vm desktop status|list [--json]
seagent vm desktop stop [name]
seagent vm desktop reset [name]   # 刪除磁碟疊加層，下次開機用新映像
```

- 設定在 `[desktop_vm]`（`memory_mb`、`cpus`、`width`/`height` 預設 1280×800、`accel = auto|kvm|tcg`、`network = user|none`、`idle_timeout_secs` …）。
- 映像內含 `fonts-noto-cjk`（繁中網頁正常顯示）與 `zh_TW.UTF-8` locale；含中文的 `type` 輸入走 virtio-serial 文字通道，由客體內 `seagent-text-input` 經剪貼簿貼上（xclip + Ctrl+V）。
- 有 `/dev/kvm` 用 KVM，否則 TCG 並警告；畫面走 QMP `screendump`，輸入走 QMP `input-send-event`（USB tablet 絕對座標），不需要 VNC 用戶端；QEMU 自帶的 VNC 在私有 unix socket 上。
- 每台 VM 有自己的磁碟疊加層（`<data>/vm/desktop/<name>/disk.qcow2`）與自己的接手租約；人接手時代理對該 VM 的所有動作都會被拒。
- 代理端：`computer_use` 的 `target = "vm:<name>"`（或 `[computer_use] target` 預設值）；核准範圍為 `desktop:vm:<name>:<action>`。
- 主控台：`view.desktop.list`、`view.desktop.{state,frame,takeover,handback,input}`（帶 `target`）、`view.vm.start|stop`（admin）。
- 內建瀏覽器：`install.sh --with-browser`／離線包 `--with-browser` 會帶固定版本的 Chrome for Testing（sha256 驗證）到 `<share>/browsers/`，`[browser] prefer_bundled = true` 時優先使用。

**瀏覽器的隱私與 SSRF 防護**（任何瀏覽器後端都適用）：

- 快照會把 `type=password` 與 `autocomplete` 為 `current-password`、`new-password`、`one-time-code`、`cc-number`、`cc-csc` 的欄位值換成 `[redacted]`；查不到欄位屬性時也遮（fail closed）。
- `[browser] allow_private_urls = false` 是嚴格模式，現在對本機瀏覽器也生效：`open`／`navigate` 會在 Chrome 送出前逐跳檢查轉址，被擋的那一跳直接失敗並回報；無法逐跳檢查的後端（Camofox）在嚴格模式下拒絕 http(s) 導航。點擊或 JS 觸發的導航仍只檢查最終網址。關閉分頁不受網址政策限制。

> 實作：`crates/seagent-browser/src/{snapshot,policy,tools}.rs`。

---

## 6. 多代理艦隊（fleet）

長時間任務可以拆給多個子代理平行做，SE Agent 負責「不要互相打架」。

```bash
seagent fleet status            # 每個代理：狀態、深度、tokens、花費、擁有檔案
seagent fleet board             # 共用公告板：誰在做什麼
seagent fleet files             # 目前被租用的檔案
seagent fleet limits            # 上限（花費／磁碟／程序數）
seagent fleet resume <session>  # 接續一個斷掉的代理
seagent fleet --json            # 給程式用
```

- **派遣**：模型用 `delegate_task`（`tasks[]`、`mode = sync|background|collect`、`worktree`、`model`、`toolsets`）、`sessions_spawn`（預設隔離、背景）、`agents_wait`、`subagents action=list|info|cancel|stop|wait` 這些工具。子代理**不會**拿到互動類工具（`clarify`、`ask_user`、channel 發送、排程…）。
- **Fork 沿用父會話的快取前綴**：`fork` 子代理沿用父會話的 system prompt、工具清單與模型路由（逐位元組相同，供應商的前綴快取可命中），角色、任務指示與輸出要求放在第一則 user 訊息；工具限制改在執行時拒絕（`ToolGuard`），而不是縮減工具清單。
- **批次快取暖機**：`[delegation] prefix_stagger_seconds = N`（預設 0 = 關閉，最多 60）讓同一批、同一路由的兄弟子代理等第一個子代理收到第一個串流片段（或第一個結束、或 N 秒到）再開始，代價約一個 TTFT，換來兄弟們命中同一份快取。
- **代理對代理的鏈結上限**：`agent_message` 每跳會標示 `hop N/max`，超過上限在投遞前就拒絕；同一條鏈對同一個對象重複同一段話會被拒；回覆給發起這一輪的代理時是 notify-only（對方不必再回）。上限是 `[gateway.bot_loop_guard] max_hops`（有設就優先），否則 `[delegation] max_hops`（預設 4）。鏈結狀態只在程序內，daemon 重啟後重算。
- **Ralph 迴圈**：`ralph` 工具每一輪開一個全新 context 的子代理，追同一個不可變的目標，只傳遞有大小上限的結構化報告；進度檔預設寫在 `<data>/ralph/<run>.md`（可用 `progress_file` 指定工作區內的相對路徑）。結果為 `complete`／`blocked`／`budget-limited`。`[delegation] ralph_max_rounds`（預設 16）是每次的輪數上限，`ralph_max_handoff_chars`（預設 16384）限制每輪交接報告大小；子代理不能再呼叫 `ralph`。
- **檔案擁有權**：`files_claim`／`files_release`／`files_owned`；租約綁定工作區相對路徑、預設 1 小時（`DEFAULT_TTL_MS`）、最長 7 天，過期自動釋放，重複索取會回報衝突。擁有權只能往下分割、不能重疊。
- **組間溝通**：`board_post`／`board_read`（共用公告板）、`agent_message`（只准父／子／兄弟）、`agent_escalate`（往上回報衝突）。
- **上限**：`[limits]` 的 `per_agent_spend_usd`、`hourly_spend_usd`、`global_spend_usd`、`max_processes_per_agent`、`disk_mb_per_agent`、`disk_mb_total`；接近上限（`warn_at`，預設 0.8）先警告再暫停。
- **孤兒程序**：每個代理的子程序在各自的 process group，代理結束（含當機）整組回收。

```toml
[delegation]
prefix_stagger_seconds = 0
max_hops = 4
ralph_max_rounds = 16
ralph_max_handoff_chars = 16384

[gateway.bot_loop_guard]
# max_hops = 3                 # 有設就蓋過 [delegation] max_hops
```

### 6.1 群聊房間（hosted rooms）

多個 profile 在同一個房間討論（最多 6 位成員）：

```bash
seagent rooms create <name> --member profile[:handle][@model] … \
  [--purpose "…"] [--notes "…"] [--routing everyone|lead|auto] [--lead <handle>]
seagent rooms update <room> [--purpose …] [--notes …] [--routing …] [--lead …]
seagent rooms list | show <room> | say <room> <text> | continue <room> | stop <room> | disband <room>
```

- `purpose`（最多 200 字）與共用 `notes`（最多 8 KB）放進成員的提示，不放進 system prompt。
- `routing = "everyone"`（預設）：沒點名的訊息每位成員都回。`lead`：新話題先交給 `--lead` 指定的成員分派（回 `{"assign":[…]}`），失敗就只有 lead 回。`auto`：由 `group_router` 輔助模型（`[model.tasks] group_router`，未設用 aux）挑成員，失敗就全部回。訊息裡明確 @點名一律優先；分派結果寫成 `room.assignment` 事件，可重播。
- 每次討論有輪數／訊息數上限；`rooms continue <room>`（或 `/room continue <room>`）再給一份完整預算，每次討論最多 5 次。
- `/room` 在對話中提供同一組操作；排程輸出可用 `deliver = "room:<room-id>"` 貼進房間（見 2.2）。

> 實作：`crates/seagent/src/main.rs`（`fleet`）、`crates/seagent/src/ops/rooms.rs`、`crates/seagent-kernel/src/coord.rs`（租約、看板、鏈結上限）、`limits.rs`、`subagents.rs`（fork、`PrefixGate`、`ralph`）。

---

## 7. 技能、外掛、hooks、自訂指令

### 7.1 技能（SKILL.md）

技能是一個目錄，裡面是 `SKILL.md`（YAML frontmatter ＋ Markdown 本文），可帶 `references/`、`templates/`、`scripts/`、`assets/`。

**搜尋順序**（先找到的贏）：`<ws>/.seagent/skills` → `<ws>/.claude/skills` → `<ws>/.agents/skills` → `<data>/skills` → 內建 `<share>/skills` → `~/.claude/skills` → `[skills] extra_dirs`。也就是說 **Claude 格式的技能目錄直接可用**；`metadata.openclaw` 與 `metadata.hermes` 也一併讀取（`requires.bins`／`anyBins`／`env`／`config`、`os`、`platforms`）。

```markdown
---
name: release-notes
description: 從 git log 產生發行說明
requires:
  bins: [git]
---
（本文就是給模型看的操作說明）
```

- 索引只給模型 `name: description (路徑)`，要用的時候才 `skill action=view` 載入（漸進揭露，省 token）。
- 可以用 `/release-notes …` 或 `/skill release-notes …` 直接叫；`/a /b do X` 可堆疊。
- 需求不符（缺執行檔、缺環境變數、OS 不符）的技能不會出現在索引裡，但明確要求仍載得到。
- 內建技能在 `share/skills/`，使用者技能在 `<data>/skills`。
- 隨附的 `productivity/notion` 與 `productivity/airtable` 已移除（上游同樣移除）；請改用廠商的 MCP server（`[mcp.notion]`、`[mcp.airtable]`）或廠商自己維護的技能來源（`seagent skills tap`）。

**技能鎖**：`seagent skills lock <name>`／`seagent skills unlock <name>`（`/skills lock|unlock` 同義）。鎖記在 `<data>/skills/.usage.json` 的 `locked`；鎖住後 agent 的任何寫入都被拒（見 4.2），curator 也不會自動封存或轉換它。只有你自己的 CLI 能解鎖。這是對指令文字的政策檢查，不是沙箱：自己寫程式繞路寫檔的情況看不到。

**技能工坊**：`[skills.workshop]` 決定 session 結束後的「經驗回顧」要不要產生技能草稿。

| 鍵 | 預設 | 說明 |
|---|---|---|
| `mode` | `off` | `off` 維持原本只列候選的 deterministic review；`propose` 把草稿放進審批佇列；`auto` 直接經守衛寫入 |
| `llm_review` | `true` | 用輔助模型把「目標＋實際跑過的工具＋目前的 SKILL.md」寫成草稿（只要 JSON 回覆，不需要 function calling）；失敗退回 deterministic 版本 |
| `model` | 空（= aux） | 回顧用的模型 |
| `diet_max_bytes` | `12000`（2 000–100 000） | `seagent curator diet` 的 SKILL.md 本文預算 |

草稿用 `/skills drafts`（或 `seagent skills drafts`、`/learn drafts`）查看，`/skills approve <id>`／`/skills reject <id>` 決定。`seagent curator diet [--max-bytes N] [--apply]` 找出過長的 SKILL.md，把尾段移到 `references/diet-<name>.md`，不刪內容；不加 `--apply` 只列出，鎖住的技能跳過。

> 實作：`crates/seagent-skills/src/skill.rs`、`core/{index,invoke,skilltool,slash,usage,review,workshop,cli}.rs`、`hub/cli.rs`。

### 7.2 外掛

外掛可以貢獻工具、hooks、channel、指令、CLI 子指令、HTTP 路由、UI、provider、service。安裝時要**宣告能力並經你同意**（`seagent plugin list` 看它提供什麼、`seagent security plugins` 看能力與同意狀態）。`seagent plugins update` 遇到掃描結果為 `caution` 的新版不會再默默接受；無人值守更新見 2.2 的 `plugin_auto_update_hours`（pinned 的 checkout 與沒有來源的外掛會跳過）。

### 7.3 Hooks（與 Claude Code 相容）

```toml
[[hooks]]
event = "pre_tool"               # 另有 post_tool、session_start/end、pre_compact、run_stopped…
matcher = "shell"
command = "~/.config/seagent/hooks/check-shell.sh"
```

新的 hook 指令**第一次要你同意**才會執行（`seagent hooks approve`、`--accept-hooks`，或互動確認）；`seagent hooks list|test <event>|doctor|revoke <cmd>`、`seagent hooks install <dir> [--link]`。內建的可選 hook 有 `command-logger`、`session-memory`、`boot-md`、`bootstrap-extra-files`、`compaction-notifier`。`run_stopped` 只能觀察（hook 擋不住明確的停止），payload 帶停止者與來源。

### 7.4 自訂指令

`/commands` 來自工作區或使用者目錄的 Markdown 檔（frontmatter 描述＋參數替換），`seagent commands` 會一併列出外掛指令與 MCP prompts。

---

## 8. MCP

```bash
seagent mcp add files -- npx -y @modelcontextprotocol/server-filesystem ~/docs
seagent mcp add github --url https://api.githubcopilot.com/mcp/      # 之後 seagent mcp login github（--device 給沒有瀏覽器的主機）
seagent mcp list | tools [server] | test <server> | refresh <server>
seagent mcp serve [--relay URL [--pair]]                              # 反過來讓別的 agent 用 seagent 的工具
```

`seagent mcp add … -- <command>` 寫入設定前會先印一行 `mcp consent:`：完整指令與 argv、環境變數名稱（非秘密的值）、cwd。名稱像秘密的旗標與環境變數的值會遮蔽（含 `--header=Authorization=…`），bidi／zero-width 與其他控制字元以 `\u{…}` 顯示，避免惡意指令改寫你在終端機上看到的內容。

```toml
[mcp.files]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/home/me/docs"]
exclude_tools = ["*delete*"]

[mcp.github]
url = "https://api.githubcopilot.com/mcp/"
auth = "oauth"
trust = "untrusted"        # 非唯讀工具每次都要核准
```

支援 stdio、Streamable HTTP、舊版 HTTP+SSE；OAuth 2.1（PKCE、動態註冊、device flow、issuer 綁定）、sampling、elicitation、roots、tasks、MCP Apps、events、成本上限。細節與逐項狀態見 [docs/parity.md](parity.md) 第二節。

**裝置上的 MCP server**（第一步）：`seagent node` 的 `node.toml` 可以寫 `[mcp.<server>]`，MCP 程序與它的憑證留在那台裝置上；每個工具以 `mcp__<server>__<tool>` 的裝置指令公告，透過既有的 `node_invoke` 呼叫。目前還不是一級的代理工具，elicitation／sampling 也不會轉給操作者。

> 實作：`crates/seagent/src/mcp_cli.rs`、`crates/seagent-plugin/`、`crates/seagent-app/src/node.rs`。

---

## 9. 模型、供應商與成本

```bash
seagent model                       # 互動選預設模型
seagent models list [provider] | providers | set <p/m> [--as aux] | aliases | fallbacks | refresh | pricing
seagent login <provider>            # 訂閱登入（ChatGPT、Claude、Copilot…）
seagent auth add|list|priority|strategy|refresh|status   # 多把金鑰輪替
seagent fallback add <p/m>
seagent usage --days 7 [--json]
```

### 9.1 模型與路由

- `[model] default`／`fallback[]`／`aux`（便宜模型：標題、MCP sampling 與各種輔助工作）。`[model.tasks] <工作> = "provider/model"`（或 `[auxiliary.<工作>]`）可替單一輔助工作指定模型。
- 編譯進執行檔的模型格式：OpenAI Chat／Responses、Anthropic、Gemini、Bedrock、OpenAI Agents API、外部 agent CLI（claude／gemini／codex、ACP、muse）、託管的 llama.cpp。精簡建置可以只留前三種（第 11 節）。
- **DeepSeek**：`deepseek` 仍是預設的 OpenAI-chat 路由。另有可選的 `deepseek-messages`（別名 `deepseek-anthropic`、`deepseek-native`），走 DeepSeek 的 Anthropic 相容 Messages 端點（`https://api.deepseek.com/anthropic/v1`、`x-api-key`、同樣用 `DEEPSEEK_API_KEY`）；思考程度 `off|low|high|max` 對應 `thinking` 與 `output_config.effort`。這條路由**尚未對真實端點驗證**。
- **Bedrock**：沒設金鑰時依 AWS 預設鏈取得憑證：環境變數 → web identity（EKS IRSA）→ shared credentials／config profile（含 `credential_process`）→ ECS 容器憑證 → EC2 IMDSv2（`AWS_PROFILE`、`AWS_SHARED_CREDENTIALS_FILE`、`AWS_EC2_METADATA_DISABLED` 等變數都認）。模型探索只列支援 `ON_DEMAND` 的基礎模型與 `ACTIVE` 的 inference profiles；明確寫在 `models` 的 id 不過濾。目前每次請求都會重新解析環境憑證（沒有快取），EC2／EKS 上每步可能多一次 metadata／STS 往返。
- **Gemini**：`/fast`（`[model] fast`）會送 `generationConfig.serviceTier`：`fast`／`priority`／`ultrafast` → `priority`、`flex` → `flex`、`standard`／`normal` → `standard`。
- **ChatGPT Codex 訂閱**：`[model] daybreak = true` 只在 `openai-codex` 路由送 `access_programs.cyber = "daybreak_blue"`（OpenAI Trusted Access for Cyber）。預設關閉；不會先查帳號的方案，帳號沒有這個方案時請求可能被拒。
- **外部 ACP agent**：`seagent acp-client` 的內建清單多了 `qoder`（`qodercli --acp`）。
- **決策模型**：`decision_evaluate` 的 provider 可設 `[decision] backend = "rerank"`，再給 `base_url`（與 `model`、`api_key`），任何 `/rerank` 端點（vLLM、TEI、Infinity、Cohere、Jina、Voyage）都能回答是非、選擇與排序題；回應不合格就報錯，不會編答案。

```toml
[decision]
backend = "rerank"                  # llm（預設）| openai | rerank
model = "local/bge-reranker-v2-m3"
base_url = "http://127.0.0.1:8080"  # POST {base_url}/rerank
api_key = ""
```

### 9.2 前綴快取與上下文

DeepSeek 等供應商以「請求前綴逐位元組相同」計算快取命中，以下設定都是為了不打斷前綴（`request_prefix_is_stable_across_steps_and_turns` 測試每一步、每一輪都檢查）：

| 設定 | 預設 | 說明 |
|---|---|---|
| 壓縮用的模型 | 對話本身的 provider/model | 摘要請求重播對話原本的 system prompt、工具清單與訊息，只在最後加一則摘要指示，命中同一份快取。`[model] aux` **不再**自動接手壓縮；要用便宜模型請明確設 `[model.tasks] compaction = "provider/model"`（或 `[auxiliary.compaction]`）。另外開的 `micro_compact` 仍走 compaction 的輔助模型 |
| `[compaction] trim_tool_results` | `"pressure"` | 只有上下文用量超過 `prune_threshold`（預設 0.5）才裁剪舊的長工具輸出；`"always"` 恢復每次請求都裁剪的舊行為（每幾次工具呼叫就讓快取失效） |
| `[model] system_updates` | `"rewrite"` | `"in_history"`：`/role`、`/personality` 與 persona 更新改成接在快取歷史之後，而不是改寫開頭的 system prompt。只有端點支援「歷史中的 system 更新」時才開（DeepSeek 公開端點是否支援尚未驗證） |
| `[model] log_requests` | `false` | 每次送給模型的請求（含裁剪、圖片處理、fallback 等之後的最終樣子）原樣存成 `Request` 事件，可逐位元組重放、查快取為何沒命中；每一步都會再存一份完整上下文，紀錄會變大 |

- 壓縮摘要固定包含 `## Unverified / Working Hypotheses` 一段（`UNVERIFIED: <主張> — <目前依據>`），尚未驗證的推測不會在壓縮後變成「事實」。
- `/context`（與 `/status`、主控台）在視窗大小只是未知模型的預設值時標 `(fallback)`；`[model] context_length` 釘選時標 `(pinned)`，並且也用在壓縮門檻的計算。
- 子代理的前綴重用見第 6 節（fork、`prefix_stagger_seconds`）。

### 9.3 觀測、評測與離線重播

- `seagent session stats --session <id>`：每一步的 TTFT、輸出 tok/s、model／tool 時間與 cache 命中率（見第 2 節）。
- **錄製與重播**：`SEAGENT_MODEL_RECORD=run.jsonl seagent …` 把每個 provider 的請求、串流片段與回應（或錯誤）寫成 JSONL；之後 `SEAGENT_MODEL_REPLAY=run.jsonl seagent …` 依序重播，不解析憑證、不連網。請求必須逐位元組相同，否則重播會指出第一個不同的地方。
- **評測基準**：`benchmark` 工具 profile 只有 `shell`、`read`、`run`。`seagent evals bench … --tool-profile benchmark` 把它套在程序內的 kernel 嘗試上（外部 agent 不受影響，並記在 run manifest）；可安裝的最小設定在 `share/evals/profiles/benchmark/`。

### 9.4 預算與金鑰

- `[budget] max_cost_usd`、`max_steps`；`seagent run --budget-usd`、`--budget-tokens`。
- 金鑰只在 daemon，子行程看不到（環境清洗 `[security] scrub_env`、`env_strip`、`env_passthrough`）。

> 實作：`crates/seagent-model/src/{catalog,anthropic,bedrock,sigv4,gemini,responses,replay,contextpin}.rs`、`crates/seagent-kernel/src/{compaction,decision,kernel,projection}.rs`、`crates/seagent/src/providers.rs`、`crates/seagent/src/agentcmds/sessions.rs`、`crates/seagent/src/ops/evalkit/`。

---

## 10. 記憶、知識庫與研究

### 10.1 知識召回閘門 `[memory.recall_gate]`

每輪回覆前先用關鍵字從知識庫挑候選頁，再讓輔助／決策模型**逐頁獨立**打相關機率，只注入過門檻的頁面。

| 鍵 | 預設 | 說明 |
|---|---|---|
| `mode` | `off` | `shadow` 照跑但只把決策寫進 `<data>/logs/recall-gate.jsonl`、不注入；`live` 才注入 |
| `candidates` | `keyword` | 目前只有關鍵字候選；`model` 尚未實作，會被拒 |
| `high_threshold` | `0.75` | 達到就注入頁面內容 |
| `medium_threshold` | 不設 | 設了就多一層「只給指標」 |
| `skip_hint_below` | 不設 | 全部分數都低於它時加一行「不需要記憶」提示 |
| `timeout_ms` | `1500` | 整個閘門的時間預算 |
| `max_candidates`／`page_chars`／`max_inject_chars` | `10`／`2800`／`6000` | 每輪評分頁數、每頁注入字數、總注入上限 |
| `store`／`model` | 空 | 讀哪個知識庫（空 = 預設）；評分模型（空 = aux） |

模型失敗或逾時記為 `unavailable`，不會假裝命中。

### 10.2 知識庫 `[memory.wiki]`：ACL、歷史、取代鏈

- **ACL**：`agent_id`（空 = `$SEAGENT_AGENT`）、預設庫的 `agents`（空 = 所有代理），以及具名庫 `[memory.wiki.stores.<name>] path = "…", agents = […]`。工具與 `seagent wiki … --store <name>` 讀寫前都先授權；沒有 `path` 的庫、不在名單上的代理一律拒絕。
- **歷史**：`history = true`（預設）在每次改寫前把舊頁存到 `.seagent-wiki/history/<page>/`，每頁保留 `history_max`（預設 50）份；`wiki_history` 工具與 `seagent wiki history <lookup>` 讀取。
- **取代鏈**：`wiki_apply {"op":"supersede","lookup":…,"by":…,"reason":…}` 把舊頁標成 superseded（記 `supersededBy`／`supersededAt`），搜尋會沿鏈回傳現行頁。
- 尚未做：上游其餘的 `knowledge_*` 工具、Git 式歷史、merge／withdraw／verify 流程、時間軸與逐關係 ACL。

### 10.3 常駐提醒 `[memory.standing]`

```toml
[memory.standing]
enabled = true          # 預設 false
max_intents = 50
cooldown_secs = 3600
max_fires = 3
```

```bash
seagent memory intents add "deploy freeze,change freeze" "提醒使用者目前凍結部署" \
  [--scope conversation|sender|channel] [--scope-value v] [--cooldown 秒] [--max-fires n] [--ttl 秒]
seagent memory intents list | remove <id> | clear
```

使用者訊息出現觸發詞時，提醒會注入那一輪；受範圍（預設 `conversation`）、冷卻、次數與到期限制。範圍比對目前以 session key 子字串為準，存放在 `<data>/memory/standing-intents.json`。

### 10.4 Embeddings 的私網政策

`[memory.search.embedding] allow_private`（預設 `true`）只影響 `ollama`：loopback／`localhost` 永遠可用；`true` 時也允許管理者設定的內網端點（常見的自架 GPU 主機）；設 `false` 只准 loopback。雲端 metadata 位址永遠拒絕。

### 10.5 深度研究 `deep_research`

有上限、可稽核的研究迴圈：最多規劃 4 個子問題，搜尋／抓取的語料上限 60 000 位元組、單頁 12 000 字；每個發現的引文必須逐字出現在來源裡，再用第二次模型呼叫稽核支持與矛盾；數字推算要有兩個有引用的輸入；最後列出明確的 gaps，遇到預算或缺口時狀態為 `partial`。只用一般的文字補全，**不需要 function calling**（DeepSeek 類供應商可用）。

輸入：`question`（必填）、`model`、`output`、`asOf`、`sources`（`web`、`urls`、`allowDomains`／`denyDomains`、`documents`；`web = false` 加 `documents` 完全離線）、`budget`（`modelCalls`、`searches`、`fetches`、`durationMs`）。工具由 `[web]` 設定一併註冊。

> 實作：`crates/seagent-memory/src/{active,wiki,standing,embed,settings}.rs`、`crates/seagent-tools/src/research.rs`、`crates/seagent/src/web_cli.rs`。

---

## 11. 建置選項與精簡執行檔

預設建置把所有聊天平台與模型格式都編進去（`--no-default-features` 才是精簡版），行為與舊版完全相同。

```bash
cargo build -p seagent --release                        # 完整（預設）
cargo build -p seagent --release --no-default-features  # 不含可選平台與額外模型格式
cargo build -p seagent --profile slim                   # 同一組功能，改用 opt-level="z"（最小）
```

哪些東西可以切、實測大小、怎麼量、大小預算怎麼檢查，全部在 [docs/BUILD.md](BUILD.md)。被切掉的平台或模型格式在設定裡仍然合法，只是啟動時警告並跳過——**不會**讓既有設定檔爆掉。

---

## 12. 疑難排解

| 症狀 | 先看 |
|---|---|
| 啟動就說設定錯誤 | `seagent config validate`、`seagent doctor` |
| 模型 401／403 | `seagent models status`、`seagent login <provider>`、`seagent auth status` |
| `API key missing` | 照訊息裡的變數名稱 `seagent secrets set <VAR>`，或 `seagent setup` |
| 匯入後一堆 `{{secret:…}}` 沒值 | `seagent migrate` 預設不搬憑證：重跑並加 `--migrate-secrets`，或逐一 `seagent secrets set` |
| 一直跳出核准 | `seagent approvals status`；`seagent approvals suggest` 找可預授權的樣式；`[approvals] preset = "relaxed"`；檢查是否有 `[tools.by_provider.*.exec]` 上限 |
| 沒問就執行了 | 看工具結果末尾的 `[approval] auto-approved: …` 那一行 |
| 某個工具不見了 | `seagent tools explain <tool> [--model M] [--channel C] [--sender S]` |
| 快取命中率低、花費偏高 | `seagent session stats --session <id>`；需要時開 `[model] log_requests` 比對請求；確認 `[compaction] trim_tool_results` 不是 `always` |
| 工作卡住不動 | `seagent gate list`（有人在等你）、`seagent pause status`（被緊急停止了嗎） |
| 花費失控 | `seagent usage --days 1`、`seagent fleet limits`、`[budget]` |
| 磁碟變大 | `seagent checkpoint prune`、`seagent system temp-clean --older-than 24`、`seagent sandbox recreate --all`；daemon 也會依 `[automation] scratch_ttl_hours`／`worktree_idle_hours` 自動清 |
| channel 沒反應 | `seagent channel list`、精簡建置的警告、`seagent webhook test` |
| 子代理互相踩檔案 | `seagent fleet files`、`seagent fleet board` |
| 代理互傳訊息被拒 | 鏈結超過 `max_hops`，或同一條鏈重複了同一段話（第 6 節） |

---

## 附錄 A：最小可用設定

```toml
[model]
default = "anthropic/claude-sonnet-5-5"
aux = "deepseek/deepseek-chat"

[budget]
max_cost_usd = 5.0
max_steps = 300

[gate]
privilege = "ask"
egress = "ask"

[channels.phone]
kind = "telegram"
token = "{{secret:TELEGRAM_TOKEN}}"
dm_policy = "pairing"
```

其餘每個鍵的說明見 [docs/config-example.toml](config-example.toml)。

## 附錄 B：指令速查

```
seagent setup | run | chat | session …(stats [--session id]) | daemon … | send/attach/interrupt | gate
seagent schedule … | goal … | system event | suggestions | kanban | fleet | rooms … | migrate …
seagent sandbox list|recreate|explain | sandbox vm status|image|snapshot|snapshots|undo|gc
seagent channel list|send | message … | webhook … | pairing
seagent approvals mode|status|list|allow|revoke|suggest|queue|test | exec-policy | gate | pause
seagent security audit|scan|plugins|check-url|creds | secrets | auth | login | models | usage
seagent mcp … | plugin list | hooks … | commands | skills …(lock|unlock|drafts) | curator …(diet)
seagent memory …(intents) | wiki …(history, --store)
seagent tools list|enable|disable|explain | browser … | screen … | computer-use … | voice | stt
seagent evals …(bench --tool-profile) | node … | nodes … | acp | acp-client | verify | plan | init | doctor | version
```
