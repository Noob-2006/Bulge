# SE Agent 使用手冊

對象：在自己機器上安裝、設定與長期操作 SE Agent 的人。

| 你想知道 | 看哪裡 |
|---|---|
| 某個平台／某個上游功能到底支援到什麼程度 | [docs/parity.md](parity.md) |
| crate 怎麼分層、新功能怎麼登記、程式碼風格規則 | [docs/ARCHITECTURE.md](ARCHITECTURE.md) |
| 建置、feature flags、精簡執行檔、大小預算 | [docs/BUILD.md](BUILD.md) |
| 完整設定範例（每個鍵都附說明） | [docs/config-example.toml](config-example.toml) |
| 台灣個資法規對照 | [docs/compliance-tw.md](compliance-tw.md) |

本手冊每一節結尾都列出實作位置，方便對照程式碼。最後一次逐項核對：**2026-11-05**（對應 `audit/GAPS-next.md` 第六輪）。

---

## 1. 安裝與第一次啟動

### 1.1 需求

- Linux x86_64（主要目標）、macOS 可跑但未驗證；單一執行檔，不需要 root、不需要資料庫、不需要 Node。
- 需要 `git` 與一個模型供應商的金鑰（或訂閱登入）。VM 功能另外需要 `/dev/kvm`（見第 6 節）。

### 1.2 建置與安裝

```bash
cargo build --release                       # 預設：所有聊天平台與模型格式都編進去
install -m 755 target/release/seagent ~/.local/bin/seagent
```

也可以改用 `packaging/install.sh`（一個指令：安裝、啟動服務與網頁主控台、印出一次性的瀏覽器設定精靈連結；`--system` 裝成系統服務，見 README）、`Dockerfile` 或 `flake.nix`。各模式的目錄配置見 [docs/paths.md](paths.md)。想要更小的執行檔（自架、只用自己的平台）見第 11 節與 [docs/BUILD.md](BUILD.md)。

### 1.3 `seagent setup`（設定精靈）

```bash
seagent setup            # 別名：seagent onboard
```

精靈依序做這幾件事，每一步都可以跳過：

1. 安全提示，並可匯入另一個 agent 的設定。
2. 選供應商：內建 preset，或自訂 OpenAI 相容端點（base URL＋金鑰環境變數名稱）。
3. 登入或貼金鑰（金鑰寫入 `secrets.toml`，權限 0600），隨即做一次連線檢查。
4. 選預設模型，然後**真的打一次**確認可用。
5. 可選：網頁搜尋供應商。
6. 可選：開網頁介面（`[app] enabled = true`，順便產生 `APP_TOKEN`）。
7. 可選：接一個聊天平台（Telegram／Discord／Slack），token 驗證過才存，並以 `dm_policy = "pairing"` 建立（陌生人不直接進來，要先配對）。
8. 最後寫入設定、驗證；驗證失敗會回復原狀。**既有設定會先備份**成 `config.toml.bak.<hex>`。

跳過精靈也可以：`seagent secrets set ANTHROPIC_API_KEY`（或 `OPENAI_API_KEY`、`DEEPSEEK_API_KEY`…）之後直接 `seagent run "..."`。

### 1.4 目錄與檔案

| 位置 | 內容 |
|---|---|
| `$SEAGENT_HOME/config/config.toml`（未設 `SEAGENT_HOME` 時：`$XDG_CONFIG_HOME/seagent/config.toml`，預設 `~/.config/seagent`） | 使用者設定 |
| `$SEAGENT_HOME/config/secrets.toml` | 秘密（0600）。永遠不寫進 `config.toml`，也永遠不進模型上下文 |
| `$SEAGENT_HOME/data/sessions/`、`data/skills/`、`data/memory/`、`data/audit/` | 事件紀錄、技能、記憶、稽核 |
| `$SEAGENT_HOME/run/seagentd.sock`（或 `$XDG_RUNTIME_DIR/seagent/`） | daemon socket（0600） |
| `<工作區>/.seagent/config.toml` | 專案設定；其中 `hooks`／`mcp`／`plugins`／`channels`／`providers`／`app` 等段**只在该目錄列於 `trusted_projects` 時生效** |

`SEAGENT_HOME` 會覆蓋全部路徑（測試與多實例都用它）。相關指令：

```bash
seagent config path | show | get <key> | validate
seagent doctor                 # 一次檢查設定、金鑰、daemon、磁碟、權限
seagent version
```

> 實作：`crates/seagent/src/setup.rs`、`crates/seagent-kernel/src/config.rs`（`Paths::from_env`）。

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
| 背景常駐 | `seagent daemon start\|stop\|status`、`seagent service install`（systemd user unit） |
| 對背景 session 下指令／跟台／打斷 | `seagent send <session> <text>`、`seagent attach <session>`、`seagent interrupt <session>` |
| 把終端對話交給聊天頻道 | `/handoff <channel>[:<chat>]`（需要 `seagentd` 與已設定的 `[channels.*]`；之後在該聊天回覆就延續同一對話） |
| 排程 | `seagent schedule add "0 9 * * 1-5" "每天早上整理 issue"`、`schedule list\|rm\|enable\|disable\|run` |
| 長期目標 | `seagent goal add "把測試覆蓋率拉到 80%" --rounds 5`、`goal list\|show\|run\|pause\|resume\|cancel` |
| 核准佇列 | `seagent gate list`、`seagent gate answer <id> once\|session\|permanent\|deny` |
| 緊急停止 | `seagent pause [原因]`、`seagent pause status`、`seagent pause resume` |
| 花費 | `seagent usage --days 7`、`seagent usage --billing`（需要管理金鑰） |
| 介面 | `seagent tui`、`seagent app open`（網頁／PWA）、`seagent acp`（Zed／JetBrains／Neovim） |

結束碼：`0` 完成、`1` 錯誤、`2` 用法錯誤、`3` 預算／上限／卡住、`130` 中斷。

> `seagent pause` 只停「排程、goal、heartbeat、channel 進來的工作、kanban 派工、上限重試」，**不會殺掉正在跑的工作**；互動的 `seagent run`／`seagent chat` 不受影響。sentinel 檔是 `<data>/ESTOP`，讀不到時視為「已暫停」（fail safe）。

排程輸出與維運相關設定（都有安全預設，不寫就維持原行為）：

```toml
[automation]
default_deliver = "slack:ops"          # 沒指定 deliver 的工作最後才用它（工作 → 建立者 → agent → 全域）
default_failure_deliver = "slack:oncall" # 失敗通知的同一套退回鏈
agent = "ops"                          # 新工作記錄的 owner，對應 [automation.agents.ops]
scratch_ttl_hours = 24                  # `<data>/tmp`、`scratch`、`art`、session artifacts 的過期時數（0 關閉）
worktree_idle_hours = 168               # 閒置且乾淨的 `.worktrees/*` 回收（0 關閉）
idle_session_secs = 1800                # seagentd 把閒置 session 的記憶體狀態退場，下次使用時重建（0 關閉）
plugin_auto_update_hours = 0            # 外掛無人值守更新；預設關，更新仍走掃描與同意流程

[automation.agents.ops]
deliver = "slack:C123"
failure_deliver = "slack:C999"

[automation.creators.alice]
deliver = "telegram:42"
```

`deliver` 另接受 `room:<room-id>`：把輸出附加到 hosted room 的日誌（只點名訊息中的 @成員，不會自動讓所有 bot 回話）。`seagent migrate ... --migrate-secrets` 才會把來源憑證寫進 vault；預設會列出略過的憑證名稱。`tools.call` ARP 方法讓 script 在既有 session 上直接呼叫工具（含 MCP），仍經過 policy、核准與 audit；需要 admin scope。
> 實作：`crates/seagent/src/main.rs`、`crates/seagent-security/src/estop.rs`。

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
- 外送 HTTP 會逐跳檢查轉址：自架的 channel 位址（Mattermost、Matrix、Nextcloud、ClickClack…）可為內網，但**轉址到另一個內網或雲端 metadata 位址會被拒絕**；附件下載（Discord CDN 等）只允許公開位址，並在跨來源轉址時丟掉授權標頭。
- `ask_user` 可帶 `options`（2–12 個選項；`multi_select = true` 可多選）。有按鈕的 channel（Telegram、Slack、Discord、Feishu…）直接顯示按鈕，其餘顯示編號清單；回覆編號或選項文字都會對應回選項。
- 在支援 threads／topics 的 channel 用 `/fork [標題]` 會把目前對話複製到同一個聊天的新 thread（Discord thread、Telegram topic；Slack 會先建立錨點訊息），原本的聊天與 session 不受影響。

```bash
seagent channel list                       # 已設定的通道（名稱、kind、dm 政策、白名單）
seagent channel send <channel> <chat> "…"
seagent message send|edit|delete|react|poll|pin|thread|read --channel <n> --chat <id> …
seagent webhook subscribe|list|rm|test …
```

支援的平台：`config::registry()` 有 **56 個 kind 名稱**（其中 13 個是別名：`teams`、`google_chat`、`lark`、`wechat`、`twilio`、`imsg`、`imap`、`nextcloud_talk`、`synology_chat`、`urbit`、`twitter`、`qa_channel`、`home_assistant`），等於 **43 個自建平台**；再加上 App Server 提供的 webchat、A2A、OpenAI 相容 API，對照表上的 46 條通道。逐平台的傳輸方式、簽章與狀態見 [docs/parity.md](parity.md)。

精簡建置可以不含某些平台，這時在設定裡寫了它不會報錯，只會警告並跳過：
`seagent: warning: channel kind `slack` is not compiled into this build …`（見第 11 節）。

> 實作：`crates/seagent-channel/src/config.rs`（registry）、`access.rs`（政策與配對）、`crates/seagent/src/ext.rs`（啟動與警告）。

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

分類器只看工具呼叫本身，**不看模型怎麼說**：它吃的是 `Candidate`（工具名、exec 參數、讀寫路徑、主機、payload、金額、是否在沙箱內、工作區與安全根目錄、金鑰名稱與值）。任何 destructive 命中會直接把等級拉到 3。

三種預設組合（`[approvals] preset`）：`relaxed`（寬鬆，T2 直接放行）、`standard`（標準，T1 加稽核）、`strict`（嚴格，T1 只有沙箱內才放行）。信封上限分別是 2／2／1 級。

`standard` 之上還有 `seagent` 的「兩道閘門」：提權（sudo、寫系統路徑）與外送（秘密、個資）由 `[gate]` 控制（`ask`／`deny`／`allow`），與上面四級是**兩層獨立防線**。

### 4.2 硬底線（等級 3 之外，不可關閉）

在問人之前，一律先過 hardline 檢查（`floors()`），它**沒有**任何設定可以關掉，`--yolo`、`approvals.mode = off`、cron 也繞不過：

- `rm -rf /`、`rm -rf` 系統目錄（`/home /root /etc /usr /var /bin /sbin /boot /lib`）或 `~`／`$HOME`
- `mkfs*`、`dd of=/dev/sd|nvme|hd|mmcblk|vd|xvd*`、`> /dev/<disk>`、`wipefs`、`shred /dev/`
- fork bomb、`kill -1`、`shutdown|reboot|halt|poweroff`、`init 0|6`、`systemctl poweroff|reboot|halt`、`telinit 0|6`
- `sudo -S` 但 vault 裡沒有 `SUDO_PASSWORD`（防止密碼猜測）

比對前會先正規化：去 ANSI/NUL、全形轉半形、反斜線接行、`$IFS`、引號拆解、`;|&` 斷句、`bash -c`／`$(…)` 內層。解析器超過上限（128 000 字元、或 4 096 字元沒有分隔、或 ≥25 000 個分隔）**一律視為拒絕**（fail closed）。`[approvals] deny` 的操作者黑名單樣式也同樣在此比對。

> 實作：`crates/seagent-security/src/hardline.rs`、`crates/seagent-kernel/src/secgate.rs`。

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
| 指令授權 | 完整指令或 glob | 複合指令（含 `;`、`&&`、管線）不准建立授權 |
| 執行檔授權 | 執行檔名或路徑 glob | 加上安全的 shell 內建（`cd`、`pwd`、`true`…）與 stdin 安全的 `jq`、`grep`、`cut`、`sort`、`uniq`、`head`、`tail`、`tr`、`wc`。`test`／`[` 只在運算元是靜態文字時才算安全：`-v`／`-R`、`$'…'`、以及含反斜線、`$`、反引號、`* ? { } [ ]` 的運算元一律回到一般核准（bash 會重新解析這些字元） |

- 期限：預設 **7 天**（`[approvals] grant_ttl_days`），讀取時才過濾（沒有背景清掃）；`seagent approvals queue allow` 這條路徑接受 0 = 永不過期。
- 存放：`<data>/approvals/allowlist.json`（目錄 0700）。
- 指令授權**永遠蓋不過等級 3**：tier-3 分支在授權檢查之前。
- 用法：`seagent approvals list`、`seagent approvals allow "<glob>" [--exec]`、`seagent approvals revoke <id|pattern>`。
- 網頁主控台的「核准」頁同樣列出常設授權（可直接撤銷）、可編輯全域執行政策，並顯示各代理的角色／工具／沙箱有效權限；「安全」頁集中顯示監聽面、權杖、頻道、風險發現與代理能力，未知角色一律標成 `unknown`。
- 建議來源：`seagent approvals suggest --days 7` 會從「過去被允許的閘門事件」挖出候選樣式（hardline／destructive 指令與 `rm`、`dd`、`sudo`、`chmod`、`kill`、`systemctl` 等不安全執行檔永遠不會被建議），你再用 `--apply 1,3` 套用。

### 4.5 核准的模式與開關

| 開關 | 值 | 作用 | 不能覆蓋什麼 |
|---|---|---|---|
| `seagent approvals mode` | `manual`（預設）／`smart`／`auto`／`off` | `smart` 由便宜模型當監護人答 APPROVE／DENY／ESCALATE；`auto` 由審查模型答 allow／deny／ask 並附風險標籤；`off` 不問 | hardline、等級 3 |
| `seagent exec-policy preset` | `yolo`／`cautious`／`deny-all` | 一次設定 exec 的 security／ask／ask_fallback | 同上 |
| `[tools.by_provider."<provider 或 provider/model>".exec]` | `mode = "deny"｜"allowlist"｜"ask"｜"auto"｜"full"`（或 `security`＋`ask`） | 只對該模型／供應商的回合夾住 exec 政策；只能收緊，`/yolo`、`/elevated` 也蓋不過 | 等級 3、hardline |
| `--yolo`（`SEAGENT_YOLO=1`、`/yolo`） | 旗標 | 這個 process／session 跳過核准提示 | 等級 3、hardline、`deny` 規則 |
| `--allow-privilege`／`--allow-egress`／`--yes` | 旗標 | 無 TTY 時的 headless 核准者：對提權／外送直接答「一次」 | hardline；`exec` 仍走 `ask_fallback`（預設 deny） |
| `seagent pause` | 全域 | 停止新的自動工作（見第 2 節） | 已在跑的工作 |

`smart` 在逾時或回覆無法解析時退回 ESCALATE（問人）；`auto` 退回 ASK。「沉默不是同意」：`[approvals] timeout_secs`（預設 600，daemon 啟動時套用）到期視為**拒絕**，閘門記錄寫 `deny (timeout)`，並在當初轉送核准的聊天室貼出「⏱ Approval … expired」。

沒有跳出提示、由政策自動放行的呼叫，工具結果末尾會附一行 `[approval] auto-approved: allow (allowlist|always|remembered|yolo|envelope|elevated|cron_mode) — <理由>`，讓模型與使用者看得到為什麼沒有問。要查某個工具為何可用或不可用，用 `seagent tools explain <tool> [--model M] [--channel C] [--sender S]`；它會逐層重放 `tools.disabled`、`tools.profile/allow/deny`、`tools.by_provider`、`tools.by_channel`、`tools.by_sender`，指出卡在哪一層與要改哪個設定。

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

### 4.6 只卡那一條、逾時也能安全繼續

- 需要問人的呼叫進入**延後佇列**（`<data>/approvals/queue.json`，pending／allowed／denied，同 session 同工具同理由去重，上限 200 筆）。排隊只擋那一個呼叫，**分支暫停、其他工作照做**；agent 會被要求回報「待人確認」而不會空轉。
- 等級 3 被拒時，若 `[approvals] tier3_fallback`（預設 true）開啟，錯誤訊息會附上**可回復的替代做法**（例如改開 PR 而不是直接推送、改產生遷移腳本而不是直接執行）。
- 核准等待時間會從 session 的時間預算中扣除（不會因為等人而把任務判定逾時）。
- 連續被拒 3 次（`[approvals] denial_breaker_threshold`）會斷路：agent 被告知停止換寫法重試，把動作交回人手。
- 破壞性動作可以先預覽：`seagent approvals test -- <command…>` 是乾跑（結束碼 0 允許／2 要問／3 拒絕）；但它只算 floors＋閘門＋exec 政策，**不計算風險等級、信封與 taint**，所以「允許」不等於 T2/T3 也會過。

### 4.7 不可信內容降權（taint）

來自網頁、issue、email、channel webhook 的工具輸出會被包進 `<<<EXTERNAL_UNTRUSTED_CONTENT id=…>>>` 標記（偽造標記與 chat-template token 會被中和）。只要最近的 event 裡出現過這種輸出，該 context 就算「髒」：

- 等級 2、3 一律要人（或被排進佇列），`yolo`／授權／白名單都不能繞；
- 等級 0、1 照常，agent 仍能讀、分析、寫草稿——這是**降權，不是停擺**。

`[security.external_content]` 可調：預設包 `web_fetch`、`web_search`、`web_extract`、`browser*`、`x_search`，以及 `webhook`、`email`、`gmail`、`msgraph_webhook` 這些通道。

### 4.8 指令代理（broker）與出口

VM 裡（或沙箱裡）的 agent 不直接碰主機的權限與網路，只能向 daemon 的 broker 請求：

- **只收 argv**：`argv` 裡任何元素含 `;`、`|`、換行、NUL、反引號、`$(` 一律拒絕；執行時用 `Command::new(argv[0]).args(...)`，不經 shell。
- **允許清單**：預設只有 `apt-get install *`、`apt-get update`、`apt update`、`dnf install *`、`systemctl restart|reload|status *`、`mount *`、`umount *`、`service * reload`。`exec_deny` 優先於 `exec_allow`；每道指令仍會再過一次風險分類，等級 3 **即使白名單也排隊**。
- 執行時洗環境、關 stdin、`timeout_secs` 到就殺。每次請求寫一行稽核到 `<data>/audit/broker.jsonl`（不含內容、不含秘密值）。
- **出口**：`[security.egress_proxy]` 的 proxy 只放行允許清單的主機，deny 與網站黑名單先檢查；`dev_hosts = true` 內建 32 個開發主機（github、crates.io、npm、pypi、debian/ubuntu 套件庫、docker registry、rustup…），這些算**操作者預先授權**的第 1 級主機，不必每次問。
- 外送秘密一律攔：payload 或 header 裡出現 vault 的秘密值、`{{secret:…}}` 佔位符、憑證檔路徑（`id_rsa`、`.ssh/`、`.aws/credentials`、`.netrc`、kubeconfig…）或 token 形狀（`ghp_`、`sk-ant-`、`AKIA…`、`xox*`、`AIza`、`glpat-`、JWT、PRIVATE KEY）→ 等級 3 或直接拒絕。

> 實作：`crates/seagent-security/src/broker.rs`、`egress_proxy.rs`、`risk.rs`（`dev_hosts`）、`crates/seagent-kernel/src/gate.rs`。

### 4.9 已知落差（本輪實測）

- 信封沒有操作介面（見 4.3）。
- `--yolo` 對 `seagent tui` 沒有效果（凍結呼叫漏了 `tui`，`crates/seagent/src/main.rs`）；其他子指令正常。
- `approvals.mode = auto`／`smart` 的審查者拿不到風險等級，只看得到閘門理由，所以「自動核准」對 T3 的保護比手動弱；T3 的預設路徑仍會問人，但請把它當成第二層而非唯一一層。
- 「核准疲勞」統計（每天問幾次、被拒比例、幾乎每次都允許就建議改成預授權）**尚未實作**；`seagent approvals status` 只報規則數量，不是詢問次數。

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

`ssh`、`modal`、`daytona`、`vercel`、`openshell`、`singularity`／`apptainer` 也各有對應等級。

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
```

`[exec.code] run_code_only = true` 讓模型只看得到 `run` 這一個直接工具：其他工具仍可在腳本內用 `seagent-call` 呼叫，但不會出現在工具清單。
SSH 後端會在同一個 ControlMaster 連線上維持一個遠端 `bash`（同步、探測與不含 stdin 的指令共用）；需要 stdin 或 PTY 的指令仍各自開一個 ssh 程序，不假裝有 PTY。
評測基準可用 `seagent evals bench --tool-profile benchmark`（工具面只有 `shell`、`read`、`run`）；完整最小設定檔在 `share/evals/profiles/benchmark/`。
模型請求可錄成 fixture 再用來離線重播：`SEAGENT_MODEL_RECORD=run.jsonl seagent …` 錄一次，之後 `SEAGENT_MODEL_REPLAY=run.jsonl seagent …` 不解析憑證、也不連網；請求必須逐位元組相同，否則重播會指名哪裡變了。

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

> 實作：`crates/seagent-vm/src/{isolation,config,image,snapshot,pool}.rs`、`crates/seagent-tools/src/exec/vm.rs`、`crates/seagent/src/exec_cli.rs`。

### 5.4 已知落差

- `[exec.vm.readonly]` 的逐工作區覆寫出現在文件裡但**未實作**（`readonly_patterns()` 固定回空），只有全域 `workspace_access` 有用。
- VM pool 的閒置回收／session teardown／broker 安裝有實作，但目前主要由 `seagent sandbox vm …` 與 `seagent exec` 路徑驅動，daemon 的自動回收尚未接上。
- 沒有 `/dev/kvm` 的機器會退回 bwrap 並警告；`seagent doctor` 不會顯示隔離等級，請看 `seagent sandbox explain`。

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
- 瀏覽器快照會把 password、`one-time-code` 與信用卡欄位（`cc-number`／`cc-csc`）的值換成 `[redacted]`；`[browser] allow_private_urls = false` 是嚴格 SSRF 模式，CDP 後端會在送出前逐跳檢查重新導向，無法檢查的後端（Camofox）會拒絕 http(s) 導航。

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
- **Fork 前綴重用**：`fork` 子代理沿用父會話的 system prompt 與工具清單（逐位元組相同，provider 快取可命中），角色與任務指示放在第一則 user 訊息；工具限制改在執行時以 `ToolGuard` 拒絕，不再改寫工具清單。
- **批次快取暖機**：`[delegation] prefix_stagger_seconds = N`（預設 0 = 關閉，上限 60）讓同路由的批次兄弟等第一個子代理的第一個串流片段（或 N 秒）再開始，代價約一個 TTFT。
- **鏈結上限**：`[gateway.bot_loop_guard] max_hops` 或 `[delegation] max_hops`（預設 4）限制代理對代理的訊息跳數；同一鏈重複相同訊息會被拒絕，回覆為 notify-only（`agent_message` 回傳 `hops` / `notify_only`）。
- **Ralph 迴圈**：`ralph` 工具以每輪全新 context 重複同一個不可變目標，只傳遞有界的結構化報告，並在工作區寫進度檔；`[delegation] ralph_max_rounds`（預設 16）是單次上限，`ralph_max_handoff_chars`（預設 16384）限制每輪交接報告大小。
- **檔案擁有權**：`files_claim`／`files_release`／`files_owned`；租約綁定工作區相對路徑、預設 1 小時（`DEFAULT_TTL_MS`）、最長 7 天，過期自動釋放，重複索取會回報衝突。擁有權只能往下分割、不能重疊。
- **組間溝通**：`board_post`／`board_read`（共用公告板）、`agent_message`（只准父／子／兄弟）、`agent_escalate`（往上回報衝突）。
- **群聊房間**：`seagent rooms create <name> --member … --purpose … --notes … --routing everyone|lead|auto [--lead <handle>]`、`rooms update`、`rooms show`、`rooms say`、`rooms continue <room>`（越過討論上限，每次 +1 完整輪次/訊息預算，最多 5 次）、`rooms stop|disband`；`/room` 提供同一組操作。
- **上限**：`[limits]` 的 `per_agent_spend_usd`、`hourly_spend_usd`、`global_spend_usd`、`max_processes_per_agent`、`disk_mb_per_agent`、`disk_mb_total`；接近上限（`warn_at`，預設 0.8）先警告再暫停。
- **孤兒程序**：每個代理的子程序在各自的 process group，代理結束（含當機）整組回收。

> 實作：`crates/seagent/src/main.rs`（`fleet`）、`crates/seagent-kernel/src/coord.rs`（租約、看板）、`limits.rs`、`subagents.rs`。

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

> 實作：`crates/seagent-skills/src/skill.rs`、`core/{index,invoke,skilltool,slash}.rs`。

### 7.2 外掛

外掛可以貢獻工具、hooks、channel、指令、CLI 子指令、HTTP 路由、UI、provider、service。安裝時要**宣告能力並經你同意**（`seagent plugin list` 看它提供什麼、`seagent security plugins` 看能力與同意狀態）。

### 7.3 Hooks（與 Claude Code 相容）

```toml
[[hooks]]
event = "pre_tool"               # 另有 post_tool、session_start/end、pre_compact…
matcher = "shell"
command = "~/.config/seagent/hooks/check-shell.sh"
```

新的 hook 指令**第一次要你同意**才會執行（`seagent hooks approve`、`--accept-hooks`，或互動確認）；`seagent hooks list|test <event>|doctor|revoke <cmd>`、`seagent hooks install <dir> [--link]`。內建的可選 hook 有 `command-logger`、`session-memory`、`boot-md`、`bootstrap-extra-files`、`compaction-notifier`。

### 7.4 自訂指令

`/commands` 來自工作區或使用者目錄的 Markdown 檔（frontmatter 描述＋參數替換），`seagent commands` 會一併列出外掛指令與 MCP prompts。

---

## 8. MCP

```bash
seagent mcp add files -- npx -y @modelcontextprotocol/server-filesystem ~/docs
# 寫入前會印出 mcp consent 一行：完整 argv、env 名稱、cwd；secret 名稱的值遮蔽、
# bidi/zero-width 字元以 \u{…} 轉義，避免惡意指令改寫終端畫面
seagent mcp add github --url https://api.githubcopilot.com/mcp/      # 之後 seagent mcp login github（--device 給沒有瀏覽器的主機）
seagent mcp list | tools [server] | test <server> | refresh <server>
seagent mcp serve [--relay URL [--pair]]                              # 反過來讓別的 agent 用 seagent 的工具
```

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

- `[model] default`／`fallback[]`／`aux`（便宜模型：標題、MCP sampling）。壓縮預設沿用對話本身的 provider/model，才能命中快取前綴；要改用便宜模型請明確設 `[model.tasks] compaction = "provider/model"`（或 `[auxiliary.compaction]`）。
- `[model] daybreak = true`：只在 `openai-codex`（ChatGPT Codex 訂閱）路由送
  `access_programs.cyber = "daybreak_blue"`；預設關閉，帳號方案仍須支援。
- `deepseek-messages`（別名 `deepseek-native`）走 DeepSeek 的 Anthropic-compatible Messages
  路由，`thinking`／`output_config.effort` 對應 `off|low|high|max`；`deepseek` 仍是預設
  OpenAI-chat 路由。
- `[decision] backend = "rerank"` 加 `base_url`：任何 `/rerank` 端點（vLLM、TEI、Infinity、
  Cohere、Jina、Voyage）都可當 `decision_evaluate` 的 provider。
- Gemini 的 `service_tier` 會從 `/fast` 對應到 `priority`，也接受 `flex`／`standard`。
- `seagent session stats --session <id>` 顯示每一步的 TTFT、輸出 tok/s、model/tool 時間與
  cache 命中率（`--json` 有 `step_stats` 與 `steps[]`）。
- `[model] log_requests = true`：每次送給模型的請求原樣存成 `Request` 事件，可逐位元組重放、查快取為何沒命中。預設關閉，因為每一步都會再存一份完整上下文。
- `[model] system_updates = "in_history"`：只有端點支援「歷史中的 system 更新」時才開；開啟後 `/role`、`/personality` 等中途的系統提示變更會接在快取歷史之後，不再改寫開頭，DeepSeek 快取前綴因此保留。預設 `"rewrite"`（相容舊行為）。
- `[compaction] trim_tool_results = "pressure"`（預設）：只有上下文真的超過 `prune_threshold` 才裁剪舊工具輸出；`"always"` 恢復舊的每次請求都裁剪。`/context` 的視窗若只是未知模型的預設值會標 `(fallback)`，`model.context_length` 釘選則標 `(pinned)`。
- `[budget] max_cost_usd`、`max_steps`；`seagent run --budget-usd`、`--budget-tokens`。
- 金鑰只在 daemon，子行程看不到（環境清洗 `[security] scrub_env`、`env_strip`、`env_passthrough`）。
- 編譯進執行檔的模型格式：OpenAI Chat／Responses、Anthropic、Gemini、Bedrock、OpenAI Agents API、外部 agent CLI（claude／gemini／codex、ACP、muse）、託管的 llama.cpp。精簡建置可以只留前三種（第 11 節）。

---

## 10. 建置選項與精簡執行檔

預設建置把所有聊天平台與模型格式都編進去（`--no-default-features` 才是精簡版），行為與舊版完全相同。

```bash
cargo build -p seagent --release                        # 完整（預設）
cargo build -p seagent --release --no-default-features  # 不含可選平台與額外模型格式
cargo build -p seagent --profile slim                   # 同一組功能，改用 opt-level="z"（最小）
```

哪些東西可以切、實測大小、怎麼量、大小預算怎麼檢查，全部在 [docs/BUILD.md](BUILD.md)。被切掉的平台或模型格式在設定裡仍然合法，只是啟動時警告並跳過——**不會**讓既有設定檔爆掉。

---

## 11. 疑難排解

| 症狀 | 先看 |
|---|---|
| 啟動就說設定錯誤 | `seagent config validate`、`seagent doctor` |
| 模型 401／403 | `seagent models status`、`seagent login <provider>`、`seagent auth status` |
| 一直跳出核准 | `seagent approvals status`；`seagent approvals suggest` 找可預授權的樣式；`[approvals] preset = "relaxed"` |
| 工作卡住不動 | `seagent gate list`（有人在等你）、`seagent pause status`（被緊急停止了嗎） |
| 花費失控 | `seagent usage --days 1`、`seagent fleet limits`、`[budget]` |
| 磁碟變大 | `seagent checkpoint prune`、`seagent system temp-clean --older-than 24`、`seagent sandbox recreate --all` |
| channel 沒反應 | `seagent channel list`、精簡建置的警告、`seagent webhook test` |
| 子代理互相踩檔案 | `seagent fleet files`、`seagent fleet board` |

---

## 12. 記憶、研究與技能治理

**知識召回閘門** `[memory.recall_gate]`：`mode = "off" | "shadow" | "live"`（預設 off）。每輪先用關鍵字挑知識頁，再讓 aux 模型逐頁打相關分數；`shadow` 只把決策寫進 `<data>/logs/recall-gate.jsonl`、不注入，`live` 才把過 `high_threshold` 的頁面注入（`page_chars`、`max_inject_chars` 有上限，`timeout_ms` 預設 1500）。`store` 可指定知識庫。

**知識庫 ACL／歷史／取代鏈** `[memory.wiki]`：`agent_id`（空 = `$SEAGENT_AGENT`）、預設庫的 `agents`、`[memory.wiki.stores.<name>] path/agents`；`history = true` 會在每次改寫前把舊頁存到 `.seagent-wiki/history/`（`history_max`）。`seagent wiki … --store <name>` 與 `wiki_history` 工具可讀歷史；`wiki_apply {"op":"supersede","lookup":…,"by":…}` 會把舊頁標成 superseded，搜尋沿 `supersededBy` 回傳現行頁。

**常駐提醒** `[memory.standing] enabled = true`，再用 `seagent memory intents add "觸發詞,另一個" "提醒內容" --scope conversation|sender|channel --scope-value … --cooldown 秒 --max-fires n --ttl 秒`；`list`／`remove`／`clear` 管理。觸發後注入該輪，受冷卻、次數與到期限制。

**技能鎖** `seagent skills lock <name>`（使用者指令；agent 的 skill 寫入、write/patch、shell 寫入都會被拒），`seagent skills unlock <name>` 解鎖。鎖存在 `skills/.usage.json` 的 `locked`，curator 不會 archive 鎖住的技能。

**技能工坊模式** `[skills.workshop] mode = "off" | "propose" | "auto"`（預設 off，保留原本 deterministic review）。`propose` 把 LLM 經驗回顧產生的草稿放進審批佇列（`/skills drafts`、`/skills approve <id>`），`auto` 直接走守衛寫入。`llm_review = false` 可只用 deterministic 版本。`seagent curator diet [--apply]` 會把過長 SKILL.md 的尾段移到 `references/`，不刪內容（`diet_max_bytes`）。

**深度研究工具** `deep_research`：有界搜尋／抓取（60 KB 語料、單頁 12k 字）、逐字引文驗證、第二輪支持／矛盾稽核、明確 gaps；只用 `complete_text`，不需要 function calling（DeepSeek 可用）。可用 `sources.documents` 完全離線，`budget` 限制模型／搜尋／抓取次數與時限。

**Ollama embeddings** `[memory.search.embedding] allow_private = true`（預設）：loopback／`localhost` 與管理者設定的 LAN 端點可用；設 false 則只准 loopback。雲端 metadata 永遠拒絕。

**已移除技能** `productivity/notion`、`productivity/airtable` 不再隨附（上游同樣移除）。改用廠商 MCP server（`[mcp.notion]`／`[mcp.airtable]`）或 vendor-owned skill taps。

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
seagent setup | run | chat | session … | daemon … | send/attach/interrupt | gate
seagent schedule … | goal … | system event | suggestions | kanban | fleet
seagent sandbox list|recreate|explain | sandbox vm status|image|snapshot|snapshots|undo|gc
seagent channel list|send | message … | webhook … | pairing
seagent approvals mode|status|list|allow|revoke|suggest|queue | exec-policy | gate | pause
seagent security audit|scan|plugins|check-url|creds | secrets | auth | login | models | usage
seagent mcp … | plugin list | hooks … | commands | skills
seagent tools list|enable|disable|explain | browser … | screen … | computer-use … | voice | stt
seagent node … | nodes … | acp | acp-client | verify | plan | init | doctor | version
```
