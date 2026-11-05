# ark 使用手冊

對象：在自己機器上安裝、設定與長期操作 ark 的人。

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
install -m 755 target/release/ark ~/.local/bin/ark
```

也可以改用 `packaging/install.sh`、`Dockerfile` 或 `flake.nix`。想要更小的執行檔（自架、只用自己的平台）見第 11 節與 [docs/BUILD.md](BUILD.md)。

### 1.3 `ark setup`（設定精靈）

```bash
ark setup            # 別名：ark onboard
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

跳過精靈也可以：`ark secrets set ANTHROPIC_API_KEY`（或 `OPENAI_API_KEY`、`DEEPSEEK_API_KEY`…）之後直接 `ark run "..."`。

### 1.4 目錄與檔案

| 位置 | 內容 |
|---|---|
| `$ARK_HOME/config/config.toml`（未設 `ARK_HOME` 時：`$XDG_CONFIG_HOME/ark/config.toml`，預設 `~/.config/ark`） | 使用者設定 |
| `$ARK_HOME/config/secrets.toml` | 秘密（0600）。永遠不寫進 `config.toml`，也永遠不進模型上下文 |
| `$ARK_HOME/data/sessions/`、`data/skills/`、`data/memory/`、`data/audit/` | 事件紀錄、技能、記憶、稽核 |
| `$ARK_HOME/run/arkd.sock`（或 `$XDG_RUNTIME_DIR/ark/`） | daemon socket（0600） |
| `<工作區>/.ark/config.toml` | 專案設定；其中 `hooks`／`mcp`／`plugins`／`channels`／`providers`／`app` 等段**只在该目錄列於 `trusted_projects` 時生效** |

`ARK_HOME` 會覆蓋全部路徑（測試與多實例都用它）。相關指令：

```bash
ark config path | show | get <key> | validate
ark doctor                 # 一次檢查設定、金鑰、daemon、磁碟、權限
ark version
```

> 實作：`crates/ark/src/setup.rs`、`crates/ark-kernel/src/config.rs`（`Paths::from_env`）。

---

## 2. 日常操作

```bash
ark run "整理這個資料夾的 README，列出待辦"     # 單次任務，結束即退出
ark run -                                     # 從 stdin 讀 prompt
ark chat                                      # 互動對話（/help 看清單）
```

| 想做什麼 | 指令 |
|---|---|
| 看／接續過去的對話 | `ark session list`、`session show <id>`、`session resume <id>`、`session fork`、`session search` |
| 匯出 | `ark session export [id] --format md\|qmd\|html\|json`（預設去識別化，`--no-redact` 關閉） |
| 背景常駐 | `ark daemon start\|stop\|status`、`ark service install`（systemd user unit） |
| 對背景 session 下指令／跟台／打斷 | `ark send <session> <text>`、`ark attach <session>`、`ark interrupt <session>` |
| 排程 | `ark schedule add "0 9 * * 1-5" "每天早上整理 issue"`、`schedule list\|rm\|enable\|disable\|run` |
| 長期目標 | `ark goal add "把測試覆蓋率拉到 80%" --rounds 5`、`goal list\|show\|run\|pause\|resume\|cancel` |
| 核准佇列 | `ark gate list`、`ark gate answer <id> once\|session\|permanent\|deny` |
| 緊急停止 | `ark pause [原因]`、`ark pause status`、`ark pause resume` |
| 花費 | `ark usage --days 7`、`ark usage --billing`（需要管理金鑰） |
| 介面 | `ark tui`、`ark app open`（網頁／PWA）、`ark acp`（Zed／JetBrains／Neovim） |

結束碼：`0` 完成、`1` 錯誤、`2` 用法錯誤、`3` 預算／上限／卡住、`130` 中斷。

> `ark pause` 只停「排程、goal、heartbeat、channel 進來的工作、kanban 派工、上限重試」，**不會殺掉正在跑的工作**；互動的 `ark run`／`ark chat` 不受影響。sentinel 檔是 `<data>/ESTOP`，讀不到時視為「已暫停」（fail safe）。
> 實作：`crates/ark/src/main.rs`、`crates/ark-security/src/estop.rs`。

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

- 秘密一律用 `{{secret:NAME}}` 引用，值放在 `ark secrets set NAME`；`config.toml` 裡沒有明文。
- **陌生人的預設待遇是拒絕**。`dm_policy = "pairing"` 時，未列在白名單的人會收到一組配對碼，你用 `ark pairing approve <channel> <code>` 放行（`ark pairing list|revoke`；8 碼、1 小時過期、只存加鹽雜湊、失敗 5 次鎖 1 小時）。
- 群組預設要 `@` 提及才回應；`require_mention = false` 可關。
- `privacy_notice`／`ai_label` 與 `[compliance] retention_days` 是法遵欄位：`dm_policy = open|pairing` 或 `group_policy = open` 卻沒設 `privacy_notice`，載入時會警告。

```bash
ark channel list                       # 已設定的通道（名稱、kind、dm 政策、白名單）
ark channel send <channel> <chat> "…"
ark message send|edit|delete|react|poll|pin|thread|read --channel <n> --chat <id> …
ark webhook subscribe|list|rm|test …
```

支援的平台：`config::registry()` 有 **56 個 kind 名稱**（其中 13 個是別名：`teams`、`google_chat`、`lark`、`wechat`、`twilio`、`imsg`、`imap`、`nextcloud_talk`、`synology_chat`、`urbit`、`twitter`、`qa_channel`、`home_assistant`），等於 **43 個自建平台**；再加上 App Server 提供的 webchat、A2A、OpenAI 相容 API，對照表上的 46 條通道。逐平台的傳輸方式、簽章與狀態見 [docs/parity.md](parity.md)。

精簡建置可以不含某些平台，這時在設定裡寫了它不會報錯，只會警告並跳過：
`ark: warning: channel kind `slack` is not compiled into this build …`（見第 11 節）。

> 實作：`crates/ark-channel/src/config.rs`（registry）、`access.rs`（政策與配對）、`crates/ark/src/ext.rs`（啟動與警告）。

---

## 4. 安全模型：四級風險、信封、授權

這一節是 ark 與「什麼都問」的差別所在。設計前提：**保護不能吃掉自主性**。能「隔離」或「回復」的，就不要「詢問」；詢問只留給「影響到 VM 以外」且「無法回復」的動作。完整設計理由見 `audit/GAPS-next.md` 第 0 段。

### 4.1 四級風險

| 等級 | 例子 | 預設處理 | 實作 |
|---|---|---|---|
| 0 `sandboxed` | 工作區內讀寫、跑測試、裝開發依賴、刪 VM 內暫存檔 | **直接放行**，只記錄 | `Tier::Sandboxed` |
| 1 `recoverable` | 對白名單主機發請求、自己的分支 commit、發訊息到自己的頻道、系統動詞（`apt-get`、`systemctl`…）**在沙箱內** | 直接放行；`standard` 會加稽核紀錄 | `Tier::Recoverable` |
| 2 `impactful` | 推送共用分支、改共用設定、對外寄信、**新主機**的對外請求、`git push`、雲端寫入 | 符合預先授權範圍→放行並通知；否則問人 | `Tier::Impactful` |
| 3 `irreversible` | 刪正式資料庫、雲端資源刪除、`git push --force`、改帳號權限、外送秘密、磁碟寫入、金額 ≥ 100 | **一律問人**，任何模式都關不掉 | `Tier::Irreversible` |

分類器只看工具呼叫本身，**不看模型怎麼說**：它吃的是 `Candidate`（工具名、exec 參數、讀寫路徑、主機、payload、金額、是否在沙箱內、工作區與安全根目錄、金鑰名稱與值）。任何 destructive 命中會直接把等級拉到 3。

三種預設組合（`[approvals] preset`）：`relaxed`（寬鬆，T2 直接放行）、`standard`（標準，T1 加稽核）、`strict`（嚴格，T1 只有沙箱內才放行）。信封上限分別是 2／2／1 級。

`standard` 之上還有 `ark` 的「兩道閘門」：提權（sudo、寫系統路徑）與外送（秘密、個資）由 `[gate]` 控制（`ask`／`deny`／`allow`），與上面四級是**兩層獨立防線**。

### 4.2 硬底線（等級 3 之外，不可關閉）

在問人之前，一律先過 hardline 檢查（`floors()`），它**沒有**任何設定可以關掉，`--yolo`、`approvals.mode = off`、cron 也繞不過：

- `rm -rf /`、`rm -rf` 系統目錄（`/home /root /etc /usr /var /bin /sbin /boot /lib`）或 `~`／`$HOME`
- `mkfs*`、`dd of=/dev/sd|nvme|hd|mmcblk|vd|xvd*`、`> /dev/<disk>`、`wipefs`、`shred /dev/`
- fork bomb、`kill -1`、`shutdown|reboot|halt|poweroff`、`init 0|6`、`systemctl poweroff|reboot|halt`、`telinit 0|6`
- `sudo -S` 但 vault 裡沒有 `SUDO_PASSWORD`（防止密碼猜測）

比對前會先正規化：去 ANSI/NUL、全形轉半形、反斜線接行、`$IFS`、引號拆解、`;|&` 斷句、`bash -c`／`$(…)` 內層。解析器超過上限（128 000 字元、或 4 096 字元沒有分隔、或 ≥25 000 個分隔）**一律視為拒絕**（fail closed）。`[approvals] deny` 的操作者黑名單樣式也同樣在此比對。

> 實作：`crates/ark-security/src/hardline.rs`、`crates/ark-kernel/src/secgate.rs`。

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

狀態：**函式庫層已完成**（`ark_security::envelope`，存放 `<data>/envelopes.json`，原子寫入，過期／撤銷自動清），kernel 也已在每次工具呼叫前查信封並執行上限檢查。**但操作面還沒接上**：目前沒有 `ark envelope …` 指令、沒有 chat 指令、沒有設定鍵，只有程式內 `envelope::create`（測試會用）。在那之前，長期授權請用 4.4 的具名授權。

> 實作：`crates/ark-security/src/envelope.rs`、`crates/ark-kernel/src/secgate.rs`（`tier <= preset.envelope_ceiling()`）。

### 4.4 有範圍、有期限的授權（不是全有全無）

「一律允許」不是永久通行證，而是**綁定樣式＋期限**的授權：

| 種類 | 綁定到 | 說明 |
|---|---|---|
| Gate 授權 | 閘門名稱＋理由字串 | 例如「只放行這個 egress 理由」 |
| 指令授權 | 完整指令或 glob | 複合指令（含 `;`、`&&`、管線）不准建立授權 |
| 執行檔授權 | 執行檔名或路徑 glob | 加上安全的 shell 內建（`cd`、`pwd`、`test`…）與 stdin 安全的 `jq`、`grep`、`cut`、`sort`、`uniq`、`head`、`tail`、`tr`、`wc` |

- 期限：預設 **7 天**（`[approvals] grant_ttl_days`），讀取時才過濾（沒有背景清掃）；`ark approvals queue allow` 這條路徑接受 0 = 永不過期。
- 存放：`<data>/approvals/allowlist.json`（目錄 0700）。
- 指令授權**永遠蓋不過等級 3**：tier-3 分支在授權檢查之前。
- 用法：`ark approvals list`、`ark approvals allow "<glob>" [--exec]`、`ark approvals revoke <id|pattern>`。
- 建議來源：`ark approvals suggest --days 7` 會從「過去被允許的閘門事件」挖出候選樣式（hardline／destructive 指令與 `rm`、`dd`、`sudo`、`chmod`、`kill`、`systemctl` 等不安全執行檔永遠不會被建議），你再用 `--apply 1,3` 套用。

### 4.5 核准的模式與開關

| 開關 | 值 | 作用 | 不能覆蓋什麼 |
|---|---|---|---|
| `ark approvals mode` | `manual`（預設）／`smart`／`auto`／`off` | `smart` 由便宜模型當監護人答 APPROVE／DENY／ESCALATE；`auto` 由審查模型答 allow／deny／ask 並附風險標籤；`off` 不問 | hardline、等級 3 |
| `ark exec-policy preset` | `yolo`／`cautious`／`deny-all` | 一次設定 exec 的 security／ask／ask_fallback | 同上 |
| `--yolo`（`ARK_YOLO=1`、`/yolo`） | 旗標 | 這個 process／session 跳過核准提示 | 等級 3、hardline、`deny` 規則 |
| `--allow-privilege`／`--allow-egress`／`--yes` | 旗標 | 無 TTY 時的 headless 核准者：對提權／外送直接答「一次」 | hardline；`exec` 仍走 `ask_fallback`（預設 deny） |
| `ark pause` | 全域 | 停止新的自動工作（見第 2 節） | 已在跑的工作 |

`smart` 在逾時或回覆無法解析時退回 ESCALATE（問人）；`auto` 退回 ASK。「沉默不是同意」：`[approvals] timeout_secs`（預設 600，daemon 啟動時套用）到期視為**拒絕**，閘門記錄寫 `deny (timeout)`，並在當初轉送核准的聊天室貼出「⏱ Approval … expired」。

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
- 破壞性動作可以先預覽：`ark approvals test -- <command…>` 是乾跑（結束碼 0 允許／2 要問／3 拒絕）；但它只算 floors＋閘門＋exec 政策，**不計算風險等級、信封與 taint**，所以「允許」不等於 T2/T3 也會過。

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

> 實作：`crates/ark-security/src/broker.rs`、`egress_proxy.rs`、`risk.rs`（`dev_hosts`）、`crates/ark-kernel/src/gate.rs`。

### 4.9 已知落差（本輪實測）

- 信封沒有操作介面（見 4.3）。
- `--yolo` 對 `ark tui` 沒有效果（凍結呼叫漏了 `tui`，`crates/ark/src/main.rs`）；其他子指令正常。
- `approvals.mode = auto`／`smart` 的審查者拿不到風險等級，只看得到閘門理由，所以「自動核准」對 T3 的保護比手動弱；T3 的預設路徑仍會問人，但請把它當成第二層而非唯一一層。
- 「核准疲勞」統計（每天問幾次、被拒比例、幾乎每次都允許就建議改成預授權）**尚未實作**；`ark approvals status` 只報規則數量，不是詢問次數。

---

## 5. microVM 與沙箱

### 5.1 隔離等級

ark 把每個執行後端對應到一個隔離等級，並且**不會靜默降級**——降級一定在 `ark sandbox explain` 與系統提示裡寫明原因：

| 等級 | 後端 | 擋得住什麼 |
|---|---|---|
| 4 `microVM` | Firecracker、QEMU/KVM | 自己的 kernel，硬體虛擬化 |
| 3 `app-kernel` | gVisor（`runsc`） | 使用者空間 kernel；kernel bug 被侷限 |
| 2 `container` | docker、podman | 自己的 rootfs，共用 host kernel |
| 1 `user-namespace` | bwrap、Landlock | namespace/seccomp，共用 kernel |
| 0 `host` | `local` | 沒有牆：以 ark 使用者身分直接跑 |

`ssh`、`modal`、`daytona`、`vercel`、`openshell`、`singularity`／`apptainer` 也各有對應等級。

```bash
ark sandbox explain            # 這個 session 實際在哪裡跑、隔離等級、警告
ark sandbox list [--json]      # 有沒有殘留的沙箱
ark sandbox recreate --all     # 重建
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

### 5.3 客體映像與快照

```bash
ark sandbox vm image build     # 下載 kernel + Alpine rootfs，放入 <data>/vm，寫 manifest.json
ark sandbox vm image verify
ark sandbox vm status [--json] # provider、隔離等級、每台 VM 的 pid／指令數／閒置秒數／快照數
ark sandbox vm snapshot --reason "before refactor"
ark sandbox vm snapshots
ark sandbox vm undo            # 回復，且回復前先把目前狀態再快照一次
ark sandbox vm gc              # 停掉閒置的 VM
```

VM 內沒有金鑰、沒有 daemon socket；指令透過 `ark-vm` 的協定進出，工作區依 `workspace_access` 同步。破壞性指令在 VM backend 下會先快照——**快照取代詢問**：錯誤用 undo 撤銷，不必事前核准。

> 實作：`crates/ark-vm/src/{isolation,config,image,snapshot,pool}.rs`、`crates/ark-tools/src/exec/vm.rs`、`crates/ark/src/exec_cli.rs`。

### 5.4 已知落差

- `[exec.vm.readonly]` 的逐工作區覆寫出現在文件裡但**未實作**（`readonly_patterns()` 固定回空），只有全域 `workspace_access` 有用。
- VM pool 的閒置回收／session teardown／broker 安裝有實作，但目前主要由 `ark sandbox vm …` 與 `ark exec` 路徑驅動，daemon 的自動回收尚未接上。
- 沒有 `/dev/kvm` 的機器會退回 bwrap 並警告；`ark doctor` 不會顯示隔離等級，請看 `ark sandbox explain`。

---

## 6. 多代理艦隊（fleet）

長時間任務可以拆給多個子代理平行做，ark 負責「不要互相打架」。

```bash
ark fleet status            # 每個代理：狀態、深度、tokens、花費、擁有檔案
ark fleet board             # 共用公告板：誰在做什麼
ark fleet files             # 目前被租用的檔案
ark fleet limits            # 上限（花費／磁碟／程序數）
ark fleet resume <session>  # 接續一個斷掉的代理
ark fleet --json            # 給程式用
```

- **派遣**：模型用 `delegate_task`（`tasks[]`、`mode = sync|background|collect`、`worktree`、`model`、`toolsets`）、`sessions_spawn`（預設隔離、背景）、`agents_wait`、`subagents action=list|info|cancel|stop|wait` 這些工具。子代理**不會**拿到互動類工具（`clarify`、`ask_user`、channel 發送、排程…）。
- **檔案擁有權**：`files_claim`／`files_release`／`files_owned`；租約綁定工作區相對路徑、預設 1 小時（`DEFAULT_TTL_MS`）、最長 7 天，過期自動釋放，重複索取會回報衝突。擁有權只能往下分割、不能重疊。
- **組間溝通**：`board_post`／`board_read`（共用公告板）、`agent_message`（只准父／子／兄弟）、`agent_escalate`（往上回報衝突）。
- **上限**：`[limits]` 的 `per_agent_spend_usd`、`hourly_spend_usd`、`global_spend_usd`、`max_processes_per_agent`、`disk_mb_per_agent`、`disk_mb_total`；接近上限（`warn_at`，預設 0.8）先警告再暫停。
- **孤兒程序**：每個代理的子程序在各自的 process group，代理結束（含當機）整組回收。

> 實作：`crates/ark/src/main.rs`（`fleet`）、`crates/ark-kernel/src/coord.rs`（租約、看板）、`limits.rs`、`subagents.rs`。

---

## 7. 技能、外掛、hooks、自訂指令

### 7.1 技能（SKILL.md）

技能是一個目錄，裡面是 `SKILL.md`（YAML frontmatter ＋ Markdown 本文），可帶 `references/`、`templates/`、`scripts/`、`assets/`。

**搜尋順序**（先找到的贏）：`<ws>/.ark/skills` → `<ws>/.claude/skills` → `<ws>/.agents/skills` → `<data>/skills` → 內建 `<share>/skills` → `~/.claude/skills` → `[skills] extra_dirs`。也就是說 **Claude 格式的技能目錄直接可用**；`metadata.openclaw` 與 `metadata.hermes` 也一併讀取（`requires.bins`／`anyBins`／`env`／`config`、`os`、`platforms`）。

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

> 實作：`crates/ark-skills/src/skill.rs`、`core/{index,invoke,skilltool,slash}.rs`。

### 7.2 外掛

外掛可以貢獻工具、hooks、channel、指令、CLI 子指令、HTTP 路由、UI、provider、service。安裝時要**宣告能力並經你同意**（`ark plugin list` 看它提供什麼、`ark security plugins` 看能力與同意狀態）。

### 7.3 Hooks（與 Claude Code 相容）

```toml
[[hooks]]
event = "pre_tool"               # 另有 post_tool、session_start/end、pre_compact…
matcher = "shell"
command = "~/.config/ark/hooks/check-shell.sh"
```

新的 hook 指令**第一次要你同意**才會執行（`ark hooks approve`、`--accept-hooks`，或互動確認）；`ark hooks list|test <event>|doctor|revoke <cmd>`、`ark hooks install <dir> [--link]`。內建的可選 hook 有 `command-logger`、`session-memory`、`boot-md`、`bootstrap-extra-files`、`compaction-notifier`。

### 7.4 自訂指令

`/commands` 來自工作區或使用者目錄的 Markdown 檔（frontmatter 描述＋參數替換），`ark commands` 會一併列出外掛指令與 MCP prompts。

---

## 8. MCP

```bash
ark mcp add files -- npx -y @modelcontextprotocol/server-filesystem ~/docs
ark mcp add github --url https://api.githubcopilot.com/mcp/      # 之後 ark mcp login github（--device 給沒有瀏覽器的主機）
ark mcp list | tools [server] | test <server> | refresh <server>
ark mcp serve [--relay URL [--pair]]                              # 反過來讓別的 agent 用 ark 的工具
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
ark model                       # 互動選預設模型
ark models list [provider] | providers | set <p/m> [--as aux] | aliases | fallbacks | refresh | pricing
ark login <provider>            # 訂閱登入（ChatGPT、Claude、Copilot…）
ark auth add|list|priority|strategy|refresh|status   # 多把金鑰輪替
ark fallback add <p/m>
ark usage --days 7 [--json]
```

- `[model] default`／`fallback[]`／`aux`（便宜模型：壓縮、標題、MCP sampling）。
- `[budget] max_cost_usd`、`max_steps`；`ark run --budget-usd`、`--budget-tokens`。
- 金鑰只在 daemon，子行程看不到（環境清洗 `[security] scrub_env`、`env_strip`、`env_passthrough`）。
- 編譯進執行檔的模型格式：OpenAI Chat／Responses、Anthropic、Gemini、Bedrock、OpenAI Agents API、外部 agent CLI（claude／gemini／codex、ACP、muse）、託管的 llama.cpp。精簡建置可以只留前三種（第 11 節）。

---

## 10. 建置選項與精簡執行檔

預設建置把所有聊天平台與模型格式都編進去（`--no-default-features` 才是精簡版），行為與舊版完全相同。

```bash
cargo build -p ark --release                        # 完整（預設）
cargo build -p ark --release --no-default-features  # 不含可選平台與額外模型格式
cargo build -p ark --profile slim                   # 同一組功能，改用 opt-level="z"（最小）
```

哪些東西可以切、實測大小、怎麼量、大小預算怎麼檢查，全部在 [docs/BUILD.md](BUILD.md)。被切掉的平台或模型格式在設定裡仍然合法，只是啟動時警告並跳過——**不會**讓既有設定檔爆掉。

---

## 11. 疑難排解

| 症狀 | 先看 |
|---|---|
| 啟動就說設定錯誤 | `ark config validate`、`ark doctor` |
| 模型 401／403 | `ark models status`、`ark login <provider>`、`ark auth status` |
| 一直跳出核准 | `ark approvals status`；`ark approvals suggest` 找可預授權的樣式；`[approvals] preset = "relaxed"` |
| 工作卡住不動 | `ark gate list`（有人在等你）、`ark pause status`（被緊急停止了嗎） |
| 花費失控 | `ark usage --days 1`、`ark fleet limits`、`[budget]` |
| 磁碟變大 | `ark checkpoint prune`、`ark system temp-clean --older-than 24`、`ark sandbox recreate --all` |
| channel 沒反應 | `ark channel list`、精簡建置的警告、`ark webhook test` |
| 子代理互相踩檔案 | `ark fleet files`、`ark fleet board` |

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
ark setup | run | chat | session … | daemon … | send/attach/interrupt | gate
ark schedule … | goal … | system event | suggestions | kanban | fleet
ark sandbox list|recreate|explain | sandbox vm status|image|snapshot|snapshots|undo|gc
ark channel list|send | message … | webhook … | pairing
ark approvals mode|status|list|allow|revoke|suggest|queue | exec-policy | gate | pause
ark security audit|scan|plugins|check-url|creds | secrets | auth | login | models | usage
ark mcp … | plugin list | hooks … | commands | skills
ark tools list|enable|disable | browser … | screen … | computer-use … | voice | stt
ark node … | nodes … | acp | acp-client | verify | plan | init | doctor | version
```
