# SE Agent 常見問題

寫信或開 issue 之前，先看這裡；大部分問題在這頁、[install.md](install.md)（安裝與疑難排解）或 `seagent doctor` 就有答案。

**目錄**：[基本](#基本) · [安裝與升級](#安裝與升級) · [模型、帳號與費用](#模型帳號與費用) · [資料與隱私](#資料與隱私) · [安全](#安全) · [使用](#使用) · [聊天平台](#聊天平台) · [瀏覽器與桌面 VM](#瀏覽器與桌面-vm) · [企業與多人](#企業與多人) · [授權與專案](#授權與專案) · [回報問題](#回報問題)

---

## 基本

**Q：SE Agent 是什麼？**
自架在你自己機器上（Windows、macOS、Linux、Android、iOS）的 AI 代理（agent）。你用自然語言交代工作，它用工具（shell、檔案、瀏覽器、桌面 VM、排程、聊天平台……）去完成，並在有風險的動作前停下來問你。名稱是 System Engineering Agent，指令是 `seagent`。

**Q：它和 ChatGPT／Claude 網頁版有什麼不同？**
網頁版的模型在對話框裡回答；SE Agent 在你的機器上**實際動手**：跑指令、改檔案、開網頁、排程、監看主機。模型只是它的「大腦」，可以換。

**Q：需要 GPU 嗎？**
不需要。模型由你選的供應商提供（雲端 API），或你自己架的本地推論伺服器（llama.cpp、Ollama、vLLM 等 OpenAI 相容端點）。SE Agent 本身只吃少量 CPU 與記憶體。

**Q：支援 Windows／macOS／手機嗎？**
支援，從 0.2.0-alpha 起都是原生版本：Windows `setup.exe`／`.msi`、macOS `.dmg`、Linux `.AppImage`／`.deb`／`.rpm`、Android `.apk`、iOS App，點兩下就裝好，內建 VM 也包在安裝檔裡。各平台驗證到什麼程度見 README 的「平台狀態」，安裝步驟見 [install.md §0](install.md#0-選擇平台與安裝檔)。

**Q：0.2.0-alpha 的「alpha」是什麼意思？可以拿來正式使用嗎？**
功能已經齊全、可以每天用，但 1.0 之前設定鍵、指令名稱與主控台還可能調整，安裝檔也還沒有程式碼簽章。重要的工作請先備份（`seagent data export`），升級前看 [CHANGELOG.md](../CHANGELOG.md)。

**Q：它參考了哪些專案？是誰寫的？**
設計逐項對照了 OpenClaw、Hermes Agent、DeepSeek Harness 與 LangChain／LangGraph（見 README「參考的上游專案」），以 Rust 重新實作，MIT 授權。程式主要由 AI 程式代理（DeepSeek Harness、Claude Code）在人類的指揮與審查下寫成，見 README「怎麼做出來的」。

**Q：以前的 `ark` 和 SE Agent 是什麼關係？**
同一個專案，改名了。舊設定、環境變數、資料會自動沿用或搬移，見 [install.md §8](install.md#8-從舊名稱-ark-升級)。

---

## 安裝與升級

**Q：最簡單的安裝方式？**
桌機、手機：從 Releases 下載對應平台的安裝檔點兩下（[install.md §0](install.md#0-選擇平台與安裝檔)）。Linux 伺服器：`curl -fsSL https://github.com/se-agent/System-Engineering-Agent/releases/latest/download/install.sh | sh`，然後照畫面上的連結開設定精靈。完整選項見 [install.md](install.md)。

**Q：可以不用 `curl | sh` 嗎？**
可以：deb、rpm、pacman、apk、npm、Nix、壓縮檔、離線包、容器、從原始碼都有，見 [install.md §3、§4](install.md#3-用發行版的套件管理員安裝)。每個發行檔都有 `SHA256SUMS` 與簽章可以先驗。

**Q：裝不起來怎麼辦？**
1. `seagent doctor`
2. 對照 [install.md §9 疑難排解](install.md#9-疑難排解)
3. 還是不行，照 [§9.8](install.md#98-還是不行) 收集資訊再回報。

**Q：怎麼升級？**
App：直接安裝新版的安裝檔（Windows `setup.exe`／`.msi`、macOS 拖進「應用程式」取代、Linux 換新的 AppImage 或裝新的 deb／rpm、Android 裝新的 apk）。CLI：重跑安裝指令；或 `seagent update`；套件安裝的就用套件管理員（`apt upgrade`、`dnf upgrade`、`pacman -Syu`、`apk upgrade`）。設定與資料不受影響。從 0.1.0 升級要注意的事、各方式的對照表見 [install.md §10](install.md#10-版本與升級)。

**Q：怎麼裝指定版本（例如 alpha）？**
到 Releases 下載該版本的安裝檔；或 `install.sh` 加 `--version v0.2.0-alpha`。不指定時安裝腳本只會裝最新的正式版。

**Q：怎麼解除安裝？資料會留下嗎？**
預設會留下設定、工作階段與稽核紀錄（它們可能是證據）。要完全清除見 [install.md §7](install.md#7-解除安裝)。

**Q：檔案放在哪？**
`seagent config path` 會印出實際位置與原因。個人安裝：`~/.config/seagent`（設定、金鑰）、`~/.local/share/seagent`（資料）、`~/.cache/seagent`（快取）。系統服務：`/etc/seagent`、`/var/lib/seagent`、`/var/log/seagent`。詳見 [paths.md](paths.md)。

**Q：可以在同一台機器跑兩份嗎？**
可以。設 `SEAGENT_HOME=<目錄>` 就是一份獨立的安裝（設定、資料、socket 全在那個目錄），或用 `seagent -p <名稱>`（profile）。

---

## 模型、帳號與費用

**Q：要付錢給 SE Agent 嗎？**
SE Agent 本身不收費。費用來自你用的模型供應商（按 token 計費），由供應商直接向你收。

**Q：支援哪些模型？**
OpenAI、Anthropic、Google Gemini／Vertex、AWS Bedrock、DeepSeek、OpenRouter、各種 OpenAI 相容端點（含本地 llama.cpp、Ollama、vLLM），以及 claude／gemini／codex 等代理 CLI。`seagent models providers` 列出全部。

**Q：可以用我的 ChatGPT／Claude 訂閱帳號嗎？**
部分供應商支援訂閱登入：`seagent login <供應商>`。是否允許、額度怎麼算，以各供應商的條款為準。

**Q：要怎麼控制花費？**
- 看用量：`seagent usage --days 7`
- 設上限：`[budget]`（每日／每月）、`seagent fleet limits`（子代理）
- 便宜的小模型做標題、審查等輔助工作：`[model] aux`（對話壓縮預設沿用對話本身的模型以命中前綴快取；真的要用便宜模型壓縮請設 `[model.tasks] compaction`）
- 看每一步的快取命中率與速度：`seagent session stats --session <id>`
- 緊急停止一切：`seagent pause`

**Q：貼了金鑰卻說格式錯誤／一直 401？**
終端機貼上時可能夾帶控制碼。用 `seagent secrets set <名稱>`（貼上、Enter、Ctrl+D）重新存，再 `seagent providers check`。

**Q：金鑰存在哪？安全嗎？**
存在加密的保管庫（`secrets.enc`，ChaCha20-Poly1305），金鑰放在系統鑰匙圈、TPM 或你設定的密碼檔；**永遠不寫進 `config.toml`，也不會進模型的上下文**。細節見 [SECURITY.md](SECURITY.md)。

---

## 資料與隱私

**Q：我的資料會被送到哪裡？**
只送到**你設定的**地方：
- 你選的模型供應商（對話內容與工具結果，這是代理運作必需的）
- 你設定的聊天平台、MCP 伺服器、webhook
- 代理在工作中造訪的網站

**Q：SE Agent 會回傳使用資料給開發者嗎？**
不會。沒有內建的分析或回報：
- 遙測（OpenTelemetry）預設**關閉**，開啟後預設只送到本機 `127.0.0.1:4318`，目的地由你設定。
- 自動檢查更新預設關閉。
- 唯一預設會連的公開服務是每天一次從 models.dev 下載模型價格表，可用 `[pricing] auto_refresh = false` 關掉。

**Q：可以完全離線嗎？**
可以，搭配本地模型（OpenAI 相容端點）與離線安裝包。設 `SEAGENT_OFFLINE=1` 會關掉所有非必要的連網。

**Q：對話紀錄存多久？可以刪嗎？**
預設永久保存在本機。可以設 `[compliance] retention_days` 自動清除，或 `seagent data export` / `seagent data delete`。

**Q：敏感資料會不會被代理送出去？**
資料外送是兩道硬閘門之一：秘密、個資離開機器前會被攔下，要你核准（或依你的政策拒絕）。日誌與匯出預設遮蔽秘密。

---

## 安全

**Q：它會不會亂刪我的檔案、跑危險指令？**
每個動作依四級風險分類：
- 唯讀、可回復、在隔離環境（VM）內的動作直接做。
- 「在 VM 外、而且不可回復」的動作一定先問你。
- 另有不可關閉的硬底線（例如刪除整個家目錄、改寫系統路徑），任何設定都無法放行。

說明見 [MANUAL.md §4](MANUAL.md#4-安全模型四級風險信封授權)。

**Q：一直跳出核准好煩？**
- `seagent approvals suggest` 找出可以預先授權的樣式。
- 核准時選「本次對話都允許」或「永久」。
- 或改用寬鬆預設：`[approvals] preset = "relaxed"`。

**Q：我可以中途接手嗎？**
可以。網頁主控台右側的工作區按「接手控制」，代理的瀏覽器與桌面操作會立刻停下，你操作完再「交還給代理」。

**Q：別人能連到我的主控台嗎？**
預設只聽 `127.0.0.1`，而且要 token。要對外開放必須明確設定反向代理與 TLS，見 [enterprise/install.md](enterprise/install.md)。

**Q：發現安全漏洞怎麼回報？**
請**不要**開公開 issue；依 [回報問題](#回報問題) 的私下管道通報。

---

## 使用

**Q：從哪裡開始？**
`seagent app open` 開網頁主控台，在對話框交代工作；或在終端機 `seagent chat`、單次任務 `seagent run "…"`。

**Q：可以讓它定時做事嗎？**
`seagent schedule add "0 9 * * 1-5" "整理昨天的告警"`；長期目標用 `seagent goal add`。

**Q：可以同時跑很多個代理嗎？**
可以（子代理艦隊）。主代理會派工、等結果；檔案有租約避免互相覆蓋。`seagent fleet` 查看。

**Q：可以接 MCP 伺服器、Claude 格式的技能嗎？**
可以。`seagent mcp add`；技能放在 `.seagent/skills`、`.claude/skills` 或資料目錄的 `skills/`。也相容 OpenClaw／Hermes 的技能格式。

**Q：工作卡住不動？**
- `seagent gate list`：是不是在等你核准。
- `seagent pause status`：是不是被緊急停止了。
- `seagent logs -n 50`：看日誌。

---

## 聊天平台

**Q：支援哪些聊天平台？**
46 條：Telegram、Discord、Slack、LINE、WhatsApp、Signal、Matrix、Teams、飛書、釘釘、企業微信、QQ、Email……完整清單與狀態見 [parity.md](parity.md)，設定見 [channel-guide.md](channel-guide.md)。

**Q：陌生人傳訊息給機器人會怎樣？**
預設 `dm_policy = "pairing"`：陌生人必須先完成配對才能下指令。

**Q：聊天平台上沒反應？**
`seagent channel list` 看連線狀態；`seagent webhook test` 測 webhook；改了頻道設定要重啟 daemon。

---

## 瀏覽器與桌面 VM

**Q：代理用的瀏覽器在哪？我看得到嗎？**
設定 `[computer_use] target = "vm:<名稱>"` 後，代理的瀏覽器跑在桌面 VM 裡，主控台右側即時顯示整個桌面，你可以隨時接手。沒有桌面 VM 時，代理用無頭瀏覽器，主控台顯示該分頁的畫面。

**Q：桌面 VM 需要什麼？**
QEMU 與硬體加速（沒有加速也能跑但很慢）。Windows 安裝包內附 QEMU，只要在「Windows 功能」勾選 Windows Hypervisor Platform；Linux 裝 `qemu-system-x86 qemu-utils` 並把自己加進 `kvm` 群組；macOS `brew install qemu`。第一次建立會下載約 418 MB 的 Debian 映像、裝好桌面後約 2.7 GB，視網路約 4–20 分鐘（下載可續傳，套件自動選最快的鏡像站）。VM 的時鐘跟著主機的時區。見 [desktop-vm.md](desktop-vm.md)。

**Q：可以在 VM 裡打中文嗎？**
可以。用你自己的輸入法在主控台打，送進 VM 的是組好的文字。VM 裡的終端機要用 Ctrl+Shift+V 才能貼上，送進終端機的最好是英數。

---

## 企業與多人

**Q：可以給團隊用嗎？**
可以：
- 安裝成系統服務。
- 主控台支援 OIDC 登入、角色權限、雙人核准、稽核匯出。
- 管理者可在 `/etc/seagent/managed.toml` 用政策鎖定設定。

見 [enterprise/](enterprise/) 目錄。

**Q：稽核紀錄能匯出給資安或稽核單位嗎？**
可以，主控台「稽核」頁可匯出 CSV／HTML 報告，也支援 syslog／SIEM 轉送。

**Q：有商業支援嗎？**
目前沒有。

---

## 授權與專案

**Q：授權條款？**
MIT。第三方元件的授權見 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

**Q：和 OpenClaw、Hermes、DeepSeek Harness、LangChain、Claude Code 有什麼關係？**
SE Agent 是獨立實作，不是任何一個的分支。它逐項對照過 OpenClaw、Hermes Agent、DeepSeek Harness 與 LangChain／LangGraph 的功能，把值得的部分以 Rust 重寫（MIT，出處見 THIRD_PARTY_NOTICES）；相容 OpenClaw、Hermes、Claude Code 的技能、hooks、外掛與設定格式，並提供匯入工具（`seagent migrate`）；LangChain 可以經 OpenAI 相容 API、MCP 或 A2A 呼叫它。對照文件在 [ecosystem/](ecosystem/README.md)。

**Q：從 OpenClaw／Hermes 搬過來，金鑰也會一起搬嗎？**
`seagent migrate` 預設**不**匯入憑證，只列出略過了哪些（`skipped credential NAME …`）。先 `seagent migrate from openclaw --dry-run` 看計畫，確定要搬金鑰再加 `--migrate-secrets`（寫進加密保管庫，不寫進 `config.toml`）；或之後逐一 `seagent secrets set NAME`。終端機精靈 `seagent setup` 的匯入步驟會先問要不要匯入設定，再另外問要不要匯入金鑰（預設不要）。各專案的來源與授權標示在 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

---

## 回報問題

| 情況 | 去哪裡 |
|---|---|
| 裝不起來、用法問題 | 先看本頁與 [install.md §9](install.md#9-疑難排解) |
| 確定是 bug | GitHub Issues，附上 [install.md §9.8](install.md#98-還是不行) 的資訊 |
| 功能建議 | GitHub Discussions |
| 安全漏洞 | **私下通報**：GitHub Security Advisories（repo 的「Security」→「Report a vulnerability」），不要公開 |

送出前請確認內容**沒有**金鑰、token、`secrets.toml`、對話中的個資。`seagent doctor` 與日誌已遮蔽秘密，但仍請自己看過。
