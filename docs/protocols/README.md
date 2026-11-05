# 協定對照表（官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ ark）

每個平台一份，回答同一個問題：**官方規格怎麼寫、三家上游 agent 實際怎麼做、ark 怎麼做、差在哪裡。**
ark 這一欄都以 `crates/ark-channel/src/<platform>.rs` 的 `file:line` 為證；上游以 `extensions/…`（OpenClaw）、`plugins/platforms/…`（Hermes）為證。

## 檔案

| 平台 | 檔案 | ark 是否對真實服務測過 |
|---|---|---|
| Telegram Bot API | `telegram.md` | ✗（無 bot token） |
| Discord Gateway/REST | `discord.md` | ✗（無 bot token） |
| Slack Socket Mode/Events | `slack.md` | ✗（無 app） |
| Microsoft Teams / Bot Framework | `teams.md` | ✗（無 Azure 應用） |
| WhatsApp Cloud API | `whatsapp-cloud.md` | ✗（無 Meta 應用） |
| Feishu / DingTalk / WeCom | `feishu-dingtalk-wecom.md` | ✗（無企業租戶） |
| LINE Messaging API | `line.md` | ✗（無 channel） |
| Matrix（CS API） | `matrix.md` | ✅ Synapse（自架） |
| Mattermost（API v4） | `mattermost.md` | ✅ Mattermost 12.0.1 + Postgres 16（自架 podman） |
| Nextcloud Talk（OCS / spreed） | `nextcloud-talk.md` | ✅ Nextcloud 29.0.7 + Talk 19.0.9（自架 podman） |
| IRC（RFC 1459/2812 + IRCv3） | `irc.md` | ✅ ngircd 27（自架） |
| Email（SMTP/IMAP/MIME） | `email.md` | ✅ GreenMail（自架） |
| ntfy | `ntfy.md` | ✅ ntfy 2.37.2（自架） |
| 模型／媒體供應商（E4／E5） | `providers-media.md` | 本機 whisper.cpp ✅、本機 Piper TTS ✅；雲端全部 ✗（無金鑰） |
| 沙箱瀏覽器（非 channel，B7 的實測記錄） | 見 `packaging/sandbox-browser/README.md` | ✅ 自建映像、容器內真 Chromium（`real_sandbox_browser.rs`） |

真實測試的程式在 `crates/ark-{channel,media,browser}/tests/real_*.rs`、操作腳本在 `tests/real/run.sh` 與 `tests/real/*_up.sh`；錄下來的位元組在 `tests/real/vectors/`。

## 方法

1. **能自架的真的跑**：podman 起服務（ntfy、GreenMail、Synapse、Mattermost + Postgres、Nextcloud + Talk）、發行版套件解到 TMPDIR（ngircd）、本機編譯（whisper.cpp）、本機安裝（Piper TTS）、自建映像（沙箱瀏覽器）、真程序（WhatsApp Baileys bridge、Chromium）。每一條都變成 `real_*.rs` 裡可重跑的測試。
2. **不能實測的對照**：先看官方文件，再看 OpenClaw／Hermes／opencode 的原始碼，最後看 ark；只寫得出來源的主張，不確定的標 ❓。
3. **opencode 的結論**：`sst/opencode` 沒有任何聊天平台通道層（36 個 `packages/` 都是 coding-agent 元件；全 repo 搜 `api.telegram.org`、`chat.postMessage`、`discord.com/api` 皆 0 命中）。它對 ark 的價值在模型供應商與 ACP，不在 channel；因此 channel 表格的 opencode 欄一律是「無對應實作（附證據）」。
4. **ark 有實測的，差異寫進「ark 的選擇與差異」並補測試**；實測發現的偏差直接修掉（Matrix 的 DM 判定、whisper.cpp 的 VAD 參數），修不掉或本輪不修的寫成「缺口」。

## 本輪由真實服務抓到的問題（都已修）

| 問題 | 平台 | 症狀 | 修法 |
|---|---|---|---|
| 具名的兩人房間被判成 DM | Matrix | 兩人的具名群組房間不再要求 @ 提及（與 Hermes／規格不符）；`real_matrix.rs` 直接斷言失敗 | `matrix.rs` 的 `is_dm` 改為「在 `m.direct` 裡，或**無名稱**的 ≤2 人房間」 |
| 管理的 whisper.cpp 指令用了 v1.7.4 沒有的 `--vad` | 本機 STT | whisper-cli 以 `error: unknown argument: --vad` 結束，沒有任何 `.txt`→ ark 報「did not produce a .txt transcript」 | `ark-media/src/stt/local.rs`：先問 `--help` 支不支援 VAD，不支援就不加那組參數（結果快取） |
| 自己的檔案分享被當成別人傳來的訊息 | Nextcloud Talk | bot 上傳檔案並分享到房間後，伺服器以 API 使用者身分回送 webhook（`actorType=users`、`file.path="Talk/<name>"`），舊過濾器兩個條件都不成立 → 假入站／自我迴圈 | `nextcloud_talk.rs`：`uploads` 表（TTL 900 s）＋`is_own_share()` 比對分享連結與檔名 |
| Piper 的 voice 名稱用錯直譯器下載、缺套件時只吐 Python traceback、暫存目錄漏清 | 本機 TTS | 有 venv 的 `piper` 但 ark 硬用系統 `python3` → `No module named piper`；`voice=<不存在的 .onnx>` 被當成「voice 名稱」去下載；每次失敗留下空的 `ark-tts-local-*` | `tts/local.rs`：`piper_python()` 取 `command` 同目錄的 `python3`；`Piper voice model not found: <path>`／缺 `.onnx.json` 直接說；`TempDir` Drop 守衛；錯誤只留最後一行例外與 exit code |
| 真伺服器沒有文件說的東西 | Mattermost | 文件寫 `seq_reply` 與 `401/403 → Auth`；12.0.1 只送 `hello`、不存在的頻道回 **403** `api.context.permissions.app_error`，`MaxPostSize` 預設是 262144 不是 16383 | 程式本來就對（ark 認 `hello`、403→`NotFound`）；修正 `mattermost.md` 的 4 處錯誤敘述與失效行號 |

## 與 0 段（保護不能吃掉自主性）的取捨

- 這些改動都**沒有新增任何核准步驟**，也沒有新增「問人」的路徑；全部是協定正確性與解析器修正。
- Matrix 的 DM 判定改嚴一格（具名兩人房間變成 Group ⇒ 需要 @ 提及）。這是把 ark 拉回 Hermes／規格的行為，代價是那種房間裡的人要 @ 一下 bot；好處是 agent 不會在當成 1:1 的房間裡對第三人的訊息全自動回話。若 owner 想恢復「一定回」，用 `dm_policy` 與提及即可，不需要新的核准關卡。
- 沒有動任何等級 2／3 的工具或硬底線，`ark-channel` 的 `allow`/`dm_policy` 行為不變。
