# 真實服務測試（tests/real）

這裡放「真的連上服務」的測試：可以用 podman 自架的，就自己架；需要帳號或憑證的，改成錄下真實請求／回應當測試向量。

## 怎麼跑

```sh
# 全套（自架 ntfy + GreenMail + ngircd + Synapse + Mattermost + Nextcloud Talk +
#       本機 Piper TTS + 沙箱瀏覽器映像 + WhatsApp bridge）
./tests/real/run.sh                 # 需要 podman、cargo、curl、node（WhatsApp）
./tests/real/run.sh --no-matrix     # 不跑 Synapse（約 340 MB、啟動 25 秒）
./tests/real/run.sh --no-mattermost --no-nextcloud --no-tts --no-sandbox
                                    # 只跑「輕」的那幾項（映像都很大／要下載）
./tests/real/run.sh --keep          # 跑完留下服務，自己收拾

# 只跑其中一項（服務要先自己起，見 run.sh 裡的位址）
SEAGENT_REAL_NTFY_URL=http://127.0.0.1:25860 cargo test -p seagent-channel --test real_ntfy
```

`run.sh` 只會刪掉**它自己**起的容器（`seagent-real-*`，以及 `tests/real/*_up.sh --keep` 交給它的 `seagent-test-*`）、程序（`$!` 記錄的 pid）與 `$TMPDIR/seagent-real-$$`。

單獨跑某一套（每一套都自己收容器，只收 `seagent-test-*`）：

```sh
eval "$(./tests/real/mattermost_up.sh --keep)"     # Mattermost + Postgres（730 MB 映像）
cargo test -p seagent-channel --test real_mattermost
./tests/real/mattermost_up.sh --down

eval "$(./tests/real/nextcloud_up.sh --keep)"      # Nextcloud 29 + Talk/spreed
cargo test -p seagent-channel --test real_nextcloud_talk
./tests/real/nextcloud_up.sh --down

eval "$(./tests/real/tts_up.sh)"                   # Piper 裝進 $TMPDIR（~150 MB）
cargo test -p seagent-media --test real_tts

eval "$(./tests/real/sandbox_browser_up.sh)"       # 建 packaging/sandbox-browser 映像
cargo test -p seagent-browser --test real_sandbox_browser
```

環境需求：
- **podman**（rootless 可）：`binwiederhier/ntfy`、`greenmail/standalone`、`matrixdotorg/synapse`、`postgres:16-alpine` + `mattermost/mattermost-team-edition`、`nextcloud:29.0.7-apache`。
- **容器 CLI**：`SEAGENT_DOCKER`，否則 `docker`，否則 `podman`（與 SE Agent 自己的解析一致；沙箱瀏覽器在只有 podman 的機器上也能用）。
- **ngircd**：系統有就用系統的，否則 `apt-get download ngircd libident0` 解到 `$TMPDIR`（不需要 root）。
- **node + `bridges/whatsapp/node_modules`**：WhatsApp bridge（`npm install` 一次）。
- **whisper.cpp**：本機 STT 測試需要自己編一份，並指定：
  ```sh
  SEAGENT_REAL_WHISPER_CPP=$PWD/whisper.cpp/build/bin/whisper-cli \
  SEAGENT_REAL_WHISPER_WAV=$PWD/whisper.cpp/samples/jfk.wav \
  ./tests/real/run.sh --no-matrix
  ```
  模型由 SE Agent 自己下載並驗 SHA-256（`[media.stt.local] models_dir`）。
- **Python 3 + 網路**（只有 TTS 那套）：`tests/real/tts_up.sh` 用 `uv`/`python3 -m venv` 把 `piper-tts` 與一個 voice 裝在 `$TMPDIR`。

## 檔案

| 檔案 | 對什麼 | 證明了什麼 |
|---|---|---|
| `crates/seagent-channel/tests/real_ntfy.rs` | ntfy 2.37.2 | 串流收訊、發佈標頭、回音防護、`since` 續接 |
| `crates/seagent-channel/tests/real_email.rs` | GreenMail（SMTP+IMAP） | 真 SMTP 交信→IMAP 收信、引用剝除、真 SMTP 寄信並用伺服器 API 驗證 |
| `crates/seagent-channel/tests/real_irc.rs` | ngircd 27 | 註冊/JOIN、頻道與私訊入站、出站送達 |
| `crates/seagent-channel/tests/real_matrix.rs` | Synapse | 邀請→自動加入→房間訊息、`PUT /send` 出站 |
| `crates/seagent-channel/tests/real_mattermost.rs` | Mattermost 12.0.1（team edition）+ Postgres 16 | WS 驗證與心跳、入站貼文、出站／編輯／討論串／DM、檔案上傳、反應、typing、錯誤映射（7 個測試） |
| `crates/seagent-channel/tests/real_nextcloud_talk.rs` | Nextcloud 29.0.7 + Talk（spreed）19.0.9 | 真 OCS 聊天 API 收發、反應、長訊息切分、檔案上傳下載、bot webhook 簽章、自己的分享不回聲（12 個測試） |
| `crates/seagent-channel/tests/real_whatsapp.rs` | Baileys bridge（未配對） | `/health`、`/qr` 真實配對載荷 |
| `crates/seagent-channel/tests/real_media.rs` | 本機 whisper.cpp | SE Agent 管理的 whisper.cpp 路徑（下載＋驗雜湊＋轉錄） |
| `crates/seagent-media/tests/real_tts.rs` | 本機 Piper（piper-tts 1.8.0、`en_US-lessac-medium`） | 真合成出合法 WAV（22 050 Hz、非靜音）、`length_scale`/`speaker_id` 真的傳到 binary、voice 名稱走 `$SEAGENT_HOME` 快取、缺引擎／缺模型的錯誤訊息、暫存檔會清掉（7 個測試） |
| `crates/seagent-browser/tests/real_sandbox_browser.rs` | `packaging/sandbox-browser` 映像（Chromium 156 + Xvfb + x11vnc + noVNC + CDP relay） | SE Agent 用 `backend="sandbox"` 起容器、真的導覽＋跑 JS＋截圖、relay 無 token／錯 token 都 401、Chromium 的 9223 不對外、非 root、關閉後容器消失（3 個測試） |
| `crates/seagent-channel/tests/vectors.rs` | 錄下來的位元組 | 不需要服務的解析器回歸（見下） |
| `tests/real/chromium_real.sh` | 本機 Chromium | headless 啟動參數、CDP 端點、JS 執行、截圖 |

各套的啟動腳本：`mattermost_up.sh`、`nextcloud_up.sh`、`tts_up.sh`、`sandbox_browser_up.sh`（都只碰自己建的 `seagent-test-*`／`$TMPDIR`，並支援 `--down` 或直接收乾淨）。

## 測試向量（`vectors/`）

全部是這台機器上真實服務吐出來的位元組，重新錄製的方法寫在各測試的註解裡：

| 檔案 | 來源 | 用途 |
|---|---|---|
| `irc_ngircd_session.txt` | ngircd 27 的真實 session（CAP NAK、001/005、JOIN、PRIVMSG） | `irc::parse_line` 對真實輸出的回歸；也記錄了 ngircd **不支援** IRCv3（沒有 message-tags ⇒ SE Agent 必須用本地 id） |
| `ntfy_publish_response.json` / `ntfy_stream_event.json` | ntfy 2.37.2 | 發佈回應與串流事件的欄位契約（id、topic、title、tags、time） |
| `greenmail_message.eml` | GreenMail 收到的 SMTP 信件 | quoted-printable、Message-ID、From 解析 |
| `synapse_sync_slice.json` | Synapse `/sync` 裁剪版 | 房間訊息 → `Inbound` 的欄位映射、自己的回音要丟掉 |

## 不在這裡的

- **需要真帳號的平台**（Telegram、Discord、Slack、Teams、WhatsApp Cloud、Feishu/DingTalk/WeCom、LINE）：沒有帳號，改成「官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ SE Agent」對照表，放在 `docs/protocols/`。
- **SE Agent 的 CDP client 對「本機自己開的」Chromium**：`chromium_real.sh` 只證明瀏覽器本身與啟動參數可用；seagent-browser 的 CDP 路徑由 crate 自己的測試與 `real_sandbox_browser.rs`（容器內 Chromium，走完整 `Manager::browser` 路徑）覆蓋。
- **KittenTTS／NeuTTS**：仍只有假 engine 的單元測試（要下載數 GB 模型，本輪沒做）。
