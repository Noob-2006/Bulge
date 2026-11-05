# 模型供應商與媒體供應商對照（E4／E5）

ark：`crates/ark-model/src/{anthropic,accounts,auth,bedrock,google,copilot,openai…}.rs`、`crates/ark-media/src/{stt,tts,image_gen,video_gen,music_gen}/*`。
上游：OpenClaw `extensions/{anthropic,openai,amazon-bedrock,anthropic-vertex,copilot,github-copilot}/`、Hermes `providers/`；opencode `packages/ai`、`packages/plugin`（provider/auth 層）。

**本輪沒有真的打過任何付費 API**（沒有金鑰，也禁止）。下表是官方規格 + 上游原始碼 + ark 原始碼的對照；E5 的本機部分（whisper.cpp STT、Piper TTS）有真實測試。

## E4 模型供應商

| 面向 | 官方規格 | OpenClaw | Hermes | opencode | ark |
|---|---|---|---|---|---|
| Anthropic 直連 | `POST /v1/messages`；`x-api-key`、`anthropic-version: 2023-06-01`、選用 `anthropic-beta`；SSE 事件 `message_start`/`content_block_start`/`content_block_delta`/`message_delta`/`message_stop`/`ping`/`error` | `extensions/anthropic` | `providers/` | `packages/ai` | 自寫（`anthropic.rs`）；`anthropic-beta` 以逗號合併既有值再加（`anthropic.rs:209-215`），OAuth 走 `anthropic-beta: oauth-2025-04-20` 且移除 `x-api-key`（`anthropic.rs:194`、`accounts.rs:82`） |
| Anthropic 訂閱（OAuth） | Claude Code 式 OAuth（PKCE），token 需 `anthropic-beta` 旗標 | 有 | — | 有（`opencode auth login`） | 有（`accounts.rs`，token 存在 ark 的 keyring 抽象裡） |
| OpenAI 相容 | `POST /v1/chat/completions`；SSE `data: {…}` 與 `data: [DONE]` | `extensions/openai` | 有 | 有 | 有（`openai.rs`），並用同一條路接 OpenRouter/DeepSeek/Mistral 等相容端點 |
| Bedrock | SigV4 簽章、`InvokeModel`/`Converse`（`bedrock-runtime.<region>.amazonaws.com`） | `extensions/amazon-bedrock` | 有 | 有 | 有（`bedrock.rs`，自寫 SigV4） |
| Vertex AI | service-account JWT → OAuth2 token，`generateContent` | `extensions/anthropic-vertex` | 有 | 有 | 有（`google.rs`） |
| GitHub Copilot | GitHub OAuth token → `copilot_internal` token，`api.githubcopilot.com` | `extensions/{copilot,github-copilot,copilot-proxy}` | 有 | 有 | 有（`copilot.rs`） |
| 串流取消 | 關閉連線即取消 | 有 | 有 | 有 | `Cancel` 貫穿 `ark_net` stream（遇到取消就關連線） |
| 速率限制／重試 | 429 + `retry-after`（Anthropic 另有 `anthropic-ratelimit-*` 標頭） | 有 | 有 | 有 | 依狀態碼分類重試（`ark-model` 的 provider error kind） |

## E5 媒體供應商

| 面向 | 官方規格 | OpenClaw | Hermes | opencode | ark |
|---|---|---|---|---|---|
| 本機 STT（whisper.cpp） | 無官方 API；whisper.cpp CLI（`-m -f -otxt -of`；VAD 參數依版本而異） | — | `tools/transcription_whisper_cpp.py` | — | **實測**：ark 管理下載＋SHA-256 驗證模型（`ggml-base.bin`、silero VAD），再跑 `whisper-cli`。本輪發現 1.7.4 沒有 `--vad`，已改成先問 `--help`（`stt/local.rs`） |
| 本機 STT（faster-whisper） | Python 套件 | — | `transcription_local.py` | — | 有（子程序跑 Python，VAD／`condition_on_previous_text=false`／信心門檻同 Hermes） |
| 本機 TTS（piper） | piper1-gpl v1.8.0：只發 wheel／sdist（**沒有** `piper_linux_x86_64.tar.gz`，那是舊 rhasspy/piper 2023.11 的產物），CLI 是 `python -m piper`（`-m/--model`、`-f/--output_file`、`--speaker`、`--length-scale`、`--noise-scale`、`--noise-w-scale`、`--volume`、`--cuda`），模型需 `<voice>.onnx` ＋ `<voice>.onnx.json` 並排 | — | 有（`type: command`） | — | **實測**：venv 裝 `piper-tts==1.8.0` ＋ `en_US-lessac-medium`，走 `[media.tts.piper] command/voice/speaker_id/length_scale`，輸出 22050 Hz／單聲道／16-bit、2.64 s、RMS 4487 的真 WAV。本輪修掉 4 個問題（見下） |
| 本機 TTS（neutts／kittentts） | Python 套件（`neutts`＋`espeak-ng`、`kittentts`＋`soundfile`） | — | 有 | — | 有（子程序跑 Python），**仍只有假引擎測試**，本輪未安裝 |
| 本機 TTS（任意指令） | — | — | 有（`type: command`） | — | 有 `[media.tts.providers.<name>] command`（`{input_path}` 等佔位符） |
| OpenAI 轉錄 | `POST /v1/audio/transcriptions`（multipart：`file`、`model`、`language`、`prompt`） | 有 | 有 | — | 有（`stt/cloud.rs`） |
| OpenAI TTS | `POST /v1/audio/speech`（`model`、`voice`、`input`、`response_format`） | 有 | 有 | — | 有（`tts/cloud.rs`） |
| ElevenLabs TTS | `POST /v1/text-to-speech/{voice_id}`，`xi-api-key` | 有 | 有 | — | 有 |
| 圖片生成 | OpenAI `POST /v1/images/generations`；fal／Replicate 為 job + poll | 有 | 有 | — | 有（`image_gen`），含 job 輪詢（`status_url`/`response_url`） |
| 影片／音樂生成 | 各家不同（fal queue、Replicate predictions、Sun/o 等） | 部分 | 部分 | — | 有（`video_gen`、`music_gen`），以 provider 介面抽象 |

## 本機 TTS 實測（Piper 1.8.0）

引擎：**piper1-gpl v1.8.0**（`piper-tts` wheel，onnxruntime 1.31.1）＋ 聲音 **`en_US-lessac-medium`**（`rhasspy/piper-voices`，22 050 Hz、單一 speaker）。裝在 `$TMPDIR`（venv，不需 root、不碰 `$HOME`），指令就是 `python -m piper`。

```sh
export TMPDIR=/scratch/ark-tts            # 安裝位置，全部寫在這裡
eval "$(tests/real/tts_up.sh)"            # 首次約 150 MB 下載、40–110 秒（暖 uv 快取 14 秒）；再跑 1.3 秒（idempotent）
cargo test -p ark-media --test real_tts   # 7 個測試，真的跑 Piper
```

`tests/real/tts_up.sh` 會建 venv、`uv pip install piper-tts==1.8.0`、用 piper 自己的下載器抓 `en_US-lessac-medium.onnx`（63 201 294 B）＋ `.onnx.json`（4 885 B），跑 `piper --help` 與一次短句合成確認可用，最後印出 `ARK_REAL_PIPER`／`ARK_REAL_PIPER_VOICE`。沒設這兩個變數時 `real_tts.rs` 直接跳過（0.00 s）。

走的是 ark 真正的路徑：`[media.tts.piper] command/voice/speaker_id/length_scale` → `tts::synthesize()`（`text_to_speech` 工具的入口）→ 子程序 → WAV bytes。實測結果：

| 項目 | 實測值 |
|---|---|
| WAV 標頭 | `RIFF`/`WAVE`、PCM、1 聲道、16-bit，`RIFF` 長度欄位與檔案大小一致 |
| 取樣率 | 22 050 Hz（與 `<voice>.onnx.json` 的 `audio.sample_rate` 相符） |
| 時長 | `"The quick brown fox jumps over the lazy dog."`（44 字）→ 2.64 s（≈0.06 s/字）；同句重複 3 次 → 約 3.0 倍音訊（測試容差 2.4–3.6） |
| 音量 | RMS 4 487、peak 32 767（piper 預設 `normalize_audio`）→ 非靜音 |
| `length_scale` | 1.0 → 2.0 得 1.65–1.81 倍時長（**非**剛好 2 倍：每音素最短時長＋隨機時長預測器），1.5–2.3 內視為通過 |
| `speaker_id` | `--speaker 0` 確實進到 argv；單 speaker 聲音接受此參數 |
| 錯誤路徑 | 缺 binary／缺 `.onnx`／缺 `.onnx.json` 都會回傳含路徑的錯誤，不 panic、不留半個 WAV |

本輪在 `crates/ark-media/src/tts/local.rs` 找到並修掉 4 個問題：

1. **語音名稱下載用錯直譯器**：venv 裝的 `piper` 旁邊就有能 `import piper` 的 `python3`，ark 卻固定用系統 `python3`（本機 3.14 沒有 `piper`）→ 一律失敗。改成 `[media.tts.piper] python` 未設時，先找 `command` 同目錄的 `python3`／`python`。
2. **失敗訊息沒有安裝指引**：`ModuleNotFoundError: No module named 'piper'` 直接外洩。現在會說「piper-tts 沒裝在 `<python>`，請 `pip install piper-tts`／`uv tool install piper-tts`，或改指到 .onnx」，並附上完整下載指令。
3. **模型路徑被當成語音名稱去下載**：`voice = "/x/missing.onnx"` 會去下載一個叫 `/x/missing.onnx` 的語音，錯誤文不對題。現在路徑（含 `/` 或 `.onnx`）不存在就直接 `Piper voice model not found: <path>`；`.onnx` 存在但少了 `.onnx.json` 會先講 `Piper voice config not found: <path>.json`（原本是 Python traceback 尾巴）。
4. **暫存目錄洩漏**：`synthesize()` 一開始就建 `$TMPDIR/ark-tts-local-*`，但 `piper_model(...)?` 等提早返回會跳過 `remove_dir_all`，實測錯誤路徑留下 9 個空目錄。改成 `TempDir`（`Drop`）守衛，提早返回也會清掉。

Piper 1.8 的錯誤輸出是 Python traceback，ark 現在只取最後一行（真正的例外）＋離開碼，不再把整段堆疊塞進錯誤訊息。仍缺：`neutts`、`kittentts` 只有假引擎單元測試（`python_engines_report_failures`），本輪沒有安裝真的套件。

## 本輪結論

- **E4 完全沒有實測**：沒有金鑰，也沒有做假伺服器（假伺服器只能驗 ark 自己的假設，價值低於對照官方規格）。
- **E5 本機部分是真的**：本機 whisper.cpp（`crates/ark-channel/tests/real_media.rs`：真 binary、真模型、真音檔、真轉錄結果）與本機 Piper TTS（`crates/ark-media/tests/real_tts.rs`：真 binary、真聲音、真 WAV，7 個測試）。雲端圖片／影片／音樂／TTS／STT 全部只有程式碼與官方文件對照。
- 兩者共同的缺口：**帳單／用量 API**（OpenAI `/v1/organization/costs`、Anthropic usage）ark 沒有對照，屬於 UI／維運層，不在本輪範圍。
