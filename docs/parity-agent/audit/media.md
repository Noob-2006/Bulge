# media 串流稽核結果

**編譯／測試**：**編譯失敗**。`seagent-media`（lib）有 16 個錯誤，lib test 有 18 個：`image_gen/mod.rs:20-35` 宣告了 15 個不存在的模組（cli、comfy、deepinfra、fal、google、krea、litellm、llama_cpp、meta_ai、microsoft_foundry、minimax、openai、openai_codex、openrouter、xai），`mod.rs:145` 引用不存在的 `video_gen::vydra`，`image_gen/common.rs:756/758` 的測試型別 `P` 缺 `Debug`。因此 workspace 測試**沒有任何一個執行**，通過 0、失敗 0。
- 原始輸出：`audit/media-tests.txt`

**狀態統計（71 列）**：✅ 0 · 🚧 9 · ⬜ 59 · N/A 3


# media 串流實作稽核（w-media，基準 5c369e5）

判定只看 `w-media` 的程式碼；`tmp-media/parked-src` 合併後的效果另列一節。
圖例：✅ 已實作、已接線、有測試　🚧 有程式碼但未接線／未測／是 stub／缺子功能　⬜ 沒有可用的程式碼（只有空骨架簽名也算 ⬜，證據欄會註明「骨架」）　N/A 附理由。

## 差異範圍

- `git diff --stat HEAD`：27 個檔案，+4613/−1。只新增 `crates/seagent-media/`（加進 workspace members 與 `[workspace.dependencies]`），另外複製兩份 inventory 文件。
- 未追蹤：`image_gen/common.rs`（802 行），以及 `tts/{azure,command,edge,elevenlabs,fish_audio,google,gradium,inworld,local,minimax,mistral,openai,volcengine,vydra,xai,xiaomi}.rs`。這些檔案在 `tts/mod.rs` 和 `image_gen/mod.rs` 都有 `pub mod` 宣告，但 TTS 各檔只有 7 行 stub（`providers() -> vec![]`），`command.rs` 也是 stub。
- **沒有接線**：`crates/seagent-tools`、`seagent-kernel`、`seagent`、`seagent-channel`、`seagent-app` 都沒有改動，也沒有任何 crate 依賴 `seagent-media`（`grep seagent-media crates/*/Cargo.toml` 為空）。所以 `seagent_media::tools()` 不會出現在模型的工具清單，也沒有 CLI、斜線指令或 inbound 路徑會呼叫它。
- **很可能編譯不過**（從原始碼判斷，請以實際 build 結果為準）：`image_gen/mod.rs` 宣告了 `pub mod comfy, deepinfra, fal, google, krea, litellm, llama_cpp, meta_ai, microsoft_foundry, minimax, openai, openai_codex, openrouter, xai, cli`，但 `image_gen/` 底下只有 `mod.rs` 和 `common.rs`。另外還引用了不存在的 `crate::video_gen::vydra::image_provider()` 和 `cli::{capabilities, cli}`。
- 有實際內容的部分：共用基礎設施 `audio.rs`、`http.rs`、`store.rs`、`config.rs`、`proc.rs`、`testutil.rs`（14 個測試）；`image_gen/mod.rs` 的工具、參數驗證與 fallback 執行邏輯；`image_gen/common.rs` 的生成共用 runtime（模型引用、候選、幾何、背景 job）；`tts/mod.rs` 的 trait 與 `tts/common.rs` 的輔助函式。其餘模組（vision、docs、understand、inbound、stt、realtime、voice、video_gen、music_gen、meeting、phone）都只有空骨架：回傳 `vec![]`、`Err("no … provider available")`，或直接原樣傳回。

## 統計

| | ✅ | 🚧 | ⬜ | N/A | 合計 |
|---|---|---|---|---|---|
| Hermes | 0 | 5 | 32 | 2 | 39 |
| OpenClaw | 0 | 4 | 27 | 1 | 32 |
| 合計 | 0 | 9 | 59 | 3 | 71 |

9 個 🚧 裡，有 4 個只是基準版本（5c369e5）原本就有的部分功能（node talk STT、Discord 語音、平台自帶轉寫、ACP 圖片），這次串流沒有新增任何東西。

w-media 現有的測試名稱：`lib::tests::tool_names_unique_and_schemas_are_objects`；`image_gen::tests::{fallback_loops_count_and_saves, parse_validates_like_upstream, tool_end_to_end_with_openai_fake, background_mode_returns_job_id}`；`image_gen::common::tests::{refs_and_candidates, geometry, jobs_complete_and_deliver}`；`tts::common::tests::sections_aliases_and_picks`；基礎設施的 `runs_with_stdin_and_times_out, templates_quote_values, json_multipart_and_errors, error_message_shapes, poll_until_done_or_timeout, dotted_lookup_and_defaults, creds_order_config_env_vault, sniff_and_ext, data_urls_roundtrip, save_never_overwrites, directives_split_reply, wav_roundtrip_and_resample, g711_roundtrip_is_close, rms_of_silence_and_tone`。只要 crate 編譯失敗，這些測試都跑不了。

## Hermes

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| vision_analyze | tools/vision_tools.py | ⬜ | `vision/mod.rs` 只有骨架：`tools()` 回傳空，`prepare()` 原樣傳回 |
| video_analyze | tools/vision_tools.py | ⬜ | `understand/mod.rs` 只有骨架：`describers()` 回傳空，`describe()` 回傳 Err |
| image_generate | tools/image_generation_tool.py | 🚧 | `image_gen/mod.rs` 的 `ImageGenerate`（parse_params、generate_with fallback、save_result、背景模式），測試 `tool_end_to_end_with_openai_fake` 等。但 14 個供應商模組與 `cli` 的檔案都不存在，編譯不過；也沒有接到任何工具註冊。parked 有完整的另一套版本 |
| video_generate | tools/video_generation_tool.py | ⬜ | `video_gen/mod.rs` 只有 8 行骨架 |
| xai_video_edit | tools/xai_video_tools.py | ⬜ | 沒有 |
| xai_video_extend | tools/xai_video_tools.py | ⬜ | 沒有 |
| text_to_speech | tools/tts_tool.py | ⬜ | `tts/mod.rs` 只有 `TtsProvider` trait 和 `tts::tools()` 回傳空；`tts/common.rs` 的輔助函式有 `sections_aliases_and_picks` 測試。parked 有供應商程式碼，但缺 tool.rs |
| 影像生成 fal | plugins/image_gen/fal | ⬜ | `image_gen/mod.rs:22` 宣告了 `pub mod fal`，但檔案不存在。parked 的 `fal.rs` 有測試 `fal_queue_end_to_end_through_the_tool`、`fal_edit_endpoint_and_upscale` |
| 影像生成 openai | plugins/image_gen/openai | ⬜ | 檔案不存在。parked 的 `openai.rs` 有 `openai_generate_and_edit`、`openai_azure_deployment_url` |
| 影像生成 openai-codex | plugins/image_gen/openai-codex | ⬜ | 檔案不存在。parked 的 `openai.rs::Codex` 有 `codex_native_and_responses_transports`、`codex_reads_auth_file` |
| 影像生成 xai | plugins/image_gen/xai | ⬜ | 檔案不存在。parked 的 `xai.rs` 有 `xai_generate_and_edit` |
| 影像生成 openrouter | plugins/image_gen/openrouter | ⬜ | 檔案不存在。parked 有 `openrouter_chat_and_image_api`、`openrouter_default_chain_falls_back` |
| 影像生成 deepinfra | plugins/image_gen/deepinfra | ⬜ | 檔案不存在。parked 的 `compat.rs::DeepInfra` 有 `deepinfra_litellm_meta` |
| 影像生成 krea | plugins/image_gen/krea | ⬜ | 檔案不存在。parked 有 `krea_job_poll_and_enhance` |
| 影像生成 meta-ai | plugins/image_gen/meta-ai | ⬜ | 檔案不存在。parked 的 `compat.rs::MetaAi` 有 `deepinfra_litellm_meta` |
| 影像生成 managed（Nous） | tools/image_generation_managed.py | N/A | Nous 自家訂閱閘道 |
| 影片生成 fal/xai/openrouter/deepinfra | plugins/video_gen/* | ⬜ | 沒有任何供應商 |
| TTS edge | tools/tts_tool_providers.py | ⬜ | `tts/edge.rs` 是 7 行 stub。parked 的 `edge.rs` 有真實的 WebSocket 實作，測試 `websocket_session` |
| TTS elevenlabs | tools/tts_tool_providers.py | ⬜ | stub。parked 的 `cloud.rs::ElevenLabs` 有 `elevenlabs_request_shape_and_voices` |
| TTS openai / deepinfra | tools/tts_tool_openai.py | ⬜ | stub。parked 的 `cloud.rs::OpenAi`（含 deepinfra、openrouter）有 `openai_request_shape`、`openrouter_extra_provider_field` |
| TTS xai / xai-oauth | tools/tts_tool_providers.py | ⬜ | stub。parked 的 `cloud.rs::Xai` 有 `xai_payload_only_sends_non_defaults`、`xai_oauth_uses_bearer_token` |
| TTS minimax / mistral / gemini | tools/tts_tool_providers.py | ⬜ | stub。parked 的 `cloud.rs` 有 MiniMax、Mistral、Gemini，測試 `gemini_generate_content_and_interactions` |
| TTS 本機 NeuTTS / Piper / KittenTTS | tools/tts_tool_local.py | ⬜ | `tts/local.rs` 是 stub。parked 的 `local.rs` 有兩個測試（行 216、232）；無 LRU 模型快取／warm-release（未確認） |
| TTS command / plugin provider | tools/tts_command_provider.py | ⬜ | `tts/command.rs` 是 stub，`resolve()` 回傳 None。parked 的 `command.rs` 有 `hermes_command_provider_runs_without_secrets`、`local_cli_file_and_stdout_modes`，`mod.rs::register` 可在執行期註冊 |
| TTS 串流＋Markdown 口語化 | tools/tts_streaming.py, tts_text_normalize.py | ⬜ | w-media 沒有。parked 有 `normalize.rs`（901 行）；`stream.rs` 有宣告但檔案不存在 |
| STT local faster-whisper | tools/transcription_local.py | ⬜ | `stt/mod.rs` 只有骨架，`providers()` 回傳空 |
| STT whisper.cpp（managed） | tools/transcription_whisper_cpp.py | ⬜ | 沒有 |
| STT 雲端 groq/openai/deepinfra/mistral/xai/elevenlabs＋切段 | tools/transcription_cloud.py | 🚧 | 只有基準版本的 node `talk.ptt` 會呼叫 OpenAI 相容 `/audio/transcriptions`（seagent-app/node/talk.rs）；`stt/mod.rs` 只有 trait 骨架，沒有任何供應商，也沒有切段 |
| STT command / plugin / streaming | tools/transcription_command.py, transcription_streaming.py | ⬜ | `realtime/mod.rs` 只有 `RealtimeStt` trait，`open_stt` 回傳 Err |
| /voice | hermes_cli/commands.py | ⬜ | 沒有斜線指令。parked 的 `tts/mod.rs` 會 re-export `commands::voice_command`，但 commands.rs 不存在 |
| /image | hermes_cli/commands.py | 🚧 | 基準版本：圖片可以經 ACP、OpenAI API、channel 附件進來；`seagent chat` CLI 沒有這個指令，w-media 也沒有變動 |
| 圖片淘汰／視覺歷史預算 | agent/image_eviction_policy.py | ⬜ | 沒有 |
| CLI 語音模式（PTT＋播放） | tools/voice_mode.py | ⬜ | `voice/mod.rs` 只有骨架；基準版本只有 node talk.ptt 能錄音和轉錄 |
| 喚醒詞 | tools/wake_word.py | ⬜ | 沒有 |
| GPT-Live 全雙工 | tools/voice_live.py | ⬜ | `realtime::RealtimeVoice` 只有 trait，`open_voice` 回傳 Err |
| 語音逐字稿過濾 | tools/voice_mode_transcript.py | ⬜ | `voice/transcript.rs` 是 stub：`filter` 只做 trim，`is_echo` 只比對相等；沒有幻覺清單和停止詞，也沒有測試 |
| gateway 語音訊息自動轉錄 | tools/transcription_tools.py | 🚧 | 只有基準版本的平台自帶轉寫（qqbot、discord_voice）；`inbound::understand()` 是骨架，也沒接到 `ext.rs` |
| gateway 自動 TTS 回覆 | tools/tts_tool.py | 🚧 | 只有基準版本的 Discord 語音頻道朗讀；通用 auto TTS 沒有。parked 的 `auto_reply` 依賴缺少的 commands.rs |
| 桌面語音設定／STT lease | tools/voice_client_config.py | N/A | Hermes 桌面 GUI |

## OpenClaw

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| read（圖片／PDF 給模型） | src/agents/agent-tools.read.ts | 🚧 | 基準版本 `seagent-tools/fs.rs` 只回傳文字，這次沒有改動；`docs::extract` 是骨架，`supported()` 回傳 false |
| view_image | src/agents/tools/image-tool.ts | ⬜ | `vision/mod.rs` 只有骨架 |
| image_generate | src/agents/tools/image-generate-tool.ts | 🚧 | 同 Hermes image_generate：工具邏輯有測試，但缺供應商檔案、編譯不過、未接線 |
| video_generate | src/agents/tools/video-generate-tool.ts | ⬜ | 骨架（`image_gen/common.rs` 的背景 job runtime 註明可給 video 使用，但沒有工具） |
| music_generate | src/agents/tools/music-generate-tool.ts | ⬜ | `music_gen/mod.rs` 只有骨架 |
| transcripts | src/agents/tools/transcripts-tool*.ts | ⬜ | 沒有 |
| tts | src/agents/tools/tts-tool.ts | ⬜ | `tts::tools()` 回傳空 |
| pdf | src/agents/tools/pdf-tool.ts | ⬜ | `docs/mod.rs` 只有骨架 |
| voice_call（Twilio/Telnyx/Plivo） | extensions/voice-call | ⬜ | `phone/mod.rs` 只有 8 行骨架 |
| google_meet | extensions/google-meet | ⬜ | `meeting/mod.rs` 只有 8 行骨架 |
| teams/zoom/slack-huddles | extensions/teams-meetings 等 | ⬜ | 同上 |
| facetime_call | extensions/facetime | N/A | 綁 macOS FaceTime |
| talk_voice | extensions/talk-voice | ⬜ | w-media 沒有。parked 的 `tts/mod.rs` 引用 `tool::TalkVoice`，但 tool.rs 不存在 |
| local_image（llama.cpp） | extensions/llama-cpp | ⬜ | `image_gen/mod.rs` 宣告了 `llama_cpp`，但檔案不存在；parked 也沒有 |
| document-extract | extensions/document-extract | ⬜ | `docs/mod.rs` 只有骨架（已加入 miniz_oxide 依賴，但沒有使用） |
| 影像生成供應商（openai, google, fal, comfy, deepinfra, litellm, microsoft-foundry, minimax, openrouter, vydra, xai） | src/image-generation, extensions/* | ⬜ | w-media 的供應商檔案一個都沒有，`providers()` 引用的模組全部不存在。parked 11 家都有 |
| 影片生成供應商（17 家） | src/video-generation | ⬜ | 一家都沒有 |
| 音樂生成供應商（comfy, fal, google, minimax, openrouter） | src/music-generation | ⬜ | 一家都沒有 |
| TTS 供應商（16 家） | src/tts, extensions/* | ⬜ | w-media 的 15 個檔案全是 stub。parked 16 家都有（openai, elevenlabs, azure-speech, microsoft/edge, google, minimax, inworld, fish-audio, gradium, volcengine, xiaomi, deepinfra, openrouter, vydra, xai, tts-local-cli） |
| media understanding（audio/image/video，18 家） | src/media-understanding | 🚧 | 只有基準版本的 node talk OpenAI 相容 STT；`understand::describers()` 回傳空，一家影像／影片描述供應商都沒有 |
| realtime transcription（openai, deepgram, elevenlabs, mistral, xai） | src/realtime-transcription | ⬜ | 只有 trait |
| realtime voice（openai, google, xai） | extensions/* realtimeVoiceProviders | ⬜ | 只有 trait |
| document extractors | extensions/document-extract | ⬜ | 骨架 |
| transcript source providers | discord, google-meet, … | ⬜ | 沒有 |
| /tts | commands-registry | ⬜ | 沒有。parked 會 re-export `tts_command`，但 commands.rs 不存在 |
| /voice | extensions/talk-voice | ⬜ | 同上 |
| infer / capability CLI | src/cli/capability-cli | ⬜ | `image_gen/mod.rs` 宣告了 `pub mod cli; pub use cli::{capabilities, cli}`，但檔案不存在；`crates/seagent/src/main.rs` 也沒有改動 |
| media understanding pipeline | src/media-understanding | ⬜ | `inbound::understand()` 是骨架，只設定 `was_voice`；附件仍然只存到 `.seagent/inbox`（基準 ext.rs） |
| TTS auto-reply（語音訊息） | src/tts | ⬜ | 沒有 |
| Talk mode | src/talk | 🚧 | 只有基準版本的 node push-to-talk STT；`voice/`、`realtime/` 是骨架 |
| meeting bot | src/meeting-bot | ⬜ | 骨架 |
| 圖片淨化／壓縮 | src/agents/image-sanitization.ts | ⬜ | `vision::prepare()` 原樣傳回；`image` crate 只被 image_gen 使用 |

## parked-src 合併後可補

**image_gen（parked，14 個檔案、約 3,600 行）**
- 這是自成一套的完整實作：`mod.rs`（875 行，`ImageGenerate` 工具支援 generate、edit、list、status，有 fallback 鏈、幾何淨化，超大輸出會重新編碼）。供應商有 14 家：fal、openai（含 Azure）、openai-codex、google（Gemini＋Imagen）、xai、openrouter、krea、deepinfra、litellm、meta-ai、minimax、microsoft-foundry、vydra、comfy（本機與雲端 workflow）。全部是對各家文件 API 的真實 HTTP 呼叫，也都有 FakeServer 測試（`tests.rs` 457 行，加上各檔的單元測試，大約 30 個）。
- 合併後的變化：Hermes 影像生成 8 個供應商列、OpenClaw 影像生成供應商列（11 家全數）、兩個 image_generate 列，都會從 ⬜/🚧 變成「程式碼＋測試齊全」。但仍然是 🚧，因為還沒接到工具註冊。OpenClaw 的 local_image（llama.cpp）parked 也沒有。
- **衝突**：parked 和 w-media 的 `image_gen/mod.rs` 是兩套不相容的設計（`ImageProvider` trait 的形狀不同，w-media 是 `ProviderInfo` + `Arc`，parked 是 `Box`）。兩邊的 `common.rs` 同名但內容完全不同：w-media 是 802 行的通用生成 runtime，含背景 job，供 video/music 共用；parked 是 109 行的 OpenAI 相容 plumbing。建議整個 `image_gen/` 換成 parked 版，w-media 的 `common.rs` 改名保留給 video/music 用。換掉之後，w-media mod.rs 裡不存在的模組引用就消失了，編譯錯誤也跟著解除。parked 依賴的 `http::{excerpt, host_of, Multipart, poll, Resp}`、`store::{class_of, sniff, stem, b64}`、`audio::*`、`testutil::{FakeServer, ws_server, temp_dir, cfg_for}`、`seagent_core::tool::{arg_opt_str, arg_opt_u64}`，在 w-media 裡都有。CLI（`capabilities`/`cli`）parked 沒有。

**tts（parked，7 個檔案、約 3,750 行）**
- 有真實的供應商程式碼與測試：`edge.rs`（WebSocket、Sec-MS-GEC 權杖）；`cloud.rs`（openai、deepinfra、openrouter、elevenlabs、xai、xai-oauth、minimax、gemini、mistral）；`misc.rs`（azure-speech、inworld、fish-audio、gradium、volcengine、xiaomi、vydra）；`local.rs`（neutts、piper、kittentts）；`command.rs`（使用者 command provider 與 tts-local-cli）；`normalize.rs`（Markdown 轉口語、SentenceChunker）；`mod.rs`（依供應商上限切段、fallback 鏈、`register` 外掛供應商）。測試約 25 個，例如 `websocket_session`、`openai_request_shape`、`elevenlabs_request_shape_and_voices`、`gemini_generate_content_and_interactions`、`azure_ssml_request`、`volcengine_seed_frames_and_legacy`、`chain_falls_back_and_records_attempts`、`split_never_drops_text`。
- **不完整，不能直接合併**：`mod.rs` 宣告了 `mod commands; mod prefs; pub mod stream; mod tool;`，但這 4 個檔案不在 parked-src 裡。也就是說，`text_to_speech`/`talk_voice` 工具、`/tts`/`/voice` 指令、偏好檔、auto_reply、串流播放的實作都遺失了，需要重寫。
- **衝突**：w-media 的 `tts/` 是另一種配置（每家一檔的 15 個 stub 加 `common.rs`），parked 是 cloud/misc 分組。合併時要刪掉 w-media 的 stub 和 common.rs，整個 `tts/` 換成 parked 版，再補上那 4 個缺的檔案。
- 補齊後可以改善的列：Hermes 的 TTS 8 列與 text_to_speech；OpenClaw 的 TTS 供應商、tts、talk_voice、/tts、/voice、TTS auto-reply。但這些都還要 inbound 和 channel 接線才能使用。

**合併後仍然完全沒有的**：vision、view_image、video_analyze、文件抽取與 pdf、所有 STT（本機、雲端、切段）、realtime STT／voice、inbound 媒體理解、影片與音樂生成、會議 bot、電話、語音模式、喚醒詞、圖片淨化與淘汰、capability CLI，以及最根本的：`seagent-media` 根本沒有被任何 crate 依賴或註冊。

## 剩餘缺口（依使用者影響排序）

1. 🚧 接線：沒有任何 crate 依賴 `seagent-media`；`seagent_media::tools()` 沒有註冊進工具清單（seagent-tools/lib.rs 或 kernel），`[media]` 設定也沒有接進主設定。
2. ⬜ 編譯錯誤：`image_gen/mod.rs` 引用了 15 個不存在的模組和 `video_gen::vydra`，整個 crate（以及 workspace 的 build）會失敗。
3. ⬜ inbound 媒體理解（OpenClaw media understanding pipeline／Hermes gateway 語音自動轉錄）：`inbound::understand()` 是骨架，channel 附件不會被轉錄、描述或抽取。
4. ⬜ STT：沒有 faster-whisper、whisper.cpp、groq/openai/deepinfra/mistral/xai/elevenlabs 雲端供應商，沒有切段，也沒有 command/plugin/streaming。
5. ⬜ vision_analyze / view_image：沒有載圖給模型的工具，也沒有非視覺模型的描述 fallback。
6. 🚧 read 工具回傳圖片／PDF ＋ ⬜ pdf 工具＋ ⬜ document-extract／extractors：`docs::extract` 是骨架（PDF、DOCX、XLSX、PPTX、ipynb 都沒有）。
7. ⬜ text_to_speech / tts 工具與 16+ 家 TTS 供應商：w-media 全是 stub。parked 有供應商，但缺 tool.rs、commands.rs、prefs.rs、stream.rs。
8. 🚧/⬜ gateway 自動 TTS 回覆／OpenClaw TTS auto-reply（語音訊息泡泡）：沒有。
9. 🚧 image_generate 與影像供應商：w-media 缺所有供應商檔案。parked 的 14 家可以直接用，但要解決 mod.rs、common.rs 的衝突，llama.cpp local_image 也還沒有。
10. 🚧 media understanding 供應商（18 家影像、影片、音訊描述）：`describers()` 回傳空。
11. ⬜ video_analyze：沒有。
12. ⬜ video_generate＋Hermes 4 家／OpenClaw 17 家影片供應商、xai_video_edit、xai_video_extend：沒有。
13. 🚧 Talk mode／⬜ CLI 語音模式／⬜ GPT-Live／⬜ realtime voice（openai/google/xai）：只有 trait，基準版本只有 node PTT。
14. ⬜ realtime transcription（openai/deepgram/elevenlabs/mistral/xai）：只有 trait。
15. ⬜ /tts、/voice（兩邊）、talk_voice：沒有指令或工具。
16. ⬜ TTS 串流與 Markdown 口語化：w-media 沒有。parked 有 normalize.rs，但缺 stream.rs。
17. 🚧 /image：CLI 不能附圖片。
18. ⬜ 圖片淨化／壓縮（送進模型前）：`vision::prepare` 原樣傳回。
19. ⬜ 圖片淘汰／視覺歷史預算：沒有。
20. ⬜ music_generate＋5 家音樂供應商：沒有。
21. ⬜ infer/capability CLI：`image_gen::cli` 檔案不存在。
22. ⬜ 語音逐字稿過濾：stub，沒有幻覺清單、停止詞，也沒有測試。
23. ⬜ 喚醒詞（openWakeWord/sherpa-onnx/Porcupine）：沒有。
24. ⬜ transcripts 工具與 transcript source providers：沒有。
25. ⬜ meeting bot、google_meet、teams/zoom/slack-huddles：骨架。
26. ⬜ voice_call（Twilio/Telnyx/Plivo）：骨架。
27. ⬜ local_image（llama.cpp）：w-media 只有模組宣告，parked 也沒有。
28. ⬜ TTS 本機 NeuTTS/Piper/KittenTTS、command/plugin（w-media）：只在 parked 有。
