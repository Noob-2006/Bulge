# Hermes → SE Agent 代理層功能盤點（2026-11-03）

範圍：Hermes（`$SEAGENT_UPSTREAM_HERMES`）所有「代理層」功能，對照 SE Agent。**不含** channel 平台、MCP、ACP、A2A、node 協議本身（已在 `seagent/docs/parity.md`）。
來源：`tools/registry.py` 註冊點（AST 掃描每個 `registry.register` / `ctx.register_tool` 的 schema）、`toolsets.py`、`hermes_cli/commands.py`（104 個 `CommandDef`）、`hermes_cli/subcommands/*.py` 與 `main.py::_BUILTIN_SUBCOMMANDS`、`plugins/*`、`agent/*`、`cron/*`。

SE Agent 路徑簡寫：`seagent-tools/x.rs` = `crates/seagent-tools/src/x.rs`，`seagent-kernel/`、`seagent-app/`、`seagent-model/`、`seagent-plugin/`、`seagent/`（= `crates/seagent/src`）同理。
狀態：✅ 已有　🚧 部分（註明缺什麼）　⬜ 缺　N/A 僅綁 Hermes 桌面 GUI／Python 專屬基礎設施／Nous 自家帳務（附理由）。

SE Agent 現有模型可呼叫工具（實測 `impl Tool for` 全列）：`read write edit patch glob grep shell web_fetch memory spawn ask_user todo skill job`（seagent-tools/lib.rs）、kernel 的 `run`(code mode)、`session_search`、`goal_done`、`tool_describe`/`tool_call`（seagent-kernel/kernel.rs:204、context.rs:153）、`channel_send`（seagent-channel/tool.rs）、外掛記憶 `memory`（seagent-plugin/plugin.rs:575）、`node_invoke`、`acp_delegate`、`a2a_*`、`seagent_session*`（mcp serve 專用，seagent-app/conversations.rs）。

---

## 1. 核心模型工具（`_HERMES_CORE_TOOLS` + 其他 toolset）

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| web_search | tools/web_tools.py | query,limit；經可插拔後端搜尋網頁，結果快取 20 分鐘，失敗走免金鑰 rescue | ⬜ | 無搜尋工具；只有 `web_fetch`（seagent-tools/web.rs） |
| web_extract | tools/web_tools.py, web_tools_extract.py, web_tools_truncate.py | urls[]、char_limit；多網址轉 markdown，支援 PDF，超長頁 head+tail 並存檔 | 🚧 | `web_fetch` 單一 URL、HTML→純文字、GET/POST（seagent-tools/web.rs）；無批次、PDF、後端、截斷存檔 |
| terminal | tools/terminal_tool.py (+_guards/_result/_sudo/_background) | command,background,timeout,workdir,pty,notify,heartbeat；多後端、sudo 密碼管線、失敗提示、ANSI 去除、遮蔽 | 🚧 | `shell`（seagent-tools/shell.rs）command/timeout_secs≤3600/cwd，本機 bash，輸出截斷、行程群組終止；無 pty、無遠端後端、無 sudo 管線、無 ANSI 去除、無失敗提示 |
| process_manage | tools/process_registry.py | list/poll/log/wait/kill/write/submit/close/handoff 背景行程，200KB 滾動緩衝，完成通知 | 🚧 | `job` start/output/wait/kill/list（seagent-tools/job.rs）；無 stdin write/submit、完成通知、handoff、跨重啟保存 |
| read_file | tools/file_tools.py, read_extract.py | path,offset,limit；行號分頁、相似檔名建議、DOCX/XLSX/ipynb/PDF/RTF 抽文字、讀取追蹤 | 🚧 | `read` 行號＋目錄列表（seagent-tools/fs.rs）；無文件抽取、無相似名建議、無讀取追蹤 |
| write_file | tools/file_tools.py, file_tools_write_guards.py, file_operations_lint.py | 覆寫檔案、建父目錄；寫入守衛（敏感路徑、過期讀取）、寫後 lint/LSP 診斷 | 🚧 | `write`（fs.rs）；僅系統路徑走 privilege gate（seagent-kernel/gate.rs:69）；無 lint/LSP、無過期讀取守衛 |
| patch | tools/file_tools.py, fuzzy_match.py, patch_parser.py, escape_drift_autocorrect.py | 找取代＋9 種模糊比對策略、V4A 多檔 patch 格式、跳脫字元漂移修正 | 🚧 | `edit` 精確比對＋`patch` 多檔原子編輯（fs.rs:217/373）；無模糊比對、無 V4A 格式 |
| search_files | tools/file_tools.py, file_operations_search.py | ripgrep 內容/檔名搜尋，glob、output_mode、context、order、offset 分頁 | 🚧 | `grep`＋`glob`（seagent-tools/search.rs）；缺 context 行、offset 分頁、count/files 輸出模式 |
| vision_analyze | tools/vision_tools.py, vision_tools_image_prep.py | 載入圖片（URL/檔案/data:）進對話，可裁切 region；非視覺模型走輔助 LLM 描述 | ⬜ | seagent-core 有 `Block::Image`（types.rs:31）只供使用者訊息；無模型可呼叫的載圖工具 |
| video_analyze | tools/vision_tools.py | 影片送 Gemini 等影片模型回答問題 | ⬜ | — |
| image_generate | tools/image_generation_tool.py | prompt,aspect_ratio；依設定的影像生成供應商產圖 | ⬜ | — |
| video_generate | tools/video_generation_tool.py | prompt,duration,aspect_ratio,resolution；派給外掛影片供應商 | ⬜ | — |
| xai_video_edit | tools/xai_video_tools.py | xAI Imagine 編輯影片 | ⬜ | — |
| xai_video_extend | tools/xai_video_tools.py | xAI Imagine 延長影片 | ⬜ | — |
| x_search | tools/x_search_tool.py | 經 xAI Responses `x_search` 搜 X 貼文/帳號，handle/日期/圖影理解篩選 | ⬜ | — |
| text_to_speech | tools/tts_tool.py | 文字轉語音回傳 MEDIA 路徑，Telegram 顯示語音泡泡 | ⬜ | — |
| skills_list | tools/skills_tool.py | 依分類列出技能 | 🚧 | 技能索引直接注入系統提示（seagent-kernel/context.rs:73）；無列表工具、無分類 |
| skill_view | tools/skills_tool.py, skills_tool_dedup.py, skills_tool_setup.py | 載入 SKILL.md 或附檔、外掛技能 `plugin:skill`、重複檢視去重、必要環境變數設定 | 🚧 | `skill action=view`（seagent-tools/plan.rs:183）列出附檔；無 plugin 技能、去重、env 變數 setup |
| skill_manage | tools/skill_manager_tool.py, skill_manager_batch.py, skill_manager_guards.py | 批次建立/編輯/patch/刪除技能，守衛、linter、ledger 回滾、寫入核准 | 🚧 | `skill create/update/archive`（plan.rs）；無 patch、批次、guard、lint、ledger、核准閘 |
| browser_navigate | tools/browser_tool.py | 開網址並建立瀏覽器 session | 🚧 | 只有 node_invoke `computer.act browser_navigate`，需使用者自開 `--remote-debugging-port` Chrome（seagent-app/node/cdp.rs:148） |
| browser_snapshot | tools/browser_tool.py, browser_tool_snapshot.py | 無障礙樹快照＋`@eN` 參照，超大樹截斷存檔、秘密遮蔽 | 🚧 | node cdp `get_browser_state`（cdp.rs:138）列互動元素；需 node |
| browser_click | tools/browser_tool.py | 依 ref 點擊 | 🚧 | node cdp `browser_click`（cdp.rs:156） |
| browser_type | tools/browser_tool.py | 依 ref 清空並輸入 | 🚧 | node cdp `browser_type`（cdp.rs:167） |
| browser_scroll | tools/browser_tool.py | 頁面捲動 | ⬜ | cdp 後端不支援（cdp.rs:174 其餘動作回錯） |
| browser_back | tools/browser_tool.py | 上一頁 | ⬜ | — |
| browser_press | tools/browser_tool.py | 按鍵（Enter/Tab/快捷鍵） | 🚧 | 僅 node `computer.act` 桌面層 xdotool/ydotool 按鍵（seagent-app/node.rs:919），非瀏覽器內 |
| browser_get_images | tools/browser_tool.py | 列頁面圖片 URL/alt | ⬜ | — |
| browser_vision | tools/browser_tool.py, browser_tool_vision.py | 截圖並視覺分析（含 annotate 標註） | 🚧 | node `screen.snapshot` 截桌面（node.rs:718 附近）；無瀏覽器頁截圖＋分析 |
| browser_console | tools/browser_tool.py, browser_tool_eval_policy.py | 讀 console/JS 錯誤、執行 expression（SSRF 與敏感 API 政策） | ⬜ | — |
| browser_cdp | tools/browser_cdp_tool.py | 任意 CDP method 直通 | ⬜ | — |
| browser_dialog | tools/browser_dialog_tool.py | 接受/關閉原生 JS 對話框（CDP supervisor 擷取） | ⬜ | — |
| browser_vault | tools/browser_vault_tool.py, agent/vault_store.py | 模型看不到秘密的瀏覽器自動填入（登入、卡片、2FA、解鎖） | ⬜ | SE Agent vault 只做工具參數 `{{secret:NAME}}` 代入（seagent-kernel/vault.rs），非網頁填表 |
| browser_exec | tools/browser_use_cli.py | browser.backend=browser-use 時以 Browser Use CLI 3.0 執行程式碼 | ⬜ | — |
| todo_list | tools/todo_tool.py | todos,merge；版本化任務清單，壓縮後重新注入 | ✅ | `todo set/list`（seagent-tools/plan.rs:68） |
| memory | tools/memory_tool.py, memory_tool_store.py | MEMORY.md/USER.md add/patch/remove＋批次 operations，字元預算、注入威脅掃描、凍結快照 | 🚧 | `memory read/add/replace/remove`（seagent-tools/memory.rs）；無威脅掃描（threat_patterns）、無批次 operations、無字元預算 |
| session_search | tools/session_search_tool.py | FTS5 發現/讀取/捲動三模式，日期、角色、profile 篩選，摘要 | 🚧 | kernel `session_search` query+limit 回片段（seagent-kernel/kernel.rs:204、store.rs:142）；無讀取/捲動/篩選模式 |
| clarify | tools/clarify_tool.py, clarify_batch.py, clarify_gateway.py | 批次多選/開放問題，CLI 面板與 gateway 卡片 | 🚧 | `ask_user` 單題自由文字（seagent-tools/agent.rs:60）；無選項、無批次 |
| execute_code | tools/code_execution_tool.py, code_kernel.py, code_execution_rpc.py | Python 腳本經 RPC 呼叫工具；session 常駐 kernel（reset）、遠端後端、env 清洗、呼叫預算 | 🚧 | kernel `run` bash/python3＋`seagent-call`（seagent-kernel/coderun.rs）；每次新行程，無常駐狀態、無遠端後端 |
| delegate_task | tools/delegate_tool*.py | tasks[] 批次子代理、background、list/steer/stop、output_schema、toolset 限制、成本彙整 | 🚧 | `spawn` task/model/fork/tools（seagent-tools/agent.rs），多呼叫可平行；無 background、steer/stop、output_schema、批次參數 |
| cronjob_manage | tools/cronjob_tools.py | 代理自建/改/暫停排程（deliver、skills、script、no_agent、context_from、workdir） | ⬜ | 排程只能經 `seagent schedule` CLI（seagent/main.rs:174、seagent-kernel/automation.rs）；無模型工具 |
| computer_use | tools/computer_use/*, plugins/computer_use/cua | cua-driver 桌面控制：截圖、滑鼠、鍵盤、捲動、拖曳、視窗，跨 macOS/Win/Linux | 🚧 | 僅 node_invoke：`computer.act`（xdotool/ydotool）、`screen.snapshot`、AT-SPI a11y（seagent-app/node.rs:919、node/a11y.rs）；需配對 Linux node，無本機直用 |
| manage_connections | tools/connectors/tool.py | 連接託管連接器帳號（Gmail、Notion…）與從內建目錄裝本地 MCP | 🚧 | `seagent mcp add/login`（seagent/main.rs:1551/1597）僅 CLI；無代理工具、無託管帳號 |
| manage_catalog | tools/connectors/catalog_tool.py | 桌面聊天中搜尋並經核准卡安裝目錄外掛/技能 | N/A | `platforms=desktop`，綁 Hermes 桌面核准卡 |
| message_agent | tools/bot_mode_dm.py | Bot Mode：代理傳訊給同機其他 profile 或對等 gateway 的代理（注入式） | 🚧 | 遠端代理可用 `a2a_*`（seagent-app/a2a.rs）；無 profile 間 Bot Mode |
| send_message（函式庫，非工具） | tools/send_message_tool.py | 跨平台送訊/列目標/表情；刻意不給模型 | ✅ | SE Agent 反而有模型工具 `channel_send`（seagent-channel/tool.rs，走 egress gate）＋`seagent channel send` |

## 2. 工具後端／供應商

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| web 後端 brave_free | plugins/web/brave_free | 免費 Brave 搜尋 | ⬜ | 無搜尋 |
| web 後端 ddgs | plugins/web/ddgs | DuckDuckGo 搜尋（免金鑰） | ⬜ | — |
| web 後端 exa | plugins/web/exa | Exa 搜尋＋抽取 | ⬜ | — |
| web 後端 firecrawl | plugins/web/firecrawl | Firecrawl 搜尋/抽取 | ⬜ | — |
| web 後端 keenable | plugins/web/keenable | Keenable 搜尋/抽取 | ⬜ | — |
| web 後端 openai_native | plugins/web/openai_native | OpenAI 內建 web search | ⬜ | — |
| web 後端 parallel | plugins/web/parallel | Parallel 搜尋/抽取 | ⬜ | — |
| web 後端 perplexity | plugins/web/perplexity | Perplexity 搜尋 | ⬜ | — |
| web 後端 searxng | plugins/web/searxng | 自架 SearXNG | ⬜ | — |
| web 後端 tavily | plugins/web/tavily | Tavily 搜尋/抽取 | ⬜ | — |
| web 後端 xai | plugins/web/xai | xAI web search | ⬜ | — |
| web keyless MCP ring | plugins/web/keyless_mcp.py, tools/web_tools_rescue.py | 金鑰失敗時一次性改走免金鑰環 | ⬜ | — |
| web 結果快取 | tools/web_result_cache.py | search/extract TTL 快取 | ⬜ | — |
| 影像生成 fal | plugins/image_gen/fal, tools/image_generation_catalog.py | FAL 模型目錄＋放大器 | ⬜ | — |
| 影像生成 openai | plugins/image_gen/openai | gpt-image | ⬜ | — |
| 影像生成 openai-codex | plugins/image_gen/openai-codex | ChatGPT 帳號產圖 | ⬜ | — |
| 影像生成 xai | plugins/image_gen/xai | Grok Imagine | ⬜ | — |
| 影像生成 openrouter | plugins/image_gen/openrouter | OpenRouter 影像模型 | ⬜ | — |
| 影像生成 deepinfra | plugins/image_gen/deepinfra | DeepInfra 影像 | ⬜ | — |
| 影像生成 krea | plugins/image_gen/krea | Krea | ⬜ | — |
| 影像生成 meta-ai | plugins/image_gen/meta-ai | Meta AI | ⬜ | — |
| 影像生成 managed（Nous 訂閱） | tools/image_generation_managed.py | Nous 託管影像閘道 | N/A | Nous 自家訂閱服務 |
| 影片生成 fal/xai/openrouter/deepinfra | plugins/video_gen/* | 四個影片供應商 | ⬜ | — |
| TTS edge | tools/tts_tool_providers.py | 免費 Edge TTS（預設） | ⬜ | — |
| TTS elevenlabs | tools/tts_tool_providers.py | ElevenLabs | ⬜ | — |
| TTS openai / deepinfra | tools/tts_tool_openai.py | OpenAI 相容 TTS | ⬜ | — |
| TTS xai / xai-oauth | tools/tts_tool_providers.py | xAI 語音 | ⬜ | — |
| TTS minimax / mistral / gemini | tools/tts_tool_providers.py | 三家雲端 TTS | ⬜ | — |
| TTS 本機 NeuTTS / Piper / KittenTTS | tools/tts_tool_local.py, neutts_synth.py | 裝置端 TTS，LRU 模型快取、warm/release | ⬜ | — |
| TTS command / plugin provider | tools/tts_command_provider.py, tts_tool_plugins.py | 使用者 shell 指令或外掛 TTS | ⬜ | — |
| TTS 串流＋Markdown 口語化 | tools/tts_streaming.py, tts_text_normalize.py, tts_tool_speaker.py | 逐句串流播放、Markdown 轉口語稿 | ⬜ | — |
| STT local faster-whisper | tools/transcription_local.py | 本機轉錄（預設），防幻覺參數 | ⬜ | node `talk.ptt` 只呼叫 node.toml 的 OpenAI 相容 `[stt]`（seagent-app/node/talk.rs） |
| STT whisper.cpp（managed） | tools/transcription_whisper_cpp.py | 受管 whisper.cpp 與模型下載驗證 | ⬜ | — |
| STT 雲端 groq/openai/deepinfra/mistral/xai/elevenlabs | tools/transcription_cloud.py, transcription_chunking.py | 雲端轉錄，依上限切段 | 🚧 | 僅 node talk 的 OpenAI 相容 `/audio/transcriptions`（talk.rs）；kernel/channel 無通用 STT |
| STT command / plugin / streaming | tools/transcription_command.py, transcription_streaming.py | 自訂指令、外掛、即時串流轉錄 | ⬜ | — |
| 瀏覽器 本機 agent-browser Chromium | tools/browser_tool.py, browser_tool_install.py | 本機 headless Chromium，自動安裝 | ⬜ | SE Agent 不啟動瀏覽器 |
| 瀏覽器 雲端 browserbase / browser_use / firecrawl | plugins/browser/*, agent/browser_provider.py | 雲端瀏覽器供應商自動偵測 | ⬜ | — |
| 瀏覽器 使用者 CDP 端點 | tools/browser_tool_cdp.py | browser.cdp_url 連使用者瀏覽器 | 🚧 | node.toml `cdp_url`（僅 loopback，seagent-app/node/cdp.rs） |
| 瀏覽器 camofox | tools/browser_camofox*.py | 反偵測 Camofox REST 後端，受管持久狀態 | ⬜ | — |
| 瀏覽器 lightpanda | tools/browser_lightpanda.py, browser_tool_lightpanda_fallback.py | Lightpanda 引擎，失敗退回 Chrome | ⬜ | — |
| 瀏覽器 real-profile | tools/browser_tool_real_profile.py | 複製使用者 Chromium profile 以真實身分瀏覽 | ⬜ | — |
| 瀏覽器 CDP supervisor | tools/browser_supervisor*.py | 常駐 CDP 監看對話框與 frame | ⬜ | — |
| 瀏覽器 extension router | tools/browser_extension_router.py | 經瀏覽器擴充控制使用者分頁 | ⬜ | — |
| terminal 後端 local | tools/environments/local.py | spawn-per-call＋session 快照（cwd/env 延續） | 🚧 | shell 每次新 bash；cwd 可傳但不延續 export/cd 狀態（seagent-tools/shell.rs） |
| terminal 後端 docker | tools/environments/docker.py, docker_egress.py | 強化容器（cap-drop、PID 限制）、egress 代理 | ⬜ | gate.rs 僅辨識 docker 指令 |
| terminal 後端 ssh | tools/environments/ssh.py | ControlMaster 遠端執行 | ⬜ | （node system.run 可遠端執行但屬 node 協議） |
| terminal 後端 modal / managed_modal | tools/environments/modal.py, managed_modal.py | Modal 雲沙箱＋快照 | ⬜ | — |
| terminal 後端 daytona | tools/environments/daytona.py | Daytona 雲沙箱 | ⬜ | — |
| terminal 後端 singularity/apptainer | tools/environments/singularity.py | 強化 HPC 容器 | ⬜ | — |
| terminal 後端 vercel_sandbox | tools/environments/vercel_sandbox.py | Vercel 沙箱 | ⬜ | — |
| terminal 後端外掛 provider | agent/terminal_env_provider.py | 外掛註冊新執行環境 | ⬜ | — |
| 遠端檔案同步／憑證檔直通 | tools/environments/file_sync.py, tools/credential_files.py | 沙箱同步工作區與必要憑證檔 | ⬜ | — |
| Bot Desktop（無頭 Xfce＋RFB） | tools/bot_desktop/* | 每 profile 一個無頭桌面供 computer_use，人類可接手 lease | ⬜ | — |
| computer_use cua-driver 後端 | tools/computer_use/cua_backend*.py | MCP stdio 驅動 cua-driver，背景優先輸入 | 🚧 | node computer.act 用 xdotool/ydotool（seagent-app/node.rs:1013） |
| 記憶外掛 byterover | plugins/memory/byterover | brv 曲線記憶同步、壓縮前 flush、`brv_*` 工具 | 🚧 | 外掛記憶介面存在（seagent-plugin/plugin.rs `"memory": true`、PluginMemory 工具）；無此供應商 |
| 記憶外掛 retaindb | plugins/memory/retaindb | 10 個 `retaindb_*` 工具（search/remember/forget/檔案） | 🚧 | 同上，需另寫外掛 |
| 記憶外掛 目錄（67 個 community） | plugin-catalog/*.yaml（category: memory） | agent_memory_es、mem0 類等 | 🚧 | 機制同上；無目錄 |

## 3. 平台綁定／外掛工具（非 channel 本身）

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| discord | tools/discord_tool.py | 讀訊息、搜成員、建 thread（依 intents 動態 schema） | ⬜ | seagent-channel/discord.rs 是 channel，無模型工具 |
| discord_admin | tools/discord_tool.py | 列頻道/角色、釘選、指派角色 | ⬜ | — |
| feishu_doc_read | tools/feishu_doc_tool.py | 讀飛書文件全文 | ⬜ | feishu/comment.rs 只處理留言事件 |
| feishu_drive_list_comments | tools/feishu_drive_tool.py | 列文件留言 | 🚧 | comment.rs 將留言串時間線注入提示，非工具 |
| feishu_drive_list_comment_replies | tools/feishu_drive_tool.py | 列留言回覆 | 🚧 | 同上 |
| feishu_drive_reply_comment | tools/feishu_drive_tool.py | 回覆局部留言 | 🚧 | channel 回覆即送到 thread（comment.rs） |
| feishu_drive_add_comment | tools/feishu_drive_tool.py | 新增全文留言（1069302 fallback） | 🚧 | comment.rs 有同樣 fallback，但非工具 |
| yb_query_group_info | tools/yuanbao_tools.py | 元寶群資訊 | ⬜ | seagent-channel/yuanbao.rs 無工具 |
| yb_query_group_members | tools/yuanbao_tools.py | 群成員查詢/找人/列 bot | ⬜ | — |
| yb_send_dm | tools/yuanbao_tools.py | 群內私訊含媒體 | ⬜ | — |
| yb_search_sticker | tools/yuanbao_tools.py | 搜內建貼圖 | ⬜ | — |
| yb_send_sticker | tools/yuanbao_tools.py | 送貼圖 | ⬜ | — |
| meet_join | plugins/google_meet/tools.py | Playwright 以訪客加入 Google Meet（可在遠端 node） | ⬜ | — |
| meet_status | plugins/google_meet/tools.py | bot 存活與逐字稿進度 | ⬜ | — |
| meet_transcript | plugins/google_meet/tools.py | 讀會議逐字稿 | ⬜ | — |
| meet_leave | plugins/google_meet/tools.py | 離開會議 | ⬜ | — |
| meet_say | plugins/google_meet/tools.py | realtime 模式代理發言 | ⬜ | — |
| Teams 會議管線 | plugins/teams_pipeline | Graph 訂閱會議、逐字稿處理管線 | ⬜ | seagent-channel/msgraph_webhook.rs 只做訊息 |
| context_engine 執行期工具 | toolsets.py `context_engine`, agent/context_engine.py | 啟用中的 context engine 暴露的工具 | 🚧 | context engine 外掛存在（seagent-kernel/engine.rs），未見 engine 自帶工具通道 |

## 4. 桌面 GUI 工具（`desktop_ui`／`project`／`onboarding`）

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| read_terminal | tools/read_terminal_tool.py | 讀桌面 app 內嵌終端窗格 | N/A | Hermes 桌面 xterm.js 窗格 |
| close_terminal | tools/close_terminal_tool.py | 隱藏背景行程終端分頁 | N/A | 桌面 GUI |
| desktop_preview | tools/preview_tool.py | 開/關/讀預覽窗格 | N/A | 桌面 GUI（SE Agent 的 node `canvas.present` 為近似） |
| drive_preview | tools/drive_preview_tool.py | 在預覽窗格點擊/輸入 | N/A | 桌面 GUI |
| annotate_preview | tools/annotate_preview_tool.py | 預覽頁持久標註 | N/A | 桌面 GUI |
| read_window_below | tools/read_window_tool.py | 辨識桌面視窗下方的 app 視窗 | N/A | 桌面 GUI |
| focus_pane | tools/focus_pane_tool.py | 聚焦 chat/files/terminal/review 窗格 | N/A | 桌面 GUI |
| react_to_message | tools/react_to_message_tool.py | 代理對訊息 tapback 表情 | N/A | 桌面 GUI 訊息存放 |
| gui_tour | tools/tour_tool.py | 桌面導覽高亮 | N/A | 桌面 GUI |
| show_tip | tools/tip_tool.py | 桌面箭頭提示 | N/A | 桌面 GUI |
| set_theme | tools/set_theme_tool.py | 改桌面主題/明暗/版面 | N/A | 桌面 GUI |
| setup_beat | tools/setup_beat_tool.py | 首次 onboarding 卡片 | N/A | 桌面 GUI |
| desktop_project | tools/project_tools.py | 建立/切換桌面 Project 工作區 | N/A | 桌面側欄 projects.db |

## 5. Kanban（多代理看板）

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| kanban_show | tools/kanban_tools.py | 看任務詳情 | ⬜ | SE Agent 無 kanban |
| kanban_list | tools/kanban_tools.py | 列任務 | ⬜ | — |
| kanban_create | tools/kanban_tools.py | 建子任務（扇出） | ⬜ | — |
| kanban_complete | tools/kanban_tools.py | 結構化交接完成 | ⬜ | — |
| kanban_block / kanban_unblock | tools/kanban_tools.py | 阻擋等人類／解除 | ⬜ | — |
| kanban_request_review / kanban_request_changes | tools/kanban_tools.py | 進入審查／退回修改 | ⬜ | — |
| kanban_heartbeat | tools/kanban_tools.py | 長任務心跳 | ⬜ | — |
| kanban_comment | tools/kanban_tools.py | 任務留言 | ⬜ | — |
| kanban_link | tools/kanban_tools.py | 任務相依連結 | ⬜ | — |
| kanban_attach / kanban_attach_url / kanban_attachments | tools/kanban_tools.py | 附檔/URL/列附件 | ⬜ | — |
| kanban_schedule | tools/kanban_tools_schemas.py | 排程任務 | ⬜ | — |
| Kanban 派工器（gateway 內） | hermes_cli/kanban_db_dispatch.py, kanban_worker_client.py | 依看板派 worker 代理到各 profile | ⬜ | — |
| kanban decompose / specify | hermes_cli/kanban_decompose.py, kanban_specify.py | 輔助 LLM 把一行需求擴成規格、拆成任務圖 | ⬜ | — |
| kanban swarm / workflow 欄位 | hermes_cli/kanban_swarm.py, kanban_workflow.py | swarm 拓撲、看板欄位與移動 | ⬜ | — |
| kanban PR acceptance | hermes_cli/kanban_pr_acceptance*.py | 以 GitHub 精確 head 驗收 PR 任務 | ⬜ | — |
| kanban 多看板/轉移/診斷 | hermes_cli/kanban_boards.py, kanban_transfer.py, kanban_diagnostics.py | 多板、搬移、健康檢查 | ⬜ | — |
| kanban 儀表板 / systemd | plugins/kanban/dashboard, plugins/kanban/systemd | Web 看板與服務單元 | ⬜ | — |

## 6. 工具基礎設施與安全行為

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| tool_search（漸進揭露） | tools/tool_search.py, tool_search_catalog.py | MCP/外掛/選定核心工具延後，BM25 目錄＋tool_search/describe/call | 🚧 | `tool_describe`/`tool_call` 與 pinned/unpinned 索引（seagent-kernel/context.rs:153）；無 BM25 `tool_search` 查詢 |
| 工具輸出上限設定 | tools/tool_output_limits.py, tool_output_truncate.py | max_bytes/max_lines，40% 頭 60% 尾截斷 | ✅ | shell 截斷（seagent-tools/shell.rs:48）、runner.spill_bytes（seagent-kernel/config.rs:101） |
| 大結果存檔（spill） | tools/tool_result_storage.py, budget_config.py | 大輸出存檔改給預覽 | ✅ | runner spill 到檔案，提示讀片段（seagent-kernel/context.rs IDENTITY 規則） |
| 參數型別修正 | tools/arg_coercion.py | 字串化數字/布林/JSON 依 schema 修正 | ✅ | seagent-kernel/normalize.rs:9 `coerce` |
| schema 淨化（llama.cpp 等嚴格後端） | tools/schema_sanitizer.py | 修 schema 讓嚴格 grammar 後端可吃 | 🚧 | 僅 MCP schema 正規化（seagent-plugin/bridge.rs）；無依後端淨化 |
| SSRF 私網封鎖 | tools/url_safety.py | 擋 private/內網位址，可設定放行 | ⬜ | web_fetch 未見私網檢查（seagent-tools/web.rs）；egress gate 只看敏感 payload |
| 網站黑名單 | tools/website_policy.py | security.website_blocklist | 🚧 | `gate.egress_deny` 主機清單（seagent-kernel/gate.rs:30） |
| 危險指令偵測 | tools/approval_detection.py, shell_heredoc.py | 正規化、tokenize、樣式表判危險指令（含 heredoc 遮罩） | ✅ | shell 分析器＋privilege 規則（seagent-kernel/shell.rs、gate.rs:332） |
| 檔案安全規則 | agent/file_safety.py, tools/path_security.py | 敏感路徑/憑證檔防護 | 🚧 | gate 擋系統路徑與 `.env` 外送（gate.rs:249）；無讀取側敏感檔守衛 |
| self-repo 守衛 | tools/self_repo_guard.py | 擋會改寫自身 checkout 的 git 操作 | ⬜ | — |
| runtime 自我保護 | agent/runtime_self_protection.py | 不可刪自身直譯器/venv | N/A | Python venv 專屬 |
| 子行程 env 秘密清洗 | tools/environments/local_env_policy.py, code_execution_env.py | 子行程移除 Hermes 管理的憑證變數 | ⬜ | 未見 env_remove/env_clear（seagent-tools、seagent-kernel） |
| 輸出秘密遮蔽 | agent/redact.py | 工具輸出/日誌遮蔽金鑰 | ✅ | vault redact（seagent-kernel/vault.rs） |
| ANSI 去除 | tools/ansi_strip.py | 去控制碼避免寫入檔案 | ⬜ | 未見 |
| 中斷（thread 範圍） | tools/interrupt.py | 只中斷該 session 的工具 | ✅ | `seagent interrupt`、Cancel（seagent-core/cancel.rs、kernel.rs:381） |
| 跨代理檔案狀態協調 | tools/file_state.py | 併發子代理同檔編輯防衝突 | ⬜ | — |
| 讀取追蹤/過期寫入警告 | tools/file_tools_read_tracking.py | 未讀先寫、讀後被改警告 | ⬜ | — |
| 威脅樣式庫（prompt injection） | tools/threat_patterns.py | 掃 context 檔、記憶、cron prompt 的注入/外洩樣式 | ⬜ | — |
| MCP 套件 OSV 惡意檢查 | tools/osv_check.py | npx/uvx 啟動前查 OSV | ⬜ | （MCP 範疇但屬安全稽核） |
| hook 輸出溢出存檔 | tools/hook_output_spill.py | hook 注入的大 context 存檔 | ⬜ | hooks additional_context 直接注入（seagent-kernel/hooks.rs） |
| PTY 查詢回應 | tools/pty_query_responder.py | 回應背景 PTY 程式的終端查詢 | ⬜ | 無 PTY |
| 失敗輸出提示 | tools/terminal_hints.py | 依失敗輸出樣式附提示 | ⬜ | — |
| 工具迴圈護欄 | agent/tool_guardrails.py, repetition_guard.py | 重複呼叫/退化重複輸出偵測 | ✅ | runner.repeat_limit（seagent-kernel/config.rs:103） |
| 平行工具執行 | agent/tool_executor.py, tool_call_batches.py | 安全工具併發 | ✅ | parallel_safe＋max_parallel_tools（config.rs:108） |
| 工具標籤/進度轉播 | tools/tool_labels.py, agent/tool_progress_relay.py | 工具進度顯示與轉播到 gateway | 🚧 | 事件匯流排推給 TUI/web/ACP（seagent-kernel/event.rs）；無 verbose 模式切換 |

## 7. 核准／安全模式

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 危險指令核准流程 | tools/approval.py, approval_prompt.py | once/session/always/deny，CLI 面板＋gateway 卡片 | ✅ | privilege/egress gate＋`once|always|deny`（seagent-kernel/gate.rs、approver.rs；`seagent gate answer`、TUI y/a/n、web gate.answer） |
| smart 核准（輔助 LLM 風險評估） | tools/approval_smart.py | 輔助模型判斷風險決定放行/詢問 | ⬜ | — |
| yolo（session 切換） | tools/approval_yolo.py | 本 session 跳過所有核准 | 🚧 | `--yes`、`--allow-privilege/--allow-egress`、gate mode=allow（seagent/args.rs、gate.rs:14）；無執行中切換 |
| floors（不可覆寫底線） | tools/approval_floors.py | hardline 封鎖、`sudo -S` 密碼管線、使用者封鎖清單，永不出現提示 | 🚧 | gate mode=deny 與 egress_deny；無獨立於 yolo 的 hardline 清單 |
| gateway 阻塞等待核准 | tools/approval_gateway_wait.py | 代理執行緒等待平台上的核准 | ✅ | 審核經 daemon 掛起，channel/web/TUI 回答（approver.rs、daemon gate.pending） |
| 人類等待計時 | tools/approval_human_wait.py | 計算阻塞在人類的時間（不計入逾時） | ⬜ | — |
| approvals suggest | hermes_cli/approvals_suggest.py | 從歷史 always 答案挖出白名單建議 | ⬜ | — |
| approvals test | hermes_cli/subcommands/approvals.py | 測試某指令會被如何判定 | ⬜ | — |
| 記憶/技能寫入核准閘 | tools/write_approval.py | 跨 session 寫入先待審 | 🚧 | 背景 learn 建議先 staged、`seagent memory review/accept/reject`（seagent/main.rs:1224）；代理直接 `memory` 寫入不經審 |
| 終端核准批次（桌面） | agent/terminal_approval_batch.py | 預備桌面終端同意 | N/A | 桌面 GUI |
| 緊急停止 ESTOP | agent/estop.py, hermes_cli/subcommands/pause.py | `hermes pause` 暫停 cron/kanban/新回合 | 🚧 | 個別 `schedule disable`、`goal pause`（main.rs:1177）；無全域暫停 |
| egress 代理防火牆（iron-proxy） | hermes_cli/proxy_cli.py, tools/environments/docker_egress.py | 沙箱流量經代理注入憑證/過濾 | 🚧 | egress gate 判定外送（gate.rs:88）；無網路層代理 |

## 8. 斜線指令（`hermes_cli/commands.py`，104 個）

SE Agent 內建斜線：chat REPL `/model /compact /status /undo /new /commands /help /exit`（seagent/main.rs:542–573）＋自訂 Markdown 指令與 MCP prompt（seagent-kernel/commands.rs）；TUI 以快捷鍵為主（seagent-app/tui.rs）。CLI 對應另註。

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| /start | hermes_cli/commands.py | 平台 start ping 靜默確認 | N/A | channel 層（見 parity.md） |
| /new (/reset) | hermes_cli/commands.py | 新 session | ✅ | REPL `/new`（main.rs:568）、TUI Ctrl+N |
| /topic | hermes_cli/commands.py | Telegram DM topic session | N/A | channel 層 |
| /clear | hermes_cli/commands.py | 清畫面並新 session | 🚧 | `/new` 有，無清畫面 |
| /redraw | hermes_cli/commands.py | 強制重繪 UI | ⬜ | — |
| /history | hermes_cli/commands.py | 顯示對話歷史 | 🚧 | `seagent session show`（CLI），聊天內無 |
| /save | hermes_cli/commands.py | 匯出對話 | 🚧 | `seagent session export` Markdown（main.rs:702）；聊天內無、無 HTML/JSON |
| /retry | hermes_cli/commands.py | 重送上一則 | ⬜ | — |
| /prompt (/compose) | hermes_cli/commands.py | 用 $EDITOR 撰寫下一則 | ⬜ | — |
| /undo | hermes_cli/commands.py | 退回 N 個使用者回合重新提問 | 🚧 | SE Agent `/undo` 是檔案 checkpoint 還原；無對話回合倒帶 |
| /title | hermes_cli/commands.py | 設 session 標題 | 🚧 | `set_title` 只經 ACP（seagent-app/acp.rs:583）；無 CLI/斜線 |
| /handoff | hermes_cli/commands.py | 把 session 交接到訊息平台 | ⬜ | — |
| /branch (/fork) | hermes_cli/commands.py | 分支 session（平台建新 thread） | 🚧 | `seagent session fork`（main.rs:673）複製全歷史；無聊天內、無 thread 分支 |
| /worktree | hermes_cli/commands.py | 列/建/清 git worktree | ⬜ | — |
| /compress (/compact) | hermes_cli/commands.py | 手動壓縮，`here N` 保留最近 N、`--preview` | 🚧 | `/compact`、`seagent session compact`（main.rs:548/719）；無 here N、無預覽 |
| /rollback | hermes_cli/commands.py | 列/還原檔案 checkpoint（保留手動修改） | ✅ | `/undo [id]`、`seagent checkpoint list|restore`（seagent-kernel/checkpoint.rs） |
| /snapshot (/snap) | hermes_cli/commands.py | Hermes 設定/狀態快照與還原 | ⬜ | — |
| /export | hermes_cli/commands.py | 匯出 profile 封存 | ⬜ | 無 profile |
| /import | hermes_cli/commands.py | 匯入 profile 封存 | ⬜ | — |
| /stop | hermes_cli/commands.py | 殺所有背景行程 | 🚧 | `job kill` 逐一；無全殺 |
| /discard | hermes_cli/commands.py | 丟棄重啟遺失的回合讓佇列繼續 | ⬜ | daemon 會自動續跑中斷 session（seagent-kernel/daemon.rs），無丟棄指令 |
| /pause | hermes_cli/commands.py | 全域緊急停止 | 🚧 | 見 ESTOP |
| /approve | hermes_cli/commands.py | 核准待決危險指令 | ✅ | `seagent gate answer`、TUI y/a、web UI |
| /deny | hermes_cli/commands.py | 拒絕（可附理由） | 🚧 | deny 有；無理由欄 |
| /bg | hermes_cli/commands.py | 在背景 session 跑提示 | 🚧 | `seagent send <session>` 交 daemon（main.rs:156）；聊天內無 |
| /btw | hermes_cli/commands.py | 不打斷的旁支提問 | ⬜ | — |
| /agents (/tasks) | hermes_cli/commands.py | 顯示活躍代理與任務 | 🚧 | `seagent session list` 顯示 running；無子代理/行程面板 |
| /journey (/learning) | hermes_cli/commands.py | 學習時間軸 | ⬜ | — |
| /queue (/q) | hermes_cli/commands.py | 排下一回合提示，list/edit/rm/move/clear | 🚧 | 輸入持久排隊（seagent-kernel/kernel.rs:345）；無列/改/刪 |
| /steer (/s) | hermes_cli/commands.py | 下個工具呼叫後插話 | ✅ | 執行中 submit 即 steer（kernel.rs:345）；`seagent send`、TUI |
| /goal | hermes_cli/commands.py | 常駐目標跨回合執行 | ✅ | `seagent goal add/run/pause/cancel`＋`goal_done`（automation.rs:202、kernel.rs:213）；聊天內無 |
| /heartbeat (/hb) | hermes_cli/commands.py | 閒置時週期重入 session | 🚧 | `seagent schedule add '@every 15m' --reuse`（cron.rs）近似；非閒置觸發 |
| /refine | hermes_cli/commands.py | 立即回顧並存教訓到記憶/技能 | 🚧 | learn 背景回顧只產記憶建議（kernel.rs:1425、config learn）；無即時、無技能 |
| /review | hermes_cli/commands.py | 派獨立子代理審查剛做的工作 | ⬜ | — |
| /loop | hermes_cli/commands.py | session 內週期重跑，LOOP_COMPLETE 結束 | 🚧 | schedule `@every`；無 session 內循環與完成詞 |
| /plan | hermes_cli/commands.py | 只寫實作計畫到 .hermes/plans/ | ⬜ | — |
| /moa | hermes_cli/commands.py | 單題 Mixture-of-Agents | ⬜ | — |
| /subgoal | hermes_cli/commands.py | 目標附加準則 | ⬜ | — |
| /status | hermes_cli/commands.py | session/模型/token/context | ✅ | REPL `/status`（main.rs:553） |
| /egress | hermes_cli/commands.py | Docker egress 代理狀態 | ⬜ | 無 docker 後端 |
| /context (/ctx) | hermes_cli/commands.py | context 用量儀表、分類、壓縮統計 | 🚧 | `/status` 只有總 token 與壓縮次數 |
| /whoami | hermes_cli/commands.py | 斜線權限（admin/user） | N/A | channel 存取層（seagent-channel/access.rs） |
| /profile | hermes_cli/commands.py | 顯示目前 profile | ⬜ | 無 profile（僅 `SEAGENT_HOME`） |
| /sethome | hermes_cli/commands.py | 設家頻道 | N/A | channel 層 |
| /resume | hermes_cli/commands.py | 恢復已命名 session | ✅ | `seagent session resume`、TUI Ctrl+↑/↓ |
| /sessions | hermes_cli/commands.py | 瀏覽/恢復 session | ✅ | `seagent session list`、TUI/web 列表 |
| /config | hermes_cli/commands.py | 顯示設定 | ✅ | `seagent config show` |
| /model | hermes_cli/commands.py | 換模型（--global 持久） | ✅ | REPL `/model`、`seagent session model`（main.rs:725） |
| /codex-runtime | hermes_cli/commands.py | 切 codex app-server 執行期 | ⬜ | — |
| /personality | hermes_cli/commands.py | 套用預設人格 | ⬜ | 只有 config `identity` 字串（config.rs:28） |
| /statusbar (/sb) | hermes_cli/commands.py | 切狀態列 | ⬜ | — |
| /battery | hermes_cli/commands.py | 狀態列電量 | ⬜ | — |
| /timestamps (/ts) | hermes_cli/commands.py | 訊息時間戳 | ⬜ | — |
| /diff | hermes_cli/commands.py | 工作目錄 git diff | ⬜ | — |
| /verbose | hermes_cli/commands.py | 工具進度顯示等級 | 🚧 | 只有 `--quiet` |
| /focus | hermes_cli/commands.py | 只顯示提問與最終答 | ⬜ | — |
| /footer | hermes_cli/commands.py | gateway 回覆附執行期資訊 | ⬜ | — |
| /yolo | hermes_cli/commands.py | 切 YOLO | 🚧 | 只有啟動旗標/設定 |
| /approvals | hermes_cli/commands.py | 顯示/設定核准模式 | 🚧 | 設定檔 gate.privilege/egress；無指令 |
| /reasoning | hermes_cli/commands.py | 推理強度與顯示 | 🚧 | 每 session thinking level 只經 ACP 設（seagent-app/acp.rs:560→projection.rs:68）；無 CLI |
| /fast | hermes_cli/commands.py | OpenAI Priority / Anthropic Fast mode | ⬜ | — |
| /skin | hermes_cli/commands.py | 換主題 | ⬜ | SE Agent 固定深紅金主題（ui/theme.css） |
| /indicator | hermes_cli/commands.py | 忙碌指示樣式 | ⬜ | — |
| /voice | hermes_cli/commands.py | 語音模式 | ⬜ | — |
| /wake | hermes_cli/commands.py | 「Hey Hermes」喚醒詞 | ⬜ | — |
| /busy | hermes_cli/commands.py | 工作中來訊行為（queue/steer/interrupt） | 🚧 | 固定 steer；不可選 |
| /autoprune | hermes_cli/commands.py | 自動清舊 session | 🚧 | `compliance.retention_days`（config.rs:63） |
| /tools | hermes_cli/commands.py | 列/停用/啟用工具 | 🚧 | config `tools.disabled/pinned`、daemon tools.list；無執行中切換 |
| /toolsets | hermes_cli/commands.py | 列 toolset | ⬜ | 無 toolset 概念 |
| /skills | hermes_cli/commands.py | 搜尋/安裝/檢視/管理技能 | ⬜ | 無 hub |
| /memory | hermes_cli/commands.py | 審待寫記憶、切核准閘 | ✅ | `seagent memory review/accept/reject`、`learn.enabled` |
| /bundles | hermes_cli/commands.py | 技能組合別名 | ⬜ | — |
| /pet | hermes_cli/commands.py | petdex 吉祥物 | ⬜ | — |
| /hatch | hermes_cli/commands.py | 生成新寵物 | ⬜ | — |
| /learn | hermes_cli/commands.py | 從描述（目錄/URL/本對話）學成技能 | ⬜ | — |
| /init | hermes_cli/commands.py | 掃 repo 產生/更新 AGENTS.md | ⬜ | — |
| /cron | hermes_cli/commands.py | 管排程 | ✅ | `seagent schedule add/list/rm/enable/disable/run` |
| /suggestions | hermes_cli/commands.py | 審自動化建議 | ⬜ | — |
| /blueprint (/bp) | hermes_cli/commands.py | 從藍圖建自動化 | ⬜ | — |
| /curator | hermes_cli/commands.py | 背景技能維護 | ⬜ | — |
| /kanban | hermes_cli/commands.py | 看板 | ⬜ | — |
| /reload | hermes_cli/commands.py | 重載 .env | ⬜ | — |
| /reload-mcp | hermes_cli/commands.py | 重載 MCP | ✅ | `seagent mcp refresh <server>`（main.rs:1532） |
| /reload-skills | hermes_cli/commands.py | 重掃技能 | 🚧 | 新 session 建提示時才掃（context.rs:73）；無即時增量（skills_index_delta） |
| /browser | hermes_cli/commands.py | 連使用者 Chromium（CDP）或切 Browser Use | 🚧 | node.toml cdp_url |
| /plugins | hermes_cli/commands.py | 列外掛 | ✅ | `seagent plugin list` |
| /commands | hermes_cli/commands.py | 瀏覽指令與技能 | ✅ | `/commands`、`seagent commands` |
| /help | hermes_cli/commands.py | 說明 | ✅ | `/help` |
| /palette | hermes_cli/commands.py | 模糊指令面板 Ctrl+P | ⬜ | — |
| /restart | hermes_cli/commands.py | 排空後重啟 gateway | 🚧 | `seagent daemon stop/start`、`seagent service`；無 drain |
| /usage | hermes_cli/commands.py | token 用量與速率窗 | 🚧 | ledger 用量（seagent-kernel/ledger.rs）；無速率窗 |
| /subscription (/upgrade) | hermes_cli/commands.py | Nous 方案 | N/A | Nous 自家帳務 |
| /login | hermes_cli/commands.py | Nous 帳號登入 | N/A | Nous 自家帳務 |
| /topup | hermes_cli/commands.py | Nous 儲值 | N/A | Nous 自家帳務 |
| /insights | hermes_cli/commands.py | 使用分析 | ⬜ | — |
| /platforms (/gateway) | hermes_cli/commands.py | 平台狀態 | 🚧 | `seagent channel list` |
| /platform | hermes_cli/commands.py | 暫停/恢復故障平台 | N/A | channel 層 |
| /copy | hermes_cli/commands.py | 複製上則回答到剪貼簿 | ⬜ | — |
| /paste | hermes_cli/commands.py | 貼上剪貼簿圖片 | ⬜ | — |
| /image | hermes_cli/commands.py | 附本機圖片給下一則 | 🚧 | 圖片可經 ACP/OpenAI API/channel 附件（seagent-app/acp.rs:698）；CLI 無 |
| /update | hermes_cli/commands.py | 自我更新 | ⬜ | — |
| /version | hermes_cli/commands.py | 版本 | ✅ | `seagent version` |
| /debug | hermes_cli/commands.py | 上傳除錯報告 | ⬜ | 只有 `seagent doctor` |
| /quit (/exit) | hermes_cli/commands.py | 離開（--delete 刪歷史） | ✅ | `/exit`；--delete 無（用 `seagent session rm`） |
| /<skill-name> | agent/skill_commands.py | 技能即斜線指令 | ⬜ | SE Agent 斜線只認 commands/ 目錄與 MCP prompt（seagent-kernel/commands.rs） |
| /<bundle-name> | agent/skill_bundles.py | 一指令載入多技能 | ⬜ | — |
| 外掛斜線指令 | hermes_cli/plugin_command_dispatch.py | 外掛註冊斜線 | ✅ | 外掛 `commands` 能力（seagent-plugin/plugin.rs:12） |
| `!cmd` shell 模式 | hermes_cli/bang_shell.py | 輸入列直接跑 shell（不經模型） | ⬜ | — |
| Ctrl+S prompt 暫存 | hermes_cli/prompt_stash.py | 暫存撰寫中提示 | ⬜ | — |

## 9. CLI 子指令（`hermes <cmd>`）

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| chat（-q/-Q/-z/stream-json） | hermes_cli/_parser.py, oneshot.py, stream_json.py | 互動/單次/安靜/逐行 JSON 輸出 | ✅ | `seagent chat`、`seagent run`（--json、--quiet、stdin `-`） |
| setup | hermes_cli/subcommands/setup.py | 互動設定精靈 | ✅ | `seagent setup`（seagent/setup.rs） |
| model | hermes_cli/subcommands/model.py | 選預設模型/供應商 | 🚧 | `seagent setup`、`seagent providers list`；無獨立選擇器 |
| config show/edit/get/set/unset/path/env-path/check/migrate | hermes_cli/subcommands/config.py | 設定檢視編修遷移 | 🚧 | `seagent config path|show|init|get|validate`；無 set/unset/edit/migrate（`--set` 僅單次） |
| auth add/list/remove/reset/priority/refresh/status/logout/upgrade | hermes_cli/subcommands/auth.py | 憑證池管理 | ⬜ | 只有 `seagent secrets set/list/rm` |
| login / logout | hermes_cli/subcommands/login.py, logout.py | 供應商 OAuth 登入/登出 | ⬜ | `seagent mcp login/logout` 只對 MCP |
| fallback list/add/remove/clear | hermes_cli/subcommands/fallback.py | 管 fallback 鏈 | 🚧 | config `model.fallback`（config.rs:84） |
| moa list/configure/delete | hermes_cli/subcommands/moa.py | MoA 槽位 | ⬜ | — |
| sessions（rename/list/export/delete/prune/archive/optimize/repair/recover/stats/pin/browse/import…23 個） | hermes_cli/subcommands/sessions.py | session 全套管理與修復 | 🚧 | `seagent session list|show|resume|fork|search|export|compact|model|rm`；無 rename/prune/archive/pin/stats/import/repair（store 有 crash repair） |
| resume | hermes_cli/main.py | 直接恢復 | ✅ | `seagent session resume` |
| cron list/create/edit/pause/resume/run/remove/status/runs/incidents/notepad/doctor/tick | hermes_cli/subcommands/cron.py | 排程管理與事件 | 🚧 | `seagent schedule add/list/rm/enable/disable/run`；無 edit/runs/incidents/notepad/doctor |
| gateway run/start/stop/restart/status/install/uninstall/setup/migrate/enroll/proxy | hermes_cli/subcommands/gateway.py | 常駐 gateway 管理 | ✅ | `seagent daemon start|stop|status|run|install`、`seagent service` |
| status | hermes_cli/subcommands/status.py | 全元件狀態 | 🚧 | `seagent daemon status`、`seagent health` |
| doctor | hermes_cli/subcommands/doctor.py | 設定/依賴檢查 | ✅ | `seagent doctor` |
| dump | hermes_cli/subcommands/dump.py | 支援用設定摘要 | ⬜ | — |
| debug share/delete | hermes_cli/subcommands/debug.py | 上傳日誌報告 | ⬜ | — |
| logs | hermes_cli/subcommands/logs.py | 檢視/篩選日誌 | 🚧 | `seagent attach --follow` 看 session；無日誌篩選 |
| tools list/disable/enable/post-setup | hermes_cli/subcommands/tools.py | 每平台工具開關 | 🚧 | config `tools.disabled`；無 CLI、無每平台 |
| skills（trust/browse/search/install/inspect/list/check/update/audit/uninstall/reset/diff/opt-out/publish/snapshot/export/import/tap/config…27 個） | hermes_cli/subcommands/skills.py | 技能 hub 全流程 | ⬜ | — |
| bundles | hermes_cli/subcommands/bundles.py | 技能組合 | ⬜ | — |
| curator | hermes_cli/subcommands/curator.py | 技能維護 | ⬜ | — |
| memory setup/status/off/reset | hermes_cli/subcommands/memory.py | 外部記憶供應商設定 | 🚧 | config `memory.provider`（config.rs:53）；`seagent memory` 只管內建 |
| journey / memory-graph / learning | hermes_cli/subcommands/journey.py | 學習時間軸 | ⬜ | — |
| plugins（install/search/browse/validate/update/adopt/trust/check-updates/remove/list/enable/disable/capabilities/doctor/pack/export/show） | hermes_cli/subcommands/plugins.py | 外掛生命週期 | 🚧 | `seagent plugin list`；外掛手寫進 config；無 install/update/validate/enable |
| mcp（serve/add/remove/list/test/configure/login/reauth/picker/catalog/install） | hermes_cli/subcommands/mcp.py | MCP 管理 | ✅ | parity.md 已涵蓋；catalog/install（optional-mcps）見 §18 |
| profile（list/use/create/delete/describe/show/alias/rename/export/import/install/update…） | hermes_cli/subcommands/profile.py, profiles.py | 多個隔離 Hermes 實例 | ⬜ | 只有 `SEAGENT_HOME` 環境變數（seagent-kernel/config.rs Paths::from_env） |
| project | hermes_cli/projects_cmd.py | 多資料夾 Project | ⬜ | — |
| secrets bitwarden/onepassword | hermes_cli/subcommands/secrets.py, agent/secret_sources/* | 外部秘密來源 | 🚧 | 本機 vault `seagent secrets`（seagent-kernel/vault.rs）；無 Bitwarden/1Password/command 來源 |
| vault | hermes_cli/subcommands/vault.py | 瀏覽器自動填入加密庫 | ⬜ | — |
| security audit | hermes_cli/security_audit.py | OSV 供應鏈稽核 venv/外掛/MCP | ⬜ | — |
| egress | hermes_cli/proxy_cli.py | iron-proxy 管理 | ⬜ | — |
| hooks list/test/revoke/doctor | hermes_cli/subcommands/hooks.py | shell hook 檢視與首次同意 | 🚧 | shell hooks 設定（seagent-kernel/hooks.rs）；無 CLI、無首次同意 |
| webhook subscribe/list/remove/test | hermes_cli/subcommands/webhook.py | 動態 webhook 訂閱 | ✅ | `seagent webhook list|subscribe|rm`（無 test） |
| pairing list/approve/revoke/clear-pending | hermes_cli/subcommands/pairing.py | DM 配對碼 | ✅ | `seagent pairing`（main.rs:185） |
| peer add/list/remove | hermes_cli/subcommands/peer.py | 跨機 bot-to-bot | 🚧 | A2A（parity.md）近似 |
| send | hermes_cli/send_cmd.py | 從 shell 傳訊到平台 | ✅ | `seagent channel send` |
| insights | hermes_cli/subcommands/insights.py | 使用分析 | ⬜ | — |
| usage | hermes_cli/subcommands/usage.py | 帳號速率窗 | ⬜ | — |
| prompt-size | hermes_cli/subcommands/prompt_size.py | 系統提示＋schema 位元組拆解 | ⬜ | — |
| backup / import | hermes_cli/backup*.py | 家目錄 zip 備份/還原 | 🚧 | `seagent data export|delete` 只針對 channel 使用者資料 |
| checkpoints | hermes_cli/subcommands/checkpoints.py | 檢視/修剪/清 checkpoint 庫 | 🚧 | `seagent checkpoint list|restore`；無 prune/clear（config max_files 自動） |
| worktree list/prune/restore | hermes_cli/worktree_cmd.py | 稽核回收 worktree | ⬜ | — |
| update / uninstall | hermes_cli/update_cmd*.py, uninstall.py | 自我更新/移除（fleet、回滾） | ⬜ | — |
| completion | hermes_cli/subcommands/completion.py | bash/zsh/fish 補全 | ⬜ | — |
| console | hermes_cli/console_engine.py | 安全指令主控台 | ⬜ | — |
| dashboard serve/register | hermes_cli/main_dashboard.py, web_server*.py | Web 儀表板 | ✅ | `seagent app`（seagent-app/server.rs，web UI PWA） |
| gui / desktop | hermes_cli/main_desktop.py | 建置啟動桌面 app | N/A | Hermes Electron 桌面 |
| acp | hermes_cli/subcommands/acp.py | ACP 伺服器 | ✅ | parity.md |
| import-agent | hermes_cli/agent_import*.py | 匯入 Claude Code / Codex CLI 設定（不含秘密） | 🚧 | SE Agent 直接讀 `.claude/commands`、`.claude/skills`、CLAUDE.md、Claude 相容 hooks；無匯入 MCP/設定 |
| claw migrate/cleanup | hermes_cli/claw.py | OpenClaw 遷移 | ⬜ | — |
| migrate xai/relay | hermes_cli/subcommands/migrate.py | 退役模型/設定遷移 | ⬜ | — |
| codex-runtime migrate | hermes_cli/subcommands/codex_runtime.py | codex 執行期 MCP 遷移 | ⬜ | — |
| computer-use install/status/doctor/permissions/grant | hermes_cli/subcommands/computer_use.py | cua-driver 管理 | ⬜ | — |
| screen status/start/stop/install | hermes_cli/subcommands/computer_use_screen.py | Bot Desktop 螢幕 | ⬜ | — |
| connectors list/accounts/connect/rename/disconnect | hermes_cli/connectors_cmd.py | 託管連接器帳號 | ⬜ | — |
| monitoring status | hermes_cli/subcommands/monitoring.py, agent/monitoring | gateway 健康＋OTLP 匯出 | 🚧 | `seagent health`；無 OTLP |
| pets | hermes_cli/pets.py | petdex 寵物 | ⬜ | — |
| skin list/use/set | hermes_cli/skin_engine.py | 主題 | ⬜ | — |
| slack manifest | hermes_cli/slack_cli.py | Slack app manifest 產生 | ⬜ | （channel 輔助） |
| whatsapp / whatsapp-cloud | hermes_cli/subcommands/whatsapp.py | WhatsApp 設定 | N/A | channel 層 |
| verify | hermes_cli/verify_cmd.py, agent/verify | 偵測專案執行配方並冒煙測試 | ⬜ | — |
| lsp | agent/lsp/cli.py | LSP 伺服器管理 | ⬜ | — |
| browser close-profile | hermes_cli/subcommands/browser.py | 關閉鎖住 profile 的瀏覽器 | ⬜ | — |
| portal / proxy | hermes_cli/portal_cli.py | Nous portal 相關 | N/A | Nous 自家服務 |
| gateway 多工 profile（multiplex） | hermes_cli/gateway_multiplex*.py | 一行程服務多 profile | ⬜ | — |

## 10. 技能系統

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 技能發現與索引注入 | agent/prompt_builder.py, skill_utils.py | `<available_skills>` 進系統提示 | ✅ | context.rs:73 discover_skills；目錄 `.seagent/skills`、`.claude/skills`、`.agents/skills`、家目錄（seagent-tools/plan.rs:166） |
| 技能索引即時增量 | agent/skills_index_delta.py | 對話中新增技能不重建提示也能看到 | ⬜ | — |
| SKILL.md 前處理 | agent/skill_preprocessing.py | `${HERMES_*}` 代入、內嵌 ``!`cmd` `` 展開 | ⬜ | — |
| 技能必要 env 與秘密收集 | tools/skills_tool_setup.py, env_passthrough.py | required_environment_variables 收集與子行程放行 | ⬜ | — |
| 外掛提供技能 | tools/skills_tool_plugin.py | `plugin:skill` | ⬜ | — |
| 內建技能同步（bundled sync） | tools/skills_sync*.py | 把 repo skills/ 種到家目錄並追蹤修改 | ⬜ | SE Agent 無內建技能包 |
| Hub：官方 optional-skills＋Hermes 索引 | tools/skills_hub_official.py | 官方來源 | ⬜ | — |
| Hub：GitHub taps | tools/skills_hub_github.py | GitHub repo/tap 來源 | ⬜ | — |
| Hub：ClawHub | tools/skills_hub_clawhub.py | clawhub.ai | ⬜ | — |
| Hub：skills.sh | tools/skills_hub_skillssh.py | skills.sh 目錄 | ⬜ | — |
| Hub：LobeHub / browse.sh / well-known / 直接 URL | tools/skills_hub_sources.py | 其他來源 | ⬜ | — |
| Hub 統一搜尋 | tools/skills_hub_search.py | 平行跨來源搜尋 | ⬜ | — |
| Hub 安裝（隔離暫存、目標安全） | tools/skills_hub_install.py | quarantine、symlink 防護 | ⬜ | — |
| Skills Guard（regex 掃描＋信任政策） | tools/skills_guard.py | 外部技能靜態掃描、trusted/community 分級 | ⬜ | — |
| SkillEvaluator 掃描 | tools/skillevaluator_scan.py | NVIDIA Tier1 建議掃描 | ⬜ | — |
| AST 深度稽核 | tools/skills_ast_audit.py | `skills audit --deep` | ⬜ | — |
| 技能 linter | tools/skill_linter.py | 結構與慣例檢查 | ⬜ | — |
| 技能 ledger＋單次回滾 | tools/skill_ledger.py | 每次變更 JSONL 稽核可回滾 | ⬜ | — |
| 技能使用遙測 | tools/skill_usage.py | 供 curator 的使用統計 | ⬜ | — |
| Curator（閒置背景維護） | agent/curator.py, curator_backup.py | 合併/封存/釘選技能，先快照可回滾 | ⬜ | — |
| 背景回顧寫技能 | agent/background_review.py | 每回合後分叉評估存記憶/技能 | 🚧 | learn 背景回顧只提記憶建議（seagent-kernel/kernel.rs:1425） |
| 技能 bundles | agent/skill_bundles.py | YAML 別名載多技能 | ⬜ | — |
| Blueprints（技能＋cron 自動化範本） | tools/blueprints.py, cron/blueprint_catalog.py | 可分享自動化 | ⬜ | — |
| 技能發佈/匯出/匯入 | hermes_cli/skills_hub.py | publish/export/import | ⬜ | — |
| 內建技能內容（skills/ 58 個） | skills/** | apple/creative/devops/email/media/research… | ⬜ | SE Agent 不附技能（可讀 Claude 相容技能） |
| optional-skills（153 個） | optional-skills/** | blockchain/finance/mlops/security… | ⬜ | — |

## 11. 記憶

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 內建 MEMORY.md / USER.md | tools/memory_tool_store.py | 有界檔案記憶，凍結快照入提示 | ✅ | seagent-tools/memory.rs、context.rs MAX_MEMORY_BYTES |
| MemoryManager（多供應商扇出） | agent/memory_manager.py, memory_provider.py | 內建＋一個外部供應商，prefetch/sync/壓縮前 hook | 🚧 | 外掛 `memory` 能力取代工具（seagent-plugin/plugin.rs:575）；無 prefetch/壓縮前 flush hook |
| 記憶查詢改寫 | plugins/memory/query_rewrite.py | 召回前改寫查詢 | ⬜ | — |
| 記憶 context 圍欄 | agent/memory_context.py | 召回內容圍起、不外洩到輸出 | ⬜ | — |
| 記憶寫入威脅掃描 | tools/threat_patterns.py | 拒絕注入式記憶 | ⬜ | — |
| 記憶 provider 設定遷移/OAuth | hermes_cli/memory_provider_migration.py, memory_oauth.py | 供應商切換與授權 | ⬜ | — |
| Honcho profile 整合 | hermes_cli/profiles_honcho.py | 每 profile Honcho 設定 | ⬜ | — |

## 12. Context、提示與壓縮

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 自動 context 壓縮 | agent/context_compressor*.py, conversation_compression*.py | 輔助模型摘要中段，保護頭尾，迭代摘要 | ✅ | 兩段式：修剪舊工具輸出→aux 摘要，品質檢查失敗走決定式摘要（seagent-kernel/compaction.rs） |
| micro-compaction | agent/micro_compaction.py | 逐交換滾動摘要 | 🚧 | 只有工具輸出修剪階段 |
| 部分壓縮「到這裡為止」 | hermes_cli/partial_compress.py | 邊界感知部分壓縮 | ⬜ | — |
| OpenAI 原生 server 端壓縮 | agent/native_compaction.py | Responses `context_management` | ⬜ | — |
| 壓縮事件/遙測 | agent/compaction_events.py | 每次改寫記錄 | ✅ | PreCompact/PostCompact hook 事件（seagent-kernel/hooks.rs） |
| Context engine 外掛 | agent/context_engine.py, plugins/context_engine | 外掛決定何時/如何壓縮 | ✅ | seagent-kernel/engine.rs、`context_engine = "<plugin>"` |
| 專案指令檔 | agent/prompt_builder.py, context_file_sources.py | AGENTS.md/CLAUDE.md 等 | ✅ | context.rs:12 PROJECT_FILES |
| 子目錄提示漸進載入 | agent/subdirectory_hints.py | 進子目錄時載入該處 AGENTS.md | ⬜ | — |
| @-參照展開 | agent/context_references.py | `@file: @folder: @diff @git: @url:` | ⬜ | — |
| SOUL.md / 預設人格 | SOUL.md, hermes_cli/default_soul.py, personality.py | 身分檔與人格覆蓋 | 🚧 | config `identity`（config.rs:28） |
| coding posture 自動切換 | agent/coding_context.py | 程式工作區自動用 coding toolset | ⬜ | — |
| 本機工具鏈探測入提示 | tools/env_probe.py | 一行 Python 工具鏈資訊 | ⬜ | — |
| Anthropic prompt caching | agent/prompt_caching.py | 4 個 cache_control 斷點 | ✅ | seagent-model/anthropic.rs、context.rs cache-first 組裝 |
| context 用量拆解 | agent/context_breakdown.py | 系統/工具/歷史分類估算 | ⬜ | — |
| context 長度 pin | agent/context_pin.py | model.context_length 覆蓋 | 🚧 | 外掛供應商可宣告 context_window（seagent-plugin/plugin.rs:14）；內建供應商只靠 caps_for 表，ProviderConfig 無覆蓋欄（seagent-model/lib.rs:31） |
| models.dev 模型中繼資料 | agent/models_dev.py, model_metadata*.py | 上下文長度/價格資料庫 | 🚧 | caps_for 啟發式表 |
| 圖片淘汰/視覺歷史預算 | agent/image_eviction_policy.py, tools/vision_tools_history_budget.py | 舊圖移出 context | ⬜ | Block::Image 只做 token 估算（types.rs:192） |
| 非視覺模型圖片退化 | agent/vision_message_prep.py | 以描述取代圖片 | ⬜ | — |
| 自動標題生成 | agent/title_generator.py | 即時決定式＋LLM 標題 | 🚧 | 建立時可帶 title（kernel.rs:317）；無 LLM 生成 |
| session recap | hermes_cli/session_recap.py | 本地摘要目前 session | ⬜ | — |
| 旁支提問 /btw | agent/side_question.py | 不入歷史的問答 | ⬜ | — |
| 空回應/截斷恢復 | agent/turn_empty_response.py, turn_truncation.py | 空回覆重試、截斷續寫 | ✅ | 推理吃光輸出時加倍重試（kernel.rs:642）、max_continuations（config.rs:106） |
| 迭代預算 | agent/iteration_budget.py | 每代理回合上限 | ✅ | max_steps_per_turn |
| 驗證迴圈 pre_verify | agent/verify_hooks.py, verification_stop.py | 改碼後回合結束前驗證 | ⬜ | Stop hook 可自寫（hooks.rs），無內建 |
| i18n 多語系 | agent/i18n*.py, locales/ | 介面翻譯 | ⬜ | SE Agent 介面固定中英 |

## 13. Checkpoint／回溯／Session 狀態

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 檔案 checkpoint（shadow git） | tools/checkpoint_manager.py | 自動快照工作目錄 | ✅ | seagent-kernel/checkpoint.rs |
| checkpoint 保留/修剪 | tools/checkpoint_maintenance.py, checkpoint_pruning.py | 保留政策、孤兒清理 | 🚧 | `checkpoint.max_files`（config.rs:154）；無修剪指令 |
| 對話 rewind | hermes_state_rewind.py | 退回到某訊息 | ⬜ | — |
| session 持久化＋FTS | hermes_state_*.py | SQLite＋FTS5、WAL、修復 | ✅ | JSONL append-only＋crash repair＋搜尋（seagent-kernel/store.rs） |
| session 匯出 HTML/MD | hermes_cli/session_export_html.py, session_export_md.py | 多格式匯出 | 🚧 | Markdown only |
| session lost-and-found | hermes_cli/session_lost_and_found.py | 損壞 DB 救援 | N/A | SQLite 專屬（SE Agent JSONL 自修） |
| 崩潰後自動續跑 | hermes_cli/session_recovery.py | 重啟恢復 | ✅ | daemon 恢復中斷 session（seagent-kernel/daemon.rs） |
| 子代理 live log | tools/delegation_live_log.py | 可 tail 的子代理逐字稿 | 🚧 | 子 session 有 parent 關係（kernel.rs:317）可 attach；無專屬 live log |
| 軌跡存檔 | agent/trajectory.py | from/value 格式存軌跡 | ⬜ | — |
| HF trace 上傳 | agent/trace_upload.py | 以 Claude Code JSONL 上傳 Hugging Face | ⬜ | — |

## 14. 排程與自動化

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| cron 排程器 | cron/scheduler*.py, jobs.py | cron 運算、工作執行、鎖、存活 | ✅ | seagent-kernel/cron.rs（5 欄＋@every）、automation.rs、daemon 排程 |
| cron 投遞到平台（deliver/failure_deliver） | cron/scheduler_delivery.py, delivery_queue.py | 結果送到指定 channel，失敗另送 | ⬜ | Job 無 deliver 欄（automation.rs:63） |
| cron 技能/腳本/no_agent | cron/scheduler_script.py | 附技能、純腳本工作 | ⬜ | — |
| cron prompt 威脅掃描 | tools/cronjob_prompt_scan.py | 掃 cron 提示注入 | ⬜ | — |
| cron incidents / runs / notepad / monitor | cron/incidents.py, notepad.py, monitor.py | 事故紀錄、執行歷史、筆記、監看 | 🚧 | last_run/last_result/last_session（automation.rs:77–81） |
| cron 每工作預算 | cron/quota_hold.py | 額度控管 | ✅ | Job.budget（automation.rs:83） |
| cron 外部供應商 chronos | plugins/cron_providers/chronos | 外部排程後端 | ⬜ | — |
| 自動化建議 | cron/suggestions.py, suggestion_catalog.py | 依使用建議自動化 | ⬜ | — |
| Goals（Ralph loop） | hermes_cli/goals.py | 每回合後輔助模型判斷是否達成 | ✅ | goal＋`goal_done`、max_rounds、budget（automation.rs:202） |
| Subgoals | hermes_cli/goal_command.py | 目標附加準則 | ⬜ | — |
| Session heartbeat | hermes_cli/heartbeat.py | 閒置重入提示 | 🚧 | schedule @every --reuse |
| /loop | hermes_cli/loops.py | session 內循環 | 🚧 | 同上 |
| 外送 webhooks（hooks.outbound） | agent/outbound_webhooks.py | pre/post_tool 等事件 POST 到 URL（HMAC） | ⬜ | hooks 只有 shell 與外掛（seagent-kernel/hooks.rs） |
| shell hooks | agent/shell_hooks.py | 設定 hook 指令＋首次同意 | ✅ | Claude Code 相容 shell hooks（hooks.rs，10 種事件） |
| 週期維護排程器 | agent/periodic_scheduler.py | 單一計時執行緒 | N/A | Python 執行緒管理細節 |

## 15. 委派／子代理

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 同步子代理 | tools/delegate_tool.py | 新對話、自身 task_id、回摘要 | ✅ | `spawn`（seagent-tools/agent.rs）、子 session |
| 批次 tasks[] | tools/delegate_tool_tasks.py, delegate_tool_dispatch.py | 一次派多子代理 | 🚧 | 模型可平行多次呼叫 spawn（parallel_safe）；無批次參數 |
| 背景（async）委派 | tools/async_delegation*.py | background=true，完成回報，崩潰恢復提示 | ⬜ | — |
| 子代理 list/steer/stop | tools/delegate_tool_registry.py | 模型控制活躍子代理 | ⬜ | — |
| output_schema 結構化輸出 | tools/delegation_output_schema.py | 子代理依 JSON Schema 回報 | ⬜ | — |
| worktree 隔離 | tools/subagent_worktree.py | 子代理各自 git worktree | ⬜ | — |
| 子代理工具集限制 | tools/delegate_tool_toolsets.py | 子代理可/不可用工具 | ✅ | spawn `tools` 參數 |
| fork 父對話 | tools/delegate_tool.py | 帶上下文 | ✅ | spawn `fork=true` |
| 子代理模型/憑證覆蓋 | tools/delegate_tool_config.py | delegation.* 模型與供應商 | ✅ | spawn `model`、`model.subagent`（config.rs:88） |
| 深度上限 | tools/delegate_tool_config.py | 最大巢狀 | ✅ | runner.max_spawn_depth（config.rs:104） |
| 成本彙整／預算共享 | tools/delegate_tool_results.py | 子代理成本加總 | ✅ | ledger 子代理扣自己與所有祖先（seagent-kernel/ledger.rs） |
| 子代理輸出遮蔽 | tools/delegation_redaction.py | 回傳前遮秘密 | ✅ | vault redact 全域 |
| 子代理生命週期 API（外掛） | agent/subagent_lifecycle.py | 外掛觀察子代理 | 🚧 | SessionStart/End hook（hooks.rs） |
| /review 獨立審查代理 | agent/review_engine.py | 背景全權限審查子代理 | ⬜ | — |
| 外部 ACP 代理委派 | （Hermes copilot_acp_client） | 驅動外部 ACP 代理 | ✅ | `acp_delegate`、`seagent acp-client`（parity.md 範疇） |

## 16. 語音

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| CLI 語音模式（PTT＋播放） | tools/voice_mode.py, hermes_cli/voice.py | 錄音→STT→回合→TTS 播放 | ⬜ | node `talk.ptt.*` 只錄音＋轉錄（seagent-app/node/talk.rs） |
| 喚醒詞 Hey Hermes | tools/wake_word.py, wake_word_engines.py | openWakeWord/sherpa-onnx/Porcupine | ⬜ | — |
| GPT-Live 全雙工 | tools/voice_live.py | 即時語音前端委派 Hermes | ⬜ | — |
| 語音逐字稿過濾 | tools/voice_mode_transcript.py | Whisper 幻覺、停止詞、回音防護 | ⬜ | — |
| gateway 語音訊息自動轉錄 | tools/transcription_tools.py | 平台語音→文字 | 🚧 | 部分 channel 用平台自帶轉寫（qqbot.rs:31、discord_voice）；無通用 STT |
| gateway 自動 TTS 回覆 | tools/tts_tool.py | 語音回覆 | 🚧 | Discord 語音頻道會念回覆（seagent-channel/discord.rs:23）；無通用 TTS |
| 桌面語音設定 / STT lease | tools/voice_client_config.py, stt_lease.py | 桌面直連語音 | N/A | 桌面 GUI |

## 17. 模型供應商與路由

SE Agent 預設（seagent-model/lib.rs:59）：openai, openai-chat, anthropic, gemini, deepseek, openrouter, groq, xai, mistral, together, fireworks, ollama, lmstudio, vllm, dashscope, moonshot, zhipu, siliconflow, minimax；任意 OpenAI/Anthropic/Gemini/Responses 相容端點可在 `[providers.x]` 自訂（seagent/providers.rs）。下表「🚧 config」= 無 preset，但能手動用 `format=openai_chat` 等設定。

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| actual | plugins/model-providers/actual | api.actual.inc | 🚧 | config |
| ai-gateway / vercel | plugins/model-providers/ai-gateway | Vercel AI Gateway | 🚧 | config |
| alibaba | plugins/model-providers/alibaba | DashScope 國際 | ✅ | preset `dashscope` |
| alibaba-coding-plan | plugins/model-providers/alibaba-coding-plan | 阿里 coding plan | 🚧 | config |
| anthropic | plugins/model-providers/anthropic | Anthropic Messages（含 OAuth/思考重播） | ✅ | preset `anthropic`（seagent-model/anthropic.rs）；無 Claude 訂閱 OAuth |
| arcee | plugins/model-providers/arcee | Arcee | 🚧 | config |
| azure-foundry | plugins/model-providers/azure-foundry | Azure AI Foundry（Entra ID） | 🚧 | api-key 可經 headers；無 Entra ID/api-version 偵測 |
| bedrock | plugins/model-providers/bedrock, agent/bedrock_adapter.py | AWS Bedrock SigV4 | ⬜ | — |
| commandcode | plugins/model-providers/commandcode | Command Code | 🚧 | config |
| copilot / github-copilot | plugins/model-providers/copilot | GitHub Copilot OAuth | ⬜ | — |
| copilot-acp | plugins/model-providers/copilot-acp, agent/copilot_acp_client.py | 經 `copilot --acp` 當模型 | 🚧 | `acp-client` 可驅動外部 ACP 代理（seagent-app/acp_client.rs），非模型供應商 |
| custom | plugins/model-providers/custom | 自訂端點 | ✅ | `[providers.*]` |
| deepinfra | plugins/model-providers/deepinfra | DeepInfra | 🚧 | config |
| deepseek | plugins/model-providers/deepseek | DeepSeek | ✅ | preset |
| fireworks | plugins/model-providers/fireworks | Fireworks | ✅ | preset |
| gemini | plugins/model-providers/gemini, agent/gemini_native_adapter.py | Gemini 原生 | ✅ | preset＋seagent-model/gemini.rs |
| gmi | plugins/model-providers/gmi | GMI Cloud | 🚧 | config |
| huggingface | plugins/model-providers/huggingface | HF Inference | 🚧 | config |
| kilocode / kilo | plugins/model-providers/kilocode | Kilo gateway | 🚧 | config |
| kimi-coding / kimi-for-coding | plugins/model-providers/kimi-coding | Kimi coding 方案 | 🚧 | 一般 Kimi 用 preset `moonshot`；coding 端點需 config |
| lmstudio | plugins/model-providers/lmstudio, agent/lmstudio_reasoning.py | LM Studio（推理控制） | ✅ | preset |
| meta-ai | plugins/model-providers/meta-ai | Meta AI API | 🚧 | config |
| minimax | plugins/model-providers/minimax | MiniMax 國際 | ✅ | preset |
| minimax-cn | hermes_cli/providers.py | MiniMax 中國 | 🚧 | config |
| minimax-oauth | hermes_cli/providers.py, auth_minimax.py | MiniMax OAuth | ⬜ | — |
| nebius-token-factory | plugins/model-providers/nebius-token-factory | Nebius | 🚧 | config |
| nous | plugins/model-providers/nous | Nous Portal（OAuth） | ⬜ | — |
| novita | plugins/model-providers/novita | Novita | 🚧 | config |
| nvidia | plugins/model-providers/nvidia | NVIDIA build | 🚧 | config |
| ollama-cloud | plugins/model-providers/ollama-cloud | ollama.com 雲端 | 🚧 | 本機 `ollama` preset 有；雲端需 config |
| openai-api | hermes_cli/providers.py | OpenAI API key | ✅ | preset `openai`（Responses）/`openai-chat` |
| openai-codex | plugins/model-providers/openai-codex | ChatGPT 帳號 Codex backend（OAuth） | ⬜ | — |
| opencode-zen / opencode-go | plugins/model-providers/opencode-zen | OpenCode | 🚧 | config |
| openrouter | plugins/model-providers/openrouter | OpenRouter | ✅ | preset |
| qwen-oauth | plugins/model-providers/qwen-oauth | Qwen portal OAuth | ⬜ | — |
| router | plugins/model-providers/router | router.com | 🚧 | config |
| solstice | plugins/model-providers/solstice | Nous portal Solstice | N/A | Nous 自家服務 |
| stepfun | plugins/model-providers/stepfun | 階躍 | 🚧 | config |
| tencent-tokenhub / tokenplan | plugins/model-providers/tencent-tokenhub | 騰訊 | 🚧 | config |
| upstage | plugins/model-providers/upstage | Upstage | 🚧 | config |
| vertex | plugins/model-providers/vertex, agent/vertex_adapter.py | Vertex AI（Google OAuth） | ⬜ | — |
| xai | plugins/model-providers/xai | xAI | ✅ | preset |
| xai-oauth | hermes_cli/auth_xai.py | xAI 帳號 OAuth | ⬜ | — |
| xiaomi | plugins/model-providers/xiaomi | 小米 MiMo | 🚧 | config |
| zai | plugins/model-providers/zai | Z.ai 國際 | 🚧 | preset `zhipu` 是 bigmodel.cn；z.ai 需 config |
| 供應商外掛註冊 | providers/base.py, agent/provider_registry.py | 外掛新增供應商/transport | ✅ | 外掛 `providers` 能力（seagent-plugin/plugin.rs:14、seagent/providers.rs register） |
| wire 格式：chat/responses/anthropic/gemini | agent/transports/* | 四種協定（另 bedrock、codex app-server） | ✅ | seagent-model openai_chat/responses/anthropic/gemini |
| fallback 鏈 | agent/fallback_cooldown.py, hermes_cli/fallback_config.py | 主模型失敗依序備援、冷卻 | ✅ | model.fallback（seagent-kernel/kernel.rs:747）；無冷卻 |
| 憑證池（同供應商多金鑰輪替） | agent/credential_pool*.py | 多 key failover、模型冷卻 | ⬜ | — |
| 供應商 OAuth（device/PKCE） | hermes_cli/auth*.py | 各家帳號登入 | ⬜ | — |
| key_cmd 動態金鑰 | agent/command_token_source.py | 執行指令取得短效 key | ⬜ | — |
| 輔助模型路由（每任務） | agent/auxiliary_client*.py, auxiliary_task_config.py | vision/壓縮/標題/搜尋各自模型、健康與 fallback | 🚧 | 單一 `model.aux`（config.rs:86） |
| 模型清單偵測 | hermes_cli/models_detect.py, inventory.py | 列可用模型 | ✅ | `list_models` GET /models（seagent-model/lib.rs） |
| 昂貴模型確認 | hermes_cli/model_cost_guard.py | 選貴模型前確認 | ⬜ | — |
| 資料政策確認 | hermes_cli/model_data_policy_guard.py | 會拿提示訓練的方案警告 | 🚧 | compliance government 擋 PRC 供應商（config.rs:68），非逐方案警告 |
| 推理強度 | agent/reasoning_effort.py, reasoning_params.py | 跨供應商 effort 對應 | 🚧 | thinking level→reasoning（context.rs:188），只能經 ACP 設 |
| 推理摘要/重播 | agent/reasoning_summaries.py, anthropic_thinking_replay.py | 推理內容保存與跨回合重播 | ✅ | encrypted reasoning 回傳（seagent-model/responses.rs:41）、跨供應商剝除簽章（kernel.rs:811） |
| Fast mode / service tier | agent/fast_mode.py | priority/ultrafast 窗 | ⬜ | — |
| Codex app-server 執行期 | agent/codex_runtime.py, transports/codex_app_server*.py | 改用 codex app-server 跑回合 | ⬜ | — |
| 受管本機 llama-server | agent/auxiliary_local_runtime.py, hermes_cli/local_runtime | 自動管理本機推論 | ⬜ | — |
| Mixture of Agents | agent/moa_loop.py, moa_trace.py | 多參考模型扇出＋聚合 | ⬜ | — |
| 速率限制追蹤 | agent/rate_limit_tracker.py | 解析 header 預判限流 | 🚧 | 錯誤分類含 rate limit 並重試（seagent-model/classify.rs） |
| 重試抖動退避 | agent/retry_utils.py | jittered backoff | ✅ | runner.retry_base_ms/max_ms（config.rs:97） |
| 串流 watchdog / 閒置逾時 | agent/auxiliary_stream_watchdog.py | 串流卡住偵測 | ✅ | idle_timeout_secs（seagent-model/lib.rs build_with_idle） |
| Proxy 繞過/自訂 CA | agent/proxy_bypass.py, ssl_verify.py | 企業網路 | ⬜ | — |

## 18. 成本與用量

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 成本估算 | agent/usage_pricing.py | 依價格表估每回合成本 | 🚧 | ledger＋`[prices]` 手動價格（seagent-kernel/ledger.rs、config.rs:18）；無內建價格表 |
| 預算上限 | hermes_cli/model_cost_guard.py, budget | token/金額上限 | ✅ | budget.max_tokens/max_cost_usd、`--budget-usd`（main.rs:292） |
| Insights 分析 | agent/insights.py | 工具/技能/模型/平台使用統計 | ⬜ | — |
| 帳號用量與速率窗 | agent/account_usage.py | 顯示供應商用量窗 | ⬜ | — |
| Nous credits / 帳單 | agent/credits_tracker.py, billing_*.py | Nous 額度 | N/A | Nous 自家帳務 |
| 輔助呼叫計帳 | agent/aux_accounting.py | aux 呼叫算入 session | ⬜ | ledger.charge 只在主回合（seagent-kernel/kernel.rs:629）；壓縮/回顧等 aux 呼叫不計 |

## 19. 外掛系統

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| 外掛載入與 manifest | hermes_cli/plugins*.py, plugins/plugin_loader.py | 外掛發現、manifest、啟用 | ✅ | SE Agent 外掛協議 v1（MCP 超集，seagent-plugin/plugin.rs） |
| 外掛 hooks | hermes_cli/plugin_events.py | pre/post tool、session 事件 | ✅ | `hooks` 能力 |
| 外掛 middleware | hermes_cli/middleware.py | 改寫請求/包住動作 | ✅ | `middleware` 能力（tool_request、llm_execution） |
| 外掛註冊工具/供應商/TTS/STT/瀏覽器/影像/影片/web 後端 | agent/*_provider.py, *_registry.py | 多種擴充點 | 🚧 | 工具/模型供應商/channel/記憶/context engine 有；TTS/STT/瀏覽器/影像/影片/web 後端擴充點無 |
| 外掛 LLM 存取 ctx.llm | agent/plugin_llm.py | 外掛借用主機 LLM | ✅ | MCP sampling（seagent/ext.rs sampling_request） |
| 外掛串流 hook | agent/plugin_stream_hooks.py | 觀察 LLM 串流 | ⬜ | seagent-plugin/events.rs 是 MCP 事件訂閱；外掛 hook 無 delta 事件 |
| 外掛隔離（子行程 host） | hermes_cli/plugin_host*.py, plugin_isolation.py | 外掛獨立行程 | ✅ | 外掛本就是 stdio 子行程 |
| 外掛安裝掃描（plugin guard） | tools/plugin_guard.py | 安裝時威脅掃描 | ⬜ | — |
| 外掛目錄（706 個 yaml） | plugin-catalog/*.yaml | tools/desktop/memory/models/automation… | ⬜ | 無目錄與安裝 |
| 外掛 UI/dashboard 分頁 | hermes_cli/plugin_validate_desktop.py | 外掛 UI | ✅ | `ui` 能力＋web plugins.ui（ui/web/app.js） |
| 內建外掛 disk-cleanup | plugins/disk-cleanup | 磁碟清理 | ⬜ | — |
| 內建外掛 security-guidance | plugins/security-guidance | 安全指引樣式 | ⬜ | — |
| 內建外掛 hermes-achievements | plugins/hermes-achievements | 成就儀表板 | ⬜ | — |
| 內建外掛 dashboard_auth（basic/nous/self_hosted） | plugins/dashboard_auth | 儀表板登入 | 🚧 | web UI 用 bearer token（seagent-app/server.rs） |

## 20. Profile／設定／秘密

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Profiles（多隔離實例） | hermes_cli/profiles*.py | 各自設定、技能、記憶、gateway | ⬜ | 只有 `SEAGENT_HOME` |
| 分層設定 | hermes_cli/config*.py | 預設/使用者/專案、遷移、備份 | ✅ | 預設→使用者→專案 `.seagent/config.toml`＋未信任專案過濾（seagent-kernel/config.rs:203） |
| 設定遷移與備份 | hermes_cli/config_migrations.py, config_backups.py | 版本升級遷移 | ⬜ | — |
| .env 載入 | hermes_cli/env_loader.py | ~/.hermes/.env | ⬜ | 用 vault/環境變數 |
| 本機秘密庫 | hermes_cli/secrets_cli.py | 秘密管理 | ✅ | `seagent secrets`（stdin 讀值）＋`{{secret:NAME}}` |
| 外部秘密來源 Bitwarden/1Password/command | agent/secret_sources/* | 啟動時注入 | ⬜ | — |
| 首次 onboarding | agent/onboarding*.py | 情境提示與首跑流程 | 🚧 | `seagent setup` 精靈 |
| 啟動提示 tips | hermes_cli/tips.py | 隨機功能提示 | ⬜ | — |
| 終端通知 OSC 9/777 | hermes_cli/terminal_notify.py | 完成時桌面通知 | ⬜ | — |

## 21. 批次／研究／評測

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| batch_runner | batch_runner.py | JSONL 資料集平行跑代理、checkpoint resume、軌跡、工具統計 | ⬜ | — |
| mini_swe_runner | mini_swe_runner.py | 在 local/docker/modal 跑任務並輸出軌跡 | ⬜ | — |
| trajectory_compressor | trajectory_compressor.py | 軌跡壓到 token 預算 | ⬜ | — |
| toolset_distributions | toolset_distributions.py | 資料生成時隨機抽 toolset | ⬜ | — |
| evals/ | evals/* | 行為探測與回歸評測 | 🚧 | SE Agent 有整合測試（seagent-kernel/tests/runner.rs），非評測框架 |
| RL（`hermes rl`） | hermes_cli/main.py `_AGENT_COMMANDS` | 遺留入口，未見實作 | N/A | 未見實作模組 |

## 22. 桌面／TUI／Web 前端

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Electron 桌面 app | apps/desktop | 原生桌面 GUI | N/A | Hermes 桌面 |
| TUI（ui-tui＋tui_gateway） | ui-tui, tui_gateway | 全螢幕 TUI、JSON-RPC gateway | ✅ | `seagent tui`（seagent-app/tui.rs）＋ARP |
| 經典 CLI（prompt_toolkit）live dock | hermes_cli/cli_subagent_monitor.py, cli_process_dock.py | 子代理/行程/目標/佇列面板 | ⬜ | — |
| 狀態列（git 分支、電量、context） | hermes_cli/cli_status_bar_mixin.py, status_bar_git.py | 狀態列 | ⬜ | — |
| Web 儀表板 | web/, hermes_cli/web_server*.py | 設定、session、cron、MCP、記憶、檔案頁 | 🚧 | web UI 有 session/核准/node/外掛 UI（ui/web/app.js）；無設定/cron/記憶/檔案頁 |
| OpenAI 相容 API server | gateway（hermes-api-server toolset） | 全代理經 HTTP | ✅ | seagent-app/openai.rs |
| mcp_serve 對話工具 | mcp_serve.py | 經 MCP 操作對話與核准 | ✅ | `seagent mcp serve`＋seagent_session*（seagent-app/conversations.rs） |
| Hosted rooms / 群組聊天 | tui_gateway/hosted_room_*.py | 多人房間 | ⬜ | — |
| 學習星圖 / journey | agent/learning_graph*.py | 學到什麼的視覺化 | ⬜ | — |
| Petdex 寵物 | agent/pet | 動畫吉祥物 | ⬜ | — |
| Skins | hermes_cli/skin_engine.py | 主題 | ⬜ | — |

## 23. 其他代理層功能

| item | Hermes source file | what it does | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| LSP 整合 | agent/lsp/* | 真實語言伺服器診斷回饋到編輯 | ⬜ | — |
| verify 子系統 | agent/verify/* | 偵測專案 run recipe 並驗證 | ⬜ | — |
| /init AGENTS.md 產生 | hermes_cli/init_command.py | repo 掃描產生指令檔 | ⬜ | — |
| /learn | agent/learn_prompt.py | 從任意描述產技能 | ⬜ | — |
| /plan 計畫模式 | agent/plan_prompt.py | 只輸出計畫檔 | ⬜ | — |
| 反應偵測（vibe） | agent/reactions.py | 偵測使用者感謝/喜愛 | ⬜ | — |
| git worktree 管理 | hermes_cli/worktree_*.py | 建/清/保留 worktree | ⬜ | — |
| 監控 OTLP 匯出 | agent/monitoring/* | gateway 健康與遮蔽診斷 OTLP | ⬜ | — |
| Google Meet 外掛 | plugins/google_meet | 入會、轉錄、realtime 發言 | ⬜ | （§3 工具） |
| 記憶體回收 malloc_trim | hermes_cli/mem_trim.py | 長駐行程釋放記憶體 | N/A | Python/glibc 專屬 |
| optional-mcps（65 個預設 MCP） | optional-mcps/* | airtable…wordpress-com 一鍵 MCP 預設 | ⬜ | SE Agent 需手動 `seagent mcp add`；無目錄 |

---

## 統計

共 589 列（依第 4 欄計數）：

| 狀態 | 數量 | 比例 |
|---|---|---|
| ✅ 已有 | 96 | 16% |
| 🚧 部分 | 145 | 25% |
| ⬜ 缺 | 312 | 53% |
| N/A | 36 | 6% |

註：內容型項目各算一列（skills/ 58 個、optional-skills 153 個、optional-mcps 65 個、plugin-catalog 706 個未逐一展開）。

## ⬜／🚧 依使用者影響排序（前 40）

1. **web_search**（＋11 個後端、快取、免金鑰 rescue）— 完全沒有搜尋，研究類任務直接卡住。
2. **web_extract 完整版** — 只有單 URL 純文字 fetch；缺 PDF、批次、乾淨 markdown、長頁截斷存檔。
3. **vision_analyze**（載入本機/URL 圖片給模型）— 截圖、設計稿、錯誤畫面都看不到。
4. **內建瀏覽器工具組**（navigate/snapshot/click/type/scroll/back/press/images/vision/console＋本機 Chromium 自動啟動）— 目前只能經配對 node＋使用者自開 CDP Chrome。
5. **delegate_task 進階**：背景委派、list/steer/stop、批次 tasks[]、output_schema、worktree 隔離。
6. **terminal 進階**：PTY、session 狀態延續（cd/export）、遠端後端（docker/ssh/modal/daytona/singularity/vercel）、sudo 管線、ANSI 去除、子行程秘密清洗。
7. **process_manage 進階**：stdin write/submit、完成通知、跨重啟保存。
8. **patch 模糊比對（9 策略）＋V4A 格式** — 模型小幅縮排差異就失敗、多輪重試。
9. **cronjob_manage 模型工具＋cron 投遞到 channel**（deliver/failure_deliver、skills、script）。
10. **技能 hub**（官方/GitHub/ClawHub/skills.sh 搜尋與安裝）＋Skills Guard 掃描。
11. **text_to_speech＋STT**（gateway 語音訊息轉錄、語音回覆、本機 whisper）。
12. **SSRF 私網封鎖** — web_fetch 可打內網/metadata 端點（安全）。
13. **threat_patterns 注入掃描**（context 檔、記憶寫入、cron prompt）（安全）。
14. **憑證池＋供應商 OAuth**（Codex/ChatGPT、Copilot、Nous、Qwen、xAI、MiniMax、Vertex、Bedrock）。
15. **image_generate**（FAL/OpenAI/xAI/OpenRouter…）。
16. **clarify 多選/批次問題** — ask_user 只能自由文字。
17. **session_search 讀取/捲動/篩選模式**。
18. **@-參照（@file/@folder/@diff/@url）**＋子目錄 AGENTS.md 漸進載入。
19. **read_file 文件抽取**（PDF/DOCX/XLSX/ipynb）＋相似檔名提示。
20. **對話回合 rewind／/undo N／/retry**。
21. **Profiles**（多隔離實例、匯出匯入）。
22. **computer_use 本機直用**（cua-driver，跨平台）— 目前需 Linux node。
23. **smart 核准＋/yolo 執行中切換＋hardline floors＋approvals suggest**。
24. **memory provider 生態**（MemoryManager prefetch/flush hook、byterover/retaindb 等）。
25. **execute_code 常駐 kernel**（狀態跨呼叫）。
26. **斜線指令缺口**：/retry /title /history /save /branch(聊天內) /context /reasoning /tools /yolo /approvals /btw /plan /review /init /learn /diff。
27. **技能自我演化**：skill_manage patch/批次、curator、ledger 回滾、背景回顧寫技能、/refine。
28. **tool_search BM25 查詢**（目前只有 describe/call 索引）。
29. **Mixture of Agents（/moa）**。
30. **x_search**（X/Twitter 搜尋）。
31. **Kanban 多代理看板**（15 工具＋派工器＋decompose/specify）。
32. **LSP 診斷與寫後 lint**。
33. **video_analyze / video_generate / xAI video edit/extend**。
34. **外送 webhooks（hooks.outbound）**。
35. **模型中繼資料（models.dev）＋內建價格表＋insights**。
36. **CLI 管理缺口**：config set/unset/edit、plugins install/update、skills/*、tools enable/disable、sessions prune/archive/rename、logs、update、completion、backup/import。
37. **語音模式（PTT＋喚醒詞＋GPT-Live）**。
38. **Discord/Feishu/元寶/Google Meet 平台工具**（channel 有，但模型不能主動查群、讀文件、管伺服器）。
39. **browser_vault 模型盲填表＋外部秘密來源（Bitwarden/1Password）**。
40. **batch_runner / mini_swe_runner / trajectory 工具鏈**（研究/資料生成用途）。

> 附註：SE Agent 獨有、Hermes 無對應者（不計入）：government 合規模式與 PRC 供應商封鎖（seagent-kernel/config.rs:59）、`channel_send` 模型工具、節點相機/定位/手機指令。
