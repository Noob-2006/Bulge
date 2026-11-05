# 缺失名單（2026-11-03 重新盤點）

由兩個唯讀稽核代理逐份編譯、測試，並逐列對照 `hermes-inventory.md`／`openclaw-inventory.md` 判定。判定標準：
- ✅ 已實作、**已接線**（使用者或模型實際用得到）、且有測試涵蓋。
- 🚧 有程式但未接線、未測試、測試失敗、是空殼，或缺上游子功能。
- ⬜ 沒有。　N/A 有具體理由才標。

每列細節（證據檔案與函式）見同目錄 `<組>.md`；原始測試輸出見 `<組>-tests.txt`。
所有副本另有 2 個 `coderun` 測試失敗，原因是稽核用的 TMPDIR 路徑過長（unix socket 超過 SUN_LEN），不計入。

## 總覽

| 組 | 範圍 | 建置／測試 | ✅ | 🚧 | ⬜ | N/A | 合計 |
|---|---|---|---|---|---|---|---|
| web | 網路搜尋／擷取 | 可編譯；1 個真實失敗 | 0 | 39 | 4 | 0 | 43 |
| media | 媒體：視覺、語音、生成 | **無法編譯**（image_gen 宣告 15 個不存在的模組） | 0 | 9 | 59 | 3 | 71 |
| browser | 瀏覽器與電腦操作 | **無法編譯**（ark-app 3 處） | 0 | 56 | 4 | 0 | 60 |
| exec | 終端機、程序、沙箱後端 | 可編譯；1 個真實失敗（bwrap 網路隔離無效） | 17 | 29 | 15 | 1 | 62 |
| security | 核准與安全 | 可編譯；2 個失敗（skills_guard） | 29 | 17 | 1 | 3 | 50 |
| agents | 委派、session、多代理 | 可編譯；1 個真實失敗（decision 機率對應） | 35 | 45 | 13 | 2 | 95 |
| automation | 排程、看板、訊息工具 | **無法編譯**（parked worktree 合併損壞，kernel 53 個錯誤） | 17 | 60 | 34 | 1 | 112 |
| skills | 技能、記憶、上下文 | 可編譯；2 個真實失敗（ark-memory） | 21 | 56 | 98 | 9 | 184 |
| ops | 指令、UI、維運 | 可編譯；全過 | 119 | 41 | 76 | 17 | 253 |
| models | 模型供應商與用量 | 可編譯；全過，e2e 37/37 | 122 | 7 | 0 | 4 | 133 |
| **合計** | | | **360** | **359** | **304** | **40** | **1063** |

合計列數含兩份清單中原本已完成的項目，各組之間也有少量重疊（例如 SSRF、env 清洗同時出現在 web／security／exec）。

## 共通問題（先修這些，成本最低）

1. **三份副本無法編譯**：media、browser、automation。browser 只差 3 處編譯錯誤，修好就能讓約 39 項由 🚧 轉 ✅。
2. **大量程式「寫了沒接線」**：web 的 17 家搜尋供應商、exec 的 ExecBackend、agents 的 Runtime::delegate、skills 的 ark-memory／refs／toolsearch、security 的審批轉發，都沒有註冊成工具或指令。接線是這輪最划算的工作。
3. **空殼模組**：ops 有 6 個已註冊但沒內容（telemetry、doctor、secretsrc、batch、evals、status）；media 的 TTS／STT／視覺等是骨架；skills 的 hub／Guard／ledger 是 stub。
4. **迴歸**：skills 副本把 `ark memory accept/reject` 導到 stub；ops 的 TUI 忽略 /new、/clear、/quit；security 的 `/pause` 不會真的停。
5. **跨組重複**：SSRF（web `ssrf.rs` 與 security `url_safety`）、env 清洗（security 與 exec）、網站封鎖清單（web 與 security），合併時要擇一。

## 各組剩餘缺口（依使用者影響排序）

### web：網路搜尋／擷取

1. web_search（Hermes／OpenClaw 兩列）— 引擎完整，缺把 `WebSearch` 註冊進 `builtin_tools()`（需傳入 `WebConfig` 與 env/vault 查找）。
2. `[web]` 設定 — kernel `Config` 需加 `web` 欄位（或 toml::Table 直通），否則所有 provider 選擇、links、blocklist 都無法設定，寫了還會讓 config 解析失敗。
3. web_fetch — 仍是舊版：缺 SSRF（`ssrf::guarded_agent`）、readability→markdown、PDF、快取、截斷＋存檔、firecrawl 後援。
4. SSRF 私網封鎖 — `ssrf.rs` 完整，但未套用到已註冊的 web_fetch。
5. web_extract — `extract.rs` 空殼；需寫工具本體並串接 provider `extract()`、readability、pdf、truncate、DiskCache。
6. 連結理解 — 已呼叫，但因設定無法開啟而形同死碼；另缺 ext.rs 整合測試。
7. 所有搜尋後端（Hermes 11 個、OpenClaw 15 個）— 程式與測試在，隨 web_search 接線即可使用。
8. keyless MCP ring — 隨 web_search 接線；extract 側無入口。
9. web 結果快取 — search memo 可用；extract/fetch 磁碟快取未接。
10. x_search（兩列）— 缺註冊。
11. firecrawl_search / firecrawl_scrape — 缺註冊。
12. web-readability／web_fetch 供應商鏈 — 缺被 web_fetch 呼叫。
13. tavily_search / tavily_extract — `vendor_tools.rs` 空殼，缺兩個專用工具。
14. github_read / github_search — `github.rs` 空殼，全缺。
15. web CLI 指令 — 缺 `ark web providers`（錯誤訊息已引用）等。
16. Wizard web search 設定 — setup.rs 缺搜尋供應商步驟。

### media：媒體：視覺、語音、生成

1. 🚧 接線：沒有任何 crate 依賴 `ark-media`；`ark_media::tools()` 沒有註冊進工具清單（ark-tools/lib.rs 或 kernel），`[media]` 設定也沒有接進主設定。
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

### browser：瀏覽器與電腦操作

0. 🚧 **編譯錯誤（擋住全部 39 列 ✅）**：`ark-app/src/server.rs:166` match 型別、`browser_view.rs:213/223` ureq API 不符、`ark-browser/src/cloud.rs:288-318` 參數數量。修好後需跑 `cargo test -p ark-browser`（含 `--ignored real_chromium_end_to_end`，本機有 chromium）。

1. 🚧 computer_use（Hermes）：沒有註冊任何本機 `computer_use` 工具，沒配對 node 就不能控制桌面；`computer/backend.rs`、`config.rs` 沒宣告 `mod`，不會編譯。
2. 🚧 computer（OpenClaw gateway 本機）：沒有本機 `computer` 工具；zoom/drag/set_value/menus 仍只有 node 版的子集。
3. 🚧 cua-driver 後端：MCP stdio 驅動只存在於死碼。
4. 🚧 cua-computer：同上。
5. 🚧 本機 Chromium 自動安裝：找不到瀏覽器只回錯誤，不會下載安裝。
6. 🚧 Bot Desktop：沒有無頭 Xvfb/Xfce＋RFB 啟動器，只有 lease 狀態機。
7. ⬜ /browser 斜線指令：`control.rs` 只有一行註解。
8. ⬜ browser close-profile CLI：沒有 `ark browser` 子指令。
9. ⬜ screen status/start/stop/install CLI：不存在（manager 卻假設 `ark screen start` 會寫 env 檔）。
10. ⬜ computer-use install/status/doctor/permissions/grant CLI：不存在。
11. 🚧 Sandbox browser（noVNC）：程式在，但 `packaging/sandbox-browser` 映像（Dockerfile）缺，啟動必失敗。
12. 🚧 extension router：relay 在，但 `ui/browser-extension` 擴充本體缺。
13. 🚧 瀏覽器／桌面檢視 UI：只有後端 API，`ui/web` 沒有面板。
14. 🚧 lightpanda：啟動與退回 Chrome 皆無測試。
15. 🚧 browser_exec：執行路徑無測試。
16. 🚧 act fill：無測試。
17. 🚧 act hover：無測試。
18. 🚧 act drag：無測試。
19. 🚧 browser focus：工具層無測試。
20. 🚧 browser close（分頁）：工具層無測試。
21. 🚧 Doctor 瀏覽器就緒：只有工具 action，沒接到 `ark doctor`。
22. （✅* 7 列：get_images、vault fill、status、start/stop、act select、act evaluate、download/text）只由 `#[ignore] real_chromium_end_to_end` 覆蓋，本機有 chromium/google-chrome，需執行 `cargo test -p ark-browser -- --ignored real_` 確認；失敗則降為 🚧。

### exec：終端機、程序、沙箱後端

1. 🚧 **ExecBackend 抽象沒接上**：`shell`/`job`/`run` 仍直接起 bash；需要在 binary 讀 `[exec]`、`exec::install`、改 shell/job/coderun 走 `ExecEnv::backend`，下面所有後端/沙箱列才算上線。
2. 🚧 **沙箱模式 off/non-main/all**：邏輯有了，但沒有 main-session 分類器、沒有設定入口、沒有工具包裝（`wrap_all` 沒呼叫）。
3. 🚧 **docker 後端**：stub，缺容器建立/掛載/使用者/cap-drop/PID 限制/egress 代理/prune。
4. 🚧 **process 互動（write/submit/send-keys/paste/close/clear/remove/handoff）**：只有 `write_stdin` 原語，沒有 `process` 工具或 job action。
5. 🚧 **背景早返回／yieldMs**：只有設定欄位，工具端沒實作。
6. 🚧 **PTY**：backend 支援，`shell` 沒有 pty 參數。
7. 🚧 **持久 cwd/export**：`session.rs` 是 stub。
8. 🚧 **本機 OS 沙箱 bwrap/landlock**：已實作，但 bwrap 網路隔離測試失敗；沒有工具使用；沒有 seccomp。
9. 🚧 **工作區存取 none/ro/rw**：沒接上。
10. 🚧 **沙箱工具政策**：`Sandboxed` 包裝沒套用。
11. 🚧 **沙箱 env 清洗／掛載驗證**：沒接上。
12. 🚧 **工作區 FS 政策**：`workspace_only` 打不開（`configure_files` 沒呼叫，`[files]` 讀不到）。
13. ⬜ **背景行程完成通知**：Notifier 從沒安裝。
14. 🚧 **ssh 後端**：stub。
15. 🚧 **podman 後端**：stub。
16. 🚧 **exec 主機路由**：沒接上，沒有 `/exec` 指令。
17. 🚧 **elevated**：沒接上，沒有 `/elevated`。
18. 🚧 **exec env 參數**：shell schema 沒有 env。
19. 🚧 **ANSI 去除**：`ansi.rs` 沒有 `mod`，不會編譯，shell 輸出沒有去除。
20. ⬜ **sudo 管線**：只有設定欄位。
21. ⬜ **失敗輸出提示**：只有設定欄位。
22. ⬜ **execute_code 常駐 kernel/reset**：coderun 未改。
23. ⬜ **execute_code env 清洗**：coderun 不清洗子行程 env。
24. ⬜ **execute_code 遠端後端**：不經 backend。
25. ⬜ **execute_code 呼叫預算**：沒有。
26. ⬜ **session／子代理 worktree 隔離**：沒有。
27. ⬜ **worktree CLI**：沒有。
28. ⬜ **/worktree 斜線指令**：沒有。
29. 🚧 **背景行程跨重啟保存**：只有 detach 原語，job 沒用。
30. 🚧 **process 200KB 滾動緩衝**：設定沒人用。
31. ⬜ **read_terminal/close_terminal**：沒有工具。
32. 🚧 **modal 後端**：程式碼與假 SDK 測試有，沒接上。
33. 🚧 **daytona 後端**：程式碼與假伺服器測試有，沒接上。
34. 🚧 **vercel 後端**：程式碼與假伺服器測試有，沒接上。
35. 🚧 **singularity/apptainer 後端**：stub。
36. 🚧 **OpenShell 後端**：stub。
37. 🚧 **外掛執行環境 provider**：沒有外掛註冊點，ExecEnv 也沒接上。
38. 🚧 **遠端檔案同步／憑證檔**：只供未接上的雲端後端使用。
39. 🚧 **沙箱範圍 session/agent/shared**：沒接上。
40. ⬜ **sandbox list/recreate/explain CLI**：沒有。
41. 🚧 **tokenjuice**：只有 JSON 輔助檔，沒有 reducer，沒有 `mod`。
42. ⬜ **hook 輸出溢出存檔**：hooks.rs 未改。
43. ⬜ **PTY 查詢回應**：沒有。
44. ⬜ **code_execution（xAI 託管）**：沒有。

### security：核准與安全

1. 🚧 核准轉送到聊天 channel：沒有程式把待核准項目（附 `appr:` 按鈕）送到 channel，也沒有把按鈕回呼／`/approve` 接到 `approver.answer`；目前 channel 按鈕只會變成一則使用者訊息。
2. 🚧 /approve（channel）：channel 入站路徑（ext.rs `handle_inbound`）沒有呼叫 `secgate::chat_command`，channel 使用者無法核准。
3. 🚧 SSRF／url_safety 政策層：`is_safe_url`/`configure` 沒有接到 `web_fetch`（或任何 HTTP 工具），只有 CLI check-url 用到（需與 web 串流整合）。
4. 🚧 ESTOP：`/pause` 沒有擋 channel 新回合（只擋 cron/goal），與回覆文字不符；daemon 層無測試。
5. 🚧 External content wrapping：`external_content.channels` 沒被讀取，webhook/email 入站訊息未包裝。
6. 🚧 egress 代理防火牆：`egress_proxy.rs` 沒在 lib.rs 宣告（死碼、測試不會跑），無設定鍵、無啟動點。
7. 🚧 skills_guard：掃描器完整但沒接到 skill 建立／安裝／載入路徑。
8. 🚧 /exec：`host=`/`node=` 只存起來，沒有任何 exec 路由使用；channel 不可用；無測試。
9. 🚧 Elevated mode：`on`/`ask` 沒有實際語意，沒有沙箱可逃出；channel 不可用、`allow_from` 不會生效。
10. 🚧 /elevated：只有 REPL/TUI/daemon；channel 不可用。
11. 🚧 egress 繞過殘餘風險：靜態分析已接線並有測試，但程式碼引用的 `docs/parity-agent/security.md` 不存在。
12. 🚧 記憶／技能寫入核准閘：已接線但無測試；記憶 `replace` 不經 staging。
13. 🚧 approvals test（`secgate::explain`）：無測試。
14. 🚧 approvals suggest（`secgate::suggest`）：無測試。
15. 🚧 exec-policy CLI：無測試。
16. 🚧 credential_files：沒有沙箱實際掛載（依賴 exec 串流）。
17. 🚧 沙箱 env 清洗／安全驗證：沒有沙箱掛載設定驗證（依賴 exec 串流）。
18. ⬜ security-guidance 內建外掛：完全沒有。

### agents：委派、session、多代理

1. delegate_task 工具（H§1）：完全沒有模型可見的 `delegate_task`；`Runtime::delegate` 只透過 spawn 單任務同步呼叫。
2. sessions_spawn（O§1）：無工具；背景生成、agentId、announce 都不可達。
3. 背景委派（H§15）：Background/Collect 模式無任何入口，daemon 未設 `auto_resume`，無測試。
4. 子代理 list/steer/stop（H§15）：`subagent_list/steer/stop` 零呼叫端、無測試。
5. subagents 工具（O§1）：無 list/cancel/wait 工具。
6. agents_wait（O§1）：`subagent_wait` 無工具、無測試。
7. sessions_yield（O§1）：`request_end_turn` 無工具呼叫。
8. 批次 tasks[]（H§15）：多 spec 能力無工具參數暴露。
9. output_schema（H§15）：spawn 不帶 schema；`spec_from` 只在測試用。
10. clarify（H§1）：`Approver::clarify` 無工具呼叫；web UI／channel 不渲染選項。
11. structured_output（O§1）：沒有任何方式設定 `OutputSchema`，工具永不出現。
12. decision_evaluate（O§1）：`DecisionEvaluate` 未註冊。
13. llm-task（O§2）：`LlmTask` 未註冊、`llm_task` 無測試。
14. Decisions runtime（O§8）：同上，provider 存在但不可用。
15. 對話 rewind（H§13）：Rewind 事件無產生者、無 kernel API、無測試。
16. /undo N（H§8）：仍只還原檔案。
17. /retry（H§8）：無。
18. /branch（H§8）：聊天內無、無依回合分支。
19. Multi-agent routing/bindings（O§8）：`agents::route` 未接到 channel 路由；無 CLI。
20. agents add/delete/bind（O§6）：無 `ark agents` CLI。
21. sessions_create（O§1）：`create_agent_session` 零呼叫端，無工具。
22. agents_list（O§1）：無工具。
23. sessions_list（O§1）：無 in-agent 工具。
24. sessions_history（O§1）：無 in-agent 工具。
25. sessions_send（O§1）：無 in-agent 工具。
26. sessions（設定）（O§1）：Meta 事件無產生者、無工具／CLI。
27. session_status（O§1）：無。
28. session_search 模式（H§1）：無 read/scroll/篩選/摘要。
29. users registry（O§8）：無 CLI，channel 不辨識使用者。
30. users CLI（O§6）：無。
31. /moa（H§8）：`moa_turn` 零呼叫端，無斜線指令、無 turn 層級測試。
32. moa CLI（H§9）：無 `ark moa`。
33. worktree 隔離（H§15）：spawn 不建 worktree。
34. Worktrees per-session（O§8）：不可達。
35. git worktree 管理（H§23）：無 CLI。
36. worktree list/prune/restore（H§9）：無 CLI、無 restore。
37. worktrees CLI（O§6）：無。
38. /worktree（H§8）：無。
39. Sub-agents announce/thread-bound/visible（O§8）：announce 不可達；無 thread-bound/visible。
40. 子代理生命週期 hooks（H§15）：新 hook 無測試，Delivery 不可達。
41. Hooks subagent_*（O§8）：同上。
42. 子代理 live log（H§13）：無測試；spawn 回傳不含路徑。
43. Steering queue modes（O§8）：仍固定 steer。
44. /queue（O§5）：無。
45. /steer（O§5）：無指令。
46. /agents（H§8）：無子代理面板。
47. /agents（O§5）：無。
48. /subagents（O§5）：無。
49. /session（O§5）：無。
50. /bg（H§8）：聊天內無。
51. sessions 23 子指令（H§9）：無 rename/prune/archive/pin/stats/import/repair。
52. /review（H§8）與 /review 審查代理（H§15）：無。
53. /learn（H§23、H§8）：無。
54. Session auto-reset（O§8）：只有 retention 刪除。
55. 監控 OTLP 匯出（H§23）：無。
56. Google Meet 外掛（H§23）：無（可能屬其他工作流）。

### automation：排程、看板、訊息工具

1. 【全域】合併損壞：hooks.rs 少 19 個 HookEvent 變體、main.rs 缺 5 個 mod 宣告、config 的 `kanban` 型別錯誤、缺 `surfaces` 欄位。整個 workspace 無法編譯，既有的 shell hooks 與 `ark webhook` 也因此退步。PROJECT_GATED 缺 `hooks_extra`（安全問題）。
2. automations／cronjob 模型工具（O§1 automations、H§1 cronjob_manage）：完全沒有，無 add/update/remove/list/run/runs/wake。
3. cron 投遞（H§14 deliver/failure_deliver、O§8 announce/webhook）：outbound.rs 投遞層已存在，但 Job 沒有 deliver 欄，也沒人呼叫 deliver；沒有 `@at` 一次性排程。
4. message 工具（O§1 message）：沒有模型工具。channel 端只有 discord/slack/telegram 的擴充動作；`normalize_poll` 不存在；send/edit/delete/react 沒有統一入口；其他 channel 沒實作。
5. Heartbeat（O§8 Heartbeat、O§1 heartbeat_respond、H§14 Session heartbeat、H§8 /heartbeat）：沒有執行器、active hours、投遞與回應工具；wake.rs 只是佇列。
6. Kanban 工具層（H§5 共 11 列工具）：tools/tests.rs 空，沒有工具層測試；orchestrator 工具（kanban_list/unblock）未註冊給任何 session。
7. Kanban 派工器（H§5）：dispatch/tests.rs 空；沒有 `ark kanban` CLI、`/kanban`（H§8）。
8. workboard_*（O§2）：39 個工具未註冊，workboard/tests.rs 空。
9. Surfaces 九項（canvas、show_widget、dashboard、gateway、progress_card、lobster、diffs、file transfer、team-reports，以及 O§8 session cards）：只差 config `surfaces` 欄位；gateway 缺 config.apply。
10. Hooks 群（O§8 pre-run／message pipeline／subagent／misc／bundled／gmail／auto-reset、H§14 outbound webhooks／shell hooks、H§9／O§6 hooks CLI 與 webhook test）：parked/wt-hooks 可補。補完後仍缺 cron_changed/cron_reconciled 觸發點與 heartbeat contribution 執行器。
11. Polls（O§8）：只有 discord/telegram，模型無法使用（沒有 message 工具）。
12. 飛書工具（H§3 feishu_doc_read、feishu_drive_*×4、O§2 feishu_*）：完全沒有，parked 也沒有。
13. kanban decompose/specify（H§5）：llm/tests.rs 空，只能經 ARP。
14. kanban 多看板轉移（H§5）：transfer.rs 未接線、沒有 CLI；swarm.rs 未接線。
15. kanban 儀表板（H§5）：沒有 web UI 頁面；Boards（O§8）有兩套重疊實作，且受合併損壞阻擋。
16. kanban PR acceptance（H§5）：受 cfg 型別錯誤阻擋，工具路徑無測試。
17. conversations_list／conversations_turn ⬜、conversations_send 🚧（O§1）：未改動。
18. message CLI（O§6）：`ark channel send` 只能送文字，`message_action` 沒接 CLI。
19. system CLI（O§6 events/heartbeat/presence）：不存在。
20. /loop（H§8、H§14、O§5）、/dashboard、/workboard、/card（O§5）、/subgoal 與 Subgoals（H§8、H§14）：不存在或只有 schedule 近似。
21. cron 技能/腳本/no_agent、prompt 威脅掃描、incidents/runs/notepad、chronos、自動化建議（H§14）；cron CLI 缺 edit/runs/incidents/notepad/doctor（H§9）。
22. 元寶工具 ×5、Google Meet ×5、Teams 會議管線（H§3）：完全沒有（config 只有 `meetings` 空骨架）。
23. whatsapp_login/whatsapp_call、discussion（clickclack）、session-share、logbook（O§2）：完全沒有。
24. Flows（O§8）：只有 `ark setup`。webhooks CLI（O§6）沒有 Gmail setup 輔助指令。
25. context_engine 執行期工具（H§3）：engine 沒有自帶工具的通道（未改動）。

### skills：技能、記憶、上下文

1. /memory（H§8）：`ark memory accept|reject` 被 `wire::owns` 導到 `ark_memory::host::cli` 的 stub，現在一律報錯（迴歸；e2e run.py:442 會失敗）。
2. memory_search（O§1）：`MemorySearch` 與 hybrid index 已寫好，但 `ark_memory::host::tools` 回傳空；要改成呼叫 `Host::new` 加 `ark_memory::tools(&h)`。
3. memory_get（O§1）：同上，未註冊。
4. embeddings providers（O§3）：程式完整，但沒有使用端（要等 memory_search 接線）。
5. MemoryManager（H§11）：`lifecycles()` 從沒被傳給 `add_lifecycle`，prefetch/sync/pre_compress 都不會發生。
6. Memory flush before compaction（O§8）：`Flush` 未註冊。
7. active-memory（O§2）：`ActiveMemory` 未註冊；它的測試失敗。
8. /active-memory（O§5）：`ark_memory::slash` 沒有包成 `Slash` 註冊。
9. dreaming（O§2）：`dreaming_tick` 沒有排程器呼叫。
10. /dreaming（O§5）：未註冊。
11. memory_recall/store/forget（O§2）：`VectorMemory` 工具與 `AutoMemory` 都未註冊。
12. wiki_*（O§2）：`wiki.rs` 沒有工具或 CLI 接線（`ark memory wiki` 會進 stub）。
13. （✅ 列的附帶缺口）內建 MEMORY.md / USER.md（H§11）的字元上限、write_approval 設定：設定不生效（`set_limits` 從未被呼叫）。
14. memory 工具（H§1）：威脅掃描 `WRITE_SCANNER` 沒有接到 `threats::scan`。
15. 記憶寫入威脅掃描（H§11）：同上。
16. 記憶 context 圍欄（H§11）：沒有 lifecycle，所以 fence 不會生效；`StreamScrubber` 沒接到輸出；fence 測試失敗。
17. 記憶查詢改寫（H§11）：`rewrite.rs` 未接線。
18. memory setup/status/off/reset（H§9）：`ark_memory::cli::run` 已實作，但 host 是 stub。
19. Memory host SDK（O§8）：`events.rs` 未接線，沒有查詢 API。
20. 記憶 provider 遷移/OAuth（H§11）：未接線，也沒有 CLI 或路由。
21. Honcho profile（H§11）：未接線。
22. personal_instructions（O§1）：工具未註冊。
23. journey CLI（H§9）：未接線。
24. /journey（H§8）：未接線。
25. skills_list（H§1）：沒有工具、沒有分類。
26. skill_view（H§1）：沒有 plugin 技能、去重、env setup。
27. skill_manage（H§1）：沒有 patch、批次、guard、lint、ledger、核准閘。
28. skills_search（O§1）：沒有搜尋工具。
29. skill_workshop（O§1）：沒有 test/publish。
30. Skill loading + gating（O§9）：沒有 requires bins/env/os 篩選；`ark_skills::skill::discover` 未使用。
31. 技能必要 env 與秘密收集（H§10）：沒有 required_environment_variables 處理。
32. Skill env/API-key 注入（O§9）：沒有。
33. SKILL.md 前處理（H§10）：沒有。
34. 技能索引即時增量（H§10）：沒有。
35. /reload-skills（H§8）：沒有即時重掃。
36. /<skill-name>（H§8）：native slash 框架在，但沒有技能處理器。
37. /skill <name>（O§5）：同上。
38. /skills（H§8）：沒有。
39. skills CLI 27 子指令（H§9）：`ark skills` 只回 stub 錯誤。
40. skills CLI list/info/check/search/install（O§6）：同上。
41. Hub：官方 optional-skills（H§10）：hub 全是 stub。
42. Hub：GitHub taps（H§10）：同上。
43. Hub：ClawHub（H§10）：同上。
44. Hub：skills.sh（H§10）：同上。
45. Hub：LobeHub/browse.sh/well-known/URL（H§10）：同上。
46. Hub 統一搜尋（H§10）：同上。
47. Hub 安裝（隔離、symlink 防護）（H§10）：同上。
48. Skill install from ClawHub（O§9）：同上。
49. clawhub 技能（O§9）：沒有。
50. Skills Guard（H§10）：沒有技能掃描。
51. AST 深度稽核（H§10）：沒有。
52. SkillEvaluator 掃描（H§10）：沒有。
53. 技能 linter（H§10）：只有名稱檢查。
54. 技能 ledger＋回滾（H§10）：沒有。
55. 技能使用遙測（H§10）：沒有 `tool_settled` 實作者。
56. Curator（H§10）：沒有。
57. curator CLI（H§9）：stub。
58. /curator（H§8）：沒有。
59. 背景回顧寫技能（H§10）：只產記憶建議，不寫技能。
60. /refine（H§8）：沒有即時版，也不寫技能。
61. /learn（H§8）：沒有。
62. /learn（O§5）：沒有。
63. 技能 bundles（H§10）：沒有。
64. bundles CLI（H§9）：stub。
65. /bundles（H§8）：沒有。
66. /<bundle-name>（H§8）：沒有。
67. 外掛提供技能 `plugin:skill`（H§10）：只有 enum。
68. 內建技能同步（H§10）：沒有。
69. 內建技能內容 skills/ 58 個（H§10）：沒有。
70. optional-skills 153 個（H§10）：沒有內容，也沒有目錄機制。
71. OpenClaw 可移植的其餘 38 個技能（O§9，1password…xurl、custodian；不含上面的 clawhub；清單見上表）：都沒有。
72. coding-agent（O§9）：沒有 SKILL.md。
73. skill-creator（O§9）：沒有 SKILL.md。
74. Blueprints（H§10）：沒有。
75. 技能發佈/匯出/匯入（H§10）：沒有。
76. tool_search BM25（H§6）：`toolsearch::Index` 沒有註冊成工具。
77. @-參照展開（H§12）：`refs::expand` 沒有在 consume_inbox 呼叫。
78. 子目錄提示漸進載入（H§12）：`subdir::Tracker` 沒有在工具迴圈呼叫。
79. micro-compaction（H§12）：`MicroState` 從未使用。
80. 驗證迴圈 pre_verify（H§12）：`verify::TurnState`、`VerifyGate` 從未使用。
81. /compress（H§8）：沒有 `here N`、`--preview`。
82. 部分壓縮（H§12）：沒有。
83. /compact（O§5）：只在 `ark chat`。
84. /context（H§8）：只有 `/status`。
85. /context（O§5）：沒有。
86. context 用量拆解（H§12）：沒有。
87. /btw（H§8）：沒有。
88. /btw（O§5）：沒有。
89. 旁支提問（H§12）：只有設定欄位。
90. 自動標題生成（H§12）：沒有 LLM 生成。
91. /title（H§8）：沒有斜線指令。
92. session recap（H§12）：沒有。
93. SOUL.md／人格（H§12）：沒有載入。
94. /personality（H§8）：沒有。
95. Project memory / bootstrap files（O§8）：沒有 SOUL/IDENTITY/BOOT。
96. /init（H§8）：沒有。
97. coding posture（H§12）：只有設定欄位。
98. 本機工具鏈探測（H§12）：只有設定欄位。
99. plugins CLI 生命週期（H§9）：`install|update|…` 進 stub。
100. plugins CLI install/update/marketplace（O§6）：同上。
101. 外掛目錄 706 yaml（H§19）：沒有。
102. ClawHub plugin marketplace（O§8）：沒有。
103. plugins 工具（O§1）：沒有。
104. /plugins list/show/enable/disable（O§5）：沒有。
105. 外掛安裝掃描 plugin guard（H§19）：沒有。
106. Claws（O§8）：沒有。
107. 外掛註冊各類後端（H§19）：沒有 TTS/STT/瀏覽器/影像/影片/web 擴充點。
108. 外掛串流 hook（H§19）：沒有。
109. dashboard_auth（H§19）：只有 bearer。
110. disk-cleanup（H§19）：沒有。
111. security-guidance（H§19）：沒有。
112. hermes-achievements（H§19）：沒有。
113. context 長度 pin（H§12）：內建供應商沒有覆蓋欄。
114. models.dev 中繼資料（H§12）：只有啟發式表。
115. OpenAI 原生 server 端壓縮（H§12）：沒有。
116. 圖片淘汰（H§12）：沒有。
117. 非視覺模型圖片退化（H§12）：沒有。
118. i18n（H§12）：沒有。

### ops：指令、UI、維運

1. OpenTelemetry 匯出（H§9 monitoring）：只有 `TelemetryConfig`，`ops/telemetry.rs` 空殼，無 OTLP traces/metrics/logs 匯出、無指令；LangSmith OTel 相容性無程式可判。
2. 外部秘密來源（H§20、H§9 secrets bitwarden/onepassword）：`ops/secretsrc.rs` 空殼，無 Bitwarden/1Password/command。
3. Doctor 修復流程（O§11 repair/lint、O§6 doctor）：`ops/doctor.rs` 空殼；無 `--fix`、未併入 service audit、無 tool-schema／channel／workspace 檢查（O§11 三列）。
4. Web UI 頁面（O§10 17 ⬜＋H§22 Web 儀表板）：`ui/web` 未改動；Config/Channels/Cron/Usage/Secrets/Terminal/Dashboards/Skills 等頁面全無，`ui_methods.rs` 空殼；Logs 只有後端 `logs.tail`。
5. Batch runner／evals（H§21）：`ops/batch.rs`、`ops/evals.rs` 空殼；mini_swe_runner、trajectory_compressor、toolset_distributions 皆無。
6. /restart（H§8 🚧、O§5 ⬜）：`service::restart_detached` 已寫但無呼叫者，無斜線；/activation、/allowlist 卻要使用者「/restart」。
7. `ark status`（H§9、O§6）：`ops/status.rs` 空殼，無全元件狀態彙整。
8. TUI 斜線 action（H§22 TUI、H§8 /statusbar /redraw…）：TUI 忽略 `action`，/new /clear /quit /copy 等在 TUI 無效；無狀態列（H§22 ⬜、/statusbar 🚧）、無指令面板（/palette 🚧）、無 live dock（⬜）。
9. 顯示偏好未套用：/verbose 只在頻道、/timestamps 只在 /history、/focus 與 /trace 無消費端（H§8、O§5）。
10. 精靈步驟（O§11）：security note、migration import、workspace、service install、official plugins、completion 推薦皆未進 `ark setup`；model auth 只有 API key、gateway/channel 部分；H§20 onboarding 情境提示無。
11. /update 斜線只檢查（H§8、O§5）；O§6 uninstall、configure 無測試；/allowlist、/activation、/send、/platforms 無測試（O§5、H§8）。
12. `ark tools` 無每平台開關／post-setup（H§9）。
13. /prompt (/compose) 只在 `ark chat`，compose 無測試（H§8）。
14. /debug、dump、debug share（H§8、H§9、O§5 /debug）：無除錯報告。
15. /diagnostics、/openclaw、/dashboard、/pair、/controlui（O§5）：無。
16. worktree（H§8 /worktree、H§9 worktree、O§6 worktrees）：無。
17. CLI 其他 ⬜：project、console、connectors、verify、lsp、gateway multiplex（H§9）；storage、triage、audit、users、worker、dns、proxy、directory（O§6）。
18. O§6 onboard、attach、channels、O§10 Chat/Model providers/Devices/Plugins/i18n/Themes、O§11 model reference/gateway checks/Docker：既有 🚧，本輪未改。
19. Skins／主題、寵物、電量、indicator、prompt stash（H§8 /skin /pet /hatch /battery /indicator、Ctrl+S；H§9 pets/skin；H§22 Petdex/Skins）：無。
20. Hosted rooms（H§22）、tips、OSC 9/777 通知（H§20）、Canvas host、Telegram mini-app（O§11）：無。

### models：模型供應商與用量

1. 輔助模型路由（H§17）：只有 compaction/review/sampling 用 `model.tasks`；vision、title、search 等任務沒有各自的模型，也沒有每任務的健康檢查或 fallback。
2. Auth profiles（O§4）：沒有每代理（per-agent）憑證順序/指定。
3. Agent harnesses（O§4）：缺 OpenAI Agents API 與 Muse CLI 後端；copilot-cli 只是文字模式。
4. copilot-acp（H§17）：不是 ACP 客戶端，只用 `copilot -p` 文字輸出，沒有串流事件與工具呼叫。
5. /login（O§5）：聊天內不能完成登入，只顯示指引。
6. nous（H§17）：缺 agent-key 換發與續期，直接用 OAuth access token；client_id 寫死 `hermes-cli`。
7. `ark model`（H§9）：已接線，但沒有任何測試跑這條路徑。
