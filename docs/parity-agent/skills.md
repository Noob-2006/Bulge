# 技能／記憶／Context／外掛 對等盤點（skills.md）

日期：2026-11-03。範圍：`docs/parity-agent/hermes-inventory.md` 的 §10 技能系統、§11 記憶、§12 Context／提示／壓縮、§19 外掛系統，以及 `docs/parity-agent/openclaw-inventory.md` 的 §9 Skills；每個盤點項目一列。

判定原則：**只依實際程式碼**（檔案路徑、函式／型別名稱、行號），不採信文件、註解或計畫。路徑皆相對於 repo 根目錄；`kernel.rs`、`context.rs`、`config.rs`、`plan.rs`、`plugin.rs`、`ext.rs`、`memory.rs` 分別指 `crates/ark-kernel/src/kernel.rs`、`crates/ark-kernel/src/context.rs`、`crates/ark-kernel/src/config.rs`、`crates/ark-tools/src/plan.rs`、`crates/ark-plugin/src/plugin.rs`、`crates/ark/src/ext.rs`、`crates/ark-tools/src/memory.rs`。行號以撰寫當下的工作樹為準。

圖例：
- ✅ 已實作，且在實際程式碼中接線可用（已提交）。
- 🚧 部分完成／進行中／尚未編譯／尚未接線。
- ⬜ 不存在。上游盤點標為 N/A 的項目（macOS 專屬等）在 ark 中同樣不存在，這裡一律標 ⬜，並在缺口欄註明。

工作樹狀態（撰寫時，未提交）：
- 修改：`Cargo.toml`（新增成員 `crates/ark-skills`、`crates/ark-memory`）、`crates/ark-kernel/src/{config,kernel,lib}.rs`、`crates/ark-tools/src/{lib,memory}.rs`。
- 未追蹤：`crates/ark-kernel/src/{ctxstate,lifecycle,refs,subdir,threats}.rs`、`crates/ark-memory/`（約 8000 行）、`crates/ark-skills/`（只有一行 doc 註解）。
- `crates/ark-kernel/src/lib.rs` 只新增了 `pub mod lifecycle;`；`ctxstate`、`refs`、`subdir`、`threats` 都沒宣告。`config.rs` 引用 `crate::ctxstate::ContextConfig` 和 `crate::toolsearch::ToolSearchConfig`，但 `toolsearch.rs` 不存在；`ctxstate.rs` 又引用不存在的 `crate::microcompact`、`crate::verify`。所以 ark-kernel（以及依賴它的 crate）目前無法編譯；依賴這些部分的項目一律標 🚧。
- `crates/ark-memory` 不被 `crates/ark` 或 `crates/ark-app` 依賴，全倉也沒有 `Runtime::add_lifecycle` 的呼叫端，所以其中功能都沒有接線（🚧）。

總計：125 項，✅ 15／🚧 23／⬜ 87。

## Hermes §10 技能系統（26 項：✅ 1／🚧 1／⬜ 24）

| 項目 | 上游來源 | 目前狀態（✅/🚧/⬜） | ark 證據或缺口 |
|---|---|---|---|
| 技能發現與索引注入 | Hermes §10：`agent/prompt_builder.py, skill_utils.py` | ✅ | `discover_skills`（`crates/ark-kernel/src/context.rs:112`）讀 `*/SKILL.md` frontmatter，`system_segments` 組 `# Skills` 段（context.rs:73-80）；目錄 `Paths::skills_dirs`（context.rs:413-416）；`skill` 工具 `Skill`（`crates/ark-tools/src/plan.rs:177`）已註冊於 `builtin_tools`（`crates/ark-tools/src/lib.rs:47`） |
| 技能索引即時增量 | Hermes §10：`agent/skills_index_delta.py` | ⬜ | system 段只在 `create_session`（`kernel.rs:343`）凍結、壓縮後才重建（`kernel.rs:1055`）；對話中新增技能不會出現在索引 |
| SKILL.md 前處理（變數代入、內嵌指令展開） | Hermes §10：`agent/skill_preprocessing.py` | ⬜ | `Skill::call` view 直接回傳檔案內容（plan.rs:202 起），無代入/展開 |
| 技能必要 env 與秘密收集 | Hermes §10：`tools/skills_tool_setup.py, env_passthrough.py` | ⬜ | `frontmatter`（context.rs:132）只解析 name/description；`crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| 外掛提供技能 | Hermes §10：`tools/skills_tool_plugin.py` | ⬜ | `PluginHost`（`crates/ark-plugin/src/plugin.rs:203`）無 skills 宣告欄位 |
| 內建技能同步（bundled sync） | Hermes §10：`tools/skills_sync*.py` | ⬜ | ark 不附技能；無同步程式 |
| Hub：官方 optional-skills＋Hermes 索引 | Hermes §10：`tools/skills_hub_official.py` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| Hub：GitHub taps | Hermes §10：`tools/skills_hub_github.py` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| Hub：ClawHub | Hermes §10：`tools/skills_hub_clawhub.py` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| Hub：skills.sh | Hermes §10：`tools/skills_hub_skillssh.py` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| Hub：LobeHub / browse.sh / well-known / 直接 URL | Hermes §10：`tools/skills_hub_sources.py` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| Hub 統一搜尋 | Hermes §10：`tools/skills_hub_search.py` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| Hub 安裝（隔離暫存、目標安全） | Hermes §10：`tools/skills_hub_install.py` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| Skills Guard（regex 掃描＋信任政策） | Hermes §10：`tools/skills_guard.py` | ⬜ | 無技能掃描；未追蹤的 `crates/ark-kernel/src/threats.rs`（`scan`:52）只針對 context 檔且未宣告為模組 |
| SkillEvaluator 掃描 | Hermes §10：`tools/skillevaluator_scan.py` | ⬜ | — |
| AST 深度稽核 | Hermes §10：`tools/skills_ast_audit.py` | ⬜ | — |
| 技能 linter | Hermes §10：`tools/skill_linter.py` | ⬜ | 僅 `valid_name`（plan.rs:159）檢查名稱 |
| 技能 ledger＋單次回滾 | Hermes §10：`tools/skill_ledger.py` | ⬜ | `skill` 的 archive 僅移走目錄，無 JSONL 稽核/回滾；`crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| 技能使用遙測 | Hermes §10：`tools/skill_usage.py` | ⬜ | 無統計。未提交的 `Lifecycle::tool_settled`（`crates/ark-kernel/src/lifecycle.rs:22`，kernel.rs:1293 呼叫）只是可掛的觀察點，沒有任何技能用量實作 |
| Curator（閒置背景維護） | Hermes §10：`agent/curator.py, curator_backup.py` | ⬜ | 無；`crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| 背景回顧寫技能 | Hermes §10：`agent/background_review.py` | 🚧 | `Runtime::review`（`kernel.rs:1434`，由 kernel.rs:708 於 `learn.enabled` 時呼叫）只萃取記憶建議並暫存到 `memory/staging`，不寫技能 |
| 技能 bundles | Hermes §10：`agent/skill_bundles.py` | ⬜ | — |
| Blueprints（技能＋cron 範本） | Hermes §10：`tools/blueprints.py, cron/blueprint_catalog.py` | ⬜ | — |
| 技能發佈/匯出/匯入 | Hermes §10：`hermes_cli/skills_hub.py` | ⬜ | — |
| 內建技能內容（skills/ 58 個） | Hermes §10：`skills/**` | ⬜ | ark repo 不附任何 SKILL.md；可讀 Claude 相容技能目錄 |
| optional-skills（153 個） | Hermes §10：`optional-skills/**` | ⬜ | — |

## Hermes §11 記憶（7 項：✅ 1／🚧 6／⬜ 0）

| 項目 | 上游來源 | 目前狀態（✅/🚧/⬜） | ark 證據或缺口 |
|---|---|---|---|
| 內建 MEMORY.md / USER.md | Hermes §11：`tools/memory_tool_store.py` | ✅ | `Memory` 工具（`crates/ark-tools/src/memory.rs:355`，註冊於 `crates/ark-tools/src/lib.rs:43`）；快照入提示（`context.rs:82-92`，`MAX_MEMORY_BYTES`:14）。未提交改動另加字元上限/批次/核准暫存（memory.rs:32 `set_limits`、:39 `set_write_approval`、:260 `apply_batch`），但 `set_limits` 只被 ark-memory 呼叫（`crates/ark-memory/src/lib.rs:83`），設定目前不生效 |
| MemoryManager（多供應商扇出） | Hermes §11：`agent/memory_manager.py, memory_provider.py` | 🚧 | `MemoryManager` 實作 `Lifecycle`（`crates/ark-memory/src/manager.rs:215`）；kernel 掛點 `add_lifecycle`（kernel.rs:251）與 prefetch/turn_end/pre_compress/tool_settled 呼叫（kernel.rs:744、705、1039、1294）皆為未提交；`crates/ark-memory` 未被任何 binary 依賴（`crates/ark`、`crates/ark-app` 的 Cargo.toml 均未引用），且依賴的 ark-kernel 目前因缺 `ctxstate`/`toolsearch` 模組無法編譯；全倉無 `add_lifecycle` 呼叫端。已提交部分僅外掛 `memory` 能力（plugin.rs:269、578） |
| 記憶查詢改寫 | Hermes §11：`plugins/memory/query_rewrite.py` | 🚧 | `rewrite::rewrite`（`crates/ark-memory/src/rewrite.rs:46`）；`crates/ark-memory` 未被任何 binary 依賴（`crates/ark`、`crates/ark-app` 的 Cargo.toml 均未引用），且依賴的 ark-kernel 目前因缺 `ctxstate`/`toolsearch` 模組無法編譯 |
| 記憶 context 圍欄 | Hermes §11：`agent/memory_context.py` | 🚧 | `lifecycle::fence`/`strip_fences`（`crates/ark-kernel/src/lifecycle.rs:27,33`，kernel.rs:745 使用）與 `sanitize_context`/`StreamScrubber`（`crates/ark-memory/src/fence.rs:9,26`）皆未提交、未接線 |
| 記憶寫入威脅掃描 | Hermes §11：`tools/threat_patterns.py` | 🚧 | 掛點 `WRITE_SCANNER`（memory.rs:29、:107 `scan`）只在測試中被設定（memory.rs:575）；`threats::scan`（`crates/ark-kernel/src/threats.rs:52`）未在 `lib.rs` 宣告為模組，也無人接上 |
| 記憶 provider 設定遷移/OAuth | Hermes §11：`hermes_cli/memory_provider_migration.py, memory_oauth.py` | 🚧 | `migrate::check_provider`（`crates/ark-memory/src/migrate.rs:57`）、`oauth::start`/`status`（`crates/ark-memory/src/oauth.rs:81,166`）；`crates/ark-memory` 未被任何 binary 依賴（`crates/ark`、`crates/ark-app` 的 Cargo.toml 均未引用），且依賴的 ark-kernel 目前因缺 `ctxstate`/`toolsearch` 模組無法編譯；無 HTTP 路由掛載 |
| Honcho profile 整合 | Hermes §11：`hermes_cli/profiles_honcho.py` | 🚧 | `migrate_honcho_profile_host`（migrate.rs:119）；`crates/ark-memory` 未被任何 binary 依賴（`crates/ark`、`crates/ark-app` 的 Cargo.toml 均未引用），且依賴的 ark-kernel 目前因缺 `ctxstate`/`toolsearch` 模組無法編譯 |

## Hermes §12 Context、提示與壓縮（25 項：✅ 7／🚧 11／⬜ 7）

| 項目 | 上游來源 | 目前狀態（✅/🚧/⬜） | ark 證據或缺口 |
|---|---|---|---|
| 自動 context 壓縮 | Hermes §12：`agent/context_compressor*.py, conversation_compression*.py` | ✅ | `Runtime::maybe_compact`/`prune`（kernel.rs:949、964）；`compaction::summarise`（`crates/ark-kernel/src/compaction.rs:102`）、品質檢查 `summary_ok`（:70）、決定式 `fallback_summary`（:77） |
| micro-compaction | Hermes §12：`agent/micro_compaction.py` | 🚧 | 只有設定欄位 `CompactionConfig.micro_compact*`（config.rs，未提交）與 `CtxState.micro`（ctxstate.rs:120）；`microcompact` 模組不存在。`crates/ark-kernel/src/ctxstate.rs` 未在 `crates/ark-kernel/src/lib.rs` 宣告為模組，且引用不存在的 `crate::microcompact`/`crate::verify`（ctxstate.rs:120-121）；`config.rs` 又引用缺少的 `crate::toolsearch`，ark-kernel 目前無法編譯 |
| 部分壓縮「到這裡為止」 | Hermes §12：`hermes_cli/partial_compress.py` | ⬜ | `Kernel::compact`（kernel.rs:449）只有整段壓縮 |
| OpenAI 原生 server 端壓縮 | Hermes §12：`agent/native_compaction.py` | ⬜ | 全倉無 `context_management` |
| 壓縮事件/遙測 | Hermes §12：`agent/compaction_events.py` | ✅ | `HookEvent::PreCompact`/`PostCompact`（`crates/ark-kernel/src/hooks.rs:34-35`），kernel.rs:1032-1051 觸發 |
| Context engine 外掛 | Hermes §12：`agent/context_engine.py, plugins/context_engine` | ✅ | `trait ContextEngine`（`crates/ark-kernel/src/engine.rs:24`）；kernel.rs:230、1009 使用；外掛 `context_engine` 宣告（plugin.rs:214） |
| 專案指令檔 | Hermes §12：`agent/prompt_builder.py, context_file_sources.py` | ✅ | `PROJECT_FILES`（context.rs:12）於 context.rs:96 載入 |
| 子目錄提示漸進載入 | Hermes §12：`agent/subdirectory_hints.py` | 🚧 | `subdir::Tracker`（`crates/ark-kernel/src/subdir.rs:165`）已寫但未在 lib.rs 宣告、kernel 無呼叫；`CtxState.subdirs`（ctxstate.rs:116）。`crates/ark-kernel/src/ctxstate.rs` 未在 `crates/ark-kernel/src/lib.rs` 宣告為模組，且引用不存在的 `crate::microcompact`/`crate::verify`（ctxstate.rs:120-121）；`config.rs` 又引用缺少的 `crate::toolsearch`，ark-kernel 目前無法編譯 |
| @-參照展開 | Hermes §12：`agent/context_references.py` | 🚧 | `refs::parse`/`expand`（`crates/ark-kernel/src/refs.rs:70,155`）已寫但未宣告、`consume_inbox`（kernel.rs:737）未呼叫；設定 `ContextConfig.references`（ctxstate.rs:15） |
| SOUL.md / 預設人格 | Hermes §12：`SOUL.md, hermes_cli/default_soul.py, personality.py` | 🚧 | 已提交：`Config.identity`（config.rs:28）附加至 identity 段（context.rs:59-62）。SOUL.md/personalities 僅設定欄位（ctxstate.rs:20-26）與 `threats::screen`（threats.rs:66），無載入邏輯 |
| coding posture 自動切換 | Hermes §12：`agent/coding_context.py` | 🚧 | 僅設定欄位 `coding_context`/`coding_instructions`（ctxstate.rs:29-31），無判斷邏輯；`crates/ark-kernel/src/ctxstate.rs` 未在 `crates/ark-kernel/src/lib.rs` 宣告為模組，且引用不存在的 `crate::microcompact`/`crate::verify`（ctxstate.rs:120-121）；`config.rs` 又引用缺少的 `crate::toolsearch`，ark-kernel 目前無法編譯 |
| 本機工具鏈探測入提示 | Hermes §12：`tools/env_probe.py` | 🚧 | 僅設定欄位 `environment_probe`（ctxstate.rs:33），無探測程式 |
| Anthropic prompt caching | Hermes §12：`agent/prompt_caching.py` | ✅ | `cache_control` 斷點（`crates/ark-model/src/anthropic.rs:30,61`）；`build_request`（context.rs:170） |
| context 用量拆解 | Hermes §12：`agent/context_breakdown.py` | ⬜ | — |
| context 長度 pin | Hermes §12：`agent/context_pin.py` | 🚧 | 外掛供應商 `context_window`（plugin.rs:122、521）；內建供應商只靠 `caps_for`（`crates/ark-model/src/lib.rs:183`），無使用者覆蓋 |
| models.dev 模型中繼資料 | Hermes §12：`agent/models_dev.py, model_metadata*.py` | 🚧 | `caps_for` 靜態啟發式表（ark-model/lib.rs:183），無 models.dev 取用 |
| 圖片淘汰/視覺歷史預算 | Hermes §12：`agent/image_eviction_policy.py, tools/vision_tools_history_budget.py` | ⬜ | `Block::Image` 只計 `IMAGE_TOKENS`（`crates/ark-core/src/types.rs:192`） |
| 非視覺模型圖片退化 | Hermes §12：`agent/vision_message_prep.py` | ⬜ | `ModelCaps.vision`（ark-model/lib.rs:189）無任何消費端 |
| 自動標題生成 | Hermes §12：`agent/title_generator.py` | 🚧 | `create_session` 可帶 title（kernel.rs:325）、`set_title`（kernel.rs:424）、子代理截取任務文字（kernel.rs:1574）；LLM 生成僅設定欄位 `title_generation`（ctxstate.rs:35） |
| session recap | Hermes §12：`hermes_cli/session_recap.py` | ⬜ | — |
| 旁支提問 /btw | Hermes §12：`agent/side_question.py` | 🚧 | 僅設定欄位 `side_question_model`（ctxstate.rs:58），無指令或執行邏輯 |
| 空回應/截斷恢復 | Hermes §12：`agent/turn_empty_response.py, turn_truncation.py` | ✅ | 推理吃光輸出時加倍重試（kernel.rs:648-650，`MAX_BOOSTED_TOKENS`:150）；`MaxTokens` 續寫受 `max_continuations` 限制（kernel.rs:683） |
| 迭代預算 | Hermes §12：`agent/iteration_budget.py` | ✅ | `runner.max_steps_per_turn`（config.rs:124），kernel.rs:601 檢查 |
| 驗證迴圈 pre_verify | Hermes §12：`agent/verify_hooks.py, verification_stop.py` | 🚧 | `ContextConfig.verify_on_stop`/`pre_verify`（ctxstate.rs:42-49）、`trait VerifyGate`（ctxstate.rs:109）；`verify` 模組不存在；config.rs 未提交改動會丟棄專案層 `context.pre_verify`。`crates/ark-kernel/src/ctxstate.rs` 未在 `crates/ark-kernel/src/lib.rs` 宣告為模組，且引用不存在的 `crate::microcompact`/`crate::verify`（ctxstate.rs:120-121）；`config.rs` 又引用缺少的 `crate::toolsearch`，ark-kernel 目前無法編譯 |
| i18n 多語系 | Hermes §12：`agent/i18n*.py, locales/` | ⬜ | — |

## Hermes §19 外掛系統（14 項：✅ 6／🚧 2／⬜ 6）

| 項目 | 上游來源 | 目前狀態（✅/🚧/⬜） | ark 證據或缺口 |
|---|---|---|---|
| 外掛載入與 manifest | Hermes §19：`hermes_cli/plugins*.py, plugins/plugin_loader.py` | ✅ | `PluginHost`（plugin.rs:203）解析宣告（plugin.rs:256-269）；主機端 `crates/ark/src/ext.rs` |
| 外掛 hooks | Hermes §19：`hermes_cli/plugin_events.py` | ✅ | plugin.rs:283 `hooks()`；接入 kernel 於 ext.rs:96、364 |
| 外掛 middleware | Hermes §19：`hermes_cli/middleware.py` | ✅ | plugin.rs:289 `middleware_kinds`、:406；ext.rs:367 |
| 外掛註冊工具/供應商/TTS/STT/瀏覽器/影像/影片/web 後端 | Hermes §19：`agent/*_provider.py, *_registry.py` | 🚧 | 有 providers/channels/memory/context_engine/node_commands/ui（plugin.rs:203-217）；無 TTS/STT/瀏覽器/影像/影片/web 後端擴充點 |
| 外掛 LLM 存取 ctx.llm | Hermes §19：`agent/plugin_llm.py` | ✅ | `sampling_request`（ext.rs:161、170）；MCP sampling（`crates/ark-plugin/src/mcp.rs:392`） |
| 外掛串流 hook | Hermes §19：`agent/plugin_stream_hooks.py` | ⬜ | 外掛 hooks 無 delta 事件 |
| 外掛隔離（子行程 host） | Hermes §19：`hermes_cli/plugin_host*.py, plugin_isolation.py` | ✅ | stdio 子行程（`crates/ark-plugin/src/transport.rs:172` `Command::new`） |
| 外掛安裝掃描（plugin guard） | Hermes §19：`tools/plugin_guard.py` | ⬜ | — |
| 外掛目錄（706 個 yaml） | Hermes §19：`plugin-catalog/*.yaml` | ⬜ | 無目錄與安裝 |
| 外掛 UI/dashboard 分頁 | Hermes §19：`hermes_cli/plugin_validate_desktop.py` | ✅ | `plugins.ui`/`plugins.ui_call`（`crates/ark/src/main.rs:809-812`）；`ui/web/app.js:179,216` |
| 內建外掛 disk-cleanup | Hermes §19：`plugins/disk-cleanup` | ⬜ | — |
| 內建外掛 security-guidance | Hermes §19：`plugins/security-guidance` | ⬜ | — |
| 內建外掛 hermes-achievements | Hermes §19：`plugins/hermes-achievements` | ⬜ | — |
| 內建外掛 dashboard_auth（basic/nous/self_hosted） | Hermes §19：`plugins/dashboard_auth` | 🚧 | 僅 bearer token（`crates/ark-app/src/server.rs:13-14,66`），無 basic/OAuth 登入 |

## OpenClaw §9 Skills（53 項：✅ 0／🚧 3／⬜ 50）

| 項目 | 上游來源 | 目前狀態（✅/🚧/⬜） | ark 證據或缺口 |
|---|---|---|---|
| 技能載入＋提示索引（含 requires bins/env/os 條件篩選） | OpenClaw §9：`src/skills, src/agents/system-prompt-skills.ts` | 🚧 | 發現與索引已有（context.rs:73、112）；無 requirements/eligibility 篩選，`frontmatter`（context.rs:132）只讀 name/description；`crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| 從 ClawHub 安裝技能 | OpenClaw §9：`skills/clawhub, src/cli/skills-cli.ts` | ⬜ | `crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| 技能 env / API key 注入 | OpenClaw §9：`src/skills` | ⬜ | — |
| 1password | OpenClaw §9：`skills/1password` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| apple-notes | OpenClaw §9：`skills/apple-notes` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| apple-reminders | OpenClaw §9：`skills/apple-reminders` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| bear-notes | OpenClaw §9：`skills/bear-notes` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| blogwatcher | OpenClaw §9：`skills/blogwatcher` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| blucli | OpenClaw §9：`skills/blucli` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| camsnap | OpenClaw §9：`skills/camsnap` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；僅需配對裝置的 node 指令 `camera.snap`（`crates/ark-app/src/node.rs:717`），非本機 RTSP/webcam |
| clawhub | OpenClaw §9：`skills/clawhub` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；`crates/ark-skills` 僅有一行 doc 註解（`crates/ark-skills/src/lib.rs:1`），無任何實作 |
| coding-agent | OpenClaw §9：`skills/coding-agent` | 🚧 | ark 不附此技能（repo 無 SKILL.md）；功能面由 `acp_delegate` 工具涵蓋（`crates/ark-app/src/acp_client.rs:741` 起） |
| control-ui | OpenClaw §9：`skills/control-ui` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| diagram-maker | OpenClaw §9：`skills/diagram-maker` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| eightctl | OpenClaw §9：`skills/eightctl` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| gemini | OpenClaw §9：`skills/gemini` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| gh-issues | OpenClaw §9：`skills/gh-issues` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| gifgrep | OpenClaw §9：`skills/gifgrep` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| github | OpenClaw §9：`skills/github` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| gog | OpenClaw §9：`skills/gog` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| goplaces | OpenClaw §9：`skills/goplaces` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| healthcheck | OpenClaw §9：`skills/healthcheck` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| himalaya | OpenClaw §9：`skills/himalaya` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| mcporter | OpenClaw §9：`skills/mcporter` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A：功能與 ark 原生 MCP（`crates/ark-plugin/src/mcp.rs`）重疊 |
| meme-maker | OpenClaw §9：`skills/meme-maker` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| model-usage | OpenClaw §9：`skills/model-usage` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| nano-pdf | OpenClaw §9：`skills/nano-pdf` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| node-connect | OpenClaw §9：`skills/node-connect` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| node-inspect-debugger | OpenClaw §9：`skills/node-inspect-debugger` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| notion | OpenClaw §9：`skills/notion` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| obsidian | OpenClaw §9：`skills/obsidian` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| openai-whisper | OpenClaw §9：`skills/openai-whisper` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| openai-whisper-api | OpenClaw §9：`skills/openai-whisper-api` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| openhue | OpenClaw §9：`skills/openhue` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| oracle | OpenClaw §9：`skills/oracle` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| ordercli | OpenClaw §9：`skills/ordercli` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| peekaboo | OpenClaw §9：`skills/peekaboo` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| python-debugpy | OpenClaw §9：`skills/python-debugpy` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| sag | OpenClaw §9：`skills/sag` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| sherpa-onnx-tts | OpenClaw §9：`skills/sherpa-onnx-tts` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| skill-creator | OpenClaw §9：`skills/skill-creator` | 🚧 | ark 不附此技能（repo 無 SKILL.md）；`skill` 工具 action=create/update/archive 可寫技能（plan.rs:179-268） |
| songsee | OpenClaw §9：`skills/songsee` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| sonoscli | OpenClaw §9：`skills/sonoscli` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| spike | OpenClaw §9：`skills/spike` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| spotify-player | OpenClaw §9：`skills/spotify-player` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| summarize | OpenClaw §9：`skills/summarize` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| things-mac | OpenClaw §9：`skills/things-mac` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；上游盤點標 N/A（macOS／OpenClaw 專屬） |
| tmux | OpenClaw §9：`skills/tmux` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| trello | OpenClaw §9：`skills/trello` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| visualize | OpenClaw §9：`skills/visualize` | ⬜ | ark 不附此技能（repo 無 SKILL.md）；亦無 show_widget |
| weather | OpenClaw §9：`skills/weather` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| xurl | OpenClaw §9：`skills/xurl` | ⬜ | ark 不附此技能（repo 無 SKILL.md） |
| custodian skills（add-model-provider, cloud-image-bake, configure-channel, diagnose-gateway） | OpenClaw §9：`custodian-skills/` | ⬜ | — |
