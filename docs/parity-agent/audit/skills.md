# 稽核：skills 串流（技能／記憶／Context／外掛）

- 串流：skills
- 目錄：`$R/w-skills`（基準 commit 5c369e5，全部改動未提交）
- 編譯/測試：建置成功；測試通過 846、失敗 4、忽略 3。失敗：`coderun::tests::{script_output_exit_codes_and_nested_protocol,failures_timeout_cancel_and_bad_lang}` 兩個失敗是稽核環境造成（TMPDIR 路徑過長，unix socket 超過 SUN_LEN），五個副本含 SE Agent 都一樣，非本流迴歸；**`seagent-memory fence::tests::sanitize_and_stream`（期望 "HelloWorld"，實得 "Hello\n\nWorld"）與 `seagent-memory active::tests::escalate_recall_agent_cache_breaker_and_toggle`（active.rs:299 unwrap None）是真實失敗**。e2e 未跑。原始輸出：`audit/skills-tests.txt`。
- 差異範圍：修改 11 檔（`Cargo.toml`、`Cargo.lock`、`crates/seagent-kernel/{Cargo.toml,src/config.rs,src/kernel.rs,src/lib.rs}`、`crates/seagent-tools/src/{lib.rs,memory.rs}`、`crates/seagent/{Cargo.toml,src/ext.rs,src/main.rs}`，+652/−65）；新增 46 檔：`crates/seagent-kernel/src/{ctxhost,ctxstate,lifecycle,microcompact,refs,slash,subdir,threats,toolsearch,verify}.rs`、`crates/seagent-memory/`（24 個 .rs，約 8000 行）、`crates/seagent-skills/`（6 個 .rs，約 1040 行）、`crates/seagent/src/wire.rs`、`docs/parity-agent/*.md`。
- 計數（184 列）：✅ 21／🚧 56／⬜ 98／N/A 9。Hermes 100 列（✅16／🚧35／⬜49）；OpenClaw 84 列（✅5／🚧21／⬜49／N/A 9）。

## 接線重新查核（上一輪已知事項）

| 已知事項 | 現況 | 證據 |
|---|---|---|
| ctxstate/refs/subdir/threats/lifecycle/toolsearch/microcompact/verify 未宣告 | **已宣告**（另加 ctxhost、slash），全部編入 seagent-kernel | `crates/seagent-kernel/src/lib.rs` 的 `pub mod` |
| 這些模組未接入 kernel | **只有 lifecycle、slash 接進 kernel**：`Runtime::add_lifecycle`、`system_segments`、`consume_inbox` 的 prefetch／fence、`turn_end`、`pre_compress`、`tool_settled`；`add_slash`/`run_slash`，ext.rs／main.rs／daemon `command.run`／channel 都會先查 native 指令。**refs、subdir、microcompact、verify、toolsearch、threats、ctxstate::CtxState 在 kernel 裡沒有呼叫端**（只有 config 型別 `ContextConfig`、`ToolSearchConfig` 被引用） | `grep 'refs::\|subdir::\|toolsearch::Index\|microcompact::\|verify::' crates` 只在模組彼此之間命中 |
| 全倉沒有任何 `add_lifecycle`／`add_slash` 呼叫 | **仍然沒有** | `seagent_memory::host::attach`、`seagent_skills::host::attach`（core/hub）、`seagent_kernel::ctxhost::attach` 函式本體都是空的 |
| crates/seagent-memory 不是 crates/seagent 的依賴 | **已加入依賴**（`crates/seagent/Cargo.toml`、workspace members），但 `seagent_memory::host::tools()` 回傳 `vec![]`、`attach()` 是 no-op、`cli()` 回傳 "`seagent {cmd}` is not implemented yet"。`lib.rs` 裡真正的 `tools(&Host)`／`lifecycles()`／`slash()`／`dreaming_tick()` 沒人呼叫，`Host::new` 也沒人呼叫，所以 `[memory]` 新設定不會生效 | `crates/seagent-memory/src/host.rs`；`crates/seagent/src/wire.rs` |
| crates/seagent-skills 是空的 | 有 `skill.rs`（多根目錄探索，1 個測試）、`yaml.rs`（YAML 子集解析器，5 個測試），其餘都是 stub：`core::tools/hub::tools` → `vec![]`，`core::cli` → "`seagent {cmd}` is not implemented yet"，`hub::cli` → "`seagent skills` is not implemented yet"，`hub::plugin_cli` → "`seagent plugins` lifecycle is not implemented yet"。`skill.rs`／`yaml.rs` 在 crate 外沒有任何使用者 | `crates/seagent-skills/src/{core.rs,hub/mod.rs}` |

**迴歸（使用者已看得到）**：`wire::owns("memory", …)` 把 `show|add|review` 以外的子指令都導到 `seagent_memory::host::cli` 的 stub，所以既有的 `seagent memory accept|reject` 現在一律失敗，訊息是 "`seagent memory` is not implemented yet"（原本由 `crates/seagent/src/main.rs` `cmd_memory` 的 `"accept" | "reject"` 分支處理）。`tests/e2e/run.py:442`（`seagent("memory","accept","1")`）應該會失敗。同理，`seagent skills|skill|hub|bundles|curator|journey` 和 `seagent plugin install…` 目前都會進入只回錯誤的 stub。
**測試（引用 `$R/audit/tmp-b/skills-full.log` 的既有紀錄，本次未執行建置）**：seagent-memory 失敗 2 個（`fence::tests::sanitize_and_stream`、`active::tests::escalate_recall_agent_cache_breaker_and_toggle`）；seagent-kernel `coderun` 失敗 2 個（不在本串流範圍）。

## Hermes §10 技能系統（26：✅1／🚧1／⬜24）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 技能發現與索引注入 | agent/prompt_builder.py, skill_utils.py（H§10） | ✅ | `discover_skills`（crates/seagent-kernel/src/context.rs:112），test `segments_are_deterministic_and_include_project_and_skills`（既有，未改動）。新的 `seagent_skills::skill::discover` 沒有使用者 |
| 技能索引即時增量 | agent/skills_index_delta.py（H§10） | ⬜ | 只有通用掛點 `Lifecycle::system_segment`（lifecycle.rs），沒有任何實作；即使有，也只在 session 建立或壓縮時重建 |
| SKILL.md 前處理 | agent/skill_preprocessing.py（H§10） | ⬜ | 沒有 `${…}` 代入，也沒有 `` !`cmd` `` 展開 |
| 技能必要 env 與秘密收集 | tools/skills_tool_setup.py, env_passthrough.py（H§10） | ⬜ | 沒有 required_environment_variables 的處理 |
| 外掛提供技能 `plugin:skill` | tools/skills_tool_plugin.py（H§10） | ⬜ | 只有列舉 `Source::Plugin`（crates/seagent-skills/src/skill.rs），PluginHost 沒有 skills 宣告 |
| 內建技能同步 | tools/skills_sync*.py（H§10） | ⬜ | 只有 `skill::share_dir`、`Source::Bundled`；沒有同步、沒有修改追蹤、沒有附帶技能 |
| Hub：官方 optional-skills | tools/skills_hub_official.py（H§10） | ⬜ | crates/seagent-skills/src/hub/mod.rs 全部是 stub |
| Hub：GitHub taps | tools/skills_hub_github.py（H§10） | ⬜ | 同上 |
| Hub：ClawHub | tools/skills_hub_clawhub.py（H§10） | ⬜ | 同上 |
| Hub：skills.sh | tools/skills_hub_skillssh.py（H§10） | ⬜ | 同上 |
| Hub：LobeHub/browse.sh/well-known/URL | tools/skills_hub_sources.py（H§10） | ⬜ | 同上 |
| Hub 統一搜尋 | tools/skills_hub_search.py（H§10） | ⬜ | 同上 |
| Hub 安裝（隔離、symlink 防護） | tools/skills_hub_install.py（H§10） | ⬜ | 同上 |
| Skills Guard | tools/skills_guard.py（H§10） | ⬜ | 沒有技能掃描；`threats::scan` 只用在 subdir（context 檔） |
| SkillEvaluator 掃描 | tools/skillevaluator_scan.py（H§10） | ⬜ | — |
| AST 深度稽核 | tools/skills_ast_audit.py（H§10） | ⬜ | — |
| 技能 linter | tools/skill_linter.py（H§10） | ⬜ | 只有名稱檢查 `valid_name`（plan.rs、skill.rs） |
| 技能 ledger＋回滾 | tools/skill_ledger.py（H§10） | ⬜ | — |
| 技能使用遙測 | tools/skill_usage.py（H§10） | ⬜ | kernel 有呼叫 `Lifecycle::tool_settled`，但沒有實作者 |
| Curator | agent/curator.py, curator_backup.py（H§10） | ⬜ | `seagent curator` 導到 stub `core::cli`，回錯誤 |
| 背景回顧寫技能 | agent/background_review.py（H§10） | 🚧 | `Runtime::review` 只產生記憶建議（既有，未改動）；不寫技能 |
| 技能 bundles | agent/skill_bundles.py（H§10） | ⬜ | `seagent bundles` 導到 stub，回錯誤 |
| Blueprints | tools/blueprints.py, cron/blueprint_catalog.py（H§10） | ⬜ | — |
| 技能發佈/匯出/匯入 | hermes_cli/skills_hub.py（H§10） | ⬜ | — |
| 內建技能內容（skills/ 58 個） | skills/**（H§10） | ⬜ | repo 內 `find -name SKILL.md` 沒有結果 |
| optional-skills（153 個） | optional-skills/**（H§10） | ⬜ | 沒有內容，也沒有目錄機制 |

## Hermes §11 記憶（7：✅1／🚧6）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 內建 MEMORY.md / USER.md | tools/memory_tool_store.py（H§11） | ✅ | `Memory` 工具（crates/seagent-tools/src/memory.rs，已註冊於 `builtin_tools`）新增 patch、原子 `operations` 批次、預設 4000 字元上限；tests `patch_keeps_rest_of_entry`、`batch_is_atomic_against_final_budget`、`whole_entry_match_wins_over_substring`。`[memory] memory_char_limit/user_char_limit/write_approval` 不會生效：`set_limits`/`set_write_approval` 只在從未被呼叫的 `seagent_memory::Host::new` 裡 |
| MemoryManager（多供應商扇出） | agent/memory_manager.py, memory_provider.py（H§11） | 🚧 | `manager::MemoryManager` 實作了 `Lifecycle`（tests `plugin_protocol_fanout`、`stuck_provider_times_out_and_is_skipped`），kernel 掛點也有呼叫；但 `host::attach` 是空的，從沒註冊 |
| 記憶查詢改寫 | plugins/memory/query_rewrite.py（H§11） | 🚧 | `rewrite.rs`（test `normalize_rules`）未接線 |
| 記憶 context 圍欄 | agent/memory_context.py（H§11） | 🚧 | `lifecycle::fence` 只在有 lifecycle 時使用（目前沒有）；`fence::StreamScrubber` 沒接到輸出串流；test `sanitize_and_stream` 依記錄是 **FAILED** |
| 記憶寫入威脅掃描 | tools/threat_patterns.py（H§11） | 🚧 | `WRITE_SCANNER`（memory.rs）只在 test `scanner_rejects` 裡設定；`threats::scan` 沒接上它 |
| 記憶 provider 遷移/OAuth | memory_provider_migration.py, memory_oauth.py（H§11） | 🚧 | `migrate.rs`、`oauth.rs`（tests `provider_check_and_backoff`、`loopback_pkce_flow`）未接線，也沒有 CLI 或路由 |
| Honcho profile 整合 | hermes_cli/profiles_honcho.py（H§11） | 🚧 | `migrate.rs` 的 honcho host（test `clone_and_honcho_host_and_import`）未接線 |

## Hermes §12 Context、提示與壓縮（25：✅7／🚧11／⬜7）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 自動 context 壓縮 | agent/context_compressor*.py（H§12） | ✅ | compaction.rs、kernel `maybe_compact`（既有，未改動） |
| micro-compaction | agent/micro_compaction.py（H§12） | 🚧 | `microcompact.rs`（tests `tick_respects_every_n`、`absorb_defrag_reset`、`next_exchange_stops_before_kept_tail`）與 config `compaction.micro_compact*` 都在，但 kernel 從未呼叫 `MicroState` |
| 部分壓縮「到這裡為止」 | hermes_cli/partial_compress.py（H§12） | ⬜ | — |
| OpenAI 原生 server 端壓縮 | agent/native_compaction.py（H§12） | ⬜ | — |
| 壓縮事件/遙測 | agent/compaction_events.py（H§12） | ✅ | hooks.rs 的 PreCompact/PostCompact（既有） |
| Context engine 外掛 | agent/context_engine.py（H§12） | ✅ | engine.rs（既有） |
| 專案指令檔 | agent/prompt_builder.py（H§12） | ✅ | context.rs `PROJECT_FILES`（既有） |
| 子目錄提示漸進載入 | agent/subdirectory_hints.py（H§12） | 🚧 | `subdir::Tracker::check`（3 個測試）在 kernel 的工具迴圈裡沒有呼叫端 |
| @-參照展開 | agent/context_references.py（H§12） | 🚧 | `refs::expand`（5 個測試，含 git 與 url）在 `consume_inbox` 沒有被呼叫 |
| SOUL.md / 人格 | SOUL.md, personality.py（H§12） | 🚧 | 只有 `identity` 與 ContextConfig 欄位；沒有載入 SOUL 或人格的程式 |
| coding posture | agent/coding_context.py（H§12） | 🚧 | 只有 ContextConfig 欄位 |
| 本機工具鏈探測 | tools/env_probe.py（H§12） | 🚧 | 只有 ContextConfig 欄位 |
| Anthropic prompt caching | agent/prompt_caching.py（H§12） | ✅ | seagent-model/anthropic.rs（既有） |
| context 用量拆解 | agent/context_breakdown.py（H§12） | ⬜ | — |
| context 長度 pin | agent/context_pin.py（H§12） | 🚧 | 未改動：內建供應商沒有覆蓋欄 |
| models.dev 中繼資料 | agent/models_dev.py（H§12） | 🚧 | 未改動：只有 `caps_for` 表 |
| 圖片淘汰 | agent/image_eviction_policy.py（H§12） | ⬜ | — |
| 非視覺模型圖片退化 | agent/vision_message_prep.py（H§12） | ⬜ | — |
| 自動標題生成 | agent/title_generator.py（H§12） | 🚧 | 只有 `CtxState.titles` 與 `title_generation` 欄位；沒有 LLM 生成，也沒有呼叫 |
| session recap | hermes_cli/session_recap.py（H§12） | ⬜ | `ctxhost.rs` 的註解提到 /recap，但 `attach` 是空的 |
| 旁支提問 /btw | agent/side_question.py（H§12） | 🚧 | 只有 `side_question_model` 欄位 |
| 空回應/截斷恢復 | agent/turn_*.py（H§12） | ✅ | kernel.rs（既有） |
| 迭代預算 | agent/iteration_budget.py（H§12） | ✅ | `max_steps_per_turn`（既有） |
| 驗證迴圈 pre_verify | agent/verify_hooks.py（H§12） | 🚧 | `verify.rs`（tests `edits_then_verification`、`modes_text_and_hook_protocol`）與 `VerifyGate` 都在，kernel 沒有呼叫；config 會丟掉專案層的 `context.pre_verify` |
| i18n | agent/i18n*.py（H§12） | ⬜ | — |

## Hermes §19 外掛系統（14：✅6／🚧2／⬜6）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 外掛載入與 manifest | hermes_cli/plugins*.py（H§19） | ✅ | seagent-plugin/plugin.rs（既有，未改動） |
| 外掛 hooks | plugin_events.py（H§19） | ✅ | 既有 |
| 外掛 middleware | middleware.py（H§19） | ✅ | 既有 |
| 外掛註冊各類後端 | agent/*_provider.py（H§19） | 🚧 | 未改動：沒有 TTS/STT/瀏覽器/影像/影片/web 後端的擴充點 |
| 外掛 LLM 存取 | agent/plugin_llm.py（H§19） | ✅ | ext.rs `sampling_request`（既有） |
| 外掛串流 hook | plugin_stream_hooks.py（H§19） | ⬜ | — |
| 外掛隔離 | plugin_host*.py（H§19） | ✅ | stdio 子行程（既有） |
| 外掛安裝掃描 | tools/plugin_guard.py（H§19） | ⬜ | — |
| 外掛目錄（706 yaml） | plugin-catalog/*.yaml（H§19） | ⬜ | 沒有目錄；`seagent plugins install` 導到 stub |
| 外掛 UI 分頁 | plugin_validate_desktop.py（H§19） | ✅ | 既有 |
| disk-cleanup | plugins/disk-cleanup（H§19） | ⬜ | — |
| security-guidance | plugins/security-guidance（H§19） | ⬜ | — |
| hermes-achievements | plugins/hermes-achievements（H§19） | ⬜ | — |
| dashboard_auth | plugins/dashboard_auth（H§19） | 🚧 | 未改動：只有 bearer token |

## Hermes 其他章節中屬本主題的列（§1/§6/§8/§9；28：✅1／🚧15／⬜12）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| skills_list | tools/skills_tool.py（H§1） | 🚧 | 沒有這個工具，也沒有分類；索引直接放在提示裡（未改動） |
| skill_view | tools/skills_tool.py 等（H§1） | 🚧 | 只有 `skill action=view`（plan.rs）；沒有 plugin 技能、去重、env setup |
| skill_manage | tools/skill_manager_tool.py 等（H§1） | 🚧 | 只有 `skill create/update/archive`；沒有 patch、批次、guard、lint、ledger、核准 |
| memory 工具 | tools/memory_tool.py（H§1） | 🚧 | patch、批次、字元預算都已完成且有測試；**威脅掃描沒接線**（`WRITE_SCANNER` 從未在測試以外設定） |
| tool_search（BM25） | tools/tool_search.py（H§6） | 🚧 | `toolsearch::Index`（tests `bm25_ranks_relevant_tools_first` 等）與 config `[tools.tool_search]` 都在；沒有註冊 `tool_search` 工具，kernel 也沒有呼叫 |
| /title | commands.py（H§8） | 🚧 | 未改動；沒有斜線指令 |
| /compress | commands.py（H§8） | 🚧 | 只有 `/compact`；沒有 `here N`、`--preview` |
| /btw | commands.py（H§8） | ⬜ | 沒有註冊任何 Slash |
| /journey | commands.py（H§8） | 🚧 | `journey.rs`（test `graph_timeline_and_mutations`）與 `seagent_memory::slash` 都在，但沒有註冊 |
| /refine | commands.py（H§8） | 🚧 | 未改動 |
| /context | commands.py（H§8） | 🚧 | 只有 `/status` |
| /personality | commands.py（H§8） | ⬜ | — |
| /skills | commands.py（H§8） | ⬜ | — |
| /memory | commands.py（H§8） | 🚧 | **迴歸**：`seagent memory accept|reject` 現在被 `wire::owns` 導到 stub，回錯誤（review 還能用）；e2e run.py:442 會失敗 |
| /bundles | commands.py（H§8） | ⬜ | — |
| /learn | commands.py（H§8） | ⬜ | — |
| /init | commands.py（H§8） | ⬜ | — |
| /curator | commands.py（H§8） | ⬜ | — |
| /reload-skills | commands.py（H§8） | 🚧 | 未改動 |
| /plugins | commands.py（H§8） | ✅ | `seagent plugin list`（既有，未改動；`wire::owns` 對 `list` 回傳 false） |
| /<skill-name> | agent/skill_commands.py（H§8） | ⬜ | 有 native 斜線框架（`slash.rs`、`Runtime::run_slash`，test `split_names_and_args`），但沒有技能處理器 |
| /<bundle-name> | agent/skill_bundles.py（H§8） | ⬜ | — |
| skills CLI（27 子指令） | subcommands/skills.py（H§9） | ⬜ | `seagent skills` → stub 回 "`seagent skills` is not implemented yet" |
| bundles CLI | subcommands/bundles.py（H§9） | ⬜ | 同上，stub |
| curator CLI | subcommands/curator.py（H§9） | ⬜ | 同上，stub |
| memory setup/status/off/reset | subcommands/memory.py（H§9） | 🚧 | `seagent_memory::cli::run` 已實作 setup/status/off/reset/approval/index（tests `memory_verbs`、`review_accept_reject_staged_ops`），但 `host::cli` 是 stub，CLI 實際回錯誤 |
| journey CLI | subcommands/journey.py（H§9） | 🚧 | `journey.rs` 在；`seagent journey` 導到 stub |
| plugins CLI 生命週期 | subcommands/plugins.py（H§9） | 🚧 | 只有 `seagent plugin list`；`install|update|…` 導到 stub `hub::plugin_cli` |

## OpenClaw §9 Skills（53：🚧3／⬜41／N/A 9）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Skill loading + index（含 requires bins/env/os 篩選） | src/skills, system-prompt-skills.ts（O§9） | 🚧 | 探索與索引沿用既有 context.rs；沒有 requirements 篩選。`seagent_skills::skill::discover` 只有探索功能且未接線 |
| Skill install from ClawHub | skills/clawhub, skills-cli.ts（O§9） | ⬜ | hub 是 stub |
| Skill env/API-key 注入 | src/skills（O§9） | ⬜ | — |
| 1password | skills/1password（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| apple-notes | skills/apple-notes（O§9） | N/A | 僅 macOS（macOS app） |
| apple-reminders | skills/apple-reminders（O§9） | N/A | 僅 macOS（macOS app） |
| bear-notes | skills/bear-notes（O§9） | N/A | 僅 macOS（macOS app） |
| blogwatcher | skills/blogwatcher（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| blucli | skills/blucli（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| camsnap | skills/camsnap（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| clawhub | skills/clawhub（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| coding-agent | skills/coding-agent（O§9） | 🚧 | 未附 SKILL.md；功能面由既有 `acp_delegate`（crates/seagent-app/src/acp_client.rs）涵蓋（既有，未改動） |
| control-ui | skills/control-ui（O§9） | N/A | OpenClaw 專屬（OpenClaw UI-specific） |
| diagram-maker | skills/diagram-maker（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| eightctl | skills/eightctl（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| gemini | skills/gemini（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| gh-issues | skills/gh-issues（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| gifgrep | skills/gifgrep（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| github | skills/github（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| gog | skills/gog（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| goplaces | skills/goplaces（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| healthcheck | skills/healthcheck（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| himalaya | skills/himalaya（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| mcporter | skills/mcporter（O§9） | N/A | 與 SE Agent 原生 MCP（crates/seagent-plugin/src/mcp.rs）重疊 |
| meme-maker | skills/meme-maker（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| model-usage | skills/model-usage（O§9） | N/A | 僅 macOS（macOS CodexBar app） |
| nano-pdf | skills/nano-pdf（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| node-connect | skills/node-connect（O§9） | N/A | OpenClaw 專屬（OpenClaw apps-specific） |
| node-inspect-debugger | skills/node-inspect-debugger（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| notion | skills/notion（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| obsidian | skills/obsidian（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| openai-whisper | skills/openai-whisper（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| openai-whisper-api | skills/openai-whisper-api（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| openhue | skills/openhue（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| oracle | skills/oracle（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| ordercli | skills/ordercli（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| peekaboo | skills/peekaboo（O§9） | N/A | 僅 macOS（macOS） |
| python-debugpy | skills/python-debugpy（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| sag | skills/sag（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| sherpa-onnx-tts | skills/sherpa-onnx-tts（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| skill-creator | skills/skill-creator（O§9） | 🚧 | 未附 SKILL.md；既有 `skill action=create/update/archive`（crates/seagent-tools/src/plan.rs，test `skill_lifecycle_and_guards`）可寫技能（既有，未改動） |
| songsee | skills/songsee（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| sonoscli | skills/sonoscli（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| spike | skills/spike（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| spotify-player | skills/spotify-player（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| summarize | skills/summarize（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| things-mac | skills/things-mac（O§9） | N/A | 僅 macOS（macOS app） |
| tmux | skills/tmux（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| trello | skills/trello（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| visualize | skills/visualize（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| weather | skills/weather（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| xurl | skills/xurl（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |
| custodian skills (add-model-provider, cloud-image-bake, configure-channel, diagnose-gateway) | custodian-skills/（O§9） | ⬜ | repo 內無任何 SKILL.md（未附帶）；hub 安裝路徑為 stub（crates/seagent-skills/src/hub/mod.rs） |

## OpenClaw 其他章節中屬本主題的列（§1/§2/§3/§5/§6/§8；31：✅5／🚧18／⬜8）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| memory_search（hybrid） | extensions/memory-core（O§1） | 🚧 | `tools::MemorySearch`、`index.rs`（FTS 加向量、MMR、時間衰減；tests `vectors_cached_and_hybrid_ranks`、`mmr_diversifies_duplicates`、`search_records_recall_and_get_reads_bounded`）都在，**但沒有註冊**：`host::tools` 回傳 `vec![]` |
| memory_get | extensions/memory-core（O§1） | 🚧 | `tools::MemoryGet` 同上，未註冊 |
| personal_instructions | personal-instructions-tool.ts（O§1） | 🚧 | `tools::PersonalInstructions`（test `personal_instructions_per_sender_with_hash`）未註冊 |
| plugins 工具 | plugins-tool.ts（O§1） | ⬜ | — |
| skill_workshop | skill-workshop-tool*.ts（O§1） | 🚧 | 未改動：只有 `skill create/update/archive` |
| skills_search | tool-catalog.ts（O§1） | 🚧 | 未改動：沒有搜尋工具 |
| skills_read | tool-catalog.ts（O§1） | ✅ | `skill action=view`（plan.rs，test `skill_lifecycle_and_guards`；既有，未改動） |
| tool_search / tool_describe | tool-search*.ts（O§1） | ✅ | `tool_describe`/`tool_call`（context.rs:153，tests/runner.rs；既有）。BM25 `toolsearch.rs` 未接線 |
| wiki_* | extensions/memory-wiki（O§2） | 🚧 | `wiki.rs`（tests `vault_lifecycle`、`lint_duplicates_conflicts_and_staleness`）未接線，沒有工具註冊 |
| memory_recall/store/forget | extensions/memory-lancedb（O§2） | 🚧 | `vector.rs` 的 `VectorMemory`、`AutoMemory`（tests `store_recall_forget_round_trip`、`auto_recall_and_capture_policy`）未接線 |
| dreaming | extensions/memory-core（O§2） | 🚧 | `dreaming.rs`（tests `sweep_promotes_recurring_recalls`、`tick_follows_cron`）；`dreaming_tick` 沒有排程器呼叫 |
| active-memory | extensions/active-memory（O§2） | 🚧 | `active.rs` 的 `ActiveMemory: Lifecycle` 未註冊；test `escalate_recall_agent_cache_breaker_and_toggle` 依記錄是 **FAILED** |
| embeddings providers | extensions/*（O§3） | 🚧 | `embed::build` 支援 openai/mistral/voyage/deepinfra/lmstudio/omlx/llama-cpp/gemini/ollama/bedrock(SigV4)/github-copilot/local，有 fake-server 測試（`openai_family_request_and_ordering`、`bedrock_titan_and_cohere_signed`…共 9 個）；只有尚未接線的 memory_search 會用到 |
| /skill <name> | commands-registry（O§5） | 🚧 | 未改動：只有自訂指令；native slash 框架是空的 |
| /learn | commands-registry（O§5） | ⬜ | — |
| /context | commands-registry（O§5） | ⬜ | — |
| /btw | commands-registry（O§5） | ⬜ | — |
| /plugins list/show/enable/disable | commands-registry（O§5） | ⬜ | — |
| /compact | commands-registry（O§5） | 🚧 | 只在 `seagent chat`（未改動） |
| /active-memory | extensions/active-memory（O§5） | 🚧 | 有 `active::command`，經 `seagent_memory::slash` 分派，但沒有註冊 |
| /dreaming | extensions/memory-core（O§5） | 🚧 | `dreaming::command` 同上，未註冊 |
| 自訂 Markdown 指令 | chat-command-invocation.ts（O§5） | ✅ | crates/seagent-kernel/src/commands.rs（既有，未改動） |
| plugins CLI install/update/marketplace | plugins-*.ts（O§6） | 🚧 | 只有 list；其他子指令導到 stub |
| skills CLI list/info/check/search/install | skills-cli.ts（O§6） | ⬜ | stub |
| Context engine plugins | src/context-engine（O§8） | ✅ | engine.rs（既有） |
| Compaction | src/agents/compaction*.ts（O§8） | ✅ | compaction.rs（既有） |
| Memory host SDK（events/query） | packages/memory-host-sdk（O§8） | 🚧 | `events.rs`（test `store_bounds_and_cursors`）未接線 |
| Memory flush before compaction | agent-tools.memory-flush.ts（O§8） | 🚧 | `flush::Flush: Lifecycle::pre_compress`（test `appends_notes_or_stays_silent`），kernel 的 pre_compress 掛點有呼叫，但沒有註冊 |
| Project memory / bootstrap files | workspace-bootstrap-*.ts（O§8） | 🚧 | 未改動：沒有 SOUL/IDENTITY/BOOT |
| Claws（ClawHub 套件） | src/claws（O§8） | ⬜ | — |
| ClawHub plugin marketplace | plugins-marketplace-list-command.ts（O§8） | ⬜ | — |

## 與 `docs/parity-agent/skills.md`（上一輪前所寫）說法不同的列

| 列 | skills.md 的說法 | 本次查核 |
|---|---|---|
| 工作樹狀態總述 | ctxstate/refs/subdir/threats 未宣告；toolsearch/microcompact/verify 不存在；seagent-kernel 無法編譯 | 全部已宣告且存在；依 skills-full.log 可以編譯（失敗的只有測試） |
| 工作樹狀態總述 | seagent-memory 不被 crates/seagent 依賴 | 已經是依賴；但 `host.rs` 的 tools/attach/cli 都是 stub，實質上仍未接線 |
| 工作樹狀態總述 | seagent-skills 只有一行 doc 註解 | 有 skill.rs、yaml.rs（約 950 行、6 個測試），其餘是 stub；仍沒有任何工具或 CLI |
| micro-compaction | `microcompact` 模組不存在 | 存在並有 3 個測試；kernel 沒有呼叫（仍 🚧） |
| 驗證迴圈 pre_verify | `verify` 模組不存在 | 存在並有 2 個測試；kernel 沒有呼叫（仍 🚧） |
| 子目錄提示、@-參照 | 未在 lib.rs 宣告 | 已宣告；kernel 沒有呼叫（仍 🚧） |
| 記憶寫入威脅掃描 | threats 未宣告 | 已宣告；仍沒接到 `WRITE_SCANNER`（仍 🚧） |
| MemoryManager／查詢改寫／遷移／Honcho | 不能編譯、未被依賴 | 可以編譯、已被依賴，但 `host::attach`/`tools` 是空的（仍 🚧） |
| 記憶 context 圍欄 | 未接線 | kernel 的 consume_inbox 已會 fence prefetch，但沒有 lifecycle 註冊；另外 fence 測試失敗 |
| OpenClaw §9 中 9 個 macOS／OpenClaw 專屬技能 | 一律 ⬜ | 判為 N/A（具體理由：僅 macOS app，或與 SE Agent 原生 MCP 重疊） |
| 範圍 | 125 列（只含 H§10/11/12/19、O§9） | 漏掉 59 列屬本主題的項目：H§1 skills_list/skill_view/skill_manage/memory、H§6 tool_search、H§8 17 個斜線、H§9 6 個 CLI、O§1/§2/§3/§5/§6/§8 31 列 |
| （skills.md 未列）/memory、`seagent memory accept/reject` | 盤點原為 ✅ | **迴歸成 🚧**：被 `wire::owns` 導到 stub |

除上述以外，skills.md 各列的狀態符號與本次查核一致；新程式雖然存在，但沒有接線，所以沒有任何一列升為 ✅。

## 剩餘缺口（依使用者影響排序）

1. /memory（H§8）：`seagent memory accept|reject` 被 `wire::owns` 導到 `seagent_memory::host::cli` 的 stub，現在一律報錯（迴歸；e2e run.py:442 會失敗）。
2. memory_search（O§1）：`MemorySearch` 與 hybrid index 已寫好，但 `seagent_memory::host::tools` 回傳空；要改成呼叫 `Host::new` 加 `seagent_memory::tools(&h)`。
3. memory_get（O§1）：同上，未註冊。
4. embeddings providers（O§3）：程式完整，但沒有使用端（要等 memory_search 接線）。
5. MemoryManager（H§11）：`lifecycles()` 從沒被傳給 `add_lifecycle`，prefetch/sync/pre_compress 都不會發生。
6. Memory flush before compaction（O§8）：`Flush` 未註冊。
7. active-memory（O§2）：`ActiveMemory` 未註冊；它的測試失敗。
8. /active-memory（O§5）：`seagent_memory::slash` 沒有包成 `Slash` 註冊。
9. dreaming（O§2）：`dreaming_tick` 沒有排程器呼叫。
10. /dreaming（O§5）：未註冊。
11. memory_recall/store/forget（O§2）：`VectorMemory` 工具與 `AutoMemory` 都未註冊。
12. wiki_*（O§2）：`wiki.rs` 沒有工具或 CLI 接線（`seagent memory wiki` 會進 stub）。
13. （✅ 列的附帶缺口）內建 MEMORY.md / USER.md（H§11）的字元上限、write_approval 設定：設定不生效（`set_limits` 從未被呼叫）。
14. memory 工具（H§1）：威脅掃描 `WRITE_SCANNER` 沒有接到 `threats::scan`。
15. 記憶寫入威脅掃描（H§11）：同上。
16. 記憶 context 圍欄（H§11）：沒有 lifecycle，所以 fence 不會生效；`StreamScrubber` 沒接到輸出；fence 測試失敗。
17. 記憶查詢改寫（H§11）：`rewrite.rs` 未接線。
18. memory setup/status/off/reset（H§9）：`seagent_memory::cli::run` 已實作，但 host 是 stub。
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
30. Skill loading + gating（O§9）：沒有 requires bins/env/os 篩選；`seagent_skills::skill::discover` 未使用。
31. 技能必要 env 與秘密收集（H§10）：沒有 required_environment_variables 處理。
32. Skill env/API-key 注入（O§9）：沒有。
33. SKILL.md 前處理（H§10）：沒有。
34. 技能索引即時增量（H§10）：沒有。
35. /reload-skills（H§8）：沒有即時重掃。
36. /<skill-name>（H§8）：native slash 框架在，但沒有技能處理器。
37. /skill <name>（O§5）：同上。
38. /skills（H§8）：沒有。
39. skills CLI 27 子指令（H§9）：`seagent skills` 只回 stub 錯誤。
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
83. /compact（O§5）：只在 `seagent chat`。
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
