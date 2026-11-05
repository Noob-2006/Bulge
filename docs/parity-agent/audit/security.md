# security 串流稽核結果

**編譯／測試**：`cargo build --workspace --all-targets` 成功；`cargo test --workspace --no-fail-fast` 通過 848、失敗 4、忽略 2。
- 失敗：`ark_security::skills_guard::tests::path_references_are_demoted_in_comments_and_denylists`（ssh_dir_access 的 denylist 斷言），以及 `ark_security::skills_guard::difftmp::diff_against_python`。後者是與 Python 版逐檔比對的暫時測試，`hermes_config_ref`、`hermes_env_access` 等 finding 缺漏多筆，表示 skills_guard 和上游尚未一致。
- coderun 兩個測試（`coderun::tests::script_output_exit_codes_and_nested_protocol`、`failures_timeout_cancel_and_bad_lang`）在五個副本都失敗，原因是稽核規定的 TMPDIR 路徑過長，Unix socket 超過 SUN_LEN（`cannot bind …/call-*.sock: path must be shorter than SUN_LEN`）。這是環境造成的，與本串流程式無關。
- ✅ 列引用的測試全部通過。
- 原始輸出：`audit/security-tests.txt`

**狀態統計（50 列）**：✅ 29 · 🚧 17 · ⬜ 1 · N/A 3


# security 串流稽核（w-security）

## 差異範圍

- 52 個檔案變更，+9527/−108（`git diff --stat HEAD`）。新 crate `crates/ark-security`（已列入 workspace members）：approvals、credfiles、envscrub、estop、external、glob、hardline、osv、paths、plugin_guard、review、threat、toolpolicy、url_safety（全部已 staged）。
- 未追蹤：`ark-security/src/skills_guard.rs`（lib.rs 已 `pub mod`，會編譯，但 crate 外無呼叫端）、`ark-security/src/egress_proxy.rs`（**lib.rs 未宣告 `mod`，是死碼；其 4 個測試不會編譯也不會執行**）。
- kernel 新檔：`secgate.rs`（取代原兩道閘的整套核准流程，kernel.rs:1290 `security_gate`、:1269 `guard_tool_output`、:188/:442 `tool_permitted`）、`interp.rs`（gate.rs:103 呼叫）、`selfrepo.rs`；整合測試 `crates/ark-kernel/tests/security.rs`（9 個）。
- CLI：`crates/ark/src/security_cli.rs`（`ark approvals …`、`ark exec-policy`、`ark security audit|scan|plugins|check-url|credential-files`、`ark pause|resume`），main.rs:124/213-227；REPL `/yolo /approvals /elevated /exec /pause /resume /approve /deny`（main.rs:571-575）；daemon `session.command`（daemon.rs:302，TUI 走這條）。
- 外部呼叫點：envscrub 套用於 shell.rs:106、job.rs:117、coderun.rs:92、hooks.rs:253、acp_client.rs:655、ark-plugin transport.rs:177；OSV 於 transport.rs:166；plugin consent 於 ext.rs `start_guarded`；threat 於 context.rs:87/101、automation.rs:165；estop 於 automation.rs:160、daemon.rs:155/199。

## 統計

| 狀態 | 數量 |
|---|---|
| ✅ | 29 |
| 🚧 | 17 |
| ⬜ | 1 |
| N/A | 3 |
| 合計 | 50 |

（✅ 為暫定：若下方列出的測試在實跑中失敗，對應列需降為 🚧。）

## 逐列狀態

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| SSRF／url_safety 政策層（私網、metadata、DNS 後檢查） | Hermes tools/url_safety.py；OC web-fetch SSRF | 🚧 | `url_safety.rs` `is_safe_url`/`resolve_safe`/`check_url_global` 完整，測試 `private_and_metadata_targets_are_blocked`、`fake_ip_ranges_are_dialable_but_cannot_cover_real_private_space`；但 `url_safety::configure` 從未被呼叫，本複本的 `web_fetch` 未使用它，只有 `ark security check-url` 用到（實際接線屬 web 串流） |
| 網站黑名單 | Hermes tools/website_policy.py | ✅ | secgate.rs `floors` 對 `Effect::Net/Remote` 呼叫 `check_website_access`；測試 `website_blocklist_rules` |
| 危險指令偵測 | Hermes approval_detection.py, shell_heredoc.py | ✅ | 原有 shell 分析器＋`hardline.rs` normalize/deobfuscate/mask_quoted；測試 `hardline_catches_catastrophic_commands`、`hardline_ignores_prose_and_ordinary_work`、`inner_payloads_from_the_parser_are_scanned` |
| 檔案安全規則／path_security（讀寫兩側） | Hermes agent/file_safety.py, tools/path_security.py | ✅ | `paths.rs` `read_block`/`write_block`/`write_needs_approval`，secgate `floors` 對 Read/Write 套用；測試 `reads_of_credential_stores_and_env_files_are_denied`、`writes_to_credentials_ark_state_and_outside_safe_roots_are_denied`、`path_floors_threats_and_output_wrapping` |
| self-repo 守衛 | Hermes tools/self_repo_guard.py | ✅ | `selfrepo.rs` `find_mutation`，secgate.rs:157（`security.self_repo_guard`，預設關）；測試 `detects_worktree_rewrites_only_inside_root`（僅單元測試，無 kernel 層測試） |
| runtime 自我保護 | Hermes agent/runtime_self_protection.py | N/A | Python venv／直譯器專屬，ark 為單一原生執行檔 |
| 子行程 env 秘密清洗 | Hermes local_env_policy.py, code_execution_env.py | ✅ | `envscrub::apply` 套用於 shell/job/coderun/hooks/ACP client/MCP transport；kernel.rs:151 `activate()`；測試 `provider_and_bot_secrets_are_blocked_user_vars_are_not`、`apply_removes_inherited_secret_from_child` |
| 輸出秘密遮蔽 | Hermes agent/redact.py | ✅ | 原有 vault redact（ark-kernel/vault.rs），secgate 送審前也 redact |
| 威脅樣式庫（context 檔、記憶、cron、工具輸出） | Hermes tools/threat_patterns.py | ✅ | `threat.rs`；context.rs:87/101（記憶快照、AGENTS.md）、secgate `floors`（memory add/replace）、automation.rs:165（cron 執行時）、`guard_tool_output`；測試 `classic_injections_are_found_everywhere`、`memory_entries_and_cron_prompts`、`poisoned_context_files_and_memory_are_blocked`、`path_floors_threats_and_output_wrapping`（cron 只有單元測試） |
| MCP 套件 OSV 惡意檢查 | Hermes tools/osv_check.py | ✅ | transport.rs:166 `osv::launch_check`；測試 `launcher_parsing`、`malware_is_blocked_cves_ignored_errors_fail_open`（本地假伺服器） |
| credential_files 直通 | Hermes tools/credential_files.py | 🚧 | `credfiles.rs` `mounts` 有測試 `entries_are_contained_and_existing`；只被 `ark security credential-files` 列出，沒有任何沙箱實際掛載（需 exec 串流後端呼叫） |
| 危險指令核准流程（once/session/always/deny） | Hermes tools/approval.py | ✅ | secgate.rs `decide`（Once/Always/Permanent/Deny、拒絕理由回傳）；測試 `deny_reason_is_relayed_and_cron_context_uses_cron_mode`、`pending_answer_and_timeout` |
| smart 核准（輔助 LLM） | Hermes tools/approval_smart.py | ✅ | `review.rs` smart_prompts/parse_smart，secgate `smart_verdict`→`aux_complete`（逾時升級為人工）；測試 `smart_and_auto_reviewers`、`smart_prompt_strips_comments_and_keeps_policy_in_system` |
| yolo 執行中切換 | Hermes tools/approval_yolo.py | ✅ | `approvals::set_session_yolo`，`/yolo`（REPL、daemon `session.command`、TUI）、`ark approvals yolo`、`--yolo`（main.rs:149）；測試 `session_command_runs_security_slash_commands`、`yolo_mode_off_and_durable_grants`、`security_commands_and_keys` |
| floors（不可覆寫底線） | Hermes tools/approval_floors.py | ✅ | `hardline::detect`/`sudo_stdin`/`user_deny` 於 secgate `floors`，yolo 下仍生效；測試 `floors_are_not_bypassable`、`sudo_stdin_guard`、`parser_limit_fails_closed`、`user_deny_rules_survive_quoting_tricks` |
| gateway 阻塞等待核准 | Hermes approval_gateway_wait.py | ✅ | 原有 approver Pending＋daemon gate.pending/answer；測試 `pending_answer_and_timeout` |
| 人類等待計時 | Hermes approval_human_wait.py | ✅ | `approvals::human_wait`，kernel.rs:592-601 `ledger.pause`；測試 `human_wait_is_excluded_from_the_wall_budget` |
| approvals suggest | Hermes hermes_cli/approvals_suggest.py | 🚧 | `secgate::suggest`＋`ark approvals suggest`（security_cli.rs:97）已接線；**無任何測試** |
| approvals test | Hermes subcommands/approvals.py | 🚧 | `secgate::explain`＋`ark approvals test`（security_cli.rs:77）已接線；**無任何測試** |
| 記憶／技能寫入核准閘 | Hermes tools/write_approval.py | 🚧 | secgate.rs:225（`approvals.memory_write_approval` → staging）、:271（`skill_write_approval` → 詢問）已接線；**無測試**；記憶只攔 `add`（`replace` 不經審） |
| 終端核准批次（桌面） | Hermes agent/terminal_approval_batch.py | N/A | Hermes 桌面 GUI 專屬 |
| 緊急停止 ESTOP（pause/resume） | Hermes agent/estop.py, subcommands/pause.py | 🚧 | `estop.rs`、`ark pause/resume`、`/pause`；cron（automation.rs:160）與 goal（daemon.rs:155）會停；**channel 新回合沒有被擋**（ext.rs 無 estop 檢查，`paused_reply` 未被使用），與 `/pause` 回覆文字不符；只有單元測試 `engage_state_and_resume` |
| egress 代理防火牆（iron-proxy） | Hermes proxy_cli.py, docker_egress.py | 🚧 | `egress_proxy.rs`（569 行，含 CONNECT 隧道、SSRF、憑證注入）**未在 lib.rs 宣告，不會編譯**；無設定鍵、無呼叫端、測試不會跑 |
| /yolo | Hermes commands.py | ✅ | secgate `chat_command` "yolo"；測試 `session_command_runs_security_slash_commands`（channel 無此指令） |
| /approvals | Hermes commands.py | ✅ | `chat_command` "approvals"、REPL `/approvals <mode>` 寫回設定（security_cli `persist_mode`）；同上測試 |
| /approve（Hermes） | Hermes commands.py | ✅ | `chat_command` approve/deny（REPL/TUI/daemon）＋原有 `ark gate answer`；`tty_choices`、`security_commands_and_keys` |
| security audit（OSV 供應鏈） | Hermes hermes_cli/security_audit.py | ✅ | `ark security audit --supply-chain`（Cargo.lock、外掛 launcher、requirements/package.json 釘版 → `osv::audit`）；測試 `lockfile_and_pin_discovery`、`malware_is_blocked_cves_ignored_errors_fail_open` |
| 內建外掛 security-guidance | Hermes plugins/security-guidance | ⬜ | 全 repo 無對應程式碼 |
| skills_guard（技能掃描/安裝政策） | Hermes tools/skills_guard.py | 🚧 | `skills_guard.rs`（823 行）＋10 個測試（如 `agent_created_gate`、`trust_levels_and_policy`；其中 `path_references_are_demoted_in_comments_and_denylists` 與 `difftmp::diff_against_python` **失敗**）；**crate 外無呼叫端**：skill 工具建立技能、技能載入都不經它 |
| plugin_guard（外掛掃描） | Hermes plugin guard | ✅ | ext.rs `start_guarded` 於外掛啟動前 `scan_dir`；`ark security scan`；測試 `benign_plugin_is_safe`、`dangerous_and_caution_findings` |
| Exec approvals（security deny/allowlist/full、ask off/on-miss/always、每個執行檔的白名單） | OC src/infra/exec-approval-* | ✅ | secgate.rs:240-265 `effective_exec`/`exec_allowlisted`/safe_bins/`ask_fallback`；測試 `exec_allowlist_ask_modes_and_fallback`、`exec_allowlist_safe_bins_and_paths`、`session_toggles_persist_and_overrides_only_tighten` |
| 核准轉送到聊天 channel（按鈕） | OC exec-approval-forwarder*.ts | 🚧 | 只有 `[approvals.forward]` 設定結構與 `approver_allowed`/`allow_forwarded` 授權輔助；**沒有任何程式把待核准項目送到 channel**；channel 收到 `appr:<id>:<choice>` 按鈕時 ext.rs:884 只當成 `[按鈕] …` 使用者訊息提交，不會回答 approver；channel 路徑也沒有呼叫 `chat_command` |
| 「永遠允許」持久化 | OC exec-approvals store | ✅ | `approvals::add_grant`/`grants`（allowlist 檔）、Permanent 答案寫入；測試 `durable_grants`、`yolo_mode_off_and_durable_grants` |
| Exec auto-reviewer（LLM 評審） | OC src/agents/exec-auto-reviewer.ts | ✅ | `mode=auto` → `auto_verdict`（含 reviewer-directive 偵測、denial breaker）；測試 `smart_and_auto_reviewers`、`auto_reviewer_parsing_is_strict`、`reviewer_directives_are_detected` |
| Elevated mode | OC /elevated、sandbox host escape | 🚧 | `elevated_level` off/on/ask/full；只有 `full` 會影響決策（exec 自動放行），`on`/`ask` 沒有實際語意；本複本沒有沙箱可「逃出到 host」；無 kernel 層測試（僅 `session_toggles_persist_and_overrides_only_tighten`） |
| Tool profiles＋allow/deny groups（per provider/channel/sender） | OC tool-catalog.ts, tool-policy*.ts | ✅ | `toolpolicy.rs`，config.rs:152-162，kernel.rs:188/442 過濾；測試 `profiles_groups_allow_deny`、`scoped_layers_narrow`、`tool_profiles_filter_per_channel` |
| Workspace FS policy／路徑限制 | OC tool-fs-policy.ts | ✅ | `security.workspace_only` → `paths::outside_workspace`（secgate floors）；測試 `workspace_containment_follows_symlinks_and_dotdot`、`path_floors_threats_and_output_wrapping` |
| Secret egress protection | OC provider-secret-egress.ts | ✅ | 原有 egress gate＋vault；`interp.rs` 補上直譯器路徑；測試 `egress_with_secrets_or_sensitive_files_asks`、`interpreter_egress_is_gated_in_the_kernel` |
| External content wrapping（提示注入） | OC src/security/external-content.ts | 🚧 | 工具輸出部分完成：`guard_tool_output`＋`external::wrap`（隨機 id、偽造標記中和）；測試 `wraps_with_matching_random_ids`、`forged_markers_and_special_tokens_are_neutralised`、`path_floors_threats_and_output_wrapping`。**`external_content.channels`（webhook/email 入站）設定沒有被任何程式讀取**，入站訊息未包裝 |
| security audit（fs 權限、暴露面、外掛信任、危險旗標） | OC src/security/audit*.ts | ✅ | `security_cli::audit`（約 30 個 check id）＋`--deep` 外掛掃描；測試 `audit_flags_foot_guns`（`--fix` 的 `fix()` 未測） |
| opengrep 規則 | OC security/opengrep | N/A | 上游 repo 開發用 SAST 工具，非代理功能 |
| 外掛安裝政策／信任同意 | OC install-policy.ts, plugin-capability-consent.ts | ✅ | `security.plugin_consent` off/warn/require＋能力擴張偵測（ext.rs `start_guarded`）、`ark security plugins accept`；測試 `consent_tracks_widening`、`install_policy_command_decides_and_fails_closed`（install_policy 指令只在 `ark security scan` 使用，因 ark 無外掛安裝指令） |
| 沙箱 env 清洗／安全驗證（拒絕危險掛載） | OC sanitize-env-vars.ts, validate-sandbox-security.ts | 🚧 | env 清洗已完成（見上）；危險掛載驗證只有 `credfiles::mount_for` 的路徑限制，沒有沙箱設定驗證（依賴 exec 串流） |
| /approve（OpenClaw，含 channel） | OC commands-registry | 🚧 | REPL/TUI/daemon 可用；**channel 打 `/approve` 不會被處理**（ext.rs 不呼叫 `chat_command`，`who` 參數從未傳入） |
| /elevated | OC commands-registry | 🚧 | REPL/TUI/daemon `chat_command`；channel 不可用；`allow_from` 檢查只在 `who` 有值時生效，但沒有任何呼叫端傳入 |
| /exec | OC commands-registry | 🚧 | security/ask 會生效；`host=`/`node=` 只存起來，**沒有任何 exec 路由讀取**；channel 不可用；無測試 |
| approvals／exec-approvals CLI | OC exec-approvals-cli.ts | ✅ | `ark approvals status/test/suggest/list/allow/revoke/yolo/elevated/exec/mode/pending/resolve`（security_cli.rs:45-208）；底層由 `durable_grants` 等測試覆蓋（CLI 分派本身沒有測試） |
| exec-policy CLI | OC exec-policy-cli.ts | 🚧 | `ark exec-policy`（security_cli.rs:349 `cmd_exec_policy`，show/set 寫回 TOML）已接線；**無測試** |
| security audit/fix CLI | OC security-cli.ts | ✅ | `ark security audit [--deep] [--fix] [--supply-chain] [--fail-on]`；`audit_flags_foot_guns` |
| egress 閘被 `python3 -c`／`node -e`／執行腳本繞過（簡報指定項目） | 簡報 | 🚧 | `interp.rs` 已接入 gate.rs:103：-c/-e/heredoc/here-string、`python3 x.py`/`bash x.sh`/`source` 讀腳本（≤1MB、深度 8）、內嵌 shell 字串、秘密/環境外送、raw socket；`strict_inline_eval`；測試 `one_liners_that_exfiltrate_are_gated`、`scripts_in_the_workspace_are_read`、`interpreter_egress_is_gated_in_the_kernel`。**殘餘風險文件不存在**：interp.rs 文件說明指向 `docs/parity-agent/security.md`，但此檔不存在 |

## 剩餘缺口（依使用者影響排序）

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
