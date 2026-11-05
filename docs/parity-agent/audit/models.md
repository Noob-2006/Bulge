# 稽核：models 串流（模型供應商、路由、認證、成本與用量）

- 串流：models（已合併、未提交於主 repo）
- 目錄：`$R/ark`（HEAD 5c369e5）
- 編譯/測試：建置成功；測試通過 848、失敗 2、忽略 2。失敗只有 `coderun::tests::{script_output_exit_codes_and_nested_protocol,failures_timeout_cancel_and_bad_lang}` 兩個失敗是稽核環境造成（TMPDIR 路徑過長，unix socket 超過 SUN_LEN），五個副本含 ark 都一樣，非本流迴歸。`target/release/ark` 比所有原始碼都新，所以有跑 `python3 tests/e2e/run.py target/release/ark`：37 通過、0 失敗（含 `model_auth_usage_and_slash_commands`）。原始輸出：`audit/models-tests.txt`。
- 差異範圍：修改 29 檔（+2783/−617），主要為 `crates/ark-model/src/{lib,anthropic,gemini,openai_chat,responses,http,classify,sse}.rs`、`crates/ark-kernel/src/{config,context,kernel,ledger,event,projection,compaction}.rs`、`crates/ark-core/src/types.rs`（新增 `RequestOptions`、`ModelRequest.options`）、`crates/ark/src/{main,providers,ext,args,setup,term}.rs`、`tests/e2e/run.py`（新增 `model_auth_usage_and_slash_commands`）。
- 新檔 22：`crates/ark-model/src/{accounts,auth,bedrock,billing,catalog,cli,codex_app,copilot,eventstream,google,local,login,moa,modelsdb,net,ratelimit,reasoning,sigv4,store}.rs`、`src/testdata/rsa_test_key.pem`、`tests/provider_knobs.rs`、`crates/ark/src/models_cli.rs`（另 `docs/parity-agent/` 兩份盤點，未採信）。所有新模組皆在 `ark-model/src/lib.rs` 以 `mod` 宣告；`models_cli` 在 `crates/ark/src/main.rs:3` 宣告。
- 接線路徑：`ark-model::catalog::catalog()`（約 100 個 preset＋別名）→ `crates/ark/src/providers.rs Providers::new/canonical/build`（store 憑證、`api_keys`、`key_cmd`、vault → 多把即 `auth::Pool`；`moa`、`cli`、`codex_app_server` 另建）→ kernel `Resolver::provider`。CLI：`main.rs dispatch` 的 `model|models|login|logout|auth|fallback|usage|insights` → `models_cli.rs`。斜線：`ark chat`（main.rs）與 channel（ext.rs）都呼叫 `models_cli::slash`；TUI/web UI 無。
- 測試現況（只讀、未執行）：ark-model 單元測試約 95 個，其中 `login::tests::fake_server`（TcpListener）被 login/copilot/google/accounts/auth(azure) 共用；`bedrock.rs`、`local.rs`、`billing.rs`、`modelsdb.rs` 各自起本機 server；`tests/adapters.rs`（23）與 `tests/provider_knobs.rs`（6）走 `tests/mock`（TcpListener）。kernel `tests/runner.rs` 新增 3 個；e2e 新增 1 個。
- release binary：`target/release/ark` mtime 2026-11-03 13:33:05，`find crates Cargo.toml Cargo.lock -newer target/release/ark` = 0 檔（最新原始檔 `models_cli.rs` 13:32:14）→ binary 比所有原始碼都新。

## 統計

| 狀態 | 數量 |
|---|---|
| ✅ | 122 |
| 🚧 | 7 |
| ⬜ | 0 |
| N/A | 4 |
| 合計 | 133（H§17 65、H§18 6、H§8 6、H§9 5、O§4 43、O§5 7、O§6 1） |

說明：一般 OpenAI/Anthropic 相容 preset 的「請求/回應程式」是共用 adapter（`openai_chat.rs`/`anthropic.rs`/`responses.rs`/`gemini.rs`），已由 `tests/adapters.rs` 對假 server 測過；preset 本身由 `catalog::tests::covers_both_upstreams`、`lib::tests::presets_are_unique_and_valid` 驗證存在與合法。沒有逐 preset 的假 server 測試，供應商特有參數（如思考參數方言）未逐一驗證。

## H§17 模型供應商與路由（65）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| actual | plugins/model-providers/actual（H§17） | ✅ | catalog.rs preset `actual`（openai_chat）；共用 adapter 測試 |
| ai-gateway / vercel | plugins/model-providers/ai-gateway（H§17） | ✅ | preset `ai-gateway`，別名 vercel |
| alibaba | plugins/model-providers/alibaba（H§17） | ✅ | preset `dashscope`（別名 alibaba），另 `dashscope-cn` |
| alibaba-coding-plan | plugins/model-providers/alibaba-coding-plan（H§17） | ✅ | preset `alibaba-coding-plan`、`-cn`、`alibaba-token-plan(-cn)` |
| anthropic | plugins/model-providers/anthropic（H§17） | ✅ | anthropic.rs；OAuth 訂閱 token：login.rs flow `anthropic`（PKCE）/`anthropic-setup-token`；測試 provider_knobs `anthropic_subscription_token_and_fast_mode`、adapters `anthropic_thinking_tools_cache_control_and_headers` |
| arcee | plugins/model-providers/arcee（H§17） | ✅ | preset `arcee` |
| azure-foundry | plugins/model-providers/azure-foundry（H§17） | ✅ | preset `azure-foundry`/`azure-openai(-entra)`/`microsoft-foundry`；auth.rs `AzureAd`（Entra client credentials，測試 `azure_client_credentials`）；`query` 欄位放 api-version（`azure_api_key_header_and_query`）；無自動 api-version 偵測 |
| bedrock | plugins/model-providers/bedrock, agent/bedrock_adapter.py（H§17） | ✅ | bedrock.rs（ConverseStream）＋sigv4.rs＋eventstream.rs；測試 `converse_stream_text_tool_reasoning_usage_and_sigv4`（本機 server）、`aws_documented_example_signature` |
| commandcode | plugins/model-providers/commandcode（H§17） | ✅ | preset `commandcode`、`commandcode-anthropic` |
| copilot / github-copilot | plugins/model-providers/copilot（H§17） | ✅ | preset `github-copilot`（auth=copilot）；copilot.rs token 交換＋endpoint；login flow `github-copilot`（device）；測試 `exchange_caches_and_uses_endpoint`（fake_server） |
| copilot-acp | plugins/model-providers/copilot-acp, agent/copilot_acp_client.py（H§17） | 🚧 | 只有 preset `copilot-cli`（別名 copilot-acp），以 `copilot -p … --silent` 文字輸出當 CLI 後端（cli.rs dialect `text`）；非 ACP 協定，無工具呼叫/串流事件 |
| custom | plugins/model-providers/custom（H§17） | ✅ | `[providers.x]`（providers.rs `overrides_extend_and_validate`） |
| deepinfra | plugins/model-providers/deepinfra（H§17） | ✅ | preset `deepinfra` |
| deepseek | plugins/model-providers/deepseek（H§17） | ✅ | preset；adapters `openai_chat_tool_calls_and_deepseek_reasoning_echo` |
| fireworks | plugins/model-providers/fireworks（H§17） | ✅ | preset（既有） |
| gemini | plugins/model-providers/gemini（H§17） | ✅ | gemini.rs；adapters `gemini_function_calls_signatures_and_names` |
| gmi | plugins/model-providers/gmi（H§17） | ✅ | preset `gmi` |
| huggingface | plugins/model-providers/huggingface（H§17） | ✅ | preset `huggingface` |
| kilocode / kilo | plugins/model-providers/kilocode（H§17） | ✅ | preset `kilocode` |
| kimi-coding | plugins/model-providers/kimi-coding（H§17） | ✅ | preset `kimi-coding`（anthropic 格式、KimiCLI UA）、`moonshot-cn` |
| lmstudio | plugins/model-providers/lmstudio, agent/lmstudio_reasoning.py（H§17） | ✅ | preset（既有）；無 LM Studio 專屬推理控制，走通用 reasoning_effort |
| meta-ai | plugins/model-providers/meta-ai（H§17） | ✅ | preset `meta-ai`（responses） |
| minimax | plugins/model-providers/minimax（H§17） | ✅ | preset `minimax`、`minimax-anthropic` |
| minimax-cn | hermes_cli/providers.py（H§17） | ✅ | preset `minimax-cn` |
| minimax-oauth | hermes_cli/auth_minimax.py（H§17） | ✅ | preset `minimax-oauth(-cn)`；login.rs Kind::MiniMax；測試 `minimax_user_code_grant` |
| nebius-token-factory | plugins/model-providers/nebius-token-factory（H§17） | ✅ | preset `nebius` |
| nous | plugins/model-providers/nous, hermes_cli/auth_nous.py（H§17） | 🚧 | preset＋login flow `nous`（device，client_id 寫死 `hermes-cli`）；直接用 OAuth access token，缺 Hermes 的 agent-key 換發/續期（auth.py agent_key*） |
| novita | plugins/model-providers/novita（H§17） | ✅ | preset |
| nvidia | plugins/model-providers/nvidia（H§17） | ✅ | preset |
| ollama-cloud | plugins/model-providers/ollama-cloud（H§17） | ✅ | preset `ollama-cloud` |
| openai-api | hermes_cli/providers.py（H§17） | ✅ | preset `openai`/`openai-chat`；adapters `openai_proper_uses_max_completion_tokens` |
| openai-codex | plugins/model-providers/openai-codex（H§17） | ✅ | preset `openai-codex`（quirk codex）；login flow device＋browser PKCE；測試 `codex_device_auth_exchange`、provider_knobs `codex_backend_shape` |
| opencode-zen / opencode-go | plugins/model-providers/opencode-zen（H§17） | ✅ | preset 兩個 |
| openrouter | plugins/model-providers/openrouter（H§17） | ✅ | preset；login `openrouter` 鑄 key（`openrouter_key_minting_and_setup_token_paste`） |
| qwen-oauth | plugins/model-providers/qwen-oauth（H§17） | ✅ | preset `qwen`；login device+PKCE（`rfc8628_device_flow_with_pkce_pending_then_token`） |
| router | plugins/model-providers/router（H§17） | ✅ | preset `router` |
| solstice | plugins/model-providers/solstice（H§17） | N/A | Nous 自家服務（沿用原判） |
| stepfun | plugins/model-providers/stepfun（H§17） | ✅ | preset `stepfun`、`stepfun-plan` |
| tencent-tokenhub / tokenplan | plugins/model-providers/tencent-tokenhub（H§17） | ✅ | preset 兩個 |
| upstage | plugins/model-providers/upstage（H§17） | ✅ | preset |
| vertex | plugins/model-providers/vertex, agent/vertex_adapter.py（H§17） | ✅ | preset `vertex`/`google-vertex`/`anthropic-vertex`；google.rs ADC/服務帳號 JWT（`service_account_jwt_grant`、`user_adc_refresh_grant`，fake_server）；`vertex_publisher_paths` |
| xai | plugins/model-providers/xai（H§17） | ✅ | preset `xai`、`xai-responses` |
| xai-oauth | hermes_cli/auth_xai.py（H§17） | ✅ | preset `xai-oauth`；login device＋OIDC discovery（`terminal_errors_and_aliases` 等） |
| xiaomi | plugins/model-providers/xiaomi（H§17） | ✅ | preset `xiaomi`、`xiaomi-token-plan` |
| zai | plugins/model-providers/zai（H§17） | ✅ | preset `zai`、`zai-coding` |
| 供應商外掛註冊 | providers/base.py（H§17） | ✅ | providers.rs `register`（既有，未改動） |
| wire 格式 | agent/transports/*（H§17） | ✅ | WireFormat 含 OpenAiChat/Responses/Anthropic/Gemini/Bedrock/Cli/CodexAppServer/Moa；adapters `text_streaming_and_usage_all_formats` |
| fallback 鏈 | agent/fallback_cooldown.py（H§17） | ✅ | kernel.rs：Auth/RateLimited 失敗的模型暫時排最後；`ark fallback` 子指令（e2e） |
| 憑證池 | agent/credential_pool*.py（H§17） | ✅ | auth.rs `Pool`（fill_first/round_robin/random/least_used、每 key/每模型冷卻、持久化）；測試 `rotates_on_429_and_cools_model_only` 等 6 個＋e2e 401 輪替 |
| 供應商 OAuth | hermes_cli/auth*.py（H§17） | ✅ | login.rs（RFC 8628 device、PKCE loopback/paste、MiniMax、OpenRouter、CLI 憑證匯入）；9 個 fake_server 測試；`ark login/logout` |
| key_cmd 動態金鑰 | agent/command_token_source.py（H§17） | ✅ | auth.rs key_cmd；`key_cmd_parsing_and_caching` |
| 輔助模型路由（每任務） | agent/auxiliary_client*.py（H§17） | 🚧 | `model.tasks` + `Config::task_model`，實際只用於 compaction/review/sampling（kernel.rs:1009/1048/1464）；vision/title/search 等任務未路由；無每任務健康檢查/fallback |
| 模型清單偵測 | hermes_cli/models_detect.py（H§17） | ✅ | lib.rs `list_models_with`；`model_lists_from_each_api_shape`、bedrock list |
| 昂貴模型確認 | hermes_cli/model_cost_guard.py（H§17） | ✅ | models_cli.rs `cost_warning`（`/model`、`ark model`、`models set` 需 confirm）；測試 `guards` |
| 資料政策確認 | hermes_cli/model_data_policy_guard.py（H§17） | ✅ | `data_policy_warning`（與上游同為 Meta contributor 規則）；測試 `guards` |
| 推理強度 | agent/reasoning_effort.py（H§17） | ✅ | reasoning.rs（正規化、依端點 clamp、預算）；`model.thinking`、`/think`；測試 4 個＋e2e `reasoning_effort=high` |
| 推理摘要/重播 | agent/reasoning_summaries.py（H§17） | ✅ | 既有，未改動（responses_tool_call_and_reasoning_roundtrip） |
| Fast mode / service tier | agent/fast_mode.py（H§17） | ✅ | `RequestOptions.service_tier`、`/fast`、auto/cold 視窗（kernel.rs）；runner `cold_fast_mode_only_on_first_turn`、provider_knobs |
| Codex app-server 執行期 | agent/codex_runtime.py（H§17） | ✅ | codex_app.rs JSON-RPC stdio；preset `codex-app-server`；`drives_a_turn_and_declines_approvals`（fake.py）。核准一律拒絕 |
| 受管本機 llama-server | agent/auxiliary_local_runtime.py（H§17） | ✅ | local.rs `Managed`（model_path 啟動、健康檢查、重啟）；`starts_health_checks_and_restarts`。不自動下載 binary/模型 |
| Mixture of Agents | agent/moa_loop.py（H§17） | ✅ | moa.rs；providers.rs `moa_resolves_its_members`、`references_fan_out_aggregator_answers_with_guidance` |
| 速率限制追蹤 | agent/rate_limit_tracker.py（H§17） | ✅ | ratelimit.rs（record 於 http.rs:73，預等 http.rs:56）；測試 3 個；`/usage` 顯示 |
| 重試抖動退避 | agent/retry_utils.py（H§17） | ✅ | 既有，未改動 |
| 串流 watchdog | agent/auxiliary_stream_watchdog.py（H§17） | ✅ | 既有（adapters `idle_timeout_after_partial_stream`） |
| Proxy 繞過/自訂 CA | agent/proxy_bypass.py, ssl_verify.py（H§17） | ✅ | net.rs（`[network]` proxy/no_proxy/ca_file/deny_hosts、metadata 封鎖），所有 HTTP 經 `net::agent`；測試 `no_proxy_forms`、`ca_bundle_errors_are_clear`；無經真 proxy 的整合測試 |

## H§18 成本與用量（6）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 成本估算 | agent/usage_pricing.py（H§18） | ✅ | modelsdb.rs 內建快照＋models.dev 更新（`snapshot_prices_and_normalisation`、`refresh_writes_cache_and_honours_etag`）；`ledger::set_price_source`（models_cli.rs:44）；cache_write 獨立費率 |
| 預算上限 | hermes_cli/model_cost_guard.py（H§18） | ✅ | 既有；新增無價格時警告（kernel.rs `has_cost_cap`） |
| Insights 分析 | agent/insights.py（H§18） | ✅ | models_cli.rs `insights`（`ark insights`、`/insights`）；e2e |
| 帳號用量與速率窗 | agent/account_usage.py（H§18） | ✅ | accounts.rs（Claude/Codex/OpenRouter/DeepSeek/Z.ai）；`ark usage --account`、`/usage`；`claude_codex_openrouter_deepseek_zai`（fake_server）；billing.rs `--billing` |
| Nous credits / 帳單 | agent/credits_tracker.py（H§18） | N/A | Nous 自家帳務 |
| 輔助呼叫計帳 | agent/aux_accounting.py（H§18） | ✅ | kernel.rs `Metered`/`aux_used`、`EventKind::AuxUsage`、`Ledger::charge_current`；runner `aux_compaction_usage_is_recorded_and_charged`、ledger `aux_calls_charge_the_running_ledger_without_steps`。注意：thread-local，只在回合執行緒內計入 |

## H§8 斜線指令（6）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /model | hermes_cli/commands.py（H§8） | ✅ | models_cli.rs `slash`（alias、allowlist、成本/資料確認），chat＋channel；e2e `/model quick`。無 `--global`（改用 `ark models set`） |
| /reasoning | hermes_cli/commands.py（H§8） | ✅ | `slash` 的 think/reasoning＋顯示 on/off（main.rs/term.rs `show_reasoning`）；e2e 只測 `/think` |
| /fast | hermes_cli/commands.py（H§8） | ✅ | `slash` fast → `Kernel::set_fast`；e2e |
| /usage | hermes_cli/commands.py（H§8） | ✅ | token/成本/context/速率窗/帳號窗＋footer 模式；e2e |
| /login | hermes_cli/commands.py（H§8） | N/A | 上游是 Nous 帳號登入（沿用原判）；ark `/login` 只列出 `ark login` 說明 |
| /insights | hermes_cli/commands.py（H§8） | ✅ | `slash` insights（同 `ark insights` 函式，e2e 測 CLI） |

## H§9 CLI 子指令（5）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| model | hermes_cli/subcommands/model.py（H§9） | 🚧 | `models_cli::cmd_model`（互動選擇器、寫 user config）已接線；無測試直接跑 `ark model`（只有 `set_config_value` 單元測試） |
| auth add/list/remove/reset/priority/… | hermes_cli/subcommands/auth.py（H§9） | ✅ | `cmd_auth`＋store.rs；e2e add/list/reset/remove；store 測試 3 個 |
| login / logout | hermes_cli/subcommands/login.py, logout.py（H§9） | ✅ | `cmd_login`/`cmd_logout` → login.rs（fake_server 測流程）；CLI 本身無 e2e（需瀏覽器/裝置碼） |
| insights | hermes_cli/subcommands/insights.py（H§9） | ✅ | `cmd_insights`；e2e |
| usage | hermes_cli/subcommands/usage.py（H§9） | ✅ | `cmd_usage`（--days/--session/--account/--billing/--json）；e2e `usage --json` |

## O§4 Models, providers, auth（43）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Preset: openai | extensions/openai（O§4） | ✅ | `openai`/`openai-chat` |
| Preset: anthropic | extensions/anthropic（O§4） | ✅ | `anthropic` |
| Preset: google (gemini) | extensions/google（O§4） | ✅ | `gemini` |
| Preset: google-vertex / google-gemini-cli | extensions/google（O§4） | ✅ | `google-vertex`（ADC，google.rs）；`gemini-cli`（cli.rs，`gemini_prompt_arg_and_codex_jsonl_and_errors`） |
| Preset: anthropic-vertex | extensions/anthropic-vertex（O§4） | ✅ | `anthropic-vertex`；`vertex_publisher_paths` 驗證 streamRawPredict 路徑 |
| Preset: amazon-bedrock / bedrock-mantle | extensions/amazon-bedrock*（O§4） | ✅ | bedrock.rs（SigV4、discovery、guardrail）＋`bedrock-mantle` |
| Preset: deepseek | extensions/deepseek（O§4） | ✅ | preset |
| Preset: openrouter | extensions/openrouter（O§4） | ✅ | preset＋login 鑄 key |
| Preset: groq | extensions/groq（O§4） | ✅ | preset |
| Preset: xai | extensions/xai（O§4） | ✅ | preset＋`xai-oauth` device flow |
| Preset: mistral | extensions/mistral（O§4） | ✅ | preset |
| Preset: together | extensions/together（O§4） | ✅ | preset |
| Preset: fireworks | extensions/fireworks（O§4） | ✅ | preset |
| Preset: ollama / ollama-cloud | extensions/ollama（O§4） | ✅ | `ollama`、`ollama-cloud`；discovery 走 list_models |
| Preset: lmstudio | extensions/lmstudio（O§4） | ✅ | preset |
| Preset: vllm | extensions/vllm（O§4） | ✅ | preset |
| Preset: sglang | extensions/sglang（O§4） | ✅ | preset `sglang` |
| Preset: llama-cpp (managed) | extensions/llama-cpp（O§4） | ✅ | preset `llama-cpp`＋`model_path` 時 local.rs 管理啟動 |
| Preset: qwen / dashscope / modelstudio / token plans | extensions/qwen（O§4） | ✅ | `dashscope(-cn)`、`alibaba-coding-plan(-cn)`、`alibaba-token-plan(-cn)`、`qwen` |
| Preset: moonshot / kimi-coding | extensions/moonshot, kimi-coding（O§4） | ✅ | `moonshot`、`moonshot-cn`、`kimi-coding` |
| Preset: zai (GLM) | extensions/zai（O§4） | ✅ | `zai`、`zai-coding` |
| Preset: minimax / minimax-portal | extensions/minimax（O§4） | ✅ | `minimax`、`minimax-cn`、`minimax-oauth(-cn)` |
| Preset: siliconflow | （ark 額外）（O§4） | ✅ | preset |
| Presets: arcee … microsoft-foundry（35 個） | extensions/<id>（O§4） | ✅ | catalog.rs 全部有 preset（含 litellm、cloudflare-ai-gateway、clawrouter、copilot-proxy、omlx…）；kie/vydra/fal 在上游是影音生成供應商，非聊天模型，不屬本表 |
| github-copilot provider | extensions/github-copilot（O§4） | ✅ | copilot.rs＋device login |
| apple-fm | extensions/apple-fm（O§4） | N/A | macOS 裝置端 |
| OpenAI OAuth (ChatGPT/Codex) | extensions/openai, src/llm/oauth.ts（O§4） | ✅ | login `openai-codex`(-browser)；`codex_device_auth_exchange`、`pkce_loopback_receives_redirect` |
| Anthropic setup-token / Claude CLI creds | extensions/anthropic（O§4） | ✅ | `anthropic-setup-token` paste；`import_external`（`imports_codex_and_claude_cli_logins`）；`ark login --import` |
| Auth profiles | src/agents/auth-profiles/（O§4） | 🚧 | 多憑證/輪替/冷卻/priority/strategy 完整（auth.rs Pool、store.rs）；缺每代理（per-agent）憑證設定 |
| Model fallback chains | src/agents/model-fallback*.ts（O§4） | ✅ | `model.fallback`＋冷卻；`ark fallback`；無圖片專用 fallback |
| Aux/utility model | src/agents/utility-model.ts（O§4） | ✅ | 既有＋`model.tasks` |
| Subagent model | src/agents/agent-scope-config.ts（O§4） | ✅ | 既有，未改動 |
| Model catalog | src/agents/model-catalog*.ts（O§4） | ✅ | modelsdb.rs（context、價格、能力；`caps_for` 先查 modelsdb，lib.rs:572）；4 個測試 |
| Model discovery / scan | src/agents/model-scan.ts（O§4） | ✅ | list_models；`ark models list/scan` |
| Model picker / aliases / allowlist | src/model-picker, model-selection*.ts（O§4） | ✅ | `ark model` 選擇器、`model.aliases`、`model.allow`、session 黏著模型；runner `aliases_allowlist_thinking_and_fast_reach_the_request` |
| Thinking levels | src/agents/thinking-runtime.ts（O§4） | ✅ | off…max、依端點 `reasoning_efforts` clamp、`/think` |
| Fast mode / service tiers | src/agents/fast-mode.ts（O§4） | ✅ | priority/ultrafast/flex/auto/cold；provider_knobs `openai_chat_service_tier_verbosity_strict_and_effort_clamp` |
| Text verbosity / strict tools | src/agents/openai-text-verbosity.ts（O§4） | ✅ | `model.verbosity`/`strict_tools`；同上測試、`proxies_never_get_billing_knobs` |
| Tool-call repair | packages/tool-call-repair（O§4） | ✅ | 既有，未改動 |
| Prompt cache tracing | src/agents/cache-trace.ts（O§4） | ✅ | 既有，未改動 |
| Provider network policy / egress proxy | src/secrets/egress-proxy（O§4） | ✅ | net.rs `[network]`（deny_hosts、proxy、metadata 封鎖、government 加 PRC_HOSTS） |
| Agent harnesses | extensions/codex, copilot, agentsapi, muse; cli-backends.ts（O§4） | 🚧 | 有 codex app-server、claude-cli/gemini-cli/codex-cli/copilot-cli 後端（cli.rs、codex_app.rs）；缺 OpenAI Agents API、Muse CLI；copilot 只是文字模式 |
| Usage/cost accounting | src/agents/usage.ts（O§4） | ✅ | ledger＋aux 計帳＋`/usage` footer |

## O§5 斜線指令（7）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /login | commands-registry.shared.ts（O§5） | 🚧 | `/login` 只列出 flow 與 `ark login` 指引，不能在聊天內完成登入 |
| /usage off/tokens/full/cost | 同上（O§5） | ✅ | footer 模式＋摘要；e2e `/usage` |
| /think (/t) | 同上（O§5） | ✅ | `slash`（含 `t` 別名）；e2e |
| /fast | 同上（O§5） | ✅ | e2e |
| /reasoning | 同上（O§5） | ✅ | 顯示 on/off/stream（stream 等同 on）；狀態是全程序 atomic，非每 session |
| /model | 同上（O§5） | ✅ | chat＋channel（ext.rs）；只作用於當前 session |
| /models | 同上（O§5） | ✅ | `slash` models；e2e |

## O§6 CLI（1）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| models (list/scan/status/set/aliases/fallbacks/auth) | src/cli/models-cli.ts（O§6） | ✅ | `cmd_models` 全部子指令；e2e 測 `models providers`、fallback、auth。小 bug：`ark models auth` 傳入空 Vault（models_cli.rs `cmd_models` "auth" 分支），vault 金鑰不會列出 |

## 剩餘缺口（依使用者影響排序）

1. 輔助模型路由（H§17）：只有 compaction/review/sampling 用 `model.tasks`；vision、title、search 等任務沒有各自的模型，也沒有每任務的健康檢查或 fallback。
2. Auth profiles（O§4）：沒有每代理（per-agent）憑證順序/指定。
3. Agent harnesses（O§4）：缺 OpenAI Agents API 與 Muse CLI 後端；copilot-cli 只是文字模式。
4. copilot-acp（H§17）：不是 ACP 客戶端，只用 `copilot -p` 文字輸出，沒有串流事件與工具呼叫。
5. /login（O§5）：聊天內不能完成登入，只顯示指引。
6. nous（H§17）：缺 agent-key 換發與續期，直接用 OAuth access token；client_id 寫死 `hermes-cli`。
7. `ark model`（H§9）：已接線，但沒有任何測試跑這條路徑。
