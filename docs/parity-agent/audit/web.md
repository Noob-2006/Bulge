# web 串流稽核結果

**編譯／測試**：`cargo build --workspace --all-targets` 成功；`cargo test --workspace --no-fail-fast` 通過 872、失敗 3、忽略 2。
- 失敗：`ark_tools::web::truncate::tests::head_tail_window_with_spill`（`char_len(&out) < 4000 + 700` 斷言失敗，**本串流真實缺陷**，影響 web_extract 的截斷與存檔）。
- coderun 兩個測試（`coderun::tests::script_output_exit_codes_and_nested_protocol`、`failures_timeout_cancel_and_bad_lang`）在五個副本都失敗，原因是稽核規定的 TMPDIR 路徑過長，Unix socket 超過 SUN_LEN（`cannot bind …/call-*.sock: path must be shorter than SUN_LEN`）。這是環境造成的，與本串流程式無關。
- 原始輸出：`audit/web-tests.txt`

**狀態統計（43 列）**：✅ 0 · 🚧 39 · ⬜ 4 · N/A 0


# web 串流稽核（w-web，基於 5c369e5 + 未提交工作）

## 差異範圍

- `git diff --stat HEAD`：45 檔、+11246／−1（含兩份 inventory 共 1404 行）。
- 實際程式：新目錄 `crates/ark-tools/src/web/`（約 10,100 行，舊 `web.rs` 已 staged 刪除並**原封不動**搬成 `web/fetch.rs`，`diff` 完全相同）。
  - 子模組：cache, config, content, extract, fetch, github, html, http, keyless, links, markdown, pdf, policy, readability, search, ssrf, truncate, vendor_tools, xsearch, testutil
  - providers/：brave, codex, deepseek, duckduckgo, exa, firecrawl, gemini, keenable, kimi, minimax, ollama, openai_native, parallel, perplexity, searxng, tavily, xai
- **空殼檔**（只有一行 `//! (stub — being implemented)`）：`web/extract.rs`、`web/github.rs`、`web/vendor_tools.rs`。
- 共用檔改動：`ark-tools/src/lib.rs` 只把 `mod web` 改成 `pub mod web`（**未新增任何工具註冊**）；`ark-tools/Cargo.toml` 加 `ark-net`；`crates/ark/src/ext.rs` 加 `link_understanding()` 並在 `handle_inbound` 呼叫。
- 無未追蹤檔（全部已 `git add`）。

## 關鍵結論（影響所有列）

1. **新工具全部未接線**：`builtin_tools()`（`ark-tools/src/lib.rs:29`）仍只有舊的 `WebFetch`；`WebSearch`（search.rs:267）、`XSearch`（xsearch.rs:26）、`FirecrawlSearchTool`/`FirecrawlScrapeTool`（providers/firecrawl.rs:328/421）在整個 workspace 中只在各自的 `#[cfg(test)]` 裡被建構。kernel、main.rs、ark-app 都沒有引用。模型無法呼叫任何新工具。
2. **`[web]` 設定無法寫入**：kernel `Config`（`ark-kernel/src/config.rs:11`）是 `deny_unknown_fields`，且沒有 `web` 欄位 → 使用者在 config.toml 寫 `[web]` 會解析失敗；`ext.rs::link_understanding` 從序列化的 Config 取 `"web"` 永遠是 `Null` → `WebConfig` 預設 `links.enabled=false` → 連結理解永遠不會執行。
3. **`web_fetch` 完全沒升級**：`web/fetch.rs` 與 HEAD 的 `web.rs` 位元組相同：無 SSRF、無 readability、無 PDF、無快取、無截斷存檔、無 firecrawl 後援。`ssrf.rs`、`readability.rs`、`pdf.rs`、`truncate.rs`、`cache.rs` 的 `DiskCache`/`fetch_memo` 都是**孤兒模組**（只被自己的測試或 links.rs 使用）。
4. 錯誤訊息提到 `ark web providers`，但 `crates/ark/src/main.rs` 無此子指令。
5. 品質面：provider 程式碼是真的 HTTP 請求/回應解析（非回 "unsupported" 的假實作），每個都有 FakeServer 測試；問題純粹是接線與入口。

## 統計

| 狀態 | 數量 |
|---|---|
| ✅ | 0 |
| 🚧 | 39 |
| ⬜ | 4 |
| N/A | 0 |
| 合計 | 43 |

（✅ 為 0：沒有任何一列同時「有程式＋可被使用者/模型觸及＋有測試」。下表 🚧 列若註明「接線即可」，表示程式與測試已具備，只差註冊與設定。測試是否通過見檔首測試結果。）

## 逐列狀態

測試名稱均位於 `ark_tools::web::<模組>::tests::<名稱>`。

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| web_search 工具 | Hermes §1 tools/web_tools.py | 🚧 | `web/search.rs` `WebSearch`：provider 解析（pin→autodetect→keyless）、過濾驗證、single-flight 快取、keyless rescue、untrusted 包裝；測試 `search::tests::{parse_and_validate,resolution_order,tool_call_renders_wrapped_json_and_caches,errors_are_structured,rescue_serves_from_ring_once_and_is_not_cached}`。**缺：未註冊進 `builtin_tools()`；`[web]` 無法設定** |
| web_extract 工具 | Hermes §1 web_tools_extract.py, web_tools_truncate.py | 🚧 | `web/extract.rs` 是空殼；零件在：`readability::extract`、`pdf::extract_text`、`truncate::truncate_with_footer`（head+tail＋存檔；**`head_tail_window_with_spill` 測試失敗**）、`cache::DiskCache`、各 provider `extract()`（tavily/firecrawl/exa/parallel/keenable）。**缺：工具本體（urls[] 批次、char_limit、後端選擇、本地後援）與註冊** |
| x_search | Hermes §1 tools/x_search_tool.py | 🚧 | `web/xsearch.rs` `XSearch`（xAI Responses `x_search`、handle/日期篩選、重試、快取）；測試 `xsearch::tests::{validation,request_shape_citations_and_cache,config_model_reasoning_inline_and_ttl,answer_parsing,degraded_when_filters_match_nothing,retries_5xx_then_succeeds_and_fails_fast_on_4xx,availability_and_missing_key}`。**缺：未註冊** |
| web 後端 brave_free | Hermes §2 plugins/web/brave_free | 🚧 | `providers/brave.rs`（alias `brave-free`，web 與 llm-context 模式）；測試 `brave::tests::{normalisers,web_mode_request_and_mapping,llm_context_mode,errors}`。缺：web_search 未接線 |
| web 後端 ddgs | Hermes §2 plugins/web/ddgs | 🚧 | `providers/duckduckgo.rs`（HTML 端點、uddg 解碼、challenge 偵測）；測試 `duckduckgo::tests::{parses_results_and_scopes_snippets,request_params_and_challenge}`。缺：未接線 |
| web 後端 exa | Hermes §2 plugins/web/exa | 🚧 | `providers/exa.rs`；測試 `exa::tests::{search_body_and_mapping,validation}`。缺：未接線；extract 無工具入口 |
| web 後端 firecrawl | Hermes §2 plugins/web/firecrawl | 🚧 | `providers/firecrawl.rs` search+scrape；測試 `firecrawl::tests::{search_items_shapes,scrape_and_extract,keyless_and_validation}`。缺：未接線 |
| web 後端 keenable | Hermes §2 plugins/web/keenable | 🚧 | `providers/keenable.rs`；測試 `keenable::tests::{keyed_search_and_fetch,keyless_and_errors}`。缺：未接線 |
| web 後端 openai_native | Hermes §2 plugins/web/openai_native | 🚧 | `providers/openai_native.rs`（Responses web_search）；測試 `openai_native::tests::responses_call`。缺：未接線 |
| web 後端 parallel | Hermes §2 plugins/web/parallel | 🚧 | `providers/parallel.rs`；測試 `parallel::tests::{search_and_extract,keyless_and_errors}`。缺：未接線 |
| web 後端 perplexity | Hermes §2 plugins/web/perplexity | 🚧 | `providers/perplexity.rs`（Search API＋OpenRouter chat transport）；測試 `perplexity::tests::{search_api_body,chat_transport_for_openrouter_and_overrides,validation_and_extract}`。缺：未接線 |
| web 後端 searxng | Hermes §2 plugins/web/searxng | 🚧 | `providers/searxng.rs`；測試 `searxng::tests::{searches_sorted_by_score_and_capped,empty_category_retries_general_and_env_url,errors}`。缺：未接線 |
| web 後端 tavily | Hermes §2 plugins/web/tavily | 🚧 | `providers/tavily.rs` search+extract；測試 `tavily::tests::{search_request_and_normalisation,keyless_when_selected_without_key,extract_pages_and_errors}`。缺：未接線 |
| web 後端 xai | Hermes §2 plugins/web/xai | 🚧 | `providers/xai.rs`；測試 `xai::tests::{answer_mode,results_mode_parsing_ladder,errors}`。缺：未接線 |
| web keyless MCP ring | Hermes §2 plugins/web/keyless_mcp.py, web_tools_rescue.py | 🚧 | `web/keyless.rs`（parallel/exa/keenable MCP JSON-RPC、failover、tier 分類），由 search.rs 使用，DDG 為最後後援；測試 `keyless::tests::{mcp_bodies,classification_and_tiers,ring_failover_across_vendors,vendor_parsers,extract_vendors}`、`search::tests::rescue_serves_from_ring_once_and_is_not_cached`。缺：隨 web_search 未接線；extract 側 ring 無入口 |
| web 結果快取 | Hermes §2 tools/web_result_cache.py | 🚧 | `web/cache.rs` 記憶體 memo（TTL、single-flight）用於 search；`DiskCache`/`fetch_memo` 未被任何工具使用；測試 `cache::tests::{buckets_and_keys,memo_ttl_and_flight,disk_cache_roundtrip_and_gates,write_refuses_to_follow_symlinks}`。缺：extract/fetch 快取未接、search 未接線 |
| SSRF 私網封鎖 | Hermes §6 tools/url_safety.py | 🚧 | `web/ssrf.rs`：私網/loopback/link-local/metadata/fake-IP 判定、`GuardResolver` 連線時再驗（防 DNS rebinding）、redirect 逐跳檢查；測試 `ssrf::tests::{private_and_metadata_ips,host_policy,fake_ip_ranges,urls,hygiene,guard_resolver_blocks_at_connect}`。**缺：唯一已註冊的 `web_fetch` 沒用它**（只有 links.rs 與部分 provider 用）|
| web_search（OpenClaw） | OpenClaw §1 src/agents/tools/web-search.ts | 🚧 | 同 Hermes web_search 列（OpenClaw 錯誤碼 `unsupported_*`、`normalizeWebSearchOutput` 形狀已移植）。缺：未註冊 |
| web_fetch | OpenClaw §1 src/agents/tools/web-fetch.ts | 🚧 | 已註冊的 `web/fetch.rs` `WebFetch` 與 HEAD 完全相同（GET/POST、regex HTML→文字）；測試 `fetch::tests::{get_html_is_stripped,...}` 為舊測試。缺：SSRF、readability→markdown、PDF、快取、截斷存檔、firecrawl 後援、extractMode/maxChars 參數 |
| x_search（OpenClaw） | OpenClaw §1 extensions/xai | 🚧 | 同 Hermes x_search 列。缺：未註冊 |
| firecrawl_search / firecrawl_scrape | OpenClaw §2 extensions/firecrawl | 🚧 | `providers/firecrawl.rs` `FirecrawlSearchTool`、`FirecrawlScrapeTool` 有 `impl Tool`；測試 `firecrawl::tests::dedicated_tools`。缺：未註冊 |
| tavily_search / tavily_extract | OpenClaw §2 extensions/tavily | ⬜ | 預定放在 `web/vendor_tools.rs`，但該檔是空殼；只有 provider 層函式（tavily.rs）。缺：兩個專用工具 |
| github_read / github_search | OpenClaw §2 extensions/github | ⬜ | `web/github.rs` 是空殼。缺：全部 |
| web-readability | OpenClaw §2 extensions/web-readability | 🚧 | `web/readability.rs` `extract()`＋`html.rs` 樹解析＋`markdown.rs`；測試 `readability::tests::{finds_main_content,short_and_degenerate_pages}`、`html::tests::*`、`markdown::tests::*`。缺：沒有任何工具呼叫它（web_fetch 仍用 regex） |
| 搜尋供應商 brave | OpenClaw §3 extensions/brave | 🚧 | `providers/brave.rs`（同上測試）。缺：未接線 |
| 搜尋供應商 duckduckgo | OpenClaw §3 extensions/duckduckgo | 🚧 | `providers/duckduckgo.rs`。缺：未接線 |
| 搜尋供應商 exa | OpenClaw §3 extensions/exa | 🚧 | `providers/exa.rs`。缺：未接線 |
| 搜尋供應商 firecrawl | OpenClaw §3 extensions/firecrawl | 🚧 | `providers/firecrawl.rs`。缺：未接線 |
| 搜尋供應商 google（Gemini grounding） | OpenClaw §3 extensions/google | 🚧 | `providers/gemini.rs`（grounding＋redirect 解析經 SSRF）；測試 `gemini::tests::{grounded_answer_and_redirects,time_ranges_and_errors}`。缺：未接線 |
| 搜尋供應商 perplexity | OpenClaw §3 extensions/perplexity | 🚧 | `providers/perplexity.rs`。缺：未接線 |
| 搜尋供應商 parallel | OpenClaw §3 extensions/parallel | 🚧 | `providers/parallel.rs`。缺：未接線 |
| 搜尋供應商 searxng | OpenClaw §3 extensions/searxng | 🚧 | `providers/searxng.rs`。缺：未接線 |
| 搜尋供應商 tavily | OpenClaw §3 extensions/tavily | 🚧 | `providers/tavily.rs`。缺：未接線 |
| 搜尋供應商 xai | OpenClaw §3 extensions/xai | 🚧 | `providers/xai.rs`。缺：未接線 |
| 搜尋供應商 moonshot（Kimi） | OpenClaw §3 extensions/moonshot | 🚧 | `providers/kimi.rs`；測試 `kimi::tests::search`。缺：未接線 |
| 搜尋供應商 minimax | OpenClaw §3 extensions/minimax | 🚧 | `providers/minimax.rs`；測試 `minimax::tests::search_and_status_errors`。缺：未接線 |
| 搜尋供應商 deepseek | OpenClaw §3 extensions/deepseek | 🚧 | `providers/deepseek.rs`；測試 `deepseek::tests::search_and_limits`。缺：未接線 |
| 搜尋供應商 ollama | OpenClaw §3 extensions/ollama | 🚧 | `providers/ollama.rs`（本機 experimental→/api/web_search→Cloud）；測試 `ollama::tests::local_fallthrough_and_cloud`。缺：未接線 |
| 搜尋供應商 codex-native | OpenClaw §3 extensions/codex | 🚧 | `providers/codex.rs`（對 app-server 跑受限 turn）；測試 `codex::tests::{bounded_turn_against_fake_app_server,projection_and_errors}`。缺：未接線 |
| web_fetch 供應商 firecrawl＋readability 抽取器 | OpenClaw §3 extensions/firecrawl, web-readability | 🚧 | 零件都在（firecrawl scrape、readability），但 web_fetch 未使用；無 fetch 後援鏈 |
| 連結理解（入站訊息自動摘要連結） | OpenClaw §8 src/link-understanding | 🚧 | `web/links.rs` `apply_link_understanding`（擷取裸連結、去重、max_links、scope 規則、SSRF 守衛抓取、blocklist、CLI processor 管線、範本）；`crates/ark/src/ext.rs` `handle_inbound` 有呼叫；測試 `links::tests::{end_to_end_fetch_process_and_enrich,blocks_loopback_and_private_targets,scope_rules_first_match_and_default,...}` 共 15 個。**缺：kernel Config 無 `web` 欄位且 `deny_unknown_fields` → 無法開啟，實際永遠停用**；無 ext.rs 層的測試 |
| Wizard：web search 設定 | OpenClaw §11 src/flows/search-setup.ts | ⬜ | `crates/ark/src/setup.rs` 無搜尋供應商步驟 |
| web 相關 CLI／斜線指令（如錯誤訊息提到的 `ark web providers`） | brief「related slash/CLI commands」 | ⬜ | `crates/ark/src/main.rs` 無 `web` 子指令；錯誤訊息指向不存在的指令 |

附註（非本串流擁有）：網站黑名單（Hermes §6 website_policy，屬 security）在 `web/policy.rs` 已實作（`[web.blocklist]` domains＋shared_files；測試 `policy::tests::{enforce_gate,rules_and_matching}`），但只有 `links.rs` 使用。

## 剩餘缺口（依使用者影響排序）

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
