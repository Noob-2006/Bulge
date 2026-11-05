# browser 串流稽核結果

**編譯／測試**：**編譯失敗**，workspace 測試**沒有任何一個執行**（通過 0、失敗 0）。
- `ark-app` lib 無法編譯：`server.rs:166` 的 match 分支型別不一致；`browser_view.rs:213` 用了 `ureq::AgentBuilder`，`browser_view.rs:223` 用了 `ureq::Error::Status`，兩者在 workspace 使用的 ureq 版本都不存在。ark-app 編不過，**`ark` 執行檔也無法建置**。
- `ark-browser` lib 本身可編譯，但 lib test 無法編譯：`cloud.rs:288/310/313/318` 呼叫的函式要 3 個參數，只傳了 2 個。
- 原始輸出：`audit/browser-tests.txt`

**降級說明**：fork 稽核時，有 39 列的程式碼、接線、測試都齊全，暫定 ✅。但執行檔建不起來，測試也編譯不過，所以這 39 列全部降為 🚧，原因寫「編譯失敗，未驗證」。修好上述 3 處編譯錯誤並跑過 `ark-browser` 測試後，這 39 列大多應可直接回到 ✅，是最便宜的一批。

**狀態統計（60 列）**：✅ 0 · 🚧 56（其中 39 列只差編譯錯誤）· ⬜ 4 · N/A 0


# browser 串流稽核（w-browser，基於 5c369e5 + 未提交工作）

## 差異範圍

- `git diff --stat HEAD`：39 檔，+10405 / −10。新 crate `crates/ark-browser`（24 檔，約 9.1k 行；已加入 workspace members 與 workspace deps，無新外部依賴）。
- 共用檔改動：`Cargo.toml`（members）、`crates/ark/src/main.rs`（`build_agent` 內 `ark_browser::tools(&cfg.browser)` 註冊工具）、`ark-kernel/config.rs`（`browser`、`computer_use` 兩個 table，列入 `PROJECT_GATED`）、`ark-kernel/kernel.rs`（`Host::analyze_image`，aux/default 視覺模型）、`ark-core/tool.rs`（`ToolHost::analyze_image` 預設回錯）、`ark-app/server.rs`（`/view/…` 路由與 `view.*` ARP 方法）、`ark-app/lib.rs`（`pub mod browser_view; pub mod computer;`）、`ark-app/node.rs`（若干函式改 `pub(crate)`、thread-local ENV 覆寫 DISPLAY）。
- 未追蹤檔：`ark-app/src/browser_view.rs`（**有** `pub mod` 宣告，會編譯）；`ark-app/src/computer/backend.rs`、`computer/config.rs`（**未**在 `computer/mod.rs` 宣告 `mod`，屬死碼，不編譯、其測試不會跑）。
- `ark-browser/src/control.rs` 只有 1 行註解（`/browser`、`ark browser` 的預定位置），**空殼**。
- `ui/web/*` 未改動；`ui/browser-extension/`、`packaging/sandbox-browser/` 不存在（程式碼中提到但檔案缺）。
- 本機瀏覽器：`/snap/bin/chromium`、`/usr/bin/google-chrome(-stable)` 存在，`#[ignore] real_chromium_end_to_end` 可在本機實跑（本稽核未執行 cargo）。

**接線結論**：`browser`（OpenClaw）＋ 14 個 Hermes `browser_*` 工具經 `build_agent` 註冊，`ark chat`／daemon／channel 路徑（皆走 `build_agent`）的模型都可呼叫；`[browser] enabled` 預設 auto（找得到瀏覽器即啟用）。`computer_use`／`computer` 工具**完全沒有註冊**，本機桌面控制在沒配對 node 時不可用。

## 統計

（fork 原始暫定：✅ 39〔其中 7 列 ✅* 只有 `#[ignore]` 實機測試〕、🚧 17、⬜ 4；編譯失敗後的最終數字見檔首。）

主要測試（`crates/ark-browser`）：`tests::hermes_tools_against_a_fake_cdp_browser`、`tests::openclaw_browser_tool_against_a_fake_cdp_browser`、`tests::real_chromium_end_to_end`（#[ignore]）、`cdp::resolves_and_multiplexes_sessions`、`manager::attaches_to_a_cdp_endpoint_and_tracks_session_tabs`、`manager::keys_profiles_and_urls`、`engine::supervisor_records_events_and_dialogs`、`engine::auto_policy_and_bridge_dialogs`、`engine::tabs_handles_labels_and_resolution`、`snapshot::renders_openclaw_line_format`、`snapshot::interactive_delta_and_truncation`、`snapshot::cursor_nodes_refs_and_queries`、`cloud::browserbase_retries_402_and_releases`、`cloud::browser_use_and_firecrawl`、`camofox::rest_flow_and_loopback_rewrite`、`launch::launch_flags_follow_openclaw`、`launch::devtools_port_file_and_stale_locks`、`launch::real_profile_copy_skips_caches_and_resyncs_auth`、`vault::totp_matches_rfc6238`、`vault::classifier_picks_current_password_and_card_fields`、`vault::local_store_and_external_managers`、`policy::navigation_guard`、`policy::eval_policy_and_literals`、`policy::redaction_and_wrapper`、`extension::relays_cdp_between_ark_and_the_extension`、`sandbox::refuses_host_network_and_stale_images`、`view::*`（5 個）、`lease::lease_transitions`、`exec::session_names`、`keys::chords`、`actions::evaluate_source_normalization`、`config::*`（2 個）；`ark-app`：`browser_view::view_routes_need_the_token_and_return_json`、`browser_view::arp_methods_are_advertised_and_dispatched`。死碼中的測試（不會執行）：`computer::backend::verdict_ladder_matches_hermes`、`image_headers`、`computer::config::defaults_doc_matches_struct`、`overlay_auto_follows_the_session_type`。

## 逐列狀態

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| browser_navigate | Hermes tools/browser_tool.py | 🚧 | `tools.rs` HermesTool `nav`；SSRF/金鑰 URL 擋下；`hermes_tools_against_a_fake_cdp_browser`；**降級：編譯失敗，測試未執行** |
| browser_snapshot（@eN、截斷存檔、遮蔽） | Hermes browser_tool_snapshot.py | 🚧 | `tools.rs` `snap`、`snapshot.rs`；fake 測試＋`interactive_delta_and_truncation`；**降級：編譯失敗，測試未執行** |
| browser_click | Hermes browser_tool.py | 🚧 | `click`，CDP `Input.dispatchMouseEvent`；fake 測試驗座標；**降級：編譯失敗，測試未執行** |
| browser_type | Hermes browser_tool.py | 🚧 | `ty`，`Input.insertText`；fake 測試；**降級：編譯失敗，測試未執行** |
| browser_scroll | Hermes browser_tool.py | 🚧 | `scroll`；fake 測試；**降級：編譯失敗，測試未執行** |
| browser_back | Hermes browser_tool.py | 🚧 | `back`；fake 測試驗回到前一 URL；**降級：編譯失敗，測試未執行** |
| browser_press | Hermes browser_tool.py | 🚧 | `press`＋`keys.rs` 組合鍵；fake 測試、`keys::chords`；**降級：編譯失敗，測試未執行** |
| browser_get_images | Hermes browser_tool.py | 🚧 | `images`；僅 `real_chromium_end_to_end`（#[ignore]）呼叫；**降級：編譯失敗，測試未執行** |
| browser_vision（截圖＋視覺分析、annotate） | Hermes browser_tool_vision.py | 🚧 | `vision` → `ToolHost::analyze_image`；kernel `Host::analyze_image`（kernel.rs）本身無測試；fake 測試用假 host；**降級：編譯失敗，測試未執行** |
| browser_console（含 expression 與 eval 政策） | Hermes browser_tool.py, browser_tool_eval_policy.py | 🚧 | `console`；fake 測試＋`policy::eval_policy_and_literals`；**降級：編譯失敗，測試未執行** |
| browser_cdp | Hermes browser_cdp_tool.py | 🚧 | `cdp`，結果遮蔽 cookie；fake 測試；**降級：編譯失敗，測試未執行** |
| browser_dialog | Hermes browser_dialog_tool.py | 🚧 | `dialog`＋engine supervisor；`supervisor_records_events_and_dialogs`、fake 測試、real 測試 accept confirm；**降級：編譯失敗，測試未執行** |
| browser_vault（list/fill/save_login/enter_code/unlock，Bitwarden/1Password） | Hermes browser_vault_tool.py, vault_store.py | 🚧 | `vault.rs`、`vault_tool.rs`；list 在 fake 測試，fill 只在 #[ignore] real 測試；store/TOTP/欄位分類有單元測試；save_login 遮罩輸入、unlock 外部管理器路徑未見測試；**降級：編譯失敗，測試未執行** |
| browser_exec（Browser Use CLI） | Hermes browser_use_cli.py | 🚧 | `exec.rs` 實作完整（stdin 餵 code、BU_CDP_* env），但只有 `session_names` 測試，執行路徑無測試；預設關閉（`exec_enabled`） |
| computer_use（Hermes） | Hermes tools/computer_use/* | 🚧 | 無任何 `computer_use` 工具註冊；`ark-app/src/computer/backend.rs`、`config.rs` 未宣告 `mod`＝不編譯的死碼；`computer/mod.rs` 只有 `screenshot_png`；仍只能經配對 node `computer.act` |
| 瀏覽器 本機 Chromium（＋自動安裝） | Hermes browser_tool.py, browser_tool_install.py | 🚧 | `launch.rs` 找執行檔、啟動、managed profile（`launch_flags_follow_openclaw`、real 測試）；**無自動安裝**，找不到只回錯誤訊息 |
| 瀏覽器 雲端 browserbase / browser_use / firecrawl | Hermes plugins/browser/*, browser_provider.py | 🚧 | `cloud.rs` 真 HTTP（ureq），自動偵測金鑰、402 重試、釋放；`browserbase_retries_402_and_releases`、`browser_use_and_firecrawl`（假伺服器）；**降級：編譯失敗，測試未執行** |
| 瀏覽器 使用者 CDP 端點 | Hermes browser_tool_cdp.py | 🚧 | `backend="cdp"`＋`cdp_url`；`attaches_to_a_cdp_endpoint_and_tracks_session_tabs`、兩個 fake CDP 測試；**降級：編譯失敗，測試未執行** |
| 瀏覽器 camofox | Hermes browser_camofox*.py | 🚧 | `camofox.rs` REST client、持久 identity、loopback 改寫；`rest_flow_and_loopback_rewrite`；**降級：編譯失敗，測試未執行** |
| 瀏覽器 lightpanda（失敗退回 Chrome） | Hermes browser_lightpanda.py, browser_tool_lightpanda_fallback.py | 🚧 | `launch::lightpanda_serve`、`tools.rs` `lp_fallback`；**無任何測試**涵蓋啟動或退回 |
| 瀏覽器 real-profile | Hermes browser_tool_real_profile.py | 🚧 | `launch::snapshot_real_profile`、`browser action=importprofile`；`real_profile_copy_skips_caches_and_resyncs_auth`；**降級：編譯失敗，測試未執行** |
| 瀏覽器 CDP supervisor（對話框、frame） | Hermes browser_supervisor*.py | 🚧 | `engine.rs` 事件監看、`supervisor_view` frame_tree；`supervisor_records_events_and_dialogs`、`auto_policy_and_bridge_dialogs`；**降級：編譯失敗，測試未執行** |
| 瀏覽器 extension router | Hermes browser_extension_router.py | 🚧 | `extension.rs` loopback WS relay（`relays_cdp_between_ark_and_the_extension`）；但瀏覽器擴充本體 `ui/browser-extension` **不存在**，使用者無法裝 |
| Bot Desktop（無頭 Xfce＋RFB、lease） | Hermes tools/bot_desktop/* | 🚧 | 只有 `lease.rs`（`lease_transitions`）與 manager 讀 `<home>/bot-desktop/env`；無啟動 Xvfb/Xfce/VNC 的程式，`ark screen start` 不存在 |
| computer_use cua-driver 後端 | Hermes cua_backend*.py | 🚧 | 只在死碼 `computer/backend.rs`／`config.rs`（未編譯）；無 MCP stdio 驅動 cua-driver |
| /browser（連 CDP／切 Browser Use） | Hermes hermes_cli/commands.py | ⬜ | `control.rs` 只有一行註解；無斜線指令 |
| computer-use install/status/doctor/permissions/grant | Hermes subcommands/computer_use.py | ⬜ | main.rs 無此子指令 |
| screen status/start/stop/install | Hermes subcommands/computer_use_screen.py | ⬜ | 無 |
| browser close-profile | Hermes subcommands/browser.py | ⬜ | 無 `ark browser` 子指令（`control.rs` 空殼）；只有工具 action `stop` |
| browser status | OpenClaw extensions/browser browser-tool | 🚧 | `openclaw.rs` `status`；僅 real 測試斷言；**降級：編譯失敗，測試未執行** |
| browser start / stop | OpenClaw browser-tool | 🚧 | `start`／`stop`；stop 僅 real 測試；start 無直接測試（其他動作會隱式啟動）；**降級：編譯失敗，測試未執行** |
| browser profiles | OpenClaw browser-tool | 🚧 | `profiles`；fake OpenClaw 測試；**降級：編譯失敗，測試未執行** |
| managed profiles（獨立 user-data-dir、顏色、多 profile） | OpenClaw browser profiles | 🚧 | `manager::profiles`、`launch.rs`；`keys_profiles_and_urls`、`devtools_port_file_and_stale_locks`；**降級：編譯失敗，測試未執行** |
| browser tabs | OpenClaw browser-tool | 🚧 | `tabs`；fake 測試、`tabs_handles_labels_and_resolution`；**降級：編譯失敗，測試未執行** |
| browser open | OpenClaw browser-tool | 🚧 | `open`＋`check_navigation`；fake 測試只驗 file:// 被擋，成功路徑在 real 測試間接（navigate）；**降級：編譯失敗，測試未執行** |
| browser focus | OpenClaw browser-tool | 🚧 | `focus`（`Target.activateTarget`）程式在，工具層無測試 |
| browser close（分頁） | OpenClaw browser-tool | 🚧 | `close` 程式在，工具層無測試 |
| browser snapshot＋aria/role refs | OpenClaw browser-tool | 🚧 | `snapshot_action`（ai/aria 格式、query、efficient）；`renders_openclaw_line_format`、`cursor_nodes_refs_and_queries`、fake 測試；**降級：編譯失敗，測試未執行** |
| browser screenshot（fullPage、ref、labels） | OpenClaw browser-tool | 🚧 | `actions::screenshot`；fake 測試 fullPage、real 測試 labels；**降級：編譯失敗，測試未執行** |
| browser navigate | OpenClaw browser-tool | 🚧 | fake 測試（含 EXTERNAL_UNTRUSTED_CONTENT 包裝）；**降級：編譯失敗，測試未執行** |
| browser console | OpenClaw browser-tool | 🚧 | fake 測試 level=warn；**降級：編譯失敗，測試未執行** |
| browser network（requests / errors） | OpenClaw browser-tool | 🚧 | `actions::debug_log`；fake 測試 `requests`（errors 未單獨測）；**降級：編譯失敗，測試未執行** |
| browser pdf | OpenClaw browser-tool | 🚧 | `actions::pdf`；fake 測試寫檔、real 測試驗 `%PDF`；**降級：編譯失敗，測試未執行** |
| browser upload | OpenClaw browser-tool | 🚧 | `actions::upload`；fake 測試（缺檔錯誤＋成功）、real 測試驗 files[0].name；**降級：編譯失敗，測試未執行** |
| browser dialog（arm／回應） | OpenClaw browser-tool | 🚧 | fake 測試 armed、real 測試；**降級：編譯失敗，測試未執行** |
| act click | OpenClaw browser-tool | 🚧 | fake 測試 batch 內 click；**降級：編譯失敗，測試未執行** |
| act type（含 submit） | OpenClaw browser-tool | 🚧 | fake 測試；**降級：編譯失敗，測試未執行** |
| act press | OpenClaw browser-tool | 🚧 | fake 測試 batch 內 press；**降級：編譯失敗，測試未執行** |
| act hover | OpenClaw browser-tool | 🚧 | `actions.rs` `hover` 有實作，無任何測試 |
| act drag | OpenClaw browser-tool | 🚧 | `drag` 有實作，無任何測試 |
| act select | OpenClaw browser-tool | 🚧 | 僅 real 測試；**降級：編譯失敗，測試未執行** |
| act fill（多欄位、checkbox/radio） | OpenClaw browser-tool | 🚧 | `fill` 有實作，無任何測試 |
| act evaluate（含 evaluateEnabled 政策） | OpenClaw browser-tool | 🚧 | 執行僅 real 測試；政策有 `eval_policy_and_literals`、`evaluate_source_normalization`；**降級：編譯失敗，測試未執行** |
| 其他動作 download / waitfordownload / emulate / text / resize / wait / batch | OpenClaw browser-tool | 🚧 | fake 測試 emulate/resize/wait/batch；download、text 在 real 測試；**降級：編譯失敗，測試未執行** |
| attach to existing Chrome | OpenClaw browser existing-session | 🚧 | cdp backend；`attaches_to_a_cdp_endpoint_and_tracks_session_tabs`；**降級：編譯失敗，測試未執行** |
| computer（gateway 本機：click/type/key/scroll/drag/zoom/a11y/set_value/menus） | OpenClaw src/agents/tools/computer-tool*.ts | 🚧 | 無 gateway 本機 `computer` 工具；只有既有 node `computer.act`（需配對 node）；zoom/drag/trajectory 仍缺 |
| cua-computer | OpenClaw extensions/cua-computer | 🚧 | 同 cua-driver 列：只在未編譯死碼 |
| Sandbox browser（noVNC） | OpenClaw src/agents/sandbox/browser*.ts, novnc-auth.ts | 🚧 | `sandbox.rs`（docker run、CDP token、noVNC 埠）、`view.rs` 一次性 ticket（`novnc_tickets_are_one_time_and_short_lived`、`refuses_host_network_and_stale_images`）；但所需映像 `packaging/sandbox-browser` **不存在**，實際無法啟動 |
| 瀏覽器／桌面即時檢視元件（UI） | OpenClaw ui/src/components/browser, desktop | 🚧 | 後端 `browser_view.rs`＋`view.rs`（frame、input、novnc）有測試；`ui/web/*` 未改，沒有畫面；desktop takeover 依賴不存在的 Bot Desktop |
| Doctor：瀏覽器就緒 | OpenClaw extensions/browser doctor-browser | 🚧 | 只有工具 `browser action=doctor`（fake 測試）；`ark doctor` CLI 未整合 |

## 剩餘缺口（依使用者影響排序）

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
