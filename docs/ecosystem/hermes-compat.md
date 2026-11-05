# Hermes 生態相容（F6）：技能、外掛、optional-MCP、記憶與設定

本輪在 ark 上實際安裝並執行 Hermes 的東西：技能（`skills/**/SKILL.md`）、設定（`config.yaml` +
`.env`）、外掛（`plugins/*/plugin.yaml` ＋ Python 套件）、optional-MCP 目錄（`optional-mcps/*/manifest.yaml`）。
Hermes 外掛是 Python，ark 的外掛是 MCP stdio 行程，所以關鍵在**產生一個講 ark 協議的 Python 墊片**
（`crates/ark-plugin/src/compat/shim/hermes_shim.py`）——這是本輪真正讓 Hermes 外掛跑起來的部分。

## 1. 結論表

| Hermes 的東西 | 狀態 | 怎麼用 | 證據 |
|---|---|---|---|
| 技能 `skills/<category>/<name>/SKILL.md` | **直接用** | `ark migrate from hermes --path <dir>`（既有）或 `ark skills compat import <dir>` | 實測 `llm-wiki`：`ark skills list` 顯示 `user available`、`ark skills view llm-wiki` 讀到全文 |
| 技能 frontmatter（`platforms:`、`metadata.hermes.tags/category`、`related_skills`） | **經轉換** | `normalize()`：`platforms` → ark 的 `os` 閘門；`metadata.hermes.*` 原樣保留 | `compat_skill_hermes_variant_maps_platforms_to_os` |
| 設定 `config.yaml`（model、mcp_servers、plugins…）＋ `.env` | **直接用** | `ark migrate from hermes`：model → `[model]`、MCP → `[mcp.*]`、`.env` → vault | 實測：`config model.default`、`config mcp.fs`、`secret ANTHROPIC_API_KEY → vault` |
| optional-MCP `optional-mcps/<name>/manifest.yaml` | **直接用** | `ark skills compat import <optional-mcps/airtable>` → `[mcp.airtable]`（`transport.type: http` ＋ `auth.type: oauth`） | 實測：`ark mcp list` 顯示 `airtable lazy 0 tools http …` 並提示 `ark mcp login airtable` |
| optional-MCP 的 `${ENV}` 佔位 URL | **不可用** | 明確拒絕並給指令（不猜、不寫死） | `compat_real_corpora_all_parse`：65 個裡 64 個轉成功、1 個（`n8n-official`）要求使用者提供 URL |
| 外掛 `plugins/<name>/plugin.yaml` ＋ `__init__.py`（`register(ctx)` 介面） | **經轉換，會真的跑** | `ark skills compat import <plugin-dir>`：產生 `hermes_shim.py` ＋ `[plugins.<name>]`；`ark plugins` 列出 hook／command | 實測 `disk-cleanup`：`hooks: pre_tool,post_tool,session_end`、`/disk-cleanup`；`ark/command status` 回真實報表 |
| `kind: model-provider` 外掛（`plugins/model-providers/*`） | **不可用** | 標為 unusable 並說明：ark 的 provider 是 `[providers.*]`／`ark/provider.complete` 協議，沒有自動映射 | `compat_hermes_model_provider_is_flagged_as_unusable` |
| 記憶供應商（`plugins/memory/*`）、backends（tts/stt/image/video/browser/web_search） | **不可用** | shim 只實作 hooks／tools／commands；這些註冊被記為 unsupported | `hermes_shim.py` 的 `Ctx`（未知註冊 API 一律 no-op） |
| plugin-catalog（`plugin-catalog/*.yaml`，700+ 審核條目） | **直接用** | `ark skills` / `ark plugins` 的 catalog（`share/plugin-catalog/index.json`） | `crates/ark-skills/src/hub/plugins.rs` |

## 2. 實測：真的把 Hermes 外掛跑起來

```sh
export ARK_HOME=$TMPDIR/f6/home
cd $TMPDIR/f6/ws
ark skills compat import /home/noob/hermes-agent/plugins/disk-cleanup
# ok  disk-cleanup  wrote $ARK_HOME/data/plugins/disk-cleanup/hermes_shim.py, [plugins.disk-cleanup]
ark plugins
# disk-cleanup  process  enabled  python3
# disk-cleanup  0 tools · hooks: pre_tool,post_tool,session_end · commands: /disk-cleanup
```

用 ark 的協議直接驅動該墊片（等同 ark 內部的 plugin host）：

```
initialize  → {"ark":{"version":1,"hooks":["pre_tool","post_tool","session_end"],
                     "commands":[{"name":"disk-cleanup","description":"Track and clean up …"}]}}
ark/hook pre_tool  {tool_name:"write_file", …} → {"decision":"allow"}
ark/hook post_tool {tool_name:"write_file", …} → {"decision":"allow"}
ark/command {"name":"disk-cleanup","args":"status"}
  → "Category  Files  Size … (nothing tracked yet) / Top 10 largest tracked files: (none)"
```

那段 `/disk-cleanup status` 是**外掛自己的 Python 程式碼**產生的（`plugins/disk-cleanup/disk_cleanup.py`），
不是 shim 的假資料。也就是說：Hermes 的 hook 與 slash command 契約在 ark 上真的可用。

兩個必要的細節（本輪補上）：

1. **sys.path**：真實外掛會 `from hermes_constants import get_hermes_home`、`from tools.* import …`。
   shim 會從外掛目錄往上找 5 層，遇到 `hermes_constants.py`（或 `hermes_cli/` ＋ `pyproject.toml`）就
   把那棵 Hermes checkout 加進 `sys.path`；`ARK_HERMES_ROOT` 可覆寫。沒有這段，所有真實外掛都會
   載入成「空外掛」。
2. **`register(ctx)`**：Hermes 外掛不是靠 `on_<hook>` 命名，而是 `register(ctx)` 呼叫
   `ctx.register_hook/register_command/register_tool`。shim 提供這些方法並保存回呼，`ark/hook` 進來時
   逐一呼叫；`ctx.get_config(key, default)` 回傳 default（Hermes 的語意，不是 None），未知的
   `register_*` 一律 no-op（不要因為不支援的 API 讓整個外掛掛掉）。

外掛啟動後 ark 會要求能力核准（`ark security plugins accept disk-cleanup`）——這是 A5 能力型權限的
既有行為：新外掛宣告的 hook／command 要操作者按一次，之後才生效。

## 3. 真實語料的解析結果

`cargo test -p ark-plugin compat -- --nocapture`：

| 語料 | 數量 | 結果 |
|---|---|---|
| `optional-mcps/*/manifest.yaml` | 65 | 64 轉成可驗證的 `[mcp.*]`、1 個要求使用者提供 URL、0 解析失敗 |
| `plugins/**/plugin.yaml` | 106 | 全部 imported，0 失敗；全部產生 python shim；17 個 env、165 條 warning |
| 技能（hermes `skills/**`） | 111 個 SKILL.md | 正規化 0 失敗（`hermes` 變體 111、`ark` 10、`openclaw` 83、`plain` 19，合計 223） |

## 4. 界線（誠實清單）

- shim 以「來源目錄就地載入」（`cwd` 指向原外掛目錄）。刪掉 Hermes 安裝，匯入就失效。
- `middleware`、`stream_hooks`、`context_engine`、channels、providers 都不轉；hook 回傳的
  `context` 欄位（ark 沒有對應）會被丟棄並在 stderr 說明。
- Hermes 的 hook 參數名稱（`tool_name`／`args`／`result`）由 shim 對應，`transform_*` 回字串 → ark 的
  `modify`；回傳 dict 的其他欄位不轉。
- Python 外掛的程式碼照原樣執行：ark 的閘門管的是它對外的 hook/tool/command 呼叫，不是它內部的
  行為。第三方外掛請用 `trust = "untrusted"` 與能力核准。

## 5. 待辦

- `kind: model-provider` 的映射（Hermes `ProviderProfile` → ark `[providers.*]`）需要一個真正的
  adapter，不是 shim 能處理的。
- 記憶供應商（`plugin.memory`）可以直接對上 ark 的 `ark/memory.call`，下一輪可做。
- `optional-mcps` 的 `${ENV}` 佔位可以支援成 `{{secret:ENV}}`（本輪刻意拒絕，避免猜錯）。
