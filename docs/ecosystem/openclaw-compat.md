# OpenClaw 生態相容（F5）：什麼直接跑、什麼要轉換、什麼不可能

本輪在 ark 上**實際安裝並執行**了 OpenClaw 的三種東西：技能（`SKILL.md`）、設定（`openclaw.json`）、
外掛（`openclaw.plugin.json` ＋ `index.js`）。下面每列都有可重跑的指令；結果分「直接用」、
「經轉換」、`「不可用（並說明原因）」三態。

## 1. 結論表

| OpenClaw 的東西 | 狀態 | 怎麼用 | 證據 |
|---|---|---|---|
| 技能 `skills/<name>/SKILL.md`（含巢狀分類） | **直接用** | `ark migrate from openclaw --path <dir>`（既有）或 `ark skills compat import <dir>`（新） | `ark skills list` 列出、`ark skills view <name>` 讀到全文 |
| 技能的 frontmatter 變體（`metadata.openclaw.requires`、`os`、`always`、`primaryEnv`、`emoji`、`install`） | **經轉換** | `ark_skills::compat::skill::normalize` 提升成 ark 的頂層 `requires.{bins,anyBins,env,config}`／`os`，其餘原樣保留 | `compat_skill_openclaw_variant_hoists_requires_and_drops_the_allowlist` |
| 設定 `openclaw.json`（JSON5：model、providers、mcp、telegram…） | **直接用** | `ark migrate from openclaw --path <dir>`（既有 `ops::migrate`）：金鑰進 vault、MCP 進 `[mcp.*]`、SOUL/MEMORY 進 memories | 本輪實跑：`config mcp.fs = {…}`、`secret ANTHROPIC_API_KEY → vault` |
| ClawHub 套件 | **直接用** | `ark skills search --source clawhub`、`ark skills install clawhub:<pkg>`、`ark plugins install clawhub:<pkg>`（既有） | `crates/ark-skills/src/hub/sources.rs`（ClawHub ZIP）、`hub/plugins.rs`（code/bundle-plugin） |
| node 裝置（`openclaw node`） | **直接用** | ark 的 node 協議（`ark node`、`crates/ark-app/src/node*`）與 `linux-node` 擴充的契約相同（配對碼、`node.*` 指令） | `ark node --help`；`docs/arp.md` |
| 外掛 manifest 的宣告（`cliCommands`、`configSchema`、`contracts`、`setup.providers.envVars`、`activation`） | **經轉換** | `ark skills compat import <plugin-dir>`：產生 `[plugins.<id>]` ＋ `openclaw_shim.mjs`，env 變成 `{{secret:NAME}}` | 171 個真實 manifest 全數解析（0 失敗），見 §3 |
| 外掛的**執行期程式**（`index.js`：channels、providers、gateway methods、HTTP routes、UI、context engine） | **不可用** | 需要 OpenClaw gateway runtime（`openclaw/plugin-sdk`、`dist/*.mjs` 的 `openBlobStore` 等），ark 不提供。shim 會載入 entry、轉發「純 `register(api)` 就能註冊」的 tool／command／hook，其餘記在 `warnings` | 實測 `diffs`：`register(api) failed … reading 'openBlobStore'`，仍正常握手、回報 0 tool |
| 外掛的 UI（`controlUi`）與 `configSchema` 表單 | **不可用** | ark 的外掛設定是 TOML（`[plugins.*]`／`[builtin_plugins.*]`），schema 只當 metadata 保留 | 同上 |

## 2. 實際跑過的指令（丟棄式 `ARK_HOME`）

```sh
export ARK_HOME=$TMPDIR/f5/home           # 不碰真實 ~/.config/ark
mkdir -p $TMPDIR/f5/openclaw/skills && cp -r /home/noob/openclaw/skills/sag $TMPDIR/f5/openclaw/skills/
# 設定（JSON5，含註解）
ark migrate from openclaw --path $TMPDIR/f5/openclaw            # → 1 skill, [mcp.fs]
ark skills compat scan  $TMPDIR/openclaw/dist/extensions/brave  # → convert（node plugin → shim）
ark skills compat import $TMPDIR/openclaw/dist/extensions/brave # → data/plugins/brave/openclaw_shim.mjs
ark plugins                                                     # process 外掛上線，provides: python3/node
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}' \
  | node $ARK_HOME/data/plugins/brave/openclaw_shim.mjs         # 正確握手（ark 插件協議）
```

實測結果：

- `sag` 遷移成功（`<data>/skills/sag/SKILL.md`），但**在 `ark skills list` 看不到**——它宣告
  `requires.bins: ["sag"]`，ark 與 OpenClaw 一樣做資格閘門；裝了 `sag` 或設 `ELEVENLABS_API_KEY`
  之後才會出現在索引裡。這是「行為一致」，不是缺口。
- `brave` 外掛：manifest 的 `contracts.webSearchProviders: ["brave"]`、`setup.providers[].envVars`
  （`BRAVE_API_KEY`）都被讀出來；shim 載入 `index.js` 成功但註冊 0 個 tool（它靠 gateway 的
  web-search provider 機制），`ark/command` 回「manifest 有宣告、ark 沒有 runtime 可實作」。
- `diffs` 擴充：manifest 解析 ＋ 其中的 **skill 直接匯入成功**（`skill → <data>/skills/diffs`）；
  `register(api)` 因為缺 gateway runtime 而失敗，shim 記 stderr 後繼續（不阻塞 agent）。

## 3. 真實語料的解析結果（無網路、唯讀）

`cargo test -p ark-plugin compat -- --nocapture`（`compat_real_corpora_all_parse`）：

| 語料 | 數量 | 結果 |
|---|---|---|
| `dist/extensions/**/openclaw.plugin.json` | 171（`dist/extensions` 直下）/ 529（整棵樹） | 全部 imported，0 解析失敗；171 個 shim、15 個附帶 skill、117 個 env 變數 |
| `ark skills compat scan dist/extensions` | 191 items | 182 `convert`、9 `direct`（技能） |

## 4. 轉換規則（`crates/ark-plugin/src/compat/openclaw.rs`）

| manifest 欄位 | 去哪 |
|---|---|
| `id` / `name` / `description` / `categories` | `[plugins.<id>]` 的識別與 `Imported` metadata（id 會正規化成合法 TOML key） |
| `activation.onStartup` | 目前只寫進 warnings（ark 沒有常駐 service 的需求） |
| `cliCommands[]` | shim 的 `ark/command` 宣告（可用 `ark <name>` 形式列出；`hasSubcommands` 不展開） |
| `setup.providers[].envVars` | `secrets`；`[plugins.<id>] env = { NAME = "{{secret:NAME}}" }` |
| `contracts.<key>` | `capabilities` 的人類可讀說明（web search / memory / channel / model provider / middleware / command / tools），並在 warnings 說明 ark 的對應機制 |
| `configSchema` / `uiHints` / `configGroups` | 只保留為 metadata（ark 沒有對應的表單/驗證層） |
| `index.js` / `package.json` | 產生 `openclaw_shim.mjs`（零依賴 Node，ark 插件協議）＋ `cwd` 指回原目錄 |

風險與界線：shim **不複製**外掛原始碼，`cwd` 指向原目錄，所以刪掉 OpenClaw 安裝後匯入就失效
（warnings 有寫）。外掛仍然是在自己的 Node 行程裡跑，ark 的閘門管的是它暴露的 hook/command/tool
呼叫，不是它內部的行為——所以第三方外掛仍應走 `[plugins.<id>] trust = "untrusted"` 與能力核准
（`ark security plugins accept <name>`）。

## 5. 還沒做的（給下一輪）

- OpenClaw 的 provider contracts（web search、memory、channel）沒有對應的橋接器：要嘛寫 ark 原生
  實作，要嘛在 shim 裡把 provider 呼叫轉成 `ark/backend.call`。
- `controlUi` 面板、`doctorContract` 的修復動作沒有對應。
- `openclaw.json` 的 `agents/*`、`hooks`、`bindings` 區段目前 `ark migrate` 沒有全部搬（見
  `crates/ark/src/ops/migrate.rs` 的 `plan_openclaw`）。
