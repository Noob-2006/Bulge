# SE Agent 的持久化流程：LangGraph 對照、與 lobster 的分工

這一頁說明 F2 的實作：`crates/seagent-app/src/surfaces/graph.rs`（工具名 `graph-flow`）——LangGraph
的執行模型（superstep、channel reducer、checkpoint、interrupt、time travel）在 SE Agent 裡的等價物，
以及它與既有 `lobster`（`crates/seagent-app/src/surfaces/lobster.rs`）的分工。上游依據見
[`langchain-internals.md`](langchain-internals.md)（Pregel `tick()`/`after_tick()`、`BaseCheckpointSaver`、
`interrupt()` 可續跑例外、`durability` 三檔）。

## 1. 差異一句話

| | `lobster`（既有） | `graph-flow`（本輪新增） |
|---|---|---|
| 形狀 | 線性 stage 管線（`a \| b \| c`）或 `steps` 清單 | 有向圖：節點＋靜態／條件邊，可迴圈、可分支 |
| 狀態 | 每個 stage 之間流動的 JSON 陣列；`state.get/set` 是全域 KV | 具名 **channel**，每個 channel 有 reducer（last/appendsum/merge） |
| 斷點 | `approve` / `ask` 兩個 stage，halt 後存 `resumeToken` | `gate` 節點＋`interrupt_before/after`，每個 superstep 都存 checkpoint |
| 續跑 | 只能續「剛剛停下的那一個」 | 可續最新，也可**指定任何舊 checkpoint**（time travel／分支） |
| 適合 | 重複性的資料處理管線（抓資料→過濾→摘要→送出） | 需要狀態機、迴圈、重試策略、長時間等待人核准的流程 |

兩者都是 SE Agent 的工具（`lobster`、`graph-flow`），共用同一組安全模型：都在呼叫前宣告
`Effect`（`Tool::effects`），由 SE Agent 既有的閘門一次性判斷整個流程，而不是每個節點問一次
（設計原則 §0：不要讓長期任務卡在核准）。

## 2. 對照表：LangGraph → SE Agent

| LangGraph | SE Agent `graph-flow` | 備註 |
|---|---|---|
| `StateGraph(state_schema)` | `{"state": {"<ch>: {"reducer": …, "default": …}}}` | SE Agent 的 channel 無型別，靠 reducer 決定合併方式 |
| `LastValue` | `"reducer": "last"`（預設） | 後寫蓋前寫 |
| `BinaryOperatorAggregate` / `add`（list） | `"reducer": "append"` | 純量自動包成 list，陣列攤平 |
| `add`（str） | `"reducer": "concat"` | 字串串接／陣列串接，兩者都保留型別 |
| `add_messages` | 未實作 | SE Agent 的訊息歷史在 kernel，不在流程層；流程只帶摘要與指標 |
| `add`（數字） | `"reducer": "sum"` | 整數保持整數 |
| dict merge | `"reducer": "merge"` | 淺合併 |
| `add_node("x", fn)` | `nodes.x = {kind: run\|tool\|llm\|set\|gate\|noop}` | 見 §3 |
| `add_edge(a, b)` / `START` / `END` | `edges: [{"from": "a", "to": "b"}]`，`from: "START"`、`to: "END"` | 沒有 START 邊時，從第一個節點開始 |
| `add_conditional_edges(a, router, map)` | `{"from": "a", "router": [{"when": "…", "to": "b"}], "default": "c"}` | `when` 是一條小條件式（§4），規則依序比對 |
| `interrupt()` | `{"kind": "gate", "mode": "approval"\|"input"}` | 節點被重跑一次並拿到答案（與上游一致：副作用要放在 gate 之後或做成幂等） |
| `interrupt_before` / `interrupt_after` | 同名規格欄位 | 停在 superstep 邊界，不需要節點裡有 gate |
| `Command(resume=…)` | `action=resume` + `approve` / `response` | `response` 會先用 gate 的 `schema` 驗證（`seagent_plugin::schema::validate`） |
| `BaseCheckpointSaver.put/get/list` | `<data>/surfaces/graph/threads/<thread>/<step>-<id>.json`＋`latest.json` | 每個 checkpoint 有 `parent`、`step`、`status`、`next`、`state`、`graph`、`input` |
| `configurable.thread_id` | `threadId`（`a-z0-9-_`，≤64） | 路徑穿越一律拒絕 |
| `checkpoint_ns`（子圖） | 未實作 | 子流程請用兩個 thread，或在工具裡再叫 `graph-flow` |
| `durability: sync/async/exit` | 永遠 sync（先寫檔再進下一步） | SE Agent 的流程一次 superstep 就是一次 commit；沒有背景寫入執行緒 |
| `update_state` / time travel | `action=resume` + `checkpointId`（從舊點分支）、`action=status` 看歷史 | 分支不覆寫舊 checkpoint，parent 鏈保留 |
| `BaseStore`（跨 thread 長期記憶） | 未實作；用 `memory` 工具或 `lobster` 的 `state.*` | 流程狀態與長期記憶刻意分開 |
| `recursion_limit` | `[surfaces.graph] max_steps`（預設 64） | 超過即 `status: "error"` 並留下 checkpoint |

## 3. 節點種類

| kind | 做什麼 | 主要欄位 | 寫入 |
|---|---|---|---|
| `run` | `sh -c`（或 `argv`）跑一個指令 | `cmd` / `argv` / `stdin` / `cwd` / `timeout_ms` / `save_json` | `save`（預設 `result`）＝stdout |
| `tool` | 呼叫 SE Agent 既有的工具 | `tool` / `args`（字串可含 `{{path}}`） | `save`＝工具輸出（`save_json` 時解析） |
| `llm` | `llm-task`：JSON-only 的模型呼叫 | `prompt` / `schema` / `model` | `save`＝已驗證的 JSON |
| `set` | 只寫狀態（不產生副作用） | `state: {ch: value}` | 逐個 channel |
| `gate` | 停下來等人 | `mode` / `message` / `schema` / `save` | 續跑後寫入答案（approval→bool、input→JSON） |
| `noop` | 佔位／測試 | — | — |

所有節點都支援 `on_error: "continue"`（把錯誤字串寫進 `error` channel 後繼續）與 `description`
（`action=explain` 會列出來）。

## 4. 條件式（刻意很小）

`when` 支援：`{{path}}` 或 `state.path` 取值、`== != >= <= > <`、`and` / `or` / `not`、
`in`、`contains(a, b)`、單獨一個路徑即真值判斷。沒有函式呼叫、沒有賦值——流程條件不是程式語言；
要複雜邏輯就放進 `llm` 或 `tool` 節點，把結果寫成布林 channel。

## 5. 執行語意（與 Pregel 一致的部分）

1. 一個 superstep ＝ `next` 清單裡的所有節點，依序執行；節點只**宣告寫入**，不直接改狀態。
2. 整批跑完才用 reducer 套用寫入（BSP）——所以同一批的兩個節點不會看到彼此的寫入（上游亦然）。
3. 套用後路由（`next_of`），寫 checkpoint，然後進入下一個 superstep。
4. 批次中途遇到 gate：已跑完的節點寫入照樣套用，還沒跑的節點與 gate 本身留在 `next`，狀態記為
   `interrupted`。續跑時 gate 重跑一次並拿到答案。
5. 逾時／取消：每個節點有自己的 timeout，整體有 `max_steps`；逾時會 kill 自己啟動的子行程。

**與上游不同的地方（誠實列出）：** 同一批節點是循序執行而非平行（SE Agent 的工具呼叫共用
`ToolCtx`，先求語意正確）；沒有 `checkpoint_ns` 子圖；沒有跨 thread 的 Store；`interrupt_after`
的 resuming 只會繼續往下，不會重跑節點（上游的 `Command(resume)` 一定是重跑）。

## 6. 工具介面

```json
{"action": "run", "graph": {...} | "path/to/flow.yaml", "threadId": "daily-report", "input": {...}}
{"action": "resume", "threadId": "daily-report", "approve": true}
{"action": "resume", "threadId": "daily-report", "response": {"host": "web1"}}
{"action": "resume", "threadId": "daily-report", "checkpointId": "0003-ab12cd34"}   // 從舊點分支
{"action": "status", "threadId": "daily-report"}    // 最新 checkpoint + 歷史
{"action": "list"}                                   // 所有 thread
{"action": "explain", "graph": "path/to/flow.yaml"}  // 節點、邊、入口（不執行）
{"action": "resume", "threadId": "…", "cancel": true}
```

`[surfaces.graph]`：`max_steps`（64）、`timeout_ms`（30000，單一節點）、`max_stdout_bytes`（512000）、
`tool_allow` / `tool_deny`（`tool` 節點可呼叫哪些工具，預設拒絕 `gateway`、`lobster`、`graph-flow`——
流程不能無限遞迴叫自己）。

ARP 方法 `graph.threads` 讓 Web UI 列出所有流程（與 `lobster.runs` 並列）。

## 7. 與安全設計的關係（§0 的兩個問題）

1. **它會讓無人看管的任務多停幾次？** 不會。只有明確寫成 `gate` 的節點會停；其餘全部在
   `effect` 宣告後由既有閘門一次判斷就放行。`gate` 是流程作者刻意放的（例如「寄出前確認」），
   而且停下來不會失敗：整個 state 都在 checkpoint 裡，幾小時後回答都還在。
2. **有沒有「隔離或回復」的替代做法？** 有，而且這是主要防線：每個 superstep 都有 checkpoint，
   所以做錯可以從任何一點分支重跑，不必事先詢問。真正不可回復的動作（對外寄送、刪除正式資源）
   才需要 gate——與 A6 的等級 3 定義一致。

## 8. 測試

`cargo test -p seagent-app --lib surfaces::graph`：15 個測試，涵蓋

- 規格驗證（打錯欄位名、未知節點種類、懸空邊、保留名 `START`/`END`、gate 模式）；
- 模板與條件式（型別保留、缺少路徑、`and/or/not/contains/in`）；
- reducer（last/first/append/concat/sum/merge）；
- 線性流程：每個 superstep 一個 checkpoint、parent 鏈可回溯、同 thread 不可覆寫；
- approval gate：停下、checkpoint 保留 state、answer 注入、prompt 模板化；
- input gate：schema 驗證（不合的答案被拒）；
- 條件邊迴圈直到條件不成立；
- `interrupt_before` 停在普通節點前並可續跑；
- time travel：從舊 checkpoint 分支（不覆寫歷史）；
- 節點失敗 → `status: error`；`on_error: continue` → 記下錯誤繼續；
- `max_steps` 擋住無窮迴圈；
- cancel / status / list；
- `tool` 節點的拒絕清單（流程不能叫自己）；
- 執行前宣告的 `Effect`（`git status {{dir}}` 會被閘門看到）；
- YAML 檔載入與 thread id 驗證（`../escape` 被拒）。
