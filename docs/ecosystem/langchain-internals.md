# LangChain 系列解剖：agent 迴圈、持久化、interrupt、工具、追蹤

上游快照（唯讀）：`/home/noob/.cache/ark-build/r5-f/lc/`。以下短名都相對於它：

- `factory.py`、`structured_output.py`、`middleware/*.py` = `langchain/libs/langchain_v1/langchain/agents/`
- `lg/…` = `langgraph/libs/langgraph/langgraph/`（例 `lg/types.py`、`pregel/_loop.py`、`graph/message.py`、`channels/binop.py`）
- `checkpoint/**` = `langgraph/libs/checkpoint/langgraph/checkpoint/`（含 `store/`、`serde/`）
- `deepagents/…` = `deepagents/libs/deepagents/deepagents/`（例 `deepagents/graph.py`、`deepagents/middleware/summarization.py`）
- `schemas.py`、`client.py`、`run_trees.py`、`_internal/**`、`processor.py` = `langsmith-sdk/python/langsmith/`
- ark 的路徑相對於本 repo 根。

標記「未確認」＝該行為的實作檔不在本次 clone 內，我不憑記憶補。`middleware/types.py` 專指 LangChain v1 的 `AgentMiddleware` 檔；LangGraph 的型別檔一律寫 `lg/types.py`。

整個堆疊的分工：LangGraph 是「有 checkpoint 的 BSP 執行器」；`create_agent` 是「用 middleware 節點拼出來的 model↔tools 圖」；deepagents 不加新執行器，只換 middleware stack 與 state schema；LangSmith 是「run 樹 + 兩條送出管道（`/runs/batch` 與 OTLP）」。

```
create_agent()                    LangGraph Pregel（每個 superstep）
──────────────                    ─────────────────────────────
StateGraph{                      tick(): 取 task → 平行執行 → after_tick(): 套 writes
  START → before_agent*            → 寫 checkpoint（durability 決定何時）
   → before_model* → model ⇄ tools  → 檢查 interrupt_before/after
   → after_model* → after_agent* → END
}                                channel(reducer) + BaseCheckpointSaver(thread_id/checkpoint_ns)
                                 interrupt() → GraphInterrupt → Command(resume=…)
```

## 1. agent 迴圈

### 1.1 `create_agent` 就是「組一張 StateGraph」

參數只有 model / tools / middleware / response_format / checkpointer / store / interrupt_before / interrupt_after 等（`factory.py:824-841`），實作不是手寫 while，而是 `StateGraph(state_schema=…, input_schema=…, output_schema=…, context_schema=…)`（`factory.py:1237-1244`）加節點、加邊、`graph.compile(...)`（`factory.py:1909-1925`）。

本體只有兩個節點：

| 節點 | 內容 | 出處 |
|---|---|---|
| `model` | `RunnableCallable(model_node, amodel_node, trace=False)` | `factory.py:1611` |
| `tools` | `ToolNode(tools=…, wrap_tool_call=…, awrap_tool_call=…)`，**只有存在 client-side 工具、或 middleware 定義了 `wrap_tool_call` 才建立** | `factory.py:1138-1148`、`1614-1615` |

其餘全是 middleware：每個 hook 各自 `add_node(f"{m.name}.before_agent")` / `.before_model` / `.after_model` / `.after_agent`（`factory.py:1636-1641`、`1660-1665`、`1684-1689`、`1708-1713`）。關鍵差別：**這些 hook 是圖上的節點**，回傳值走 channel、會被 checkpoint、也能被中斷；而 `wrap_model_call` / `wrap_tool_call` 不是節點，是在節點內被 compose 成洋蔥（`factory.py:1206-1224`、`1098-1125`），第一個 middleware 在最外層（`factory.py:281-298`、`middleware/types.py:515`）。

### 1.2 一次模型呼叫的實際路徑

`model_node`（`factory.py:1520-1549`）依序做四件事：先 `_patch_invalid_tool_calls(state["messages"])`，模型吐出解析不了的 tool call 時補一則 `ToolMessage` 讓對話合法（`factory.py:1522`、`692-707`）；再建 `ModelRequest(model, tools, system_message, response_format, messages, tool_choice, state, runtime)`（`factory.py:1523-1532`）；沒有 `wrap_model_call` 就 `_execute_model_sync(request)`，有就 `wrap_model_call_handler(request, _execute_model_sync)`（`factory.py:1535-1543`）；最後 `_build_commands(...)` 轉成 `list[Command]`（`factory.py:1537-1548`、`222-260`）。

`_execute_model_sync`（`factory.py:1493-1518`）= `_get_bound_model` → 選擇性前置 system message → `model.invoke` → `_handle_model_output`。`_get_bound_model`（`factory.py:1350-1491`）把 tools 綁上模型，並在此**決定 structured output 策略**（見 1.5）。

### 1.3 三條路由邊

| 邊 | 判斷 | 出處 |
|---|---|---|
| `tools → loop_entry / exit` | 執行到的工具全部 `return_direct=True` → exit；結構化輸出工具成功（`status != "error"`）→ exit；否則回 model | `factory.py:2072-2111`（判斷 `2097-2104`） |
| `loop_exit → tools / exit / loop_entry` | 1) state 有 `jump_to` 用它；2) 找不到 AIMessage → exit；3) `tool_calls` 為空 → exit；4) 有未回應的 tool call → **每個 call 一個 `Send("tools", [tool_call])`**（平行工具呼叫）；5) 有 `structured_response` → exit；6) 有 tool_calls 但都已回應（middleware 注入假 ToolMessage）→ 回 model | `factory.py:1991-2042`（`2031-2032` 平行派送） |
| `model → 最後一個 after_model` | 硬邊 | `factory.py:1857` |

`loop_exit_node` 是「第一個 `after_model` 或 `model`」，`loop_entry_node` 是「第一個 `before_model` 或 `model`」，`exit_node` 是「最後一個 `after_agent` 或 `END`」（`factory.py:1715-1741`）；`START` 只接進入點一次（`1743`），所以 `before_agent` / `after_agent` 一輪只跑一次。`recursion_limit` 硬設 9999（`factory.py:1897-1900`），並在 metadata 標 `ls_integration=langchain_create_agent`（`1900`）。

### 1.4 middleware 掛鉤點（以原始碼為準）

| hook | 語意 | 出處 | 形態 |
|---|---|---|---|
| `before_agent` / `abefore_agent` | `(state, runtime) -> dict \| None`，整體開始前一次 | `middleware/types.py:431`、`442` | 節點 |
| `before_model` / `abefore_model` | 每輪模型呼叫前 | `middleware/types.py:455`、`466` | 節點 |
| `after_model` / `aafter_model` | 每輪模型呼叫後 | `middleware/types.py:479`、`490` | 節點 |
| `wrap_model_call` / `awrap_model_call` | `(request, handler)`，可重試、短路、改 request | `middleware/types.py:503`、`598` | 洋蔥 |
| `wrap_tool_call` / `awrap_tool_call` | `(request, handler) -> ToolMessage \| Command` | `middleware/types.py:674`、`756` | 洋蔥 |
| `after_agent` / `aafter_agent` | 結束前一次 | `middleware/types.py:650`、`661` | 節點 |

另有四個類別屬性：`state_schema`（`middleware/types.py:397`）、`tools`（`400`）、`trace_policy`（`403`）、`transformers`（`413`）。middleware 也能用 state 的 `jump_to` 改下一站（`AgentState.jump_to` 是 `EphemeralValue + PrivateStateAttr`，`middleware/types.py:353`；解析在 `factory.py:1955-1967`；改寫在 `_add_middleware_edge`，`factory.py:2114-2159`）。`wrap_model_call` 內**不能**用 `Command(goto=…)`，會報錯並要求改用 `jump_to`（`factory.py:262-267`）：goto 改圖拓樸，wrap 只包住一次呼叫。

### 1.5 structured output 就是 tool calling（或 provider 的 response_format）

- `ProviderStrategy`：schema 轉成 `{"type":"json_schema","json_schema":{…}}` 當 `response_format` kwarg 綁進模型（`structured_output.py:296-317`、`factory.py:1443-1456`）。
- `ToolStrategy`：替 schema 造一個**假工具**（`StructuredTool(args_schema=json_schema, name=schema_name)`，`structured_output.py:339-355`），塞進 `final_tools`（`factory.py:1428-1440`）並強制 `tool_choice="any"`（`factory.py:1474-1475`）。
- `AutoStrategy`：看模型能力自動選一種（`factory.py:1407-1422`，能力判斷 `1411`）。

模型回話後由 `_handle_model_output` 收斂（`factory.py:1246-1348`）：Provider 策略直接 parse（`1257-1272`）；Tool 策略解析假工具的 `args`、補一則**真的** ToolMessage（「Returning structured response: …」）並寫 `structured_response`（`1307-1328`）。驗證失敗把錯誤包成 ToolMessage（模板 `factory.py:125`，使用點 `1330-1346`），模型下一輪讀到錯誤自己重試——`handle_errors=True` 本質上就是「用對話重試」。兩條路在 state 都收斂成同一個 `structured_response`（`middleware/types.py:354`），並用 `OmitFromInput` 擋使用者注入；`_build_commands` 會在本輪沒有結構化輸出時顯式清空，避免殘留（`factory.py:257-260`）。

### 1.6 deepagents 加了什麼

`create_deep_agent` 不新增節點型態，只 `create_agent(middleware=…, state_schema=DeepAgentState)`（`deepagents/graph.py:1008-1025`）再 `.with_config({"recursion_limit": 9999, "ls_integration": "deepagents"})`（`deepagents/graph.py:1018-1030`）。

- **state**：`messages` 改用 `DeltaChannel(_messages_delta_reducer, snapshot_frequency=50)`（`deepagents/graph.py:77-80`），checkpoint 只存 delta + 每 50 次快照，避免 O(N²)；reducer 仍是 by-id 合併 / `RemoveMessage` 墓碑（`deepagents/_messages_reducer.py:31-45`）。
- **檔案系統**：`FilesystemMiddleware` 給 `ls`/`read_file`/`write_file`/`edit_file`/`glob`/`grep`，backend 有 shell 再加 `execute`（`deepagents/middleware/filesystem.py:1820-1836`）；預設是 thread 內的 `StateBackend`（`1846-1848`），過大的工具結果會 evict 成檔案（`1835-1836`）。
- **子代理**：`SubAgentMiddleware` 掛一個 `task` 工具（`deepagents/middleware/subagents.py:905-913`），內部對子 agent runnable `invoke`（`865`），只回一則 ToolMessage 給父層（`782-787`）——子對話不進父 context，這是它最重要的隔離。
- **摘要**：`create_summarization_middleware`（`deepagents/middleware/summarization.py:1877-1885`），trigger 依 model profile 取 `("fraction", 0.85)`、keep `("fraction", 0.10)`；沒 profile 則 `("tokens", 170000)` / `("messages", 6)`（`288-325`）。與 LangChain 版最大差別是**不改 state**：摘要記在私有 `_summarization_event`、由 `wrap_model_call` 生效，被擠掉的訊息先寫到 `/conversation_history/{session_id}.md`（`1895-1913`）。
- **planning/todo**：默認 stack（`deepagents/graph.py:907-948`）**沒有** `TodoListMiddleware`，`write_todos` 只從 profile 來（`deepagents/profiles/harness/_openai_codex.py:77`）；`deepagents/libs/ARCHITECTURE.md:81` 卻寫 built-in 含 todo management——文件與程式不一致，以程式為準。

## 2. 持久化

### 2.1 superstep / BSP

主迴圈是 `tick()` + `after_tick()`（`pregel/_loop.py:650`、`700`）：`tick()` 檢查步數上限（`658-662`）、準備 task、套用上一輪載回的 pending writes（`672-674`）、檢查靜態斷點（`677-681`）；`after_tick()` 把所有 task 的 writes 一次 `apply_writes`（`702-730`）、存 checkpoint（`766`）、檢查 `interrupt_after`（`768-771`）、`self.step += 1`（`1384`）。同一輪的節點平行跑，writes 只在 barrier 後合併——這就是 BSP，也是「同一 superstep 內看不到彼此更新」的來源。

### 2.2 channel 與 reducer

`BaseChannel` 定義 `update(values) -> bool` / `get()` / `consume()` / `checkpoint()` / `from_checkpoint()`（`channels/base.py:19`、`49-61`、`70`、`90`、`101`）。

| 類別 | 語意 | 出處 |
|---|---|---|
| `LastValue` | 一步最多一個值，多於一個丟 `InvalidUpdateError`（提示改用 Annotated key） | `channels/last_value.py:20`、`56-67` |
| `BinaryOperatorAggregate` | `operator(舊, 新)` 摺疊；`Overwrite` 可繞過 reducer，同一 superstep 限一個 | `channels/binop.py:66`、`127-149` |
| `add_messages` | 依 `id` 合併、`RemoveMessage(id=…)` 刪除、`REMOVE_ALL_MESSAGES` 清空、缺 id 補 uuid4 | `graph/message.py:41`、`63`、`204-244` |
| `DeltaChannel`（beta） | checkpoint 只存 sentinel，靠 replay 祖先 writes 重建；reducer 必須可批次不變 | `channels/delta.py:25-64` |

`AgentState.messages` 就是 `Annotated[list[AnyMessage], add_messages]`（`middleware/types.py:352`）：「工具結果自動進歷史」是 reducer 做的，不是 agent 迴圈。

### 2.3 `BaseCheckpointSaver` 的介面與欄位

介面（`checkpoint/base/__init__.py:199`）：`get`（`250`）、`get_tuple`（`262`，回傳的 `pending_writes` 必須依 `writes_sort_key` 排序，`262-275`）、`list`（`277`）、`put(config, checkpoint, metadata, new_versions)`（`301`）、`put_writes(config, writes, task_id, task_path)`（`324`）、`delete_thread`/`copy_thread`/`prune`（`344`/`374`/`398`）、`serde`（`233`，預設 `JsonPlusSerializer`，`serde/jsonplus.py:104`）。

- `Checkpoint`：`v`、`id`（唯一且單調遞增，可排序）、`ts`、`channel_values`、`channel_versions`、`versions_seen`（node → 看過的版本，決定下一步跑誰）、`updated_channels`（`checkpoint/base/__init__.py:93-125`）。
- `CheckpointTuple`：`config`、`checkpoint`、`metadata`、`parent_config`、`pending_writes`（`140-148`）——**`parent` 叫 `parent_config`，`pending_writes` 掛在 tuple 上，不在 Checkpoint 裡**。
- `CheckpointMetadata`：`source`（`input`/`loop`/`update`/`fork`）、`step`、`parents`（ns → checkpoint id）、`run_id`（`checkpoint/base/__init__.py:39-70`）。

### 2.4 checkpoint 何時寫、`durability` 怎麼決定

| 時機 | source | 出處 |
|---|---|---|
| 帶新 input 的第一個 tick 前 | `input` | `pregel/_loop.py:1185` |
| 每個 superstep 結束 | `loop` | `pregel/_loop.py:766` |
| `update_state()` | `update` | `pregel/main.py:1751`、`2075` |
| 從舊 checkpoint 重跑的分支 | `fork` | `pregel/main.py:1883` |
| `durability="exit"` 的離開點 | 繼承 | `pregel/_loop.py:1507-1517` |

`durability` 是 `Literal["sync","async","exit"]`（`lg/types.py:98`），語意在 `99-104`：`sync` = 下一步開始前落地、`async` = 與下一步同時、`exit` = 只在離開時。預設 `"async"`（`pregel/main.py:2691-2692`）。實作上 `put` 是 executor 的 future（`pregel/_loop.py:1363-1375`），只有 `sync` 會在每個 superstep 後 blocking 等它（`pregel/main.py:3079-3081`）；`exit` 連 `put_writes` 都跳過（`pregel/_loop.py:515`），存檔條件變成 `exiting or durability != "exit"`（`pregel/_loop.py:1289-1291`）。舊參數 `checkpoint_during` 是 deprecated 別名（`pregel/main.py:2816-2824`）；沒有 checkpointer 時 `durability` 無效（`2905-2907`）。

### 2.5 thread 與 namespace

`thread_id` 是主要索引鍵：沒有它就不能存、不能 resume、不能 time travel（`checkpoint/base/__init__.py:213-215`）。`checkpoint_ns` 預設 `""`（`langgraph/libs/langgraph/langgraph/_internal/_constants.py:61`）；子圖 ns 是 `parent_ns + "|" + node`（`pregel/_algo.py:614`、`832`），task 層再串 `":" + task_id`（`623`），分隔字元 `|` / `:`（`langgraph/libs/langgraph/langgraph/_internal/_constants.py:90`、`92`）。有 checkpointer 時 config 至少要給 `thread_id` / `checkpoint_ns` / `checkpoint_id` 之一（`pregel/main.py:2678-2682`）；要定址歷史點就把 `checkpoint_id` 放進 `configurable`（`get_state` 用它判斷是否 live，`pregel/main.py:1482`）。

### 2.6 Store 與 checkpointer 的分工

`BaseStore` 是**跨 thread** 的 KV（`store/base/__init__.py:708-714`），資料單元是 `Item(namespace: tuple[str,…], key, value, created_at, updated_at)`（`51-105`），操作 `get`/`put`/`search`/`list_namespaces`（`756+`），可選向量索引與 TTL（`716-727`）。checkpointer 是**單一 thread 的狀態歷史鏈**（可回放、可 fork），Store 是**跨 thread 的長期記憶**（無歷史、直接覆寫）。deepagents 用 `StoreBackend(namespace=lambda rt: (…))` 把檔案放進 Store（`deepagents/backends/store.py:90-118`），Checkpointer 留給 graph state——兩者刻意不互相取代。

## 3. interrupt / human-in-the-loop

### 3.1 `interrupt()` 的機制

`interrupt(value, *, response_schema=None)`（`lg/types.py:903-1046`）依序：從 config 拿 scratchpad，`idx = scratchpad.interrupt_counter()`（`1020-1021`）＝節點內第幾個 interrupt；`scratchpad.resume` 已有第 idx 個值就回傳（可選 pydantic 驗證），並把已消費的前綴寫回 `RESUME` channel（`1023-1028`）；否則 `get_null_resume(True)` 取這次帶進來的 resume 值，append 進 `scratchpad.resume` 並寫 `RESUME`（`1030-1036`）；都沒有就 `raise GraphInterrupt(Interrupt.from_ns(value, ns=checkpoint_ns))`（`1038-1046`）。

`Interrupt.id = xxh3_128_hexdigest(checkpoint_ns)`（`lg/types.py:634-646`），而 ns 含 node 名與 task_id（`pregel/_algo.py:623`），所以 id 是「這個節點在這個位置」的穩定雜湊，重跑同位置得到同一個 id。

### 3.2 為什麼節點必須 idempotent

docstring 明講：「The graph resumes from the start of the node, **re-executing** all logic」（`lg/types.py:918`）。resume 不是從 interrupt 那行接回去，而是**整個節點重跑**，這次 `interrupt()` 直接回傳答案。因此 interrupt 之前的副作用（寫檔、發 HTTP、扣款）會再執行一次，之後的只執行一次。規則：副作用放 interrupt 之後，或做成幂等。

### 3.3 resume 的路徑與多個 interrupt 的比對

用戶端送 `Command(resume=…)`（`lg/types.py:833`、`857`）：`_first` 把 Command 轉成 writes（`pregel/_loop.py:1041-1059`），若 resume 的 key 全是 interrupt id 的 hash 就放進 `CONFIG_KEY_RESUME_MAP`（`1024-1028`，消費端 `pregel/_algo.py:1311-1313`），否則寫成 `(NULL_TASK_ID, RESUME, value)` pending write，由 `get_null_resume` 消費（`pregel/_algo.py:1319-1330`）。**多個 pending interrupt 時必須帶 id map**，否則直接報錯（`pregel/_loop.py:1029-1035`）；子圖的 resume 不走 Command，而是父層設 `CONFIG_KEY_RESUMING`（`pregel/_loop.py:970-976`）；沒有 checkpointer 時 `Command(resume=…)` 直接 `RuntimeError`（`pregel/_loop.py:1021-1024`，docstring `lg/types.py:924-925`）。

節點內多個 interrupt 靠**順序**對應：第 n 個 interrupt 拿 `scratchpad.resume[n]`（`lg/types.py:920-922`、`1023-1026`）。前面插一個新 interrupt，後面所有答案就錯位——**順序是協定的一部分**。

### 3.4 靜態斷點

`create_agent(interrupt_before=…, interrupt_after=…)`（`factory.py:835-836`）傳進 `compile()`（`1912-1913`）；執行期在 `tick()` 前檢查 before（`pregel/_loop.py:677-681`）、`after_tick()` 後檢查 after（`768-771`），條件是「自上次中斷以來有任何 channel 更新」且「觸發的節點在名單內」（`pregel/_algo.py:156-181`），`"*"` 代表全部（`lg/types.py:106-107`）。它不需要節點裡有 `interrupt()`，就是停在 superstep 邊界，續跑等同「同一份 state 再跑下一個節點」。

### 3.5 `update_state` / time travel

`update_state(config, values, as_node=None)` 的語意是「就像這些 values 由 `as_node` 產生」（`pregel/main.py:2613-2620`），會寫一個 `source="update"` 的新 checkpoint（`1751-1756`），歷史多一個節點、原鏈被分支。要從更早的點重跑就帶 `checkpoint_id`（live 判斷 `1482`）；`get_state_history` 沿 `parent_config` 逐個列 `StateSnapshot`（`1510-1550`、`lg/types.py:711-731`）。`StateSnapshot.interrupts` 的語意：讀最新 checkpoint 只含「還沒回答的」；讀指定 checkpoint 或歷史則含該步最後一次中斷（`lg/types.py:729-735`）。

### 3.6 `HumanInTheLoopMiddleware`：兩種暫停粒度

docstring 明確寫「需要 checkpointer、用 `Command(resume=…)` 續跑」（`middleware/human_in_the_loop.py:401-402`）。`batched`（預設）在 `after_model` 對本輪所有受管工具**一次** `interrupt(HITLRequest(action_requests, review_configs))`（`810-816`），拿到 `decisions` 後改寫 `last_ai_msg.tool_calls`（只留核准的），拒絕/回答變人工 ToolMessage（`826-859`）；決策數不符直接 `ValueError`（`818-824`）。`per_call` 則在 `wrap_tool_call` 對每個受管呼叫各自 `interrupt(value, response_schema=…)`（`698-757`），答案以 interrupt id 索引（`453-484` 範例）。四種決策 `approve`/`edit`/`reject`/`respond`（`117-160`）；`edit` 會實際改寫 args（`751-757`），並用 `_EDITED_TOOL_CALLS_KEY` 帶給 `wrap_tool_call`（`855-860`）。

## 4. 工具與記憶抽象

### 4.1 `BaseTool` / `StructuredTool` 的 schema

`BaseTool` 欄位：`name`、`description`、`args_schema`、`return_direct`、`handle_tool_error`、`handle_validation_error`、`response_format`（`content` / `content_and_artifact`）（`tools/base.py:474`、`477`、`483`、`495`、`527`、`542`、`547`）。給模型看的 schema 是 `tool_call_schema`：濾掉 injected 參數並對生成的 pydantic 類別做 memo（`tools/base.py:677-700`）。`StructuredTool.from_function` 沒給 `args_schema` 就用 `create_schema_from_function` 從簽名生成（`tools/structured.py:258-266`），description 預設取 docstring（`266-277`），兩者皆無則 `ValueError`（`277-279`）。呼叫時 `_parse_input` 驗證並注入（`tools/base.py:778-860`）。

### 4.2 錯誤處理：錯誤變成資料

`invoke` 的分支（`tools/base.py:1115-1129`）：`ValidationError` 看 `handle_validation_error`、`ToolException` 看 `handle_tool_error`（`bool|str|Callable`），未設定就 re-raise；被處理的錯誤產生 `ToolMessage(status="error")`（格式化在 `_format_output`，`1390-1420`）。「錯誤變 ToolMessage」是整個生態的共同語言：迴圈不用 try/except，模型自己讀錯誤修正；`ToolStrategy.handle_errors` 用的是同一招（`structured_output.py:216-229`）。

### 4.3 `ToolNode` 與 `wrap_tool_call`

`ToolNode` 原始碼不在 clone（`factory.py:35` 從 `langgraph.prebuilt.tool_node` 匯入，但 clone 沒有 `langgraph/prebuilt/`）——**內部實作未確認**。可確定的對外契約：建構時吃 `tools=` 與 compose 好的 `wrap_tool_call`/`awrap_tool_call`（`factory.py:1138-1148`）；提供 `tools_by_name` 給驗證與路由（`factory.py:1378`、`2090-2099`）；建構後 `default_tools` 用轉換過的 `BaseTool` 而非原始 callable（`factory.py:1150-1157`）。middleware 的 `wrap_tool_call` 可用 `request.override(tool_call=… / tool=…)` 換掉實際執行內容（`middleware/types.py:704-714`），也可連呼叫多次做重試（`718-729`）。

### 4.4 `add_messages` 的補述

`RemoveMessage(id=X)` 會把 X 從歷史移除，X 不存在則 `ValueError`（`graph/message.py:228-241`）；`RemoveMessage(id=REMOVE_ALL_MESSAGES)` 則是「砍掉前面全部、只留這則之後的」（`212-216`）。`_build_commands` 就是靠它把修補過的歷史整段換掉（`factory.py:249-254`）。

### 4.5 deepagents 的 virtual filesystem backend

`BackendProtocol`（`deepagents/backends/protocol.py:404`）是一組純檔案語意方法：`ls`（`436`）、`read`（`454`）、`grep`（`499`）、`glob`（`598`）、`write`（`659`）、`edit`（`685`）、`delete`（`722`）、`upload_files`（`754`）、`download_files`（`786`），每個都有 async 版。檔案資料固定為 `{content, encoding, created_at, modified_at}`（`424-433`），錯誤碼固定為 `file_not_found` / `permission_denied` / `is_directory` / `invalid_path`（`41-55`），批次上傳/下載允許部分成功。`SandboxBackendProtocol` 再加 `execute`（`489-531`）。

三種持久化層級：`StateBackend`（thread 內、跟 checkpoint 走）、`StoreBackend`（跨 thread，namespace 由 factory 決定，`deepagents/backends/store.py:90-118`）、`CompositeBackend`（依路徑前綴路由，例如 `/memories/` 走 Store、其餘走 state，`deepagents/middleware/filesystem.py:1874-1876`）。`FilesystemMiddleware` 負責包成工具並套權限（`1820-1836`）。

### 4.6 Store 的 namespace / key

`Item.namespace` 是 `tuple[str,…]`（`store/base/__init__.py:51-79`），操作有 `GetOp(namespace, key)`（`157`）、`SearchOp(namespace_prefix, …)`（`203`）、`ListNamespacesOp`（`368`），比對支援 `prefix`/`suffix` 與 `*`（`310-368`）。沒有 thread、沒有版本、沒有 parent——就是帶階層的 KV，跨 thread 共享。deepagents 的 `StoreBackend` 會驗證 namespace 元件字元（`deepagents/backends/store.py:45-50`），因為它直接被拼進儲存路徑。

## 5. 追蹤格式

### 5.1 run 模型

`RunBase`（`schemas.py:313-372`）：`id`、`name`、`start_time`、`run_type`、`end_time`、`extra`（metadata 在 `extra["metadata"]`，`374-379`）、`error`、`serialized`、`events`、`inputs`、`outputs`、`reference_example_id`、`parent_run_id`、`tags`。`Run` 再加 `trace_id`（`454`）、`dotted_order`（`456`）、`session_id`（`403`）。`run_type` 合法值：`tool`/`chain`/`llm`/`retriever`/`embedding`/`prompt`/`parser`（`332-334`）。LangChain 的 `Run` 就是 `langsmith.RunTree` 的別名（`langchain/libs/core/langchain_core/tracers/schemas.py:7`），tracer 記的和送出去的是同一份模型。

### 5.2 `dotted_order`

`dotted_order = 父的 dotted_order + "." + 自己的 "<start_time %Y%m%dT%H%M%S%fZ><run uuid>"`，root 無前綴（`run_trees.py:1692-1698`、`550-560`）。子 run 的 id 預設 `uuid7(start_time)`（`780-790`），所以同層內 uuid 字典序＝時間序；子 run 的 `start_time` 會被夾成不早於父（`762-770`），避免排序錯亂。root 的 `trace_id` 等於自己的 `id`（`schemas.py:474-475`）。

### 5.3 批次端點與 payload

- 端點 `POST {api_url}/runs/batch`，header 帶 `x-api-key`（`client.py:3333-3390`，路徑在 `3383`，key 常數 `399`）。
- body 形狀 `{"post": [...], "patch": [...]}`（`client.py:3103-3108`），每筆是**完整 run dict**（`id`、`trace_id`、`dotted_order`、`run_type`、`inputs`、`outputs`、`extra`、`tags`、`error`…），不是差異物件（`_internal/_operations.py:197-218` 把大欄位抽出分別序列化，其餘放 `_none`）。除錯標記是 `trace={trace_id},id={run_id}`（`client.py:3131-3132`）。
- `patch` 是同 id 的第二次送出（`operation="patch"`，`_internal/_operations.py:20-21`），只帶有變的欄位，典型是 `outputs`/`end_time`/`error`。
- body 依 size limit 切塊後逐塊 POST（`client.py:3146-3180`）；生命週期是 `RunTree.post()` → `client.create_run(**run_dict)`（`run_trees.py:994-1023`），結束後 `patch()`（`1037+`）。

### 5.4 SDK 內建的 OTLP 匯出

**URL**：`{LANGSMITH_ENDPOINT or https://api.smith.langchain.com}` + `/otel` + `/v1/traces`（`_internal/otel/_otel_client.py:115-124`）；`OtelExporter` 走 `urljoin(base_url, "otel/v1/traces")`（`processor.py:101-105`）。若 `OTEL_EXPORTER_OTLP_ENDPOINT` 已以 `/traces` 結尾則原樣使用（相容舊設定，`_internal/otel/_otel_client.py:120-122`）。

**Header**：`x-api-key` + `Langsmith-Project`（`processor.py:129-133`；名稱在 `_internal/_addressing.py:154-168`）。**project 放 header、不放 resource**——最常做錯的一點。用 agent address 時改送 `Langsmith-Agent-Id` / `Langsmith-Agent-Environment`（`_internal/_addressing.py:163-167`）；缺 api key 會直接 `ValueError`（`processor.py:112-116`）。

**Resource**：`service.name`（`OTEL_SERVICE_NAME`，預設 `"langsmith"`）與 `langsmith.internal_provider=true`（`_internal/otel/_otel_client.py:140-147`）。

**Span 對應**（`_internal/otel/_otel_exporter.py`）：

| run 欄位 | span 上的東西 | 行 |
|---|---|---|
| `name` | span name（`start_span(run_info["name"], …)`） | `365-380` |
| `run_type` | attribute `langsmith.span.kind` | `103`、`549-550` |
| `run_type` | `gen_ai.operation.name`：`llm→chat`、`tool→execute_tool`、`retriever/embedding→embeddings`、`prompt→chat` | `115-127`、`563-566` |
| `name` | `langsmith.trace.name` | `104`、`552-553` |
| `session_id` / `session_name` | `langsmith.trace.session_id` / `…session_name` | `101-102`、`555-560` |
| `tags` | `langsmith.span.tags`（list 以 `", "` 串接） | `106`、`609-614` |
| `extra.metadata[*]` | `langsmith.metadata.<key>` | `105`、`603-607` |
| `inputs` | `gen_ai.prompt`（整段 JSON 字串） | `721-761` |
| `outputs` | `gen_ai.completion`（整段 JSON 字串） | `763-843` |
| `run_type=="tool"` | `gen_ai.tool.name` / `gen_ai.tool.call.id` | `595-601` |
| token 計數 | `gen_ai.usage.input_tokens` / `output_tokens` / `total_tokens` | `578-587` |
| `error` | `set_status(ERROR)` + `record_exception` | `385-390` |

**SpanKind 沒被設定**：`start_span(name, context=…, start_time=…)` 沒有 `kind=`（`365-380`；全檔 `kind` 只出現在 `LANGSMITH_RUN_TYPE` 那個字串裡，`103`）。所以「run_type → span kind」的正確理解是：**kind 一律 INTERNAL，語意靠 `langsmith.span.kind` 屬性**。

**ID 對應**：OTLP `trace_id` = run UUID 的 128-bit 整數（`_internal/_otel_utils.py:6-16`），`span_id` = run UUID 前 8 bytes（`19-29`）。要讓 span 與 run 對得上就必須用同一組 UUID 派生，不能隨機。

**模式**：`TracingMode = Literal["langsmith","otel","hybrid"]`（`client.py:145`），舊 `OTEL_ENABLED`（→ hybrid）/ `OTEL_ONLY`（→ otel）仍相容（`client.py:241-307`）。`OtelExporter` 繼承 `OTLPSpanExporter`（`processor.py:64`），內容型別由 `OTLPSpanExporter` 決定（OpenTelemetry 套件的預設是 protobuf，不是 JSON；此處未固定，見附錄）。

### 5.5 「照這樣送，LangSmith 才收」清單

1. `POST {endpoint}/otel/v1/traces`，`endpoint` 預設 `https://api.smith.langchain.com/otel`。
2. Header：`x-api-key`（缺了 `OtelExporter` 直接 `ValueError`，`processor.py:112-116`）+ `Langsmith-Project`。
3. 每個 span 至少 `langsmith.span.kind`；建議加 `langsmith.trace.name`。
4. 同一 trace 的所有 span 共用同一個 `trace_id`；`parent_span_id` 指父 run 的 uuid 前 8 bytes。
5. 時間用 unix nano，子 span 不可早於父。
6. metadata 放 `langsmith.metadata.<key>`（不是 resource），因為 LangSmith 用它們查詢（`processor.py:221-227` 的 `set_metadata` 說明 threads 檢視需要）。
7. `service.name` 放 resource；`langsmith.internal_provider` 是 SDK 自用標記，自建 exporter 可省。

## 6. ark 缺什麼／該借鏡什麼

原則：**保護不能吃掉自主性——能隔離或回復就不要問人**。凡是「每步都等核准」一律標不採用。

| 上游機制 | 上游出處 | ark 現況 | 決定 |
|---|---|---|---|
| model↔tools 迴圈（有未回應 tool call 就回 tools，否則結束） | `factory.py:1991-2042`、`2072-2111` | `crates/ark-app/src/surfaces/lobster.rs:538` 的 `run_stages` 是線性 stage pipeline，只能用 `Ran::Halted` 停住；ark 的 turn 迴圈在 `crates/ark-kernel` 內，沒有顯式規則 | 採用概念（把結束條件寫成可檢驗規則）；不引入圖引擎 |
| middleware hook 作為圖節點（狀態更新會被 checkpoint） | `factory.py:1636-1713`、`middleware/types.py:431-673` | `crates/ark/src/agentcmds/monitoring.rs:285-304` 的 `MonitoringHook` 是旁觀式：`run(&self, e, p) -> Result<HookDecision, String>`，不改 state、不持久化 | 部分採用：加「可回傳 state patch 的 before_model/after_model」；不採用「每個 hook 一個 checkpoint」 |
| structured output 用假工具 + 失敗以 ToolMessage 回饋 | `structured_output.py:339-355`、`factory.py:1474-1475`、`1330-1346` | `lobster.rs:697-710`（`llm.invoke`）已在做同一件事：把 schema 驗證錯誤接回 prompt 重試，但只在單一工具呼叫內；agent 迴圈層遇到工具錯誤仍整段失敗 | 採用（把同一招上移到 turn 層） |
| superstep/BSP + channel reducer | `pregel/_loop.py:650-730`、`channels/binop.py:127-149`、`graph/message.py:204-244` | `crates/ark-kernel/src/store.rs:1-7` 是 append-only JSONL 事件日誌（每 session 一檔、預設 fsync），狀態靠重放推導 | 部分採用：日誌已有，缺「reducer」與「同輪更新一次套用」的邊界 |
| `BaseCheckpointSaver`（per-thread 鏈 + `pending_writes` + `parent_config`） | `checkpoint/base/__init__.py:199-345`、`140-148` | 無 per-run 復原點。中斷只有全域 ESTOP（`crates/ark/src/security_cli.rs:412-432`）與 lobster 的 paused 檔 | **採用（最大缺口）**：JSONL 已足夠當 WAL，補「每輪快照 + 父指標」即可 time travel |
| `durability="sync"/"async"/"exit"` | `lg/types.py:98-104`、`pregel/main.py:2691-2692`、`3079-3081` | `store.rs:38-42` 只有 `sync: bool`（每筆 fsync），沒有「每輪」與「離開時」 | 採用：三檔比一顆 bool 更貼近取捨（daemon async / CLI sync / 批次 exit） |
| `interrupt()` 整節點重跑 + `Command(resume=…)` + id=ns 雜湊 | `lg/types.py:903-1046`、`918`、`634-646` | `lobster.rs:1054-1082` 的 `Paused` 存 `resume_at`/`step`；resume 時**不重跑**已完成 stage，直接從下一 stage 開始（`1414-1464`），token 一次性（`1409` 先刪檔） | 部分採用：ark 的「不重跑」比 LangGraph 更安全（無 idempotent 問題），代價是無法在 stage 中途改參數重試。採用「resume 值可按位置定址」，不採用「整節點重跑」 |
| 靜態斷點 `interrupt_before/after` | `factory.py:1912-1913`、`pregel/_algo.py:156-181` | 無。lobster 的 `approve`/`ask` 是**寫在 pipeline 裡**的 stage（`lobster.rs:655-671`），要在腳本明寫 | 不採用「每步斷點」；保留「任意 stage 間插 gate」的心智模型（ark 已等價） |
| `HumanInTheLoopMiddleware`（每個受管工具先問） | `middleware/human_in_the_loop.py:397-421`、`810-816` | lobster 只有顯式 `approve` stage 與 `required_approver` 檢查（`lobster.rs:1399-1408`） | **不採用**「每步都等核准」：違反「能隔離或回復就不要問人」。只採它的 `when` predicate（`human_in_the_loop.py:358-386`）對高風險工具開啟 |
| `update_state` 產生 `source="update"` 分支 | `pregel/main.py:2613-2620`、`1751-1756` | `crates/ark-kernel/src/automation.rs:17-41` 的 `with_list` 只讀改寫「現狀」，`goals.json` 沒有歷史 | 採用：goal 每輪寫一筆快照，才能回答「第 3 輪為什麼走歪」 |
| `add_messages`（by-id 合併、墓碑） | `graph/message.py:204-244` | 事件日誌 append-only（`store.rs:108`、`290`），訊息無 id，改歷史只能再寫一則 | 採用 id 化：沒有 message id 就無法編輯歷史上某一則或去重 |
| `BackendProtocol`（ls/read/grep/glob/write/edit/delete/upload/download + 標準錯誤碼） | `deepagents/backends/protocol.py:404-433`、`41-55` | lobster 只有 `exec` 與 `state.get/set`（`lobster.rs:655-682`）；檔案存取靠 `crates/ark-tools/src/fs.rs` 直接碰真檔案系統 | 採用錯誤碼與「部分成功」語意；不採用「虛擬檔案系統當預設」——ark 賣點是本機真檔案 |
| `StoreBackend`（跨 thread、namespace factory） | `deepagents/backends/store.py:90-118` | lobster kv 是 `<data>/lobster/kv/<key>.json`（`lobster.rs:420-429`），**所有 session 共用同一組 key** | 採用 namespace：至少加 `session/workspace` 前綴，否則兩個 workflow 會互踩 `state.set` |
| `task` 子代理（子對話不進父 context） | `deepagents/middleware/subagents.py:647-660`、`782-787`、`865` | ark 有 `spawn`（`crates/ark/src/ops/context.rs:30`）與 `acp_delegate`（`crates/ark-app/src/acp_client.rs:761`）；`automation.rs:416-441` 的 goal 迴圈每輪重下 prompt，但沒有「父層只收摘要」的硬邊界 | 採用：明文規定子代理只回最後一則訊息 + 結構化欄位 |
| summarization（依 profile fraction 觸發，摘要前先落檔） | `deepagents/middleware/summarization.py:288-325`、`1895-1913` | 無自動壓縮；`crates/ark-kernel/src/context.rs:73-80` 只注入技能索引，長 session 靠使用者自己開新的 | 採用（含先落檔）：`conversation_history/*.md` 正合 ark 的檔案優先風格 |
| `write_todos`（每輪最多一次） | `langchain/libs/langchain_v1/langchain/agents/middleware/todo.py:174-186`、`deepagents/libs/deepagents/deepagents/profiles/harness/_openai_codex.py:77` | ark 已有 `todo` 工具與 goal/subgoal（`automation.rs:326-345`） | 不採用 middleware 版：缺的只是「每輪最多一次」的約束 |
| LangSmith run 模型 + `dotted_order` + `/runs/batch` | `schemas.py:313-372`、`run_trees.py:1692-1698`、`client.py:3333-3390` | `monitoring.rs:1-16`、`285-304` 只送 gateway health / diagnostic / cron 事件，**沒有 turn/tool 層 trace** | 部分採用：不需要它的儲存後端，但需要「run 樹 + dotted order」把一個 turn 的工具呼叫排成時間軸 |
| OTLP：`langsmith.span.kind`、`Langsmith-Project`、UUID 派生 id | `_internal/otel/_otel_exporter.py:101-127`、`processor.py:129-133`、`_internal/_otel_utils.py:6-29` | `monitoring.rs:259-265` 每事件一 span：`traceId`/`spanId` **隨機**、`start==end`、`kind=1`、attribute 只有 `ark.*`（`196-208`）、resource 無 project（`228-236`） | 採用（若要接 LangSmith）：現在進得了 collector、進不了 trace 檢視。改動很小：`random_hex(32)` 換成 turn 的 uuid，再補 3 個 attribute |
| Skills 漸進揭露（metadata 先、`SKILL.md` 按需） | `deepagents/middleware/skills.py:914-948` | `crates/ark-skills/src/core/invoke.rs:188-210` 把整份 `SKILL.md` 注入成一則使用者訊息 | 部分採用：索引與內文已分開（`context.rs:73-80` 只放索引），可再補「先給 metadata、模型再要內文」 |

### 我認為 ark 最該抄的三件事

1. **每輪 checkpoint + `parent_config`**（`checkpoint/base/__init__.py:140-148`、`pregel/_loop.py:766`）：這是「能回復就不要問人」的技術前提。ark 已有 append-only JSONL，補可定址快照與父指標，就能不打斷 agent 地做事後追查與分支重跑。
2. **錯誤變成 ToolMessage，而不是例外**（`tools/base.py:1115-1129`、`factory.py:1330-1346`）：ark 的 stage／工具失敗目前會讓整段工作結束；把錯誤當資料餵回模型，比加 approval gate 更能保護自主性。
3. **run 樹 + dotted order 的追蹤格式**（`run_trees.py:1692-1698`、`_internal/otel/_otel_exporter.py:101-127`）：`monitoring.rs` 只送點事件，看不出一個 turn 內工具呼叫的先後與耗時；用同一組 UUID 派生 trace/span id，就能同時滿足自架 collector 與 LangSmith 的檢視。

## 附錄：未確認與已知落差

- `ToolNode` 內部（`langgraph/prebuilt/tool_node.py` 與整個 `prebuilt` 套件不在 clone 內）；`ToolRuntime` 欄位（`Runtime` 在 `lg/runtime.py:125-141`，`ToolRuntime` 在 `prebuilt`）。
- LangSmith 伺服器是否接受 OTLP/HTTP **JSON**（SDK 走 `OTLPSpanExporter` 預設 protobuf）。
- `AsyncSubAgentMiddleware` 的遠端協定細節（只確認存在，`deepagents/graph.py:939-941`）。
- `deepagents/libs/ARCHITECTURE.md:81` 說默認含 todo management，但 `deepagents/graph.py:907-948` 沒有——以程式為準。
