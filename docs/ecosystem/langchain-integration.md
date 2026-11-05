# 從 LangChain 接入 ark：三條路

ark 不是模型供應商，是一個**完整的 agent**（工具、記憶、閘門、排程）。LangChain/LangGraph 要接它，
有三個層次，差別在「誰擁有迴圈」：

| 方式 | 誰跑 agent 迴圈 | 什麼時候用 | ark 端開關 |
|---|---|---|---|
| A. OpenAI 相容 API | **ark** | 想用 LangChain 的 `ChatOpenAI`／`ChatModel` 介面，但把工具、記憶、核准都交給 ark | `[app] enabled, openai_api = true` |
| B. MCP（`ark mcp serve`） | LangChain 的 agent | 想在 LangGraph 的圖裡直接使用 ark 的檔案／shell／記憶工具 | 無（stdio 行程） |
| C. A2A | ark 或對方 agent | 兩個 agent 互相派工（跨機器、跨語言） | `[app] a2a = { enabled = true }` |

以下三個範例都實際跑過（見 §4 的輸出）。

## A. OpenAI 相容 API（ark 擁有迴圈）

ark 提供 `GET /v1/models`、`POST /v1/chat/completions`（含 SSE 串流）、`POST /v1/responses`。
**一個對話＝一個 ark session**：`X-Ark-Session` 標頭（或 body 的 `session`、或
`previous_response_id`）可延續同一個 session；新 session 的 id 會回在 `X-Ark-Session`。

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="http://127.0.0.1:8640/v1",   # [app] listen
    api_key="<[app] token>",               # ark 的 app token，不是 OpenAI 的 key
    model="ark",                           # 或 "anthropic/claude-sonnet-5-5"（見 /v1/models）
    default_headers={"X-Ark-Session": "my-thread-1"},
)
print(llm.invoke("把昨天的 CI 失敗整理成一段摘要").content)
```

重點：

- `model` 填 `ark` 表示「用 ark 預設模型跑整個 agent」；填 `<provider>/<model>` 則覆寫模型。
- 這個請求會走 ark 的**完整**管線：系統提示、技能、記憶、工具、權限閘門。所以 LangChain 端不需要
  再給工具——給了也不會被使用（模型只看到 ark 的工具集）。
- 串流是標準 `chat.completion.chunk`（`data: {...}` + `data: [DONE]`）。
- 認證：`Authorization: Bearer <token>`。`openai_api` 預設**關閉**（A10 端點最小化），要明確打開。
- 不支援的部分：`tools`/`tool_choice`（工具由 ark 決定）、`response_format` 的 JSON schema 強制、
  `logprobs`、`n>1`。

LangGraph 的用法就是把它當任何 chat model 節點：

```python
from langgraph.graph import StateGraph, START, END
g = StateGraph(dict)
g.add_node("ark", lambda s: {"messages": s["messages"] + [llm.invoke(s["messages"])]})
g.add_edge(START, "ark"); g.add_edge("ark", END)
```

（反過來「ark 當工具」也可以：在 ark 裡設定 `[mcp.<name>]` 指向 LangChain 的 MCP server，或用 A2A。）

## B. MCP：把 ark 的工具放進 LangGraph

`ark mcp serve` 把 ark 的內建工具（檔案、搜尋、shell、記憶，加上 `ark_session_*` 來驅動／核准
執行中的 session）以 MCP stdio server 形式提供，呼叫一樣過 ark 的權限與出口閘門。

```python
# pip install langchain-mcp-adapters
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({"ark": {"command": "ark", "args": ["mcp", "serve"], "transport": "stdio"}})
tools = await client.get_tools()
agent = create_react_agent("anthropic:claude-sonnet-5-5", tools)
await agent.ainvoke({"messages": [("user", "看看 src/ 裡有什麼，然後跑 cargo test")]})
```

- `--workspace`、`--yes` / `--allow-privilege` / `--allow-egress` 與 ark CLI 相同語意；不給
  `--yes` 時，需要核准的呼叫會被閘門擋下並回錯誤（不會靜靜地執行）。
- Claude Desktop / Cursor 等任何 MCP client 也能用同一條命令。

## C. A2A：agent 對 agent

```toml
[app]
enabled = true
a2a = { enabled = true, name = "ark-ops", description = "ops agent" }
```

- Agent card：`GET /.well-known/agent-card.json`（舊路徑 `agent.json` 亦可）。
- JSON-RPC：`POST /a2a/v1`（`SendMessage`、`SendStreamingMessage`(SSE)、`GetTask`、`CancelTask`…），
  認證是 bearer（app token 或 `[app.a2a] peers` 的 peer token）。
- ark 也能當 client：`[app.a2a] agents = { peer = { url = "https://…/a2a/v1", token = "{{secret:X}}" } }`
  之後可用 `a2a_*` 工具派工給對方。

## 4. 本輪實際驗證（丟棄式 `ARK_HOME`，假模型）

用一個本機假 OpenAI provider（`base_url = http://127.0.0.1:4477/v1`）＋ `ark daemon run`：

```
GET  /v1/models
  → {"data":[{"id":"ark",…},{"id":"fake/m","owned_by":"fake"}],"object":"list"}
POST /v1/chat/completions {"model":"fake/m","messages":[{"role":"user","content":"hi"}]}
  → {"choices":[{"message":{"content":"hello from the fake model","role":"assistant"}}],
     "usage":{"prompt_tokens":15263,…}}              # 15263 = ark 的完整系統提示＋工具，證明不是直通模型
POST /v1/chat/completions {"stream":true}
  → data: {"choices":[{"delta":{"content":"hello from"},…}]} … data: [DONE]
回應標頭 → x-ark-session: 20261104-131753-8d28ef   # 同一個標頭可續接
GET  /.well-known/agent-card.json
  → {"name":"ark-test","protocolVersion":"1.0","capabilities":{"streaming":true,"pushNotifications":true},…}
printf 'initialize' | ark mcp serve
  → {"result":{"capabilities":{"tools":{}},"serverInfo":{"name":"ark","version":"0.1.0"},
     "instructions":"Ark's file, search, shell and memory tools, plus ark_session_* …"}}
```

## 5. 注意事項

- **不要**把 ark 的 app token 放進 LangChain 的 `LANGCHAIN_*` 環境變數或 URL；用 `api_key=`
  （它就是 `Authorization: Bearer`）。
- 走 OpenAI 相容 API 時，LangChain 的 callback／tracing 只會看到一次 LLM 呼叫；ark 內部的工具迴圈
  不會變成 LangGraph 節點（要逐節點追蹤請用 B 或 C）。
- 需要 LangSmith 追蹤 ark 自己的執行，請看 [`langsmith.md`](langsmith.md)。
