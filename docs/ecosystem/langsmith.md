# LangSmith 相容：ark 的 OTel 匯出怎麼送進 LangSmith

F3 的結論與做法。ark 的匯出器是 `crates/ark/src/agentcmds/monitoring.rs`（OTLP/HTTP JSON），
LangSmith 的匯入是 `langsmith-sdk` 的 `OtelExporter`；LangSmith 不是通用 collector，它有幾個
硬性要求，ark 以前只送「通用 OTLP」，現在會依端點自動切換。

## 1. LangSmith 的匯入規格（照 SDK 原始碼核對）

| 項目 | 值 | 出處 |
|---|---|---|
| 端點 | `{LANGSMITH_ENDPOINT}/otel/v1/traces`（預設 `https://api.smith.langchain.com/otel/v1/traces`） | `langsmith/integrations/otel/processor.py:103-110`（`urljoin(base_url, "otel/v1/traces")`）、`_internal/otel/_otel_client.py:86-124` |
| 認證 | `x-api-key: <LANGSMITH_API_KEY>`，缺少時 SDK 直接丟 `ValueError` | `processor.py:120-127` |
| 專案 | **HTTP header** `Langsmith-Project`，不是 resource attribute | `_internal/_addressing.py:154-168` |
| Agent 位址（beta） | `Langsmith-Agent-Id` + `Langsmith-Agent-Environment`（與 project 互斥） | 同上 |
| 傳輸 | OTLP/HTTP；SDK 用 protobuf（`OTLPSpanExporter`），OTLP 規格也允許 `application/json` | `processor.py:129`（`super().__init__(endpoint=…, headers=…)`） |
| resource | `service.name` 必填（SDK 預設 `"langsmith"`） | `_otel_client.py:140-146` |
| span 型別 | `langsmith.span.kind` 屬性（`llm`／`tool`／`chain`／`retriever`…），SDK 不設 OTel SpanKind | `_internal/otel/_otel_exporter.py:103`（`LANGSMITH_RUN_TYPE`）、`WELL_KNOWN_OPERATION_NAMES` |
| 其他 LangSmith 屬性 | `langsmith.trace.name`、`langsmith.trace.session_id`、`langsmith.metadata`、`langsmith.span.tags` | `_otel_exporter.py:104-110` |

## 2. ark 的做法（`monitoring/langsmith.rs`）

`[telemetry] endpoint` 指向 LangSmith 時（`api.smith.langchain.com`、任何 `*.langsmith.com` /
`*.langsmith.dev`，或路徑以 `/otel` 結尾的自架實例），匯出器自動切換：

1. **URL**：`…/otel` → `…/otel/v1/traces`；已經是 `/v1/traces` 就保留；一般 collector 仍是
   `…/v1/traces`（不是 LangSmith 的端點保持原行為）。
2. **Headers**：`Langsmith-Project` 若沒在 `[telemetry] headers` 裡設定，會從 `LANGSMITH_PROJECT`
   補上。`x-api-key` 也會從 `LANGSMITH_API_KEY` 補——**但只限 LangSmith 自己的主機且必須是
   `https://`**：自架的 `…/otel` 端點（可能來自專案設定）只會拿到 URL 改寫與 project header，
   不會拿到環境裡的 key，否則就是一條外送金鑰的路徑（`the_key_never_leaks_to_a_self_hosted_otel_endpoint`）。
   `{{secret:NAME}}` 仍由 vault 在送出時解析（值永遠不進 log）；未解析的 secret 不會被當字面值送出。
3. **span 對應**：每個 span 加上 `langsmith.span.kind = "chain"` 與
   `langsmith.trace.name = <span 名稱>`（ark 的監控 span 是「步驟」而非 LLM 呼叫，`chain` 是 SDK
   對非 LLM run 的預設）。
4. **送出前驗證**：LangSmith 匯出前跑 `validate_otlp_json`——`service.name` 必填、`traceId` 32 位
   hex、`spanId` 16 位 hex、`*UnixNano` 必須是字串（uint64 的 JSON 表示）、每個 attribute 只能有
   一個 `*Value`。不合格就回報錯誤而不是靜默丟掉。

```toml
[telemetry]
enabled = true
endpoint = "https://api.smith.langchain.com"          # 自動變成 …/otel/v1/traces
headers = { "x-api-key" = "{{secret:LANGSMITH_API_KEY}}", "Langsmith-Project" = "ark-prod" }
```

`ark telemetry status` 會顯示 `langsmith: true` 與解析後的 project（只顯示 header 名稱，不顯示值）。

## 3. 驗證到什麼程度（誠實分級）

| 檢查 | 方法 | 結果 |
|---|---|---|
| URL／header／屬性和 SDK 一致 | 對 `langsmith-sdk` 原始碼逐項核對（上表）＋單元測試 `langsmith_endpoints_are_rewritten_like_the_sdk`、`headers_carry_the_key_and_the_project`、`spans_get_a_langsmith_run_type` | ✅ |
| 送出的本體是合法 OTLP（receiver 會收的形狀） | `validate_otlp_json`（Rust，隨每次 LangSmith 匯出執行）＋ 把實際送出的 JSON 用官方 `opentelemetry-proto` 的 `ExportTraceServiceRequest` **protobuf 描述子解析**（見 §4） | ✅ |
| 端點真的存在、真的要求金鑰 | `ark telemetry test --endpoint https://api.smith.langchain.com`（無金鑰）→ **HTTP 403**（不是 404：路徑存在、被認證層擋下） | ✅（§4 有實際輸出） |
| LangSmith SaaS **接受並顯示** trace | 需要真的 `LANGSMITH_API_KEY` 與付費/註冊帳號，本輪不做（規則禁止真金鑰） | ⬜ 未驗證 |
| protobuf 編碼 | ark 送 OTLP/JSON（OTLP 規格的一種編碼）；SDK 送 protobuf | 🚧 JSON 已驗證可被 `opentelemetry-proto` 解析；若某個 LangSmith 部署只收 protobuf，需要再加一個 encoder |

## 4. 重跑方式

```sh
export ARK_HOME=$TMPDIR/ls-home   # 丟棄式
ark config set telemetry.enabled true
ark config set telemetry.endpoint http://127.0.0.1:4318/otel     # 本機假 collector，走 LangSmith 分支
ark config set 'telemetry.headers."Langsmith-Project"' ark-prod
ark telemetry test --json
```

本輪的做法：起一個本機 collector 記錄請求，`ark telemetry test` 送出一發，然後

```python
from google.protobuf import json_format
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
req = json_format.Parse(open("captured.json").read(), ExportTraceServiceRequest())
```

—— 能 Parse 就代表欄位名、型別、必填項都符合 OTLP 協定（欄位名打錯或數字用成 JSON number 會直接
`ParseError`）。實際輸出記在 `audit/round5/F.md`。

## 5. 還缺什麼（給下一輪）

- **turn／tool 層的 trace 還沒有**：目前只有 `gateway_health`、`gateway_diagnostic`、
  `cron_execution` 三種事件，且每個事件是各自獨立的 trace（`traceId` 隨機）。LangSmith 的價值在
  看到「一個 turn 裡的模型呼叫→工具→再呼叫」的樹，那需要 run 樹（parent/child span、`dotted_order`
  等價物），見 `langchain-internals.md` §5 與 §6。
- `[telemetry] traces/metrics/logs/sample_ratio/flush_secs` 這些鍵目前只出現在 `ark telemetry status`
  與文件裡，實際匯出沒有用到（metrics/logs 端點沒有實作）。
- protobuf 編碼（若需要）。
