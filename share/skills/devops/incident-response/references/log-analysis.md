# Log analysis patterns

Narrow by labels first, then by text, then by time. Every tool output is capped; when the
result says "truncated", read the spilled file in parts instead of widening the query.

## Loki (LogQL) with `loki_query`
- Errors of one service: `{namespace="shop", app="checkout"} |= "error"`
- HTTP 5xx from JSON logs: `{app="api"} | json | status >= 500`
- Exclude noise: `{app="api"} |= "timeout" != "healthcheck"`
- Error rate as a metric (summarised like Prometheus series):
  `sum by (app) (rate({namespace="shop"} |= "error" [5m]))`
- First occurrence: `direction=forward`, `start` a few minutes before the alert, `limit=20`.

## Elasticsearch / OpenSearch with `elastic_search`
- `index=logs-*`, `query="service.name:checkout AND log.level:error"`, `since=now-30m`
- Top messages: `size=0`-style aggregation via `aggs={"top":{"terms":{"field":"message.keyword","size":10}}}`
- Count only: `count_only=true` to see the volume before pulling documents.

## Reading what comes back
- Group identical messages and report counts, not every line.
- Note the first timestamp per message type; compare with deploy and alert times.
- Stack traces: quote the exception type and the first frame in your own code, not the whole trace.
- Correlate request ids across services when the logs carry them (trace_id, request_id).

## Pitfalls
- Clock skew between hosts: trust the log shipper's timestamp only after checking one known event.
- Sampling: some pipelines drop debug or high-volume logs; absence is not proof.
- Multi-line logs split into separate entries: search for the exception type, then widen the window.
