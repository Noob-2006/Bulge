# Building the incident timeline

## Sources, in order of trust
1. Monitoring data (Prometheus / Grafana): first bad datapoint, recovery datapoint.
2. Change records: `deploy action=history` and the audit log (`seagent audit events --kind deploy`),
   CI/CD runs, config management, feature-flag changes.
3. Logs: first occurrence of each new error type.
4. Human actions: pages, acknowledgements, chat decisions (PagerDuty `incident` timeline).

## Format
```
| time (UTC)          | source      | event                                         |
|---------------------|-------------|-----------------------------------------------|
| 2026-11-05 13:58:10 | deploy      | plan 3f2a… applied: checkout v2.14 (INC-123)   |
| 2026-11-05 14:02:00 | prometheus  | checkout 5xx ratio leaves baseline (0.2% → 4%) |
| 2026-11-05 14:04:30 | alertmanager| CheckoutErrorRate firing (severity=page)       |
| 2026-11-05 14:06:12 | pagerduty   | acknowledged by on-call                        |
```
- One event per row, oldest first, absolute UTC timestamps, the source of each row.
- Mark inferred rows (`inferred:`) separately from observed ones.

## Post-incident review (blameless)
- Summary, impact (duration, users, data), detection (how and how fast), response, recovery.
- Contributing factors, not a single root cause; what made it worse or better.
- Action items with owners and due dates: prevent, detect sooner, recover faster.
- Store the review with the ticket (`jira action=comment` or ServiceNow work note).
