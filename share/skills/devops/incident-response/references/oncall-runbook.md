# On-call runbook: the first 15 minutes

Applies to any page from Alertmanager, Grafana or PagerDuty that reaches an seagent session
(webhook route, scheduled `incident-triage` blueprint, or a human asking).

## 0–2 min: own it
- Acknowledge the page: `pagerduty action=acknowledge incident_id=<id>` (or `dedup_key` for
  Events v2). Acknowledging is recorded in the audit log; it does not resolve anything.
- Open or find the incident ticket (`jira action=search jql="labels = incident AND statusCategory != Done"`).

## 2–5 min: is it real?
- `alertmanager_alerts kind=alerts active=true` — the full set of firing alerts; look for one
  root alert (a database, a network link) under many symptoms.
- `prometheus_query kind=targets` — scrape failures masquerade as outages.
- Re-run the alert expression with `prometheus_query kind=range start=now-1h`.

## 5–10 min: scope and suspect
- Impact in user terms (error ratio, latency percentile, affected regions / tenants).
- What changed: `deploy action=history`, `grafana_query action=annotations from=now-3h`.
- Logs around the first bad minute: see `log-analysis.md`.

## 10–15 min: decide
- If a recent change correlates: prepare the rollback (`deploy action=show plan_id=…` shows
  the prepared command) and ask the on-call human to approve `deploy action=rollback`.
- If not: escalate with the summary template from SKILL.md to the owning team; keep querying.

## Escalate immediately when
- Data loss or corruption is suspected (stop, do not attempt repairs; page the data owner).
- A security incident is suspected (preserve evidence; switch to `security-alert-triage`).
- The fix needs production writes the role policy refuses (for example `kubectl` against a
  context named prod under the devops preset): hand the prepared plan to a human operator.

## Hand-off checklist
- Ticket updated with timeline, impact, actions taken (with audit references) and open questions.
- Pages acknowledged or reassigned; silences (if a human added them) have an expiry and owner.
- Follow-ups listed: alert tuning, missing dashboards, runbook gaps, tests.
