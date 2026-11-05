---
upstream: "ark/skills original to ark (MIT)"
name: incident-response
description: "Investigate an alert or outage: scope impact, query metrics and logs, build a timeline, find the cause, hand off or roll back."
version: 1.0.0
author: ark
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [devops, sre, incident, on-call, observability, logs, prometheus, loki]
    category: devops
    related_skills: [deploy-rollback]
---

# Incident response and on-call investigation

Use this skill when an alert fires, a user reports that something is broken or slow, or the
on-call engineer asks "what is going on with X". The goal is a short, evidence-backed answer:
what is affected, since when, the most likely cause, and the safest next step. You investigate
with read-only tools; anything that changes a system goes through the approval gates.

## When to use

- An Alertmanager / Grafana / PagerDuty alert, or a webhook that started this session.
- "Is the API down?", "why are checkouts failing?", "error rate spiked after lunch".
- A post-incident write-up that needs a timeline built from metrics, logs and deploy history.

Not for: routine capacity planning, writing new alert rules, or security incidents involving
an attacker (switch to `security-alert-triage`, and preserve evidence before changing anything).

## Tools

| Need | Tool | Notes |
|---|---|---|
| What is firing | `alertmanager_alerts` (kind=alerts, groups, silences) | oldest firing alert first: usually closest to the cause |
| Metrics | `prometheus_query` (instant, range, targets, rules) | range results come back summarised (min/max/last + sample) |
| Logs | `loki_query`, `elastic_search` | newest lines first, capped; narrow by labels before text |
| Dashboards, annotations | `grafana_query` (search, dashboard, annotations, query) | dashboard panels give you the team's own queries |
| What changed | `deploy action=history`, `grafana_query action=annotations` | correlate change times with the first bad datapoint |
| Paging and tickets | `pagerduty`, `jira`, `servicenow` | writes are audited and go through approval |

If a tool is missing, its `[integrations.<id>]` section is not configured; say which one and
continue with what you have (the shell can run `kubectl get`, `journalctl`, `curl` read-only).

## Procedure

1. **Acknowledge and scope (2 minutes).** Restate the symptom in one line. Identify the
   service, environment and the time the problem started. If paged, offer to acknowledge in
   PagerDuty (`pagerduty action=acknowledge`), but do not resolve anything yet.
2. **Confirm the signal.** Query the alert's own expression with `prometheus_query kind=range`
   over the last hour (or since one hour before the start). Check whether it is still bad,
   flapping or recovered. Check `kind=targets` for scrape failures: a missing exporter looks
   like an outage but is a monitoring problem.
3. **Measure impact.** Use the RED signals for request-driven services (rate, errors,
   duration p95/p99) and USE for resources (utilisation, saturation, errors). Express impact
   in user terms: "about 12% of checkout requests fail since 14:02 UTC".
4. **Find what changed.** List deploys (`deploy action=history`), config changes, Grafana
   annotations, scaling events and dependency incidents in the window. A change that starts
   within minutes before the first bad datapoint is the lead suspect, not proof.
5. **Read the logs around the first bad minute.** Start narrow: the service's stream selector
   plus `|= "error"` or a status filter, a 10 to 15 minute window around the start. Group
   repeated messages; quote at most three representative lines. Look for the first occurrence,
   not the loudest.
6. **Form and test one hypothesis at a time.** Each hypothesis must predict something you can
   query ("if the new release broke DB pooling, connection errors start at the deploy time and
   only on new pods"). Record what you checked and the result, including what ruled things out.
7. **Decide the next step.** Prefer the smallest reversible action: roll back the suspect
   change (see `deploy-rollback`), shift traffic, scale out, or disable a feature flag. Write
   the proposal with its evidence and the exact command or plan id. Do not execute it without
   the on-call human's approval; the deploy tool will ask anyway.
8. **Communicate.** Post the status summary (template below) to the incident ticket or the
   channel the human chooses. Update it when something material changes.
9. **Close out.** After recovery is confirmed by the same signal that alerted, resolve the
   page, keep the timeline, and list follow-ups (alert tuning, tests, runbook gaps).

## Status summary template

```
[INCIDENT] <service> <symptom> — <status: investigating | mitigating | monitoring | resolved>
Impact: <who / what / how much>, since <UTC time>
Timeline: see below (UTC, oldest first)
Likely cause: <one sentence> — confidence <low|medium|high>; evidence: <queries / log lines>
Next step: <proposed action, plan id, who approves>
Open questions: <what is still unknown>
```

## Rules

- Times in UTC, absolute, oldest first. Never write "a few minutes ago" in a timeline.
- Quote queries you ran so a human can re-run them; keep tool output summarised, not pasted.
- Do not silence alerts, delete pods, restart services or roll back on your own initiative.
  Propose; the human approves; the tools enforce it.
- Separate facts (observed) from inferences (likely) in every summary.
- If the investigation touches customer data, keep it out of tickets and chat; reference IDs.

## References

- `references/oncall-runbook.md` — first 15 minutes, escalation, hand-off checklist.
- `references/log-analysis.md` — LogQL / Lucene patterns that narrow fast.
- `references/incident-timeline.md` — building and publishing the timeline and the review.
