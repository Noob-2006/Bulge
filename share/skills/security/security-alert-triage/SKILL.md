---
upstream: "ark/skills original to ark (MIT)"
name: security-alert-triage
description: "Triage SIEM and AppSec alerts (Wazuh, Elastic Security, Splunk, Semgrep): group, enrich, decide true or false positive, escalate."
version: 1.0.0
author: ark
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, secops, siem, soc, wazuh, elastic, splunk, semgrep, alert-triage]
    category: security
    related_skills: [vuln-triage, incident-response]
---

# Security alert triage

Use this skill to work through a queue of security alerts: the SOC morning queue, a burst
after a rule change, or a single alert someone forwards. The output is a decision per alert
group (benign, false positive, needs investigation, incident) with the evidence for it, and
escalations that a human acts on. This is analysis: do not block accounts, isolate hosts or
change firewall rules yourself.

## Tools

- `siem_alerts` — open alerts from every configured source (Wazuh indexer, Elastic Security,
  Splunk notables or a read-only SPL search, Semgrep findings), normalised to time, severity,
  rule, asset; identical rule × asset alerts are merged with a count. `source`, `since`,
  `query`, `min_severity`, `min_level` narrow it.
- `elastic_search`, `loki_query` — the raw events around an alert (authentication logs,
  process events, web logs).
- `prometheus_query` — traffic or resource anomalies that corroborate (egress spikes, CPU).
- `osv_query`, `scan_report` — when an alert points at a vulnerable component.
- `jira` / `servicenow` / `pagerduty` — escalation, after the human agrees.

## Procedure

1. **Pull and group.** `siem_alerts since=now-24h min_severity=medium`. Work on groups (same
   rule, same asset), most severe first. Note counts: a rule firing 400 times on one host is
   one problem.
2. **Classify each group** with the questions below; write the answer and the evidence:
   - Is the asset real and in scope? (decommissioned hosts, test labs)
   - Is the behaviour expected? (scheduled job, admin activity with a change ticket, scanner)
   - Is there corroboration? (successful login after failures, new process after download,
     outbound traffic to a rare destination)
   - What is the blast radius if true? (privileged account, production data, internet-facing)
3. **Enrich true or unclear cases** with raw events in a narrow window around the first alert:
   who, from where, what ran, what changed. Map to MITRE ATT&CK techniques when the rule does.
4. **Decide.**
   - False positive / benign: document why and propose a tuning change for the rule owner.
   - Needs investigation: list the next queries and who owns the asset.
   - Incident: escalate now (`pagerduty action=trigger severity=critical` or the SOC process)
     with the evidence summary; recommend containment steps for the human to take.
5. **Preserve evidence.** Before anyone changes an affected host, record alert ids, raw event
   references and timestamps in the ticket. Do not copy secrets or personal data into tickets.
6. **Report.** Counts per decision, top noisy rules (tuning candidates), escalations made.

## Severity mapping used by `siem_alerts`

| source | critical | high | medium | low |
|---|---|---|---|---|
| Wazuh rule level | 13–15 | 10–12 | 7–9 | 4–6 |
| Elastic `kibana.alert.severity` | critical | high | medium | low |
| Splunk ES urgency | critical | high | medium | low |
| Semgrep severity | — | high | medium | low |

## References

- `references/siem-triage-runbook.md` — source setup (read-only accounts), queries per
  source, escalation template.
