---
upstream: "seagent/skills original to SE Agent (MIT)"
name: vuln-triage
description: "Turn scanner output into a short, ranked fix list: parse, de-duplicate, rank by exploitability, group by fix, open tickets."
version: 1.0.0
author: SE Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, secops, vulnerability, sarif, trivy, grype, nessus, osv, cve, triage]
    category: security
    related_skills: [security-alert-triage, compliance-audit]
---

# Vulnerability triage

Use this skill when someone hands you scanner results (SARIF from Semgrep / CodeQL, Trivy or
Grype JSON, Nessus `.nessus` or CSV), asks "what should we fix first", or the weekly
`vuln-triage` blueprint runs. The output is a ranked, de-duplicated list grouped by the change
that fixes it, with tickets drafted for the top groups. You never run active scanners against
hosts from this skill; the secops role allows those only for allowlisted targets, with approval.

## Tools

- `scan_report paths=[…] kev_file=… output=reports/ranked.csv` — parses every supported format,
  merges duplicates across files and scanners (a CVE reported by Trivy and the GHSA reported
  by Grype for the same package are one finding), ranks and assigns P1–P4 with the reason.
- `osv_query packages=[…] | lockfile=… | ids=[…]` — fixed versions and aliases for package
  findings, or for a lockfile nobody has scanned yet.
- `jira` / `servicenow` — remediation tickets, after the human approves the list.

## Ranking rules (what `scan_report` does, so you can explain it)

1. Known exploited first: CISA KEV list (`kev_file` or `[integrations.secops] kev_file`),
   Nessus `exploit_available`, Grype `knownExploited`. A known-exploited high or critical is P1.
2. Then likelihood of exploitation: EPSS when the scanner provides it.
3. Then impact: CVSS base score, then the scanner's severity.
4. A fix being available raises the priority slightly (it is actionable now).
Add the context the scanner cannot know before finalising: internet exposure, whether the
vulnerable code path is used, compensating controls. Say when you lower or raise a priority
and why.

## Procedure

1. **Collect.** Find the reports (CI artifacts, `reports/scans/`, attachments). Note the scan
   date and target of each; stale reports (older than the last deploy) get a warning.
2. **Parse and rank.** Run `scan_report` over all of them together so duplicates merge. Write
   the full list with `output=` (CSV for spreadsheets, JSON for automation).
3. **Check fixes.** For P1/P2 package findings without a fixed version, run `osv_query` with
   the package, version and ecosystem; record the fixed version or "no fix yet".
4. **Group by fix.** One base-image bump or one dependency upgrade often closes dozens of
   findings. Group by package (and by base image for container findings); a group inherits its
   highest priority.
5. **Draft tickets.** One ticket per group: title `[P1] Upgrade openssl to 3.0.9 in api image`,
   body with the finding ids (CVE and aliases), evidence (scanner, asset, file:line), the fix,
   the reason for the priority, and an owner hint from the asset (repository, image, host).
   Show the drafts as a list; create them only after the human approves (bulk ticket creation
   is listed under "ask first" for the secops role).
6. **Report.** Counts by priority and severity, the duplicates merged, what changed since the
   last run, and anything that needs a human decision (accept risk, false positive).

## Service levels (adjust to the organisation's policy)

| priority | meaning | typical target |
|---|---|---|
| P1 | known exploited or critical with an easy path | fix or mitigate within days |
| P2 | high and likely exploitable | within the sprint |
| P3 | medium, or high without exposure | planned work |
| P4 | low, informational | backlog / accept |

## References

- `references/vuln-triage-runbook.md` — end-to-end example (scan → dedup → rank → tickets) and
  how to wire it to CI and the weekly blueprint.
