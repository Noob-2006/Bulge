# Runbook: scan → de-duplicate → rank → tickets

## Inputs
- Container: `trivy image --format json -o trivy.json <image>` and/or
  `grype <image> -o json > grype.json` (run by CI, not by the agent).
- Code: `semgrep ci --sarif --output semgrep.sarif`, CodeQL SARIF.
- Hosts: Nessus export (`.nessus` or CSV) from the scanning team.
- Optional KEV list: CISA `known_exploited_vulnerabilities.json`, mirrored internally;
  set `[integrations.secops] kev_file = "/srv/feeds/kev.json"`.

## Run
```
scan_report paths=["reports/scans/trivy.json","reports/scans/grype.json","reports/scans/semgrep.sarif","reports/scans/q3.nessus"]
            kev_file="feeds/kev.json" min_severity="medium" output="reports/ranked-2026-11-05.csv"
```
Read `by_priority`, `duplicates_merged`, and the `top` list. Each item carries `why`
("known exploited, severity high, EPSS 42%, CVSS 8.1, fix available").

## Enrich
```
osv_query packages=[{"name":"openssl","version":"3.0.1","ecosystem":"Debian:12"}]
osv_query lockfile="package-lock.json"
```
OSV calls send package names and versions to the OSV endpoint (`[integrations.osv] url` can
point at an internal mirror). The first call may ask for approval; add the host to
`[gate] egress_allow` to make it a recorded, unprompted read.

## Tickets
- Jira: `jira action=create project=SEC issuetype=Bug summary="[P1] Upgrade openssl to 3.0.9 (api image)" labels=["vuln","P1"] description=…`
- ServiceNow: `servicenow action=create table=problem fields={"short_description": …, "urgency": "1"}`
- Every create is in the audit log (`ticket.create`) with the summary and the resulting key.

## Weekly automation
`seagent` blueprint `vuln-triage` (catalog) runs this procedure on a schedule and delivers the
ranked list and drafted tickets for approval. It never creates tickets on its own.

## False positives and accepted risk
Record the decision in the ticket (who, why, until when). Do not delete findings from the
reports; the next run would bring them back without the context.
