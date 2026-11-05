# SIEM triage runbook

## Source setup (read-only accounts)
```toml
[integrations.wazuh]            # the Wazuh indexer (OpenSearch), not the manager API
url = "https://wazuh-indexer.internal:9200"
user = "seagent-ro"                 # role with read on wazuh-alerts-*
password = "{{secret:WAZUH_RO_PASSWORD}}"
min_level = 7

[integrations.elastic]          # shared with elastic_search
url = "https://es.internal:9200"
token = "{{secret:ES_API_KEY}}"
auth = "header"
header = "Authorization"        # value "ApiKey <base64>" stored in the vault
siem_index = ".alerts-security.alerts-default"

[integrations.splunk]           # management port, a role without delete / outputlookup
url = "https://splunk.internal:8089"
token = "{{secret:SPLUNK_TOKEN}}"
search = "search index=notable"

[integrations.semgrep]
token = "{{secret:SEMGREP_APP_TOKEN}}"
deployment = "acme"
```
Splunk searches that write or execute (`| delete`, `| outputlookup`, `| collect`,
`| sendemail`, `| script`, `| map`, `| rest`, …) are refused by the tool.

## Useful narrowing
- Wazuh brute force: `siem_alerts source=wazuh query="rule.groups:authentication_failed" since=now-6h`
- Elastic by host: `siem_alerts source=elastic query="host.name:web-1"`
- Splunk ES: `siem_alerts source=splunk query="index=notable urgency=critical"`
- Raw events: `elastic_search index="logs-*" query="user.name:alice AND event.outcome:success" since=now-2h`

## Escalation template
```
[SECURITY] <rule / technique> on <asset> — <decision: investigate | incident>
First seen: <UTC>   Count: <n>   Sources: <wazuh, elastic…>
Evidence: <alert ids, 2-3 key events>
Assessment: <what likely happened, confidence>
Recommended containment (for a human to execute): <steps>
Data handling: <personal data involved? notification duties?>
```
For organisations under 資通安全管理法, an incident decision starts the notification clock
(see compliance-audit references); note the time the incident was confirmed.
