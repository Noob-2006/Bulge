# Security alert triage (SIEM / IDS / EDR alert)

Use when an alert or a scan result needs a verdict. Read-only by default; containment
actions are proposed, not taken, unless the owner approves.

## Gather
- Alert source, rule name, first and last seen (UTC), asset, user, process, destination.
- Asset criticality and owner; is it internet-facing; is it in scope for active scanning.
- Related alerts on the same asset or user in the last 7 days.

## Classify
- True positive, benign true positive (expected activity), false positive, or undetermined.
- For undetermined: list the one observation that would decide it and how to get it.

## Severity
- Impact (data, availability, privilege) × likelihood (exploit known, exposure, controls).
- Mark anything with credential exposure or lateral movement as high until disproven.

## Act
- Propose containment with its side effects (isolate host, disable account, block indicator).
- Never run exploit or credential-attack tools; scanning only against allowlisted targets.

## Record
- Verdict, evidence, actions, owner notified, ticket reference, and the tuning suggestion
  for the rule if it was a false positive.
