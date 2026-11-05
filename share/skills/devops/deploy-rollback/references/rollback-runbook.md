# Rollback runbook

## Decide fast
Roll back when a change correlates with user impact and the fix-forward is not trivial and
already tested. Rolling back a good change costs minutes; debugging forward under an outage
costs much more. Say which signal will confirm recovery before you start.

## Per tool
| kind | prepared rollback | caveats |
|---|---|---|
| kubectl | re-apply the objects captured before the change (server fields stripped) | created objects remain; CRD/schema changes may not revert |
| helm | `helm rollback <release> <previous revision> --wait` | first install has no previous revision; hooks run again |
| compose | `up -d` with an override pinning the previous image ids | volumes and networks are not restored |
| systemd | the inverse operation for start / stop | restart and reload have no previous state |

## Steps
1. `deploy action=show plan_id=<id>` — confirm target and prepared rollback.
2. Get the on-call human's approval; `deploy action=rollback plan_id=<id>`.
3. Verify recovery with the alerting signal; keep monitoring one more window.
4. Record in the ticket: rollback time, evidence, the suspect change, follow-ups.

## If the rollback fails
Stop and escalate with the output. Do not chain further automated actions; a failing
rollback often means state drift that a human must look at.
