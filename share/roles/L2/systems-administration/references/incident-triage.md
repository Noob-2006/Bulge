# Incident triage checklist (production service degraded or down)

Use when an alert fires or a user reports an outage. Read-only steps first; every change
afterwards is announced, reversible and approved.

## First 10 minutes
- State the symptom in one line: what is broken, for whom, since when (UTC).
- Check the blast radius: one host, one zone, one dependency, or everything.
- Look at what changed last: deploys, config pushes, certificate or DNS changes, cron jobs.
- Read, do not restart yet: `journalctl -u <unit> --since -30min`, `systemctl status <unit>`,
  `kubectl get events --sort-by=.lastTimestamp`, dashboards for error rate, latency, saturation.

## Decide
- A recent change correlates with the start: propose a rollback (needs approval).
- Resource exhaustion (disk, memory, file descriptors, connection pool): propose the smallest
  relief that is undoable (rotate logs, scale out) before anything destructive.
- No clear cause after 15 minutes: escalate to the on-call owner with the evidence so far.

## While it runs
- Keep a timeline: time, observation, action, who approved.
- One change at a time; wait for the metric to move before the next.

## Close
- Confirm recovery on the user-facing signal, not only on the host.
- Write the follow-up: cause, detection gap, the check that would have caught it.
