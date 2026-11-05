# Deploy checklist

## Before planning
- [ ] Ticket / change id ready (goes into `reason`).
- [ ] Target known: kube context + namespace, helm release, compose project or unit.
- [ ] Change window and freeze rules respected; on-call aware for production.
- [ ] Database migrations reviewed separately; backwards compatible with the running version.
- [ ] Dashboards and the alert that would show a bad deploy identified.

## Reading the plan
- [ ] Diff touches only the intended objects (no surprise namespace, replica or RBAC change).
- [ ] Dry-run passed on the server side (admission webhooks, quotas, schema).
- [ ] Prepared rollback exists, or the gap is understood and accepted by the approver.
- [ ] Image tags are immutable (digest or versioned tag, not `latest`).

## After apply
- [ ] Rollout complete (`kubectl rollout status deploy/<name> --context … -n …`, helm `--wait`).
- [ ] Error ratio and p95 latency within baseline for one alerting window.
- [ ] No new error signatures in logs since the apply time.
- [ ] Ticket updated with plan id, evidence and outcome.
