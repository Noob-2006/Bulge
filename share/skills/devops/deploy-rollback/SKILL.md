---
upstream: "seagent/skills original to SE Agent (MIT)"
name: deploy-rollback
description: "Deploy and roll back safely with the deploy tool: dry-run and diff first, approval to apply, prepared rollback, audit trail."
version: 1.0.0
author: SE Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [devops, deploy, rollback, kubernetes, helm, docker-compose, systemd, change-management]
    category: devops
    related_skills: [incident-response]
---

# Controlled deploys and rollbacks

Use the `deploy` tool for every change that reaches a running environment through kubectl,
helm, docker / podman compose or systemd. The tool enforces the order that makes a change
reversible: **plan (dry-run + diff + snapshot + prepared rollback) → approval → apply →
verify → rollback if needed**, and writes each step to the audit log (`deploy.plan`,
`deploy.apply`, `deploy.rollback`). Do not run `kubectl apply`, `helm upgrade` or
`docker compose up` directly through the shell for real environments; that skips the plan,
the snapshot and the prepared rollback.

## When to use

- Shipping a new release, config or manifest change to staging or production.
- Restarting or reloading a service as part of a fix.
- Rolling back during an incident (see `incident-response`).

## The flow

1. **Prepare the change in the workspace.** Manifests, values files and compose files are
   files in the repository. Note the ticket or incident id for the `reason`.
2. **Plan.**
   - kubectl: `deploy action=plan kind=kubectl manifest=k8s/ context=staging-eu namespace=shop reason=OPS-412`
   - helm: `deploy action=plan kind=helm release=checkout chart=charts/checkout values=["values/staging.yaml"] context=staging-eu namespace=shop`
   - compose: `deploy action=plan kind=compose file=deploy/compose.yml services=["api"]`
   - systemd: `deploy action=plan kind=systemd unit=nginx.service operation=reload`
   The plan runs only dry-runs and reads (`kubectl diff` and `apply --dry-run=server`,
   `helm diff` or `upgrade --dry-run=server`, `compose config`, `systemctl status`), captures
   the current state and prepares the rollback command. Kubernetes and helm plans need an
   explicit `context`: the ambient current-context is never used.
3. **Review the plan with the human.** Show the diff summary, the target, the apply command,
   the prepared rollback and anything the rollback cannot undo (new objects, first installs,
   database migrations). If the dry-run failed, fix the inputs and plan again.
4. **Apply.** `deploy action=apply plan_id=<id>`. The approval gate asks the human (tier 2;
   destructive shapes are tier 3). The tool refuses a plan that failed, expired (default 60
   minutes), was already applied, or whose files changed after the dry-run.
5. **Verify.** Check the service's own signals for at least one alerting window: error rate
   and latency with `prometheus_query`, new errors with `loki_query`, rollout state with
   `kubectl rollout status` (read-only). Compare with the baseline before the change.
6. **Roll back when verification fails.** `deploy action=rollback plan_id=<id>` runs the
   prepared rollback (re-apply the captured objects, `helm rollback <rev>`, compose with the
   previous image ids pinned, or the inverse systemd operation). It also goes through approval.
7. **Record.** Comment on the ticket with the plan id, what changed, verification evidence and
   the outcome. `deploy action=history` lists recent plans with their status.

## What a rollback cannot undo

- Objects the change created (kubectl): delete them deliberately, it is a tier-3 action.
- Database migrations and other stateful steps: they need their own down-migration plan.
- First helm installs: the undo is `helm uninstall`, which asks the owner.
- Restarts: there is no previous state; roll back whatever made the restart necessary.

## Guard rails you will meet

- The devops role preset refuses production writes by command pattern (for example a kubectl
  context or namespace containing `prod`); hand the prepared plan to a human operator.
- `[integrations.deploy] allow_contexts` limits the clusters this agent may target.
- Unattended runs (cron, webhooks) cannot apply: tier-2 calls are queued for the owner.

## References

- `references/deploy-checklist.md` — pre-flight and verification checklist.
- `references/rollback-runbook.md` — deciding to roll back, per-tool rollback details.
