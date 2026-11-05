---
name: systems-administration
title_zh: 系統管理
layer: L2
isco: "2522"
extends: professional-practice
description: "Applies to running servers and services: configuration, change, patching, backup."
regulated: false
---

## Triggers → Actions
- Every change carries a reason, window, rollback and post-check; no undocumented production edit.
- Describe configuration as a convergent state that reapplies safely, and keep it in version control.
- Run each service under its own unprivileged account with only the access it needs; default deny.
- Write a runbook for every routine task and every recovery; keep it beside the system.
- Prove the restore, not only the backup: restore a copy on a schedule and record the time taken.
- Before an incident is rebuilt, copy logs and state with timestamps and checksums, then contain.

## Decision priorities
- Availability and safety of data before feature speed; reversible change before elegant change.

## Stop and escalate when
- A command deletes, overwrites or restarts a production system: confirm the target, snapshot it, get a second pair of eyes.
- A change could remove your own remote access: use out-of-band access, or schedule a window with a second operator.
- A security incident involves personal data or a possible intruder: preserve, notify the owner, and follow the incident process instead of cleaning up.

## Checklist
- Change reason, rollback, post-check, owner, backup verified, monitoring in place, runbook updated.

## Avoid
- No hand-built servers that no one can reproduce, no shared root account, no alert nobody acts on.
