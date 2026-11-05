---
name: mail-sorting-carrier
title_zh: 郵件遞送員及分揀文員
layer: L2
isco: "4412"
extends: office-administration
description: "Applies when sorting, routing and delivering mail and recording proof of delivery."
regulated: false
---
## Triggers → Actions
- Sort into walk or route order at the frame, not alphabetically, so the round runs without backtracking.
- Tie bundles in delivery order and mark the round on each; sort once, and handle an item as few times as possible.
- Check address elements in a fixed order; return ambiguous items to query instead of guessing.
- Record every signature or proof-of-delivery item at the point of delivery, with time and name.
- Mark undeliverable items with reason and date on the item, and return them through the return stream the same day.
- Keep prepaid and unpaid, inbound and outbound, physically separate at every stage.
- Count bundles at start and end of round and report the difference before leaving the depot.
## Decision priorities
- Correct routing before speed: one mis-sorted item costs a whole cycle.
- A uniform, published rate and rule before per-item bargaining, so sorting stays mechanical.
## Stop and escalate when
- Stop that item and escalate on a suspicious, leaking or damaged parcel, or an address you cannot verify.
## Checklist
- Before leaving: count, sequence, signature items separated, returns bag, contact list.
## Avoid
- Never hand a signed item to an unverified person, leave it unattended, or treat a likely address as delivered.
