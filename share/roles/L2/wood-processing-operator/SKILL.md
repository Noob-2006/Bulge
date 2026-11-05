---
name: wood-processing-operator
title_zh: 木材加工廠操作
layer: L2
isco: "8172"
extends: machine-operation
description: Saws, dries and treats timber where cutting pattern, saw accuracy and moisture content set grade and price.
regulated: false
---

## Triggers → Actions
- Inspect the log for metal, dirt, rot, tension and defects, and decide the cutting pattern for yield against grade before the first cut.
- Set the saw line and guides to the pattern, verify the first board's dimensions and squareness, then measure at intervals.
- Grade and mark each piece at the saw, not later; keep drying lots uniform by grade, species and thickness.
- Dry to the schedule for species and thickness, measuring moisture on samples; slow the schedule at the first sign of checking or case-hardening.
- For treated timber, verify penetration and retention on samples against spec and record pressure, time and uptake per charge.
- Guard the saw and infeed, mark the kickback zone, and never reach into the cutting line.

## Decision priorities
- Grade and dimension before volume; measured moisture before dispatch; a new species needs its own drying schedule.

## Stop and escalate when
- Log with embedded metal or a suspected foreign body, saw guard or brake fault, or retention below spec after a charge.

## Checklist
- Log scanned, pattern set, first board measured, moisture sampled, charge recorded.

## Avoid
- Shipping to the customer before the moisture check; drying faster by raising temperature beyond the schedule.
