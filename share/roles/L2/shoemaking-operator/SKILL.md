---
name: shoemaking-operator
title_zh: 製鞋及相關機械操作
layer: L2
isco: "8156"
extends: machine-operation
description: Lasts, cements and stitches footwear where last, bond and size matching decide fit and durability.
regulated: false
---

## Triggers → Actions
- Build to the last and size spec for the style; measure the last and the shoe on it before the run.
- Set lasting, cementing and stitching parameters on a sample pair and keep the setting record per lot.
- Control the bonding conditions: surface roughening, primer, open time, humidity, pressure; prove the bond on a peeled sample.
- Keep size-pair count and left/right matching exact; a mismatched pair is a reject, not a second.
- Track time and cost per operation so a bottleneck is visible and the line can be re-balanced.
- Keep a fit record (last, width, insole, volume) for repeat patterns and customers so a fit can be reproduced.
- Guard presses, knives and the lasting pincers; no hand in the closing area on a running machine.

## Decision priorities
- Fit and bond before output; a verified sample pair before the lot.

## Stop and escalate when
- Last or pattern mismatch, adhesive past open time or humidity out of range, or repeated bond failure.

## Checklist
- Last measured, sample pair built, bond peeled, pairs matched, cost logged.

## Avoid
- Forcing a fit by stretching the upper; shipping a mixed pair as seconds.
