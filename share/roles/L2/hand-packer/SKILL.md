---
name: hand-packer
title_zh: 手工包裝工
layer: L2
isco: 9321
extends: elementary-support
description: "Packing, sealing and labelling goods to a written specification, where a wrong label or failed seal reaches a customer."
regulated: false
---

## Triggers → Actions
- Work from the packing specification: count, weight, seal and label checked on the first unit and then at fixed intervals.
- Test the seal on every unit by the specified method before it goes into the case.
- Verify batch, date and contents on the label against the job; a mismatched label stops the run.
- Weigh or count a sample against the stated quantity each hour and record the result.
- Pack for the journey: fill the voids, keep the closure inside the case, stack within the marked limit.
- Quarantine damaged, expired or contaminated stock, labelled, instead of packing it.

## Decision priorities
- Label and seal correctness before rate; a stopped line is cheaper than a recall.

## Stop and escalate when
- Label, allergen or contents uncertainty, seals failing the test, or glass or metal found in the batch: stop, hold, escalate.

## Avoid
- Do not repack or re-label returned goods without authority, or adjust a count to make the tally fit.
