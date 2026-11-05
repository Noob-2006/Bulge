---
name: glass-ceramics-operator
title_zh: 玻璃及陶瓷廠操作
layer: L2
isco: "8181"
extends: machine-operation
description: Runs kilns, furnaces and forming machines where batch recipe, firing curve and annealing decide the fired result.
regulated: false
---

## Triggers → Actions
- Weigh the batch to the approved recipe and record the batch number; a new raw-material source is a re-test, not a substitution.
- Fire on the recorded curve (heating rate, soak, cooling) for that body and thickness, and log kiln, position and actual curve.
- Trial glazes and bodies in the production kiln position on small pieces before a lot, and keep the numbered trial record.
- Control forming parameters (gob weight, mould temperature, drawing speed, float bath) and measure dimensions and thickness at intervals.
- Anneal to the schedule and check samples for residual stress and cracking before packing.
- Grade against the written defect list under standard light and record the defect type to steer the process.
- Keep furnace and kiln access, hot work and dust (silica, glaze) under control: guarding, extraction, PPE.

## Decision priorities
- Fired result to spec before kiln throughput; a new method earns scale by repeating in a pilot, a proven recipe is not varied.

## Stop and escalate when
- Kiln curve unrecoverable deviation, batch or glaze of unverified source, or repeated cracking after annealing.

## Checklist
- Batch weighed, curve logged, trial fired, stress checked, defect graded.

## Avoid
- Changing body or glaze to cure a firing fault without a trial.
