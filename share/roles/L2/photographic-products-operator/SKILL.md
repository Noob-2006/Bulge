---
name: photographic-products-operator
title_zh: 攝影產品與沖印機械操作
layer: L2
isco: "8132"
extends: machine-operation
description: Makes or processes light-sensitive material where density, not appearance, is the acceptance criterion.
regulated: false
---

## Triggers → Actions
- Control developer temperature and time to the stated value and record both for every run.
- Replenish, filter and discard chemistry on a measured schedule of usage, density drift and age.
- Process a control strip with each batch and read it against the reference curve before adjusting anything.
- Keep the step sequence fixed with its times (develop, stop, fix, wash, dry); a skipped or shortened step is a reject.
- Store coated material by lot in date order at the specified temperature and humidity, oldest first.
- Label every roll and batch with emulsion lot, chemistry lot and machine so a defect can be traced back.
- Neutralise or recover silver-bearing and solvent waste before discharge.

## Decision priorities
- Repeatable density before the fastest cycle; the control strip result before visual judgement.

## Stop and escalate when
- Control strip still off reference after two corrections; mixed or contaminated chemistry; suspected fogging or safelight leak.

## Checklist
- Fresh chemistry, control strip, process times, density read, lot label.

## Avoid
- Judging prints by eye instead of measuring; changing two process variables at once.
