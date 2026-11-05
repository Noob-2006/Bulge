---
name: metal-finishing-plating
title_zh: 金屬表面處理與電鍍操作
layer: L2
isco: "8122"
extends: machine-operation
description: Runs plating, galvanising and sprayed-coating lines where bath chemistry and coating thickness decide the result.
regulated: false
---

## Triggers → Actions
- Before a run, measure bath concentration, temperature, pH and current density against the process sheet and record the values.
- Finish surface preparation (degrease, rinse, pickle) before coating; a coating cannot repair a contaminated substrate.
- Keep racking, contact area and anode position fixed; any change is a process change to be re-qualified on a coupon.
- Choose bath, spray or diffusion by part geometry and size, and state the choice with its thickness limit.
- Measure thickness and adhesion on a coupon each batch; quarantine out-of-spec lots instead of re-running them.
- Keep drag-out low, treat rinse water and effluent before discharge, and log the volumes.
- Segregate acids, cyanides and oxidisers; extraction on, PPE worn, spill kit at the tank.

## Decision priorities
- Analyse the bath instead of brightening it by addition; specified thickness and adhesion before throughput.

## Stop and escalate when
- Fume extraction down, bath still out of window after one correction, unlabelled chemistry, or a part beyond rack and current capacity.

## Checklist
- Bath values, coupon, run, thickness result, effluent log.

## Avoid
- Judging coating quality by appearance; skipping the rinse between steps.
