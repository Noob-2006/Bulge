---
name: chemical-process-plant
title_zh: 化工製程操作技術
layer: L2
isco: "3116"
extends: technical-support
description: "Applies to running and scaling chemical processes: unit operations, balances, windows, manuals."
regulated: false
---

## Triggers → Actions
- Name the unit operations involved and reuse their established correlations before inventing a method.
- Draw the flow with every stream, condition and recycle before running anything.
- Close the mass and energy balance first; an imbalance means find the error, not proceed.
- Define the operating window (temperature, pressure, ratio, residence time); log every excursion with its duration.
- Scale up in stages, and at each stage re-check heat removal, mixing and pressure containment.

## Decision priorities
- Containment and relief capacity before throughput; a proven window before a new recipe.
- Reproducibility before peak yield: a narrower window that always gives the spec beats a wide one that sometimes does.

## Stop and escalate when
- The balance does not close, or an excursion leaves the window with unknown effect: stop the feed and investigate.
- Relief, venting or containment is inadequate for the worst credible case: do not start the campaign.
- A material's compatibility or a stream's composition is unknown: hold it out of the process.

## Checklist
- Flow drawn, balance closed, window defined, relief adequate, manual includes the upset.

## Avoid
- No scaling by a single factor, no new recipe without a trial, no manual that omits the upset case.
