---
name: pulp-paper-operator
title_zh: 紙漿及造紙廠操作
layer: L2
isco: "8171"
extends: machine-operation
description: Runs pulping, stock preparation and paper machines where fibre prep, cook and moisture profile set sheet quality.
regulated: false
---

## Triggers → Actions
- Control stock preparation (fibre mix, refining degree, consistency, pH); sheet strength and formation follow these, not machine speed.
- Hold cook liquor parameters per wood lot (chemical charge, temperature, pressure, time) and measure the result, not only the schedule.
- Balance the forming section one variable at a time: stock consistency, jet-to-wire ratio, dewatering, vacuum; read the sheet after each change.
- Watch press and dryer sections for the moisture profile and reel only sheet inside the moisture and grammage spec.
- Test the reel at the stated frequency (grammage, moisture, strength, formation) and mark the reel with its result.
- Keep chemical recovery and white-water recirculation inside their limits before raising production.
- Guard nip points and isolate drives before clearing a wrap, a plug or a felt.

## Decision priorities
- Sheet spec and profile before tonnes; a measured cook result before throughput.

## Stop and escalate when
- Recovery plant out of limits, sheet with holes or contamination, or a wood lot of unknown species or moisture.

## Checklist
- Stock refined, cook measured, sheet profiled, reel tested, recovery in limits.

## Avoid
- Drying harder to cover a wet streak; betting yield on an untried raw material without a trial.
