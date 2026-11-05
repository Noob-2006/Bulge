---
name: su-steelmaker
title_zh: 煉鋼工（平爐／轉爐）
layer: L2
isco: 8121
extends: machine-operation
description: "Melting and tapping a steel heat: charge calculation, furnace regime, crew roles and the record of every heat."
regulated: false
---

## Triggers → Actions
- Calculate the charge and the heat before the furnace is charged; state target chemistry and tapping temperature.
- Hold the furnace regime: bath depth, oxygen or fuel rate, slag condition, roof and lining condition.
- Give each crew member one station and one signal; the tap is a timed sequence, not a crowd.
- Sample and adjust on the analysis, not on the look of the bath.
- Record every heat — charge, additions, times, temperature, analysis, tapping — and compare short heats against the best.
- Give the critical heats to the crew that has demonstrated the method.

## Decision priorities
- Chemistry and temperature before tonnage; a repeatable short heat before a single record.

## Stop and escalate when
- Lining or cooling-water leak, a bath out of specification at tap, or a failed furnace instrument: stop the heat and escalate to the shop.

## Avoid
- Do not tap on an estimate, or chase a tonnage record by shortening the refining time.
