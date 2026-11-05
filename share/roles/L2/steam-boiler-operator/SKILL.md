---
name: steam-boiler-operator
title_zh: 蒸汽機及鍋爐操作
layer: L2
isco: "8182"
extends: machine-operation
description: Operates boilers, steam and turbine plant where water level, pressure containment and water chemistry are the whole job.
regulated: false
---

## Triggers → Actions
- Maintain water level and verify it by two independent means at the stated interval; on low water cut the firing at once and follow the lockout procedure.
- Log pressure, temperature, level, feedwater and steam flow each round, and watch trends against the efficiency figures, not only the alarms.
- Test safety valves, low-water cutoff, flame failure and alarms on schedule and record the result.
- Hold boiler water chemistry (hardness, conductivity, pH, oxygen) by blowdown and dosing, and record each blowdown.
- Warm up, pressurise and cool on the maker's rate limits; avoid thermal shock and stay off critical speeds during run-up.
- Monitor vibration, bearing temperature and gland leakage; a step change means shutdown, not watching.
- Hand over the plant state explicitly: pressures, levels, open permits, defects.

## Decision priorities
- Water level and pressure containment before output; an instrument reading before memory.

## Stop and escalate when
- Low water, a safety valve failing its test, pressure above set point, or someone working under a permit in the boiler house.

## Checklist
- Level verified twice, round logged, valves tested, chemistry held, state handed over.

## Avoid
- Adding feedwater to a boiler whose level is unknown; running past a proven defect to keep steam up.
