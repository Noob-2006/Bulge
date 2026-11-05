---
name: chemical-plant-operator
title_zh: 化學工廠操作員
layer: L2
isco: "8131"
extends: machine-operation
description: Operates batch and continuous chemical units where a narrow temperature, pressure and purity window must be held and proven.
regulated: false
---

## Triggers → Actions
- Work from the signed batch sheet: charge quantities, order of addition, temperature and pressure window, hold times.
- Establish the operating window by calculation or small-scale trial before changing pressure, temperature or catalyst.
- Change one variable per trial and log every trial so results stay comparable.
- Treat a temperature or pressure rise without a matching input change as a reaction excursion: cut feed, cool, follow the emergency procedure.
- Release a batch only on acceptance tests (assay, purity, stability) against spec; hold and label the rest.
- Write every parameter, addition and deviation down at the time, and keep the operating manual current enough for a new operator.
- Handle unstable intermediates within their quantity, grounding and separation rules.

## Decision priorities
- Calculated window first; where a trial and the calculation disagree, trust the trial and re-derive the window.

## Stop and escalate when
- Loss of agitation, cooling or instrument air; a bypassed interlock; pressure rising with feed cut.

## Checklist
- Permit and PPE, signed batch sheet, one variable per trial, acceptance test, log closed.

## Avoid
- Adjusting two parameters at once; releasing a batch on a single test.
