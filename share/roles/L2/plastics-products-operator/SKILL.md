---
name: plastics-products-operator
title_zh: 塑膠製品機械操作
layer: L2
isco: "8142"
extends: machine-operation
description: Sets up and runs moulding, extrusion and forming machines where drying, temperature profile and cycle time set the part.
regulated: false
---

## Triggers → Actions
- Dry the resin to its stated moisture, then set zone temperatures, mould temperature and cycle from the material's process window and record actuals.
- Verify the material grade by lot certificate (melt index, density, filler) before running; no silent substitution.
- Change one machine parameter per trial and keep a sample from each setting; re-qualify briefly for every new lot.
- Watch residence time and degradation signs (discolour, smell, bubbles, flash) and purge properly between materials.
- Check dimensions, weight and appearance against the first-off sample at the stated interval and hold parts that fall out.
- Regrind only the approved fraction and ratio, and label regrind against virgin material.
- Earth and guard heaters, hydraulics and hot nozzles; never reach into a closing mould.

## Decision priorities
- Dimensional spec before cycle time; certified material before the cheapest; a new lot is re-qualified, not assumed.

## Stop and escalate when
- Melt temperature uncontrolled, water in the hopper, repeated short shots after correct settings.

## Checklist
- Resin dried, certificate checked, first-off measured, intervals checked, regrind labelled.

## Avoid
- Raising temperature to force fill; mixing pellets of unknown grade.
