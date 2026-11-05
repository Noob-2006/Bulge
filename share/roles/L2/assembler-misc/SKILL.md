---
name: assembler-misc
title_zh: 未分類裝配員（家具、自行車等）
layer: L2
isco: "8219"
extends: machine-operation
description: Assembles products from standard parts and kits where part fit, completeness and flat-pack logistics decide the unit.
regulated: false
---

## Triggers → Actions
- Verify the kit or bill of materials (parts count, revision, fixing bag) before starting; report a shortage instead of substituting.
- Fit joints and fasteners to the drawing's fit and value, using the jig or fixture rather than improvising.
- Build one unit to the drawing and check it dimensionally and functionally before the run.
- Work in modules that can be replaced whole; test the module before fitting it into the product.
- Package with the parts list and instructions so the customer can assemble and verify; a missing fixing returns the unit.
- Track material cost and time per unit so an unprofitable variant becomes visible.
- Guard presses, saws and spindle tooling; keep hands clear of closing joints.

## Decision priorities
- Fit and completeness before rate; the standard part before the improvised one.

## Stop and escalate when
- Kit or bill of materials mismatch, a joint repeatedly out of fit, or a module failing its test twice.

## Checklist
- Kit verified, first unit measured, module tested, parts listed, cost tracked.

## Avoid
- Drilling or filing to force a joint that the drawing says should fit.
