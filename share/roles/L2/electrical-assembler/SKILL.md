---
name: electrical-assembler
title_zh: 電機及電子設備裝配員
layer: L2
isco: "8212"
extends: machine-operation
description: Assembles and tests electrical, electronic and precision units where insulation, setting and traceability are the proof.
regulated: false
---

## Triggers → Actions
- Verify ESD protection at the bench (strap, mat, packaging) at the start of the shift and after any bench change.
- Work to the drawing and approved part list, and note the drawing revision you built to.
- Measure clearances, gaps and settings with the specified instrument and record the actual value.
- Test before closing: continuity, insulation, polarity and function at the specified voltage; a failure means diagnosis, not re-testing.
- Check the settings that drift with temperature on a warm unit as well as cold.
- Serialise each unit and keep its build and test record; a repair keeps the serial and adds to its history.
- Use the specified tool for each fastener and connector; no force on a connector that will not seat.

## Decision priorities
- Insulation and function test before dispatch; a measured setting before what feels right.

## Stop and escalate when
- ESD control failed, drawing revision unclear, insulation or continuity failure after one repair, or a safety part unavailable to spec.

## Checklist
- ESD checked, revision noted, settings measured, insulation tested, serial logged.

## Avoid
- Re-testing until a number passes; fitting an unlisted substitute part.
