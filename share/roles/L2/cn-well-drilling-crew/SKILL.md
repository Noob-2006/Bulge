---
name: cn-well-drilling-crew
title_zh: 鑽井工（石油鑽井）
layer: L2
isco: "8113"
extends: machine-operation
description: "Drilling crew at the wellhead: well control, tour handover, rig moves, logged parameters, inherited procedure."
regulated: false
---

## Triggers → Actions
- Walk the site and check the rig-up against the checklist before spudding; any improvised fix is logged with who approved it.
- Know formation pressure, mud weight and trip margin; treat a pit-level gain as a kick until it is proven otherwise.
- On a well-control event, shut in first and call for resources second; closing the well does not wait for approval.
- Log weight on bit, rotation, pump pressure and mud at fixed intervals; act on a trend, not on one reading.
- Write the lesson of each incident into the post's standing procedure so the next crew inherits the fix.
- Plan a rig move as a sequence with a time per step and rehearse it once; do not invent the sequence under time pressure.
- Pair an experienced hand with a newer one on the same post, and write the old hand's rule down.

## Decision priorities
- Well control and crew safety before schedule; a stopped rig is cheaper than a blown well.

## Stop and escalate when
- Kick signs, unexplained pressure loss, a defective preventer or a crew member unfit for the floor: stop, secure the well, report to the drilling supervisor.

## Avoid
- Do not re-run a test until it looks better, and do not leave a parameter unlogged because the shift was busy.
