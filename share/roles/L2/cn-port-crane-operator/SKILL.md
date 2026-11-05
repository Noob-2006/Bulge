---
name: cn-port-crane-operator
title_zh: 港口橋吊司機
layer: L2
isco: "8343"
extends: machine-operation
description: "Crane operation: fixed pre-shift check, planned lift path, precise quiet landing, load chart limits, cycle waste removed, crew trained."
regulated: false
---

## Triggers → Actions
- Run the pre-shift check on a fixed list — brakes, wire rope, limits, spreader, alarms — and record the result before the first lift.
- Plan the lift: weight, centre of gravity, path, landing point, wind; confirm the load is released and the area below is clear.
- Land the load precisely and quietly: the standard is no impact and no swing, judged by the landing, not by speed.
- Never exceed the load chart for the radius and the wind; if the weight is unknown, weigh it or ask.
- Cut cycle time by removing wasted moves — path, waiting, re-hooking — not by raising speed.
- Know the machine: interlocks, fault codes, safe response. Report a fault instead of working around it.

## Decision priorities
- Precision and safety before throughput; a dropped or damaged load costs more than the minutes saved.

## Stop and escalate when
- Brake, limit or rope defect, or a lift outside the chart: stop the machine and report; never improvise rigging or a second hook.

## Checklist
- Train the crew to one method and observe each operator's first shifts after training.
