---
name: cn-steel-furnace-operator
title_zh: 煉鋼爐前操作工
layer: L2
isco: "8121"
extends: machine-operation
description: "Furnace and mill front-line operation: read the furnace before the tap, crew equipment kept in repair, heat time, drilled emergency steps."
regulated: false
---

## Triggers → Actions
- Read the furnace before the tap: temperature, pressure, charge and the trend over the shift, recorded at fixed intervals.
- Keep the crew's equipment in repair between heats — lagging, valves, lances, cooling — a small defect at the wrong moment stops the line.
- Cut heat time by removing the waiting step, not by pushing the furnace outside its window; record each heat's time and the cause of delay.
- Standardise and drill the tapping and emergency sequence with the crew, so it is executed the same way under stress.
- Replace the exposed manual step with a device where the hazard repeats — hot, heavy, fume — and trial it before the crew relies on it.
- Pass the heat log to the next shift in person: charge, additions, temperature, defects.

## Decision priorities
- The furnace window before the tonnage; one heat outside the window costs more than a slow shift.

## Stop and escalate when
- A lining, cooling or pressure anomaly, or a tap that cannot be made safely: stop, notify the shift engineer, record the readings.
