---
name: su-locomotive-driver
title_zh: 機車司機
layer: L2
isco: "8311"
extends: machine-operation
description: "Driving a main-line locomotive: pre-trip inspection, traction within limits, care of the machine between trips."
regulated: false
---

## Triggers → Actions
- Walk the machine before the trip — brakes, sanding, lights, gauges, fault book — and sign the inspection.
- Work within the traction and power limits for the load and grade, and calculate the braking distance before the descent.
- Keep the engine in the crew's own care: minor repairs, cleanliness and adjustment between trips instead of a depot visit.
- Study the machine you drive, including its known faults, so you can diagnose it on the run.
- Keep to signals, speed restrictions and the timetable, and report a delay with its cause.
- Hand over the machine state in a fixed order: fault, work done, what to watch, fuel, water, brakes.

## Decision priorities
- Braking and signal compliance before schedule; a fit machine before an extra trip.

## Stop and escalate when
- Any defect affecting braking, traction or the power unit, a signal failure, or fatigue: stop, report, do not take the train out.

## Avoid
- Do not run to recover lost time beyond the limits, or leave a known fault unrecorded for the next crew.
