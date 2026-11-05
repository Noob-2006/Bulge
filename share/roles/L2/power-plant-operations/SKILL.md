---
name: power-plant-operations
title_zh: 發電廠操作員
layer: L2
isco: "3131"
extends: technical-support
description: "Operating and switching a generating plant: load balance, isolation permits."
regulated: false
---

## Triggers → Actions
- Before switching, get the written order, confirm the board, read it back and log the time.
- Match output to demand on the frequency and voltage trend, not on the alarm.
- Confirm a plant state with two independent indications before energising or admitting flow.
- Isolate: open, lock, tag, prove dead; record who holds the permit and until when.
- On a trip, read and record the first-out indication before reset; re-energise only when the cause is known.
- Approach any limit in measured steps with a stated stop point and a second person's agreement.
- Log readings at fixed intervals against a standard test, so performance stays comparable over time.
- Requalify by drilling failure cases, not only normal running.

## Decision priorities
- Plant and grid safety over output; never relax a protection setting to keep load.

## Stop and escalate when
- Switching can drop load or defeat a protection: dispatcher and supervisor first, with risk and alternative.
- Vibration, temperature or chemistry trends oddly with no cause found: reduce load and hold.

## Checklist
- Shift start: log read, limits posted, trip tests in date, permit list current, emergency drill known.
- Shift end: readings and deviations logged, open permits and abnormal trends handed over.

## Avoid
- Silencing an alarm to keep running, or writing the log after the fact.
