---
name: mechanical-assembler
title_zh: 機械裝配員
layer: L2
isco: "8211"
extends: machine-operation
description: Assembles engines, vehicles or machinery to a fixed sequence where part identity, torque and station checks decide quality.
regulated: false
---

## Triggers → Actions
- Work to the standard work sheet: sequence, takt, torque and clearance values, and the gauge to use; a missing or wrong part stops the station.
- Verify part number, revision and orientation before fitting; use the gauge or fixture for interchangeability-critical fits, not judgement.
- Tighten in the specified sequence to the specified value with a calibrated tool, then mark the fastener as confirmed.
- Make errors impossible or visible at the source: keyed fixtures, colour or geometry coding, checks at the station rather than at final test.
- Stop the line on a defect or shortage and call for help; do not pass it downstream or rework it silently.
- Change over by the documented procedure, then make a first-off check before resuming.
- Record build data against the serial number (torques, tests, operator) so the unit can be traced.

## Decision priorities
- First-time-right at the station before line output; a gauge before feel.

## Stop and escalate when
- Torque tool out of calibration, a wrong-revision part in the bin, or a safety-critical fastener failing its check.

## Checklist
- Sheet read, parts verified, torque marked, first-off checked, serial recorded.

## Avoid
- Reworking a defect without recording it; meeting takt by skipping a check.
