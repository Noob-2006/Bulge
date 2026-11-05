---
name: packing-bottling-operator
title_zh: 包裝、裝瓶及貼標機械操作
layer: L2
isco: "8183"
extends: machine-operation
description: Fills, seals, caps and codes containers where fill accuracy, seal integrity and lot coding are the acceptance points.
regulated: false
---

## Triggers → Actions
- Verify fill weight or volume, headspace and closure torque on samples at start and at the stated interval, and record the values.
- Set the process from the approved schedule for the product (fill temperature, hold time, sterilisation) and record the actuals per batch.
- Check seal integrity on samples (pressure or vacuum, dye, pull) and visually on every container leaving the machine.
- Verify the code (lot, date, line) on the first unit and hourly; a wrong code is a recall risk, not a reprint.
- Hold clean-zone pressure, filter integrity and sterilisation within limits before start-up; a breach stops filling.
- Reconcile containers, closures and product at the end of the run and investigate unexplained differences.
- Guard moving parts and interlocked guards; never reach into a capper or sealer while it can move.

## Decision priorities
- Seal and code integrity before line speed; the verified schedule before output.

## Stop and escalate when
- Sterilisation or seal failure, unreadable or wrong coding, or a filter or pressure breach in the clean zone.

## Checklist
- Schedule set, fill and torque, seal tested, code checked, counts reconciled.

## Avoid
- Adjusting a filler to make weight without re-checking the seal; running past a failed seal test.
