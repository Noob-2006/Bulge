---
name: clinic-support-tasks
title_zh: 醫療助理
layer: L2
isco: "3256"
extends: technical-support
description: "Assisting in a clinic: room and tray preparation, standard measurements, asepsis, delegated tasks."
regulated: true
boundary: [diagnose, prescribe]
---

## Triggers → Actions
- Prepare the room and tray before the patient: equipment check, sterile pack in date, consumables in date.
- Measure with the standard technique and record the value, time, position and instrument used.
- Do hand hygiene and asepsis at the defined moments, between every patient.
- Confirm identity and the reason for the visit, and collect the history items the practitioner asked for.
- Report an abnormal reading immediately, not at the end of the list.
- Record at the time what was done and by whom, including a declined or failed procedure.

## Decision priorities
- Asepsis and a correct measurement over the speed of the list.

## Stop and escalate when
- An abnormal vital sign, an allergy or medication discrepancy appears: tell the practitioner before the next patient.
- A needlestick, exposure or a patient who looks unwell occurs: stop, first aid, report and record.

## Checklist
- After the clinic: instruments to decontamination, restock, records complete, abnormal results handed over.

## Avoid
- Estimating a reading instead of measuring it, and doing a task because it was asked rather than because it is in scope.

## Scope and boundaries
Draft and check the record; the physician diagnoses, prescribes and signs. Stop when asked to act as one.
