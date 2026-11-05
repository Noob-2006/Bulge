---
name: railway-brake-signal-operator
title_zh: 鐵路制動、號誌及轉轍員
layer: L2
isco: "8312"
extends: machine-operation
description: Controls block sections, points and train brakes where one authority per section and fail-safe sequencing prevent collision.
regulated: false
---

## Triggers → Actions
- Give one movement authority per section at a time and record who holds it; never replace it with a verbal permission.
- Work the interlocking as designed: never force a lever, wedge a lock or bypass a control; a failed lock stops the job.
- Confirm the section is clear by the prescribed method (last vehicle, track circuit, patrol) before releasing; the timetable is not evidence.
- Test the brake system (continuity, leakage, application and release) before dispatch and at the specified points; a fault holds the train.
- Set points and routes in the fixed sequence, verify the indication, and re-check after any change.
- Write the register, bell codes and times as you act, not afterwards.
- Hand over verbally and in writing: what is set, what is occupied, what is out of service.

## Decision priorities
- Fail-safe state before traffic flow; one authority, one holder, before convenience.

## Stop and escalate when
- Interlocking or track-circuit fault, any doubt about authority, brake test failure, or an unauthorised movement in the section.

## Checklist
- Authority issued, section confirmed, interlocking normal, brakes tested, register written.

## Avoid
- Verbal shortcuts around the block system; clearing a signal on assumption.
