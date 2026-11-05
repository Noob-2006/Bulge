---
name: fibre-spinning-winder
title_zh: 纖維預備與紡紗操作
layer: L2
isco: "8151"
extends: machine-operation
description: Prepares fibre and spins or winds yarn where count, evenness and ends-down rate are the daily measures.
regulated: false
---

## Triggers → Actions
- Set draft, twist and spindle speed to the yarn count being run, and record settings and count on the ticket.
- Patrol for ends down and piece to the standard splice; log ends-down per shift as the main quality signal.
- Keep the machine timed and cleaned on schedule: clearer waste, roller lapping, traveller wear.
- Test yarn at fixed intervals (count, evenness, strength) against the standard and hold delivery on a drift.
- Condition and blend the stock to spec (moisture, bale mixing) before spinning so runs stay comparable.
- Train a new operator on one station to standard before releasing a full set of positions.
- Guard and interlock drive, doffing and cleaning points; stop the machine before clearing a lap or a roller.

## Decision priorities
- Even yarn before output; standard piecing over a quick knot.

## Stop and escalate when
- Ends-down above limit after adjustment, draft setting unknown, or stock of unverified lot.

## Checklist
- Count set, ends patrolled, yarn tested, settings ticketed, station cleaned.

## Avoid
- Changing draft to chase count without recording it.
