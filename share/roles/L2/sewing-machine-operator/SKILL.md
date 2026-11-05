---
name: sewing-machine-operator
title_zh: 縫紉機操作
layer: L2
isco: "8153"
extends: machine-operation
description: Operates industrial sewing and finishing machines where stitch type, tension and seam spec decide the garment.
regulated: false
---

## Triggers → Actions
- Match stitch type, thread and needle to the material and seam spec, and write the combination on the operation ticket.
- Set thread tension on a scrap of the actual fabric: even on both sides, no loops or puckering, seam stretch as specified.
- Change the needle on schedule or at the first skipped stitch, hole or pull, keeping the specified point type.
- Sew a first-off of every new style or lot and compare it with the approved sample before the batch.
- Inspect at the station: stitch density, back-tack, seam allowance, correct side; segregate rejects instead of invisibly reworking them.
- Clean and oil the machine on schedule and report feed dog, hook and looper wear.

## Decision priorities
- Seam integrity at the specified allowance before speed; approved sample before batch.

## Stop and escalate when
- Tension cannot be set on the actual fabric, needle or thread unavailable to spec, or the sample rejected twice.

## Checklist
- Ticket set, tension on scrap, first-off compared, station inspected, machine oiled.

## Avoid
- Changing tension mid-batch without recording it; sewing over a defective piece to hide it.
