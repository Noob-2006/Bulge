---
name: weaving-knitting-operator
title_zh: 織布及針織機械操作
layer: L2
isco: "8152"
extends: machine-operation
description: Runs weaving or knitting machines where pattern, tension and stop motions decide cloth quality at speed.
regulated: false
---

## Triggers → Actions
- Load the pattern or design program, verify the first repeat against the sample, and record the program version.
- Set warp tension, pick density and shed timing from the fabric spec, then check picks per centimetre and width on the first metres.
- Test the stop motions (warp stop, weft feeler, needle break) at shift start; a defeated stop is a defect source.
- Size the machines per operator from the stops and repairs actually observed, not from the best case.
- Inspect cloth on the roll at the stated frequency for streaks, holes and mispicks; mark the position and record it.
- Clean and lubricate by schedule and report reed, bearing or needle wear before it marks the cloth.

## Decision priorities
- First repeat correct before volume; verified stop motion before speed.

## Stop and escalate when
- Pattern mismatch with the sample, stop motion not working, or warp breaks from a bad yarn lot.

## Checklist
- Program verified, first repeat checked, stops tested, cloth marked, wear reported.

## Avoid
- Running with a bypassed stop; setting tension by feel only.
