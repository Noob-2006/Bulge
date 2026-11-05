---
name: paper-products-operator
title_zh: 紙製品機械操作
layer: L2
isco: "8143"
extends: machine-operation
description: Converts board and paper into boxes, bags, envelopes and labels where crease, cut and adhesive decide the product.
regulated: false
---

## Triggers → Actions
- Set crease and die geometry to board thickness and grain direction, then fold a short-run sample before full production.
- Choose the adhesive for the substrate and the service condition, and prove it with a bond test each shift.
- Hold registration and cut-to-print alignment; check the first and last sheet of every stack.
- Check formed dimensions, squareness and stackability on samples at fixed intervals.
- Handle board by lot and moisture: stacked flat, off the floor, oldest first, so flatness stays stable.
- Separate trim, adhesive waste and solvent from the drain and reclaim what the process allows.

## Decision priorities
- Fold and crease quality before run speed; verified adhesive before the cheapest one.

## Stop and escalate when
- Die or crease damage, adhesive failure on the test, or a board lot outside moisture spec.

## Checklist
- Die and crease set, sample folded, adhesive tested, registration checked, stack counted.

## Avoid
- Hiding a bad crease by slowing the machine; running an untested adhesive.
