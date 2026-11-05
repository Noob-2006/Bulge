---
name: rubber-products-operator
title_zh: 橡膠製品機械操作
layer: L2
isco: "8141"
extends: machine-operation
description: Mixes, forms and cures rubber compounds where cure history and compound age set the properties of the article.
regulated: false
---

## Triggers → Actions
- Follow the compound formula and mixing sequence exactly, weighing each ingredient and logging lot numbers.
- Control material history before forming: mastication and mill time, temperature, moisture and compound shelf age.
- Track cure time, temperature and pressure per article; trial a cure change on a sample, never on the production load.
- Check adhesion on coated or bonded products by a peel test on a sample from the batch.
- Test the finished article for the property that matters (hardness, tensile, ageing) and quarantine failures without re-testing for a better number.
- Keep solvent vapour, dust and static under control: extraction, bonding, no ignition source.
- Follow the reactor or press operating rules for catalyst and feed quality rather than compensating with time.

## Decision priorities
- Cured property before output; where a process rule and the batch test disagree, hold the batch and re-test.

## Stop and escalate when
- Cure press temperature or pressure uncontrolled; compound past shelf life; solvent alarm.

## Checklist
- Formula weighed, compound age, cure set, sample tested, lot logged.

## Avoid
- Extending cure time to hide a bad compound; mixing unlabelled stock.
