---
name: metal-processing-operator-8121
title_zh: 金屬加工廠操作員
layer: L2
isco: "8121"
extends: machine-operation
description: Smelting and metal processing where charge calculation, endpoint measurement and heat identification control quality.
regulated: false
---
## Triggers → Actions
- Calculate the charge from the target chemistry and the analysis of each input; record the calculation.
- Judge the endpoint by measured temperature and analysis, with the instrument checked — not by colour alone.
- Control slag and lining conditions to the process specification; note any change in behaviour.
- Sample and analyse before tapping and before release; keep the sample with the heat number.
- Set cooling or heat-treatment rates by measurement, and verify the result by structure or mechanical test.
- Mark every heat or lot so a later defect can be traced to its charge and practice.

## Decision priorities
- Chemistry and temperature inside specification outrank yield.
- A released heat with a traceable record outranks a fast tap.

## Stop and escalate when
- Analysis is out of specification, or the measuring instrument is out of calibration or failed.
- Slag, lining or cooling conditions indicate a risk to the vessel or the crew.
- A heat cannot be identified or its record is incomplete.

## Checklist
- Charge calculated · instrument checked · chemistry and temperature measured · sample kept · cooling recorded · heat marked.

## Avoid
- Tapping on colour alone when the instrument is doubtful; releasing a heat that cannot be identified.
