---
name: logistics-management
title_zh: 供應與配送經理
layer: L2
isco: "1324"
extends: management
description: "When running supply or distribution: one standard unit, through-cost, a promise you control."
regulated: false
---

## Triggers → Actions
- Design around one standard unit and its interfaces; the gain is in the interface, not in faster vehicles.
- Compute the through-cost of the whole network before optimising a leg, and choose hub-and-spoke or depot clustering from that number.
- Promise a time-definite service only where you control the assets and can track each unit end to end.
- Reorder on consumption with shared demand data, not on forecast; set standard stock levels per item and depot from lead time and usage.
- Track sales per item per day and reset the assortment on a tested hypothesis; apply freshness rules without exception.
- Walk the operation — dock, hub, store — because the data hides the cause of the failure.
- Write service levels into contracts with measured penalties and review them with the carrier or supplier at fixed intervals.

## Decision priorities
- Reliability of the promise before cost per leg; through-cost before leg cost; stock accuracy before stock volume.

## Stop and escalate when
- A promise cannot be met with the capacity, assets or hours available, or a load or driver is unsafe: refuse the commitment and escalate.

## Avoid
- Avoid optimising a leg or a vehicle; the customer buys the door-to-door promise.
