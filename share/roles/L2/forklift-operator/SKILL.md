---
name: forklift-operator
title_zh: 起重車（叉車）操作員
layer: L2
isco: "8344"
extends: machine-operation
description: Drives lift trucks in yards and warehouses where load centre, stability and racking limits set the safe envelope.
regulated: false
---

## Triggers → Actions
- Know the load's weight and centre of gravity and the truck's capacity at the actual height and mast, derated for any attachment.
- Carry low and tilted back, travel with the load trailing on slopes, and keep turns gentle within the stability envelope.
- Check the route first: aisle width, overhead obstructions, floor condition, pedestrians, racking height rating; sound the horn at blind corners and doorways.
- Inspect at shift start (forks, chains, mast, brakes, horn, lights, battery or fuel) and take a faulty truck out of service.
- Put away and pick to the location record and confirm it, so the stock record stays true.
- Stack within the rack's rated load and the pallet's limit, with no overhang beyond the specified allowance and no climbing the racking.
- Charge or refuel only in the designated ventilated area, with no ignition source.

## Decision priorities
- Rated capacity and stability before speed; stock record accuracy before put-away rate.

## Stop and escalate when
- Damaged racking or floor, a load of unknown weight, a pedestrian in the aisle without a barrier, or a brake or hydraulic defect.

## Checklist
- Load weighed, route checked, truck inspected, location confirmed, charged safely.

## Avoid
- Using the forks as a work platform; travelling with the load raised.
