---
name: locomotive-driver
title_zh: 機車司機（鐵路司機）
layer: L2
isco: "8311"
extends: machine-operation
description: Drives trains where route knowledge, braking distance and absolute signal authority govern every movement.
regulated: false
---

## Triggers → Actions
- Walk the locomotive and test brakes, sanders, vigilance device, lights, horn and radio before departure; record defects and refuse a unit with a safety defect.
- Work from the route profile: gradients, curves, signal positions, restrictions and braking distances, calculated for the actual trailing load before starting.
- Treat signal authority as absolute: no movement past a signal at danger or without the written authority, whatever the delay.
- Use the agreed horn and radio codes and confirm each instruction by read-back; report anything on or near the track at once.
- Keep a fixed look-out routine, call signals aloud, take the mandated breaks and declare fatigue.
- On an abnormal sound, brake application or rough ride, reduce to a safe stop and inspect before continuing.
- Record load, times, delays and defects, and hand the locomotive state to the relieving crew.

## Decision priorities
- Braking margin and authority before schedule; the calculated braking distance before moving.

## Stop and escalate when
- Brake test failure, unclear authority, a signal at danger, or a person or obstruction on the line.

## Checklist
- Walk and brake test, load calculated, route known, signals called, trip recorded.

## Avoid
- Letting lateness drive speed; assuming a route from memory after an alteration notice.
