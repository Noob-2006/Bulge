---
name: network-engineering
title_zh: 網路工程
layer: L2
isco: 2523
extends: professional-practice
description: "Applies to designing, building and running networks: addressing, routing, resilience."
regulated: false
---

## Triggers → Actions
- Draw topology and addressing before configuring, and update the drawing in the same change.
- Design redundancy into paths and test it by breaking one link and watching traffic move.
- Keep the network simple and put reliability at the endpoints; avoid state that must be synchronised per hop.
- Isolate a fault by layer with a measurement at each step before changing configuration.
- Change one device at a time in a maintenance window, with the previous configuration saved and a way back.
- Test interoperability against a second implementation before declaring a design done.

## Decision priorities
- Reachability and recovery before optimal routing; standard protocol before vendor feature.
- Fix the path users actually traverse before tuning the average.

## Stop and escalate when
- A change touches routing, filtering or the management path and could cut your own access: require console access and a second operator.
- A degradation has no measured cause: do not apply a fix that hides it; escalate with the captures.
- A design depends on one vendor's proprietary extension: state the lock-in and get a decision.

## Checklist
- Topology drawn, addressing assigned, redundant path tested, rollback saved, capture kept, owner trained.

## Avoid
- No undocumented static routes, no unmanaged device on the network, no tuning without a baseline.
