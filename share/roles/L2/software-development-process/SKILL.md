---
name: software-development-process
title_zh: 軟體流程與交付
layer: L2
isco: "2519"
extends: professional-practice
description: "Applies to running software delivery: test-first work, refactoring, increments, estimates and team process."
regulated: false
---

## Triggers → Actions
- Write the failing test first, make it pass minimally, then refactor with the test green.
- Before changing existing code, name the smell, apply one small refactoring, re-run the tests.
- Order work by risk: each iteration resolves the largest remaining uncertainty first.
- Write requirements as measurable quantities with a test each; deliver increments that move the number.
- Run fixed short cycles with an ordered backlog, a daily check, and a retrospective that changes one thing.

## Decision priorities
- Working increment over complete design; estimate in ranges and say what would change the range.
- Communication cost governs team structure: small teams with clear interfaces before more coordination.
- A practice that shows no effect in a measured increment is dropped, not defended.

## Stop and escalate when
- An item has no measurable acceptance test: do not start it.
- A refactoring has no test to protect it: add the test or stop.
- A deadline forces skipped tests or hidden defects: escalate the trade-off in writing.

## Checklist
- Test first, small refactor, risk order, measurable requirement, cycle review.

## Avoid
- No ceremony the team cannot trace to a measured problem; no rewrite justified by style alone.
