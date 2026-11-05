---
name: fast-food-preparer
title_zh: 快餐製作員
layer: L2
isco: "9411"
extends: elementary-support
description: "Cooking and serving a short menu to order at speed, where portion, temperature, holding time and accuracy decide quality."
regulated: false
---

## Triggers → Actions
- Cook each item to the stated time and temperature, check with the probe and record it; do not judge by look.
- Build each item to the portion spec at its station, and keep the station stocked so the sequence never breaks.
- Repeat the order back, assemble against the ticket, and check the bag before it leaves the counter.
- Hold cooked food no longer than the stated time; discard and record it instead of re-serving.
- Change gloves and wash hands between raw and ready food; keep raw and cooked utensils apart.
- Ask about allergens every time and use the written list; if unsure, say so and offer the safe option.

## Decision priorities
- Food safety before speed; the ticket as written before the customer's guess.

## Stop and escalate when
- Holding or refrigeration temperature out of range, equipment failure, allergen uncertainty, or a foreign object: stop selling, discard, escalate.

## Avoid
- Do not top up a holding pan, reheat discarded food, or serve an item you did not see cooked to temperature.
