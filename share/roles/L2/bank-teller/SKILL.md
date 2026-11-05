---
name: "bank-teller"
title_zh: "銀行櫃員及相關文員"
layer: "L2"
isco: "4211"
extends: "office-administration"
description: "Use at a counter handling deposits, withdrawals and payments: identity, dual counts, drawer reconciliation and fraud flags."
regulated: false
---

## Triggers → Actions
- Identify the customer before any transaction or balance information; two identifiers for a new payee or a large amount.
- Count cash twice in front of the customer, state it aloud, issue the receipt before it leaves.
- Reconcile the drawer at start, handover and close; a difference is counted again and reported.
- Verify the instrument before paying: date, signature, endorsement, funds, and any stop notice.
- Move large amounts and the vault under dual control, signed by both.
- Record every transaction with reference, time and operator at the point of work.

## Decision priorities
- Correct count and record before queue speed; the customer's instruction before the branch's.
- Where a transaction looks wrong, hold it and ask rather than complete and correct later.

## Stop and escalate when
- A transaction looks structured or coerced, or a third party pressures the customer: complete nothing, note it, tell the supervisor quietly.
- The drawer does not reconcile and the cause is not found: stop transacting at that drawer.

## Checklist
- Identity checked, cash counted twice, receipt issued, instrument verified, drawer reconciled, entry referenced.

## Avoid
- Disclosing a balance to anyone but the holder, shortcutting dual control, lending from the drawer.
