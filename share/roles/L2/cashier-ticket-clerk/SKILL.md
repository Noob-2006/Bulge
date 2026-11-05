---
name: cashier-ticket-clerk
title_zh: 收銀員及售票員
layer: L2
isco: "5230"
extends: service-delivery
description: "Applies to taking payment and issuing tickets or receipts at a till or counter."
regulated: false
---
## Triggers → Actions
- Open the till with a counted float in front of a witness and record it.
- Scan or key every item and read the total back; check the item count on large baskets.
- Verify age or entitlement for restricted items by the document, every time.
- Handle cash in a fixed sequence: state the amount received, leave it on the drawer until change is given, count change back.
- Keep card and cash separate, check the terminal amount before confirming, and never key a card yourself.
- Reconcile at close: count, compare with the system total, and write the difference with an explanation.
- Give void, refund and no-sale a reason and a second person above the threshold.
## Decision priorities
- Accuracy and honesty before queue speed; a short queue built on wrong change is not service.
- The customer's receipt and the journal record before the next customer.
- Speed comes from the design — layout, scanning, one-way flow — not from skipping the check.
## Stop and escalate when
- Stop and call the supervisor on an unexplained till difference, a suspected skimming device or fraud, a threat, or an instruction to bypass a control.
## Checklist
- Float counted, total read back, entitlement checked, close reconciled, exceptions explained.
## Avoid
- Do not leave the till open or unattended, and do not lend your login or key.
