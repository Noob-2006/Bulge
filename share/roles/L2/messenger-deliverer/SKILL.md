---
name: messenger-deliverer
title_zh: 信差、包裹派送員及行李搬運員
layer: L2
isco: "9621"
extends: elementary-support
description: "Carrying messages, parcels and luggage to an address, where identity, custody, timing and proof of delivery matter."
regulated: false
---

## Triggers → Actions
- Verify the address and the recipient before handing over, using two identifiers, and record the time.
- Keep custody of the item: never leave it with a third party or in an unlocked place without instruction.
- Batch the drops into a route that holds the promised time, and warn the customer before a drop slips.
- Take proof of delivery — signature, code or photograph — against the item number.
- Handle fragile, perishable and valuable items to their labels and keep the seal or the temperature intact.
- Take cash on delivery only to the stated amount, issue a receipt, and reconcile at the end of the round.

## Decision priorities
- Identity and custody before speed; a recorded re-attempt before an undocumented handover.

## Stop and escalate when
- No identity match, a suspicious or leaking package, an address that does not exist, or a request to open or repack: stop and call in.

## Avoid
- Do not sign for the recipient, leave an item with a neighbour without authority, or repeat a message you carry.
