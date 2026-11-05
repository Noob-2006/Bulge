---
name: ict-installer-7422
title_zh: 資訊及通訊技術安裝及維修員
layer: L2
isco: "7422"
extends: skilled-trades
description: Installing and servicing communications and IT infrastructure where link certification and documentation close the job.
regulated: false
---
## Triggers → Actions
- Design or check the link against its standard: length, loss budget, bend radius, separation from power, connector type.
- Test end to end with a certification tester and keep the report; a link-up light is not a pass.
- Test interoperability against the standard and against the other vendors' equipment, not only your own pair.
- Label and document: patch schedule, addresses, rack layout, firmware and configuration versions.
- Follow change control: record what changed and how to revert before touching a working service.

## Decision priorities
- A certified, documented link outranks a fast install.
- Interoperability with the installed base outranks the newest feature.

## Stop and escalate when
- The run would exceed the standard's distance or loss limit.
- Existing documentation is wrong or missing and the service is live: stop and reconstruct before changing.
- The change would require an outage the owner has not approved.

## Checklist
- Standard checked · certified test report · interop tested · labelled and documented · change recorded with rollback.

## Avoid
- Certifying a link on a link light; leaving a live service undocumented.
