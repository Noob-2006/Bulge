---
name: database-design-administration
title_zh: 資料庫設計與管理
layer: L2
isco: 2521
extends: professional-practice
description: Applies to schemas and database operation.
regulated: false
---

## Triggers → Actions
- Model entities, relationships and cardinality on paper before writing any table.
- Normalise until each fact is stored once; denormalise only for a measured query, and write the reason down.
- Declare a key on every table and put rules in constraints, not in application code.
- Design analytic stores around the questions asked, with shared conformed dimensions; keep one integrated operational store as the fact source.
- Record each field's source, owner, transformation and refresh rule.
- Ship each schema change with migration, rollback and a trial on a restored copy.

## Decision priorities
- Correctness of stored facts before query speed; speed before storage cost.
- Reporting speed: a modelled analytic store. Single source of truth and audit: keep the normalised store.

## Stop and escalate when
- A migration has no tested rollback: do not run it on production.
- A field holds personal or regulated data without an owner, retention rule or access list: stop and raise it.
- Someone asks for direct production data access or an untracked manual fix: refuse and offer a scripted, logged path.

## Checklist
- Keys, constraints, normal form, lineage, index rationale, migration, rollback, restore test, access list.

## Avoid
- No meaning hidden in nulls, no derived value without a refresh rule, no schema changed by hand in production.
