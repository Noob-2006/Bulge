# Worked example: "Which region grew fastest last quarter?"

The point is the order of the steps and the checks, not the SQL itself. Source `sales`
(PostgreSQL), tools `sql_schema` and `sql_query`.

## 1. Restate and define

"Revenue growth by region, last quarter (2024-04-01 to 2024-06-30) against the quarter
before (2024-01-01 to 2024-03-31); revenue = paid orders, net of refunds, in the order's
currency converted to TWD." Two unknowns: is *region* the customer's or the shipping
region, and is a refund counted in the quarter of the refund or of the order? Ask once:

> I'll use the shipping region and count a refund in the quarter of the original order.
> Say if you want the customer's region instead.

## 2. Explore

`sql_schema {source: "sales"}` -> tables `orders`, `order_items`, `refunds`, `customers`,
`regions`, `fx_rates`. `sql_schema {source: "sales", table: "orders"}` -> `id, customer_id,
region_id, status, total_cents, currency, created_at, paid_at`.

```sql
SELECT status, COUNT(*) AS n FROM orders GROUP BY status ORDER BY n DESC
```
-> `paid 91%, pending 6%, cancelled 2%, test 1%`. Decision: `paid` only; `test` is excluded
and mentioned in the caveats.

## 3. Small first

```sql
SELECT COUNT(*) AS n, MIN(paid_at) AS first, MAX(paid_at) AS last FROM orders WHERE status = 'paid' AND paid_at >= '2024-01-01' AND paid_at < '2024-07-01'
```
-> 41,877 orders, the range is complete (no gap week). Then the aggregation with the
refunds pre-aggregated so the join cannot multiply rows:

```sql
WITH rf AS (SELECT order_id, SUM(amount_cents) AS refunded FROM refunds GROUP BY order_id),
q AS (
  SELECT r.name AS region,
         CASE WHEN o.paid_at >= '2024-04-01' THEN 'Q2' ELSE 'Q1' END AS quarter,
         SUM(o.total_cents - COALESCE(rf.refunded, 0)) / 100.0 AS revenue
  FROM orders o JOIN regions r ON r.id = o.region_id LEFT JOIN rf ON rf.order_id = o.id
  WHERE o.status = 'paid' AND o.currency = 'TWD' AND o.paid_at >= '2024-01-01' AND o.paid_at < '2024-07-01'
  GROUP BY 1, 2)
SELECT region,
       MAX(CASE WHEN quarter = 'Q1' THEN revenue END) AS q1,
       MAX(CASE WHEN quarter = 'Q2' THEN revenue END) AS q2
FROM q GROUP BY region ORDER BY region
```

## 4. Check before believing

- **Total**: the sum of regions for Q2 equals `SELECT SUM(total_cents - COALESCE(...)) ... ` without
  the region join: 61.2 M both ways. A mismatch would mean orders without a region (inner join dropped them).
- **Multiplication**: `COUNT(*)` of orders before and after the refunds join is the same, because `rf` has one row per order.
- **Currency**: the query kept only TWD; a separate count shows 4.1% of orders in other
  currencies. Either convert with `fx_rates` or state the exclusion. (Here: stated.)
- **Plausibility**: the largest region's growth of +212% is suspicious; look at it: one
  enterprise order of 9.8 M. Report growth with and without it.
- **Truncation**: 7 rows, `truncated: false`.

## 5. Report

Use `references/report-template.md`. The answer line:

> **North grew fastest: +34% (NT$ 11.2 M to 15.0 M), or +9% if one 9.8 M enterprise order in June is excluded.**

then the table, the definitions (paid, TWD only, net of refunds in the order's quarter,
shipping region), the final query, the checks above, the caveats (TWD-only excludes 4.1% of
orders; 1% test orders removed), and what was not checked (late refunds after 2024-07-01).

## 6. If a chart is wanted

Export the 7-row result with `run` (the aggregated rows are small), then:

```python
import matplotlib.pyplot as plt
plt.bar(regions, growth); plt.ylabel("Growth Q2 vs Q1 (%)"); plt.axhline(0, color="black", lw=0.5)
plt.savefig("growth_by_region.png", dpi=150, bbox_inches="tight")
```
