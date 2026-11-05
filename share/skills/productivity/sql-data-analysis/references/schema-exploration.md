# Schema exploration

Do this before the first join. It takes four or five small calls and saves the wrong answer.

## 1. Which source, which tables

`sql_schema` with no arguments lists the sources and what the operator says is in them.
`sql_schema {source}` lists tables and views. Pick the two to five whose names match the
question; ignore `*_backup`, `*_old`, `tmp_*`, `_migrations`, `django_*`.

## 2. Columns of each candidate

`sql_schema {source, table}` gives column, type, nullability. Note:

- the **primary key** (usually `id`) and the **foreign keys** (`customer_id`, `order_id`);
- the **time column** you will filter on: `created_at`, `order_date`, `event_time`. Check
  whether it is a date, a timestamp with or without timezone, or text.
- the **status/flag columns** (`status`, `is_deleted`, `cancelled_at`) that decide what counts.
- money columns: integer cents or decimal? which currency column?

## 3. Look at real rows

```sql
SELECT * FROM orders ORDER BY created_at DESC LIMIT 5
```

Check that the columns mean what the names say. A `total` can be before or after tax.

## 4. Size and shape

```sql
SELECT COUNT(*) AS n, MIN(created_at) AS first, MAX(created_at) AS last, COUNT(DISTINCT customer_id) AS customers FROM orders
```

Row count tells you whether a full scan is cheap. The date range tells you whether
"last month" exists in the data at all. Distinct counts tell you the join keys' cardinality.

## 5. Distinct values of a status column

```sql
SELECT status, COUNT(*) AS n FROM orders GROUP BY status ORDER BY n DESC
```

Never guess which statuses count as completed; list them and decide (or ask).

## 6. Join keys before joining

```sql
SELECT COUNT(*) AS orders, COUNT(c.id) AS matched FROM orders o LEFT JOIN customers c ON c.id = o.customer_id
```

If `matched` is lower than `orders`, some orders have no customer: decide how to treat
them. If a one-to-many join multiplies rows, aggregate the many side first in a `WITH`.

## 7. Time zones and boundaries

Say which timezone "a day" means. A timestamp stored in UTC and reported for Taipei needs
`AT TIME ZONE` (PostgreSQL), `CONVERT_TZ` (MySQL), `toTimeZone` (ClickHouse). A month
filter is `>= '2024-05-01' AND < '2024-06-01'`, never `BETWEEN` with the last day's date
(that drops the last day of timestamps).

## Write down what you learned

Keep a short list in your answer: tables used, the filter that defines the population,
known data-quality gaps. The report template has a place for it.
