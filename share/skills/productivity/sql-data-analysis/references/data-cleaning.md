# Data cleaning

Cleaning is a set of explicit decisions, each with a count of rows affected. Do the
inspection in SQL (read-only) and do the transformation on exported rows with the `run`
tool (pandas), never by changing the source. Report every rule and its count.

## Inspect first

| Question | Query pattern |
|---|---|
| How many rows, how many distinct keys | `SELECT COUNT(*), COUNT(DISTINCT id) FROM t` |
| Duplicate keys | `SELECT id, COUNT(*) n FROM t GROUP BY id HAVING COUNT(*) > 1 ORDER BY n DESC LIMIT 20` |
| Duplicate records that differ only in id | `GROUP BY` all business columns `HAVING COUNT(*) > 1` |
| NULL / empty per column | `SELECT SUM(CASE WHEN col IS NULL OR col = '' THEN 1 ELSE 0 END) FROM t` |
| Numbers stored as text | look for non-digits: PostgreSQL `col !~ '^[0-9.]+$'`, SQLite `col GLOB '*[^0-9.]*'` |
| Impossible values | negative quantities, dates in the future, ages over 120 |
| Outliers | compare `MAX`, `AVG`, and a percentile (`percentile_cont(0.99)` or `quantile(0.99)(col)`) |
| Inconsistent categories | `SELECT lower(trim(col)), COUNT(*) FROM t GROUP BY 1 ORDER BY 2 DESC` |
| Date formats | `SELECT DISTINCT length(col) FROM t` then sample each length |

## Decide, then apply

For each problem choose one action and write it down:

- **Duplicates**: keep the latest (`ROW_NUMBER() OVER (PARTITION BY key ORDER BY updated_at DESC) = 1`)
  or the first; say which and how many were dropped.
- **NULLs**: leave as unknown, fill with a stated default, or exclude from that calculation.
  Never fill with 0 when 0 is a legitimate value.
- **Types**: cast explicitly; rows that fail the cast are listed, not silently dropped.
- **Categories**: map variants to one value with an explicit table (`'tw', 'TW', 'Taiwan' -> 'TW'`).
- **Outliers**: keep and flag by default. Remove only with a reason you can state ("test
  accounts have the email domain @example.com").
- **Dates**: parse with the format named; keep original text next to the parsed value while checking.

## Applying in pandas (through `run`)

```python
import pandas as pd
df = pd.read_csv("export.csv", dtype=str)          # read as text, convert on purpose
before = len(df)
df = df.drop_duplicates(subset=["order_id"], keep="last")
df["total"] = pd.to_numeric(df["total"], errors="coerce")
bad = df[df["total"].isna()]
print(before, len(df), len(bad))                  # rows in, rows kept, rows that failed the cast
```

Write the cleaned file next to the original under a new name; never overwrite the export.

## Report the cleaning

A table of: rule, rows affected, reason. Then the row count before and after. A reader
must be able to reproduce the cleaned set from this table alone.

## Red flags that mean "stop and tell the user"

- More than a few percent of rows hit one rule: the rule or the data export is wrong.
- Keys that should be unique are not: the export joined something it should not have.
- A column's meaning changes mid-way (units, currency) at a date: split the analysis there.
