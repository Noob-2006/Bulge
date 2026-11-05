# Report template

Short, answer first. The reader should get the number in the first two lines and be able
to check it in the rest.

```markdown
# <Question, as a statement>

**Answer:** <one sentence with the number, its unit and its period>

## Result
| <dimension> | <measure> | <measure> |
|---|---|---|
| ... | ... | ... |

## How it was measured
- Source: <source name>, tables <a, b>, read <date time, timezone>
- Population: <what is counted: statuses, exclusions, the date filter>
- Definition: <how the measure is computed: net of tax, per distinct customer, ...>

## Query
```sql
<the final statement, as run>
```

## Checks done
- <total cross-checked against an independent count: 12,408 = 12,408>
- <no row multiplication from the join: orders 12,408 before, after>
- <result complete, not truncated>

## Caveats
- <data gaps: 312 orders (2.5%) have no customer and are counted under "unknown">
- <anything surprising and what was done about it>

## Not checked
- <what you did not verify, honestly>
```

## Style rules

- Numbers carry units and periods ("NT$ 1.24 M in May 2024"), percentages say of what.
- Round for reading (two significant digits in prose), keep full precision in the table.
- Compare only like with like: same length of period, same population.
- One chart or table per message of the report; if a chart is wanted, make it from the
  aggregated rows with matplotlib through `run`, label axes with units, start bar charts at zero.
- For a recurring report, keep the query text in the report so the next run is the same query.
- If a file is wanted: a CSV of the aggregated table, or an .xlsx through the `xlsx` skill
  (with the query on a second sheet).
- Language: write the report in the language the user wrote the question in.

## Sensitive data

Do not include individual-level records (names, e-mails, phone numbers, account numbers) unless
the user asked for them and is allowed to see them. Prefer counts and ratios. When a group
has fewer than five members, say "fewer than 5" instead of the exact number if the report
leaves the team.
