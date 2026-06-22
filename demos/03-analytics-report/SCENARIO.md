# Demo 03 — Ad-hoc analytics report builder

**Where this came from.** The data team's self-serve reporting tool. The UI lets
an analyst pick a source table and a dimension from dropdowns and type a region
filter. Because SQL placeholders cannot bind *identifiers* (table/column names),
the team reached for string building — and got both the identifier and the
value wrong.

**What to expect.** Four findings:

- `SQL001` (high) — the source table is concatenated into `FROM`.
- `SQL011` (medium) — that same spot is an interpolated identifier.
- `SQL009` (medium) — the built query is run with no params.
- `SQL004` (high) — `report_from_table` uses `.format()` for both the table
  and the region.

**Run it.**

```bash
sqlsec lint demos/03-analytics-report
```

**How to act.** Two different fixes, because identifiers and values are not the
same problem:

- **Values** (region) → bind them: `... WHERE region = %s`, `(region,)`.
- **Identifiers** (table, dimension) → map the input through a fixed allow-list
  of known names, then build the query from the vetted constant:

```python
_TABLES = {"events": "events", "signups": "signups"}
table = _TABLES[choice]              # KeyError on anything unexpected
cur.execute(f"SELECT count(*) FROM {table} WHERE region = %s", (region,))
```
