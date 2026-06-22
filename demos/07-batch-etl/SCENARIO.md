# Demo 07 — Nightly ETL job (%-formatting)

**Where this came from.** A scheduled job that loads a partner feed into a
warehouse. The job config supplies a partner id and a run date, and the code
glues them into the SQL with old-style `%`-formatting.

**Why this slips through review.** `%s` *looks* like a database placeholder, so
people assume it is being bound. It is not — `"... = '%s'" % value` is plain
Python string substitution and is exactly as injectable as concatenation.

**What to expect.** Two HIGH findings:

- `SQL003` × 2 — the `DELETE ... WHERE` clause and the `UPDATE ... SET` clause
  are both assembled with `%`-formatting.

**Run it.**

```bash
sqlsec lint demos/07-batch-etl
```

**How to act.** Drop the `%` operator and pass the values to `execute()`. With
most drivers the placeholder is *also* `%s`, but the value goes in the params
tuple — never on the SQL string:

```python
cur.execute(
    "DELETE FROM staging WHERE partner = %s AND load_date = %s",
    (partner_id, run_date),
)
```
