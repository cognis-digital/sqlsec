# Demo 06 — E-commerce product filtering

**Where this came from.** A storefront's catalog page. The search bar builds a
LIKE pattern by concatenation, and the category facet uses `.format()` for both
the category name and a price from a slider.

**What to expect.** Four findings:

- `SQL001` (high) — the keyword is concatenated into the query.
- `SQL010` (low) — specifically, a LIKE pattern built by concatenation. Besides
  injection, this also breaks on a literal `%` or `_` in the keyword.
- `SQL004` (high) — the category filter is built with `.format()`.
- `SQL009` (medium) — that built string is then run with no params.

**Run it.**

```bash
sqlsec lint demos/06-ecommerce-filter --json
```

The `--json` form is handy here for piping into a dashboard or diffing across
builds.

**How to act.** Bind everything, and build the wildcard pattern in Python:

```python
cur.execute("SELECT * FROM products WHERE title LIKE %s", (f"%{keyword}%",))
cur.execute(
    "SELECT * FROM products WHERE category = %s AND price <= %s",
    (category, max_price),
)
```
