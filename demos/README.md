# sqlsec demos

Realistic, self-contained scenarios for `sqlsec lint`. Each folder holds an
input file **in the tool's real input format** (a `.py` or `.sql` source) and a
`SCENARIO.md` that explains where the data came from, the exact command to run,
what findings to expect, and how to fix it.

All sample code is **DEMONSTRATION ONLY** — intentionally unsafe so the linter
has something to detect. Do not copy these patterns into real code. The fixes
are described in each scenario; demo 08 is a fully clean rewrite.

Run any one:

```bash
sqlsec lint demos/01-flask-user-search
```

Or scan them all at once:

```bash
sqlsec lint demos
```

| Demo | Scenario | Key rules | Severity |
| --- | --- | --- | --- |
| [01-flask-user-search](01-flask-user-search/) | Flask search box + status dropdown glued into SQLite | SQL002, SQL001 | high |
| [02-auth-review](02-auth-review/) | Login handler with a left-over bypass probe | SQL007, SQL008, SQL009 | high |
| [03-analytics-report](03-analytics-report/) | Self-serve report builder; table/dimension as identifiers | SQL011, SQL001, SQL004 | high |
| [04-legacy-stored-proc](04-legacy-stored-proc/) | T-SQL proc running assembled SQL with `EXEC()` | SQL005, SQL001 | critical |
| [05-data-migration](05-data-migration/) | SQLite `executescript()` on assembled DDL | SQL012, SQL006, SQL001 | high |
| [06-ecommerce-filter](06-ecommerce-filter/) | Storefront LIKE search + `.format()` category facet | SQL010, SQL004, SQL001 | high |
| [07-batch-etl](07-batch-etl/) | Nightly ETL using `%`-formatting for the WHERE clause | SQL003 | high |
| [08-clean-refactor](08-clean-refactor/) | The parameterized rewrite of demo 01 — **lints clean** | (none) | — |
| [09-orm-raw-escape](09-orm-raw-escape/) | ORM app reintroducing risk in its raw-SQL fast paths | SQL009, SQL006 | medium |
| [10-ci-gate](10-ci-gate/) | Wiring `--fail-on` and `--sarif` into CI / code scanning | SQL002, SQL009 | high |

Together the demos exercise **every** authored rule (SQL001–SQL012) at least
once; `tests/test_demos.py` enforces that.
