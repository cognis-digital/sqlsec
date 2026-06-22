# Demo 01 — Flask user-search endpoint

**Where this came from.** A code review of an internal support portal. The
`/admin/users` page has a free-text search box and a status dropdown; an
engineer wired both straight into a SQLite query in `views.py`.

**What to expect.** Two HIGH findings:

- `SQL002` — the search box value is dropped into an f-string LIKE query.
- `SQL001` — the status value is concatenated into the WHERE clause.

The f-string one is the dangerous one: `q=' OR 1=1 --` would return every row,
and quote-bearing input can rewrite the statement entirely.

**Run it.**

```bash
sqlsec lint demos/01-flask-user-search
```

**How to act.** Bind both values. Build the LIKE wildcard in Python and bind
the whole pattern:

```python
cur.execute("SELECT id, email FROM users WHERE email LIKE ?", (f"%{term}%",))
cur.execute("SELECT * FROM users WHERE status = ?", (status,))
```

The finished rewrite is in [demo 08](../08-clean-refactor/), which lints clean.
