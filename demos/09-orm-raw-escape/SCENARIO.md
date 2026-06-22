# Demo 09 — ORM project dropping to raw SQL

**Where this came from.** A Django service that is safe by default through the
ORM, then reintroduces risk in the handful of places it escapes to
`connection.cursor()` for a "fast path." This is a common real-world pattern:
the ORM lulls reviewers, and the raw spots get less scrutiny.

**What to expect.** Two MEDIUM findings:

- `SQL009` — `fast_lookup` runs a pre-built query string with no params. If the
  caller assembled `prebuilt_query` from input upstream, the binding was lost
  here.
- `SQL006` — `purge_and_log` stacks two statements in one string. If any part is
  built from input, an attacker can append a third after the `;`.

**Run it.**

```bash
sqlsec lint demos/09-orm-raw-escape --select SQL006,SQL009
```

The `--select` flag focuses the run on just these two rules — useful when you
are triaging a specific class of issue across a large repo.

**How to act.** Keep the ORM for these; if you must use raw SQL, pass params and
run one statement per call:

```python
cur.execute("DELETE FROM tokens WHERE acct = %s", (account_id,))
cur.execute("DELETE FROM audit  WHERE acct = %s", (account_id,))
```
