# Demo 02 — Auth handler with a left-over bypass probe

**Where this came from.** A security audit of a legacy intranet login. The
handler builds its query from the raw `username`/`password` form fields, and a
developer left a manual "does the bypass work?" probe in the file.

**What to expect.** Three findings:

- `SQL009` (medium) — `check_login` runs a pre-built query string with no params.
- `SQL008` (medium) — the probe literal contains a `--` comment introducer.
- `SQL007` (high) — the probe literal contains the classic `OR '1'='1'` tautology.

The tautology + comment pair is the textbook shape of an auth-bypass payload.
Even though `debug_probe` looks harmless, shipping that literal in source means
the vulnerable code path exists and was demonstrably reachable.

**Run it.**

```bash
sqlsec lint demos/02-auth-review --fail-on high
```

The `--fail-on high` flag makes this exit non-zero (the tautology is HIGH), so
a CI job would block the merge.

**How to act.** Delete the probe. Parameterize the login lookup and verify the
password hash in application code, never in the SQL literal:

```python
cur.execute("SELECT pass_hash FROM accounts WHERE user = ?", (username,))
# then compare hashes with a constant-time check in Python
```
