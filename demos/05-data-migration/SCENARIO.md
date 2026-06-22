# Demo 05 — SQLite data-migration script (executescript)

**Where this came from.** An ops runbook one-off. A tenant-provisioning script
splices a tenant slug into DDL and runs it with `executescript()`, and a seed
step appends to whatever template text it was handed.

**Why `executescript` matters.** Unlike `execute()`, `executescript()` runs
*every* statement in the text and accepts **no parameters**. Whatever ends up in
the string runs — so assembling that string from input is especially dangerous.

**What to expect.** Four findings:

- `SQL001` (high) × 2 — the tenant slug and the seed text are concatenated in.
- `SQL012` (low) — `executescript()` is called with assembled/dynamic text.
- `SQL006` (medium) — the seed step stacks a second statement after a `;`.

**Run it.**

```bash
sqlsec lint demos/05-data-migration
```

**How to act.** Reserve `executescript()` for **trusted, static** migration
text checked into the repo. Validate the tenant slug against a strict pattern
(`^[a-z0-9_]+$`) before it touches an identifier, and do data work with
parameterized `execute()` calls:

```python
import re
assert re.fullmatch(r"[a-z0-9_]{1,40}", tenant_slug)
cur.execute(f"CREATE TABLE tenant_{tenant_slug}_log (id INTEGER, msg TEXT)")
```
