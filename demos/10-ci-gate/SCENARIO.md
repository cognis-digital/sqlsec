# Demo 10 — Wiring sqlsec into CI

**Where this came from.** A service module as it would arrive in a pull request.
This demo is about the **workflow**, not one rule: the file carries one HIGH
finding (an f-string query) and one MEDIUM finding (a pre-built `execute`).

**What to expect.**

- `SQL002` (high) — `order_total` interpolates `order_id` with an f-string.
- `SQL009` (medium) — `run_report` runs a pre-built string with no params.

## The gate

`--fail-on` sets the severity at which the linter exits non-zero, so CI blocks
the merge:

```bash
sqlsec lint demos/10-ci-gate --fail-on high   # exits 1 (SQL002 is high)
sqlsec lint demos/10-ci-gate --fail-on critical  # exits 0 (nothing is critical)
```

Check the exit code:

```bash
sqlsec lint demos/10-ci-gate --fail-on high; echo "exit=$?"
```

## SARIF for code scanning

Emit SARIF 2.1.0 and upload it so findings show up inline on the PR in GitHub's
Security tab:

```bash
sqlsec lint demos/10-ci-gate --sarif > sqlsec.sarif
```

A minimal GitHub Actions step:

```yaml
- run: sqlsec lint . --sarif > sqlsec.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sqlsec.sarif
```

The SARIF maps sqlsec severities to SARIF levels (high/critical → `error`,
medium → `warning`, low/info → `note`) and carries a `security-severity` score
so GitHub renders the right High/Medium/Low badge.

**How to act.** Bind the value and pass params:

```python
cur.execute("SELECT sum(amount) FROM line_items WHERE order_id = ?", (order_id,))
```
