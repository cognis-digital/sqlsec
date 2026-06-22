# sqlsec

**A defensive SQL-safety linter and trainer.** `sqlsec` scans your SQL strings
and source files for the construction patterns that lead to SQL injection, and
ships a small interactive trainer that teaches parameterized-query safety.

It is **educational and defensive only**. It does not execute attacks, connect
to any database, or run the SQL it inspects — it reads source text and reports.

In plain terms: SQL injection happens when input is glued into a query as part
of its *structure* instead of being passed as *data*. `sqlsec` looks for the
glue (string concatenation, f-strings, `%`-formatting, `.format()`, dynamic
`EXEC`, stacked statements, and friends) and points it out with a safe rewrite.

It ships **two complementary analysis engines**:

- **`sqlsec lint`** — a fast, line-by-line heuristic that flags unsafe
  *construction patterns* wherever they appear.
- **`sqlsec taint`** — an **AST data-flow** analyzer that traces an untrusted
  source (request data, `input()`, env, argv, function args) into a SQL
  execution sink across multiple lines, and stays silent when the value is bound
  or allow-listed. It catches multi-line flows the line linter misses and
  suppresses false positives it can't. See
  [`docs/TAINT_ANALYSIS.md`](docs/TAINT_ANALYSIS.md).

- Maintainer: **Cognis Digital**
- License: **COCL 1.0**
- Python 3.10+, **standard library only** (no third-party runtime deps)

---

## Install

```bash
pip install -e .
# or, with the test extra:
pip install -e ".[dev]"
```

This installs the `sqlsec` console command.

## Usage

### Lint sources for unsafe SQL construction

```bash
sqlsec lint path/to/file.py
sqlsec lint path/to/project/          # recurses; scans .py and .sql
sqlsec lint examples/vulnerable.py    # the bundled bad sample
sqlsec lint examples/safe.py          # the bundled clean sample (no findings)
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--json` | Emit findings as JSON (for CI / tooling). |
| `--sarif` | Emit findings as **SARIF 2.1.0** for GitHub code scanning / CI dashboards. |
| `--fail-on <severity>` | Exit non-zero if any finding is at or above this severity (`info`/`low`/`medium`/`high`/`critical`). Use it as a CI gate. |
| `--select SQL001,SQL004` | Run only the named rules. |
| `-v` / `--verbose` | Print extra hints. |

Example table output:

```
SEVERITY  RULE    LOCATION                    MESSAGE
--------  ------  --------------------------  -----------------------------------------
HIGH      SQL001  examples/vulnerable.py:16:13  SQL query built by string concatenation...
CRITICAL  SQL005  examples/vulnerable.py:46:5   Dynamic execution of a concatenated SQL...
```

Exit codes: `0` = ok / gate not tripped, `1` = `--fail-on` threshold met,
`2` = bad invocation (missing path, unknown rule).

### Export SARIF for code scanning

`--sarif` emits a SARIF 2.1.0 log that GitHub code scanning, Azure DevOps, and
most security dashboards ingest directly. sqlsec severities map to SARIF levels
(`high`/`critical` -> `error`, `medium` -> `warning`, `low`/`info` -> `note`)
and each result carries a `security-severity` score so GitHub renders the right
High/Medium/Low badge.

```bash
sqlsec lint . --sarif > sqlsec.sarif
```

```yaml
# GitHub Actions
- run: sqlsec lint . --sarif > sqlsec.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sqlsec.sarif
```

See [`demos/10-ci-gate`](demos/10-ci-gate/) for the full gate + SARIF workflow.

### Taint: trace untrusted input into SQL sinks

Where `lint` is a per-line pattern matcher, `taint` parses the file into an AST
and follows whether an untrusted value actually *reaches* a SQL execution sink
while still untrusted — across assignments, f-strings, `+`, `%`, `.format()`,
and `.join()`. It catches multi-line flows `lint` cannot connect, and it does
**not** flag a query built from constants (the false positive `lint` will raise).

```bash
sqlsec taint path/to/file.py                  # parameter-seeded (high recall)
sqlsec taint path/to/project/                 # recurses .py files
sqlsec taint examples/taint_flow.py --explicit-only   # 9 critical flows
sqlsec taint examples/taint_safe.py --explicit-only   # clean
```

| Flag | Effect |
| --- | --- |
| `--explicit-only` | Only report flows starting at an explicit source (request data / `input()` / env / argv); do **not** treat bare function parameters as tainted. Higher precision, lower recall — ideal for a CI gate. |
| `--json` / `--sarif` | Machine-readable output, same shape as `lint`. |
| `--fail-on <severity>` | CI gate exit code, same semantics as `lint`. |
| `-v` / `--verbose` | Extra hints. |

It reports two data-flow rules:

| ID | Severity | Fires when |
| --- | --- | --- |
| SQL100 | critical | untrusted value reaches `execute`/`executemany` built into the query text |
| SQL101 | critical | untrusted value reaches `executescript` (runs every statement, binds nothing) |

Full write-up, threat context, and a diagram:
[`docs/TAINT_ANALYSIS.md`](docs/TAINT_ANALYSIS.md).

### Explain a rule

```bash
sqlsec explain            # list every rule
sqlsec explain SQL002     # what it catches + the safe pattern
```

### Train

An interactive multiple-choice quiz drawn from an authored lesson bank on SQL
injection and parameterized queries.

```bash
sqlsec train --list             # list lesson topics (non-interactive)
sqlsec train --topic basics     # quiz one topic
sqlsec train --topic all        # quiz everything
```

At each question, type the choice number, or `q` to quit.

---

## Rule set

`sqlsec` ships an authored rule set (no copied content). Each rule fires on a
bad sample and stays quiet on the safe equivalent.

| ID | Severity | Catches |
| --- | --- | --- |
| SQL001 | high | SQL built by string concatenation (`"..." + var`) |
| SQL002 | high | f-string interpolation into SQL |
| SQL003 | high | printf-style `%`-formatting building SQL |
| SQL004 | high | `str.format()` building SQL |
| SQL005 | critical | dynamic `EXEC` / `sp_executesql` / `EXECUTE IMMEDIATE` of assembled SQL |
| SQL006 | medium | stacked / multi-statement query in one string |
| SQL007 | high | always-true (tautology) condition embedded in SQL |
| SQL008 | medium | SQL comment sequence (`--`, `/*`, `#`) inside a query literal |
| SQL009 | medium | `execute()` called with a pre-built string and no params |
| SQL010 | low | `LIKE` pattern built by concatenation |
| SQL011 | medium | table/column identifier interpolated into SQL |
| SQL012 | low | `executescript()` with assembled/dynamic text |

The linter strips Python `#` comments (outside strings) before matching, so
commentary about SQL is not flagged — except where a rule deliberately targets a
comment sequence *inside a string literal*.

## The safe pattern, in one line

Keep the SQL text fixed in code; pass values separately as bound parameters:

```python
# unsafe
cur.execute("SELECT * FROM users WHERE id = " + user_id)
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")

# safe
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))   # sqlite3 / qmark
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # many drivers
```

Placeholders bind **values**, not identifiers. For a table/column name chosen
from input, map it through a fixed allow-list before it touches the SQL.

## Examples

- `examples/vulnerable.py` — intentionally unsafe; exercises every Python rule.
- `examples/safe.py` — the parameterized counterparts; lints clean.

```bash
sqlsec lint examples/vulnerable.py   # many findings
sqlsec lint examples/safe.py         # none
```

## Demos

[`demos/`](demos/) holds ten realistic, self-contained scenarios — each a
source file in the tool's real input format plus a `SCENARIO.md` (where the data
came from, the exact run command, expected findings, and how to fix it). They
span web search endpoints, an auth-bypass review, a self-serve report builder, a
legacy T-SQL stored proc, a SQLite migration, an e-commerce filter, a nightly
ETL job, an ORM raw-SQL escape, a clean parameterized rewrite, and a full CI
gate + SARIF workflow. Between them they exercise every rule (SQL001–SQL012).

```bash
sqlsec lint demos                       # scan them all
sqlsec lint demos/04-legacy-stored-proc # one scenario (a .sql file)
```

See [`demos/README.md`](demos/README.md) for the index.

## Development

```bash
pip install -e ".[dev]"
python -m pytest          # on Windows: set PYTHONUTF8=1
```

Tests assert each rule fires on a bad sample and stays silent on a safe one,
check severities and the `--fail-on` gate exit codes, and verify the lesson bank
loads and the quiz loop runs without real stdin.

## Scope and limits

`sqlsec` is a heuristic linter, not a parser. It is tuned to flag the common,
dangerous construction patterns with few false positives on idiomatic safe code.
It will not catch every possible unsafe query, and a clean run is not a proof of
safety — treat it as one layer alongside code review, parameterized queries by
default, least-privilege DB accounts, and input validation.

License: COCL 1.0.
