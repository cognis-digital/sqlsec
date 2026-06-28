# sqlsec

**A defensive SQL-safety linter and trainer.** `sqlsec` scans your SQL strings
and source files for the construction patterns that lead to SQL injection, and
ships a small interactive trainer that teaches parameterized-query safety.

It is **educational and defensive only**. Its passive engines do not execute
attacks, connect to any database, or run the SQL they inspect — they read source
text and report. The one active capability (`sqlsec probe`) is off by default,
authorized-use-only, and never sends SQL or payloads (see below).

In plain terms: SQL injection happens when input is glued into a query as part
of its *structure* instead of being passed as *data*. `sqlsec` looks for the
glue (string concatenation, f-strings, `%`-formatting, `.format()`, dynamic
`EXEC`, stacked statements, and friends) and points it out with a safe rewrite.


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ sqlsec --version
sqlsec 1.0.0
```

```console
$ sqlsec --help
usage: sqlsec [-h] [--version] {lint,taint,deps,probe,explain,train} ...

Defensive SQL-safety linter + trainer. Scans source for unsafe query
construction and teaches parameterized-query safety. It does not execute
attacks.

positional arguments:
  {lint,taint,deps,probe,explain,train}
    lint                scan .sql/.py files for unsafe query-construction
                        patterns
    taint               AST data-flow analysis: trace untrusted input into SQL
                        sinks
    deps                audit a manifest/lockfile/SBOM against the bundled
                        offline vuln DB (PASSIVE -- no network)
    probe               ACTIVE: reachability/banner check of a DB endpoint you
                        are AUTHORIZED to inspect (OFF by default; requires
                        --authorized + --target-allowlist + a rate limit).
                        Sends NO SQL/login/payloads.
    explain             describe a rule id and show its safe pattern
    train               interactive SQL-safety quiz from the lesson bank

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

> Blocks above are real `sqlsec` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
  "results": [
    {
      "file": "/path/to/file.sql",
      "issues": [
        {
          "line": 10,
          "column": 5,
          "message": "Unparameterized query: SELECT * FROM users WHERE name = 'John'",
          "severity": "warning"
        }
      ]
    },
    {
      "file": "/path/to/another/file.py",
      "issues": [
        {
          "line": 20,
          "column": 10,
          "message": "Untrusted input used in SQL query: user_input = request.args.get('username')",
          "severity": "error"
        }
      ]
    }
  ]
}
```

<!-- cognis:example:end -->

## Passive by default, active only with explicit authorization

`sqlsec` is **passive by default**: every default subcommand analyzes input you
provide on disk and touches **no network**. There is exactly one active
capability — `sqlsec probe` — and it is **off by default** and
**authorized-use-only** (see below).

**Passive engines (the safe default — no network):**

- **`sqlsec lint`** — a fast, line-by-line heuristic that flags unsafe
  *construction patterns* wherever they appear.
- **`sqlsec taint`** — an **AST data-flow** analyzer that traces an untrusted
  source (request data, `input()`, env, argv, function args) into a SQL
  execution sink across multiple lines, and stays silent when the value is bound
  or allow-listed. It catches multi-line flows the line linter misses and
  suppresses false positives it can't. See
  [`docs/TAINT_ANALYSIS.md`](docs/TAINT_ANALYSIS.md).
- **`sqlsec deps`** — an **offline dependency / SBOM audit**: it parses a
  `requirements.txt`, `package.json`, `package-lock.json`, `Cargo.lock`/`.toml`,
  `go.mod`, or a CycloneDX SBOM you point it at and cross-references each package
  against the **bundled 262k-vulnerability database** — fully offline, air-gap
  ready, no network and no API key.

**Active engine (authorized-use-only, OFF by default):**

- **`sqlsec probe`** — a defensive reachability/banner check of a database
  endpoint **you are authorized to inspect**. It is gated behind an explicit
  `--authorized` flag, a `--target-allowlist` (scope), and a `--rate-limit`, and
  it sends **no SQL, no login, and no exploit payloads**. See
  [Active probe](#active-probe-authorized-use-only).

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

### Audit dependencies against the bundled vuln DB (passive, offline)

`sqlsec deps` reads a dependency manifest, lockfile, or SBOM you provide and
cross-references every package against the bundled 262k-record OSV corpus. It is
**fully offline** — no network, no key — so it works in an air-gapped CI.

```bash
sqlsec deps requirements.txt              # PyPI
sqlsec deps package-lock.json             # npm lock tree
sqlsec deps Cargo.lock                     # crates.io
sqlsec deps go.mod                         # Go modules
sqlsec deps sbom.cdx.json                  # CycloneDX SBOM (any ecosystem)
sqlsec deps requirements.txt --json        # machine-readable
sqlsec deps requirements.txt --fail-on high  # CI gate
```

The format is sniffed from the filename and content. Each vulnerable package is
reported as a `DEP001` finding listing the matching advisory ids (CVE / GHSA /
PYSEC / RUSTSEC …). The match is by package name (and ecosystem when known);
confirm the affected version range against the upstream advisory before acting.
Output supports `--json` and `--sarif`, identical in shape to `lint`/`taint`.

### Active probe (authorized-use-only)

> **⚠ AUTHORIZED USE ONLY.** `sqlsec probe` is the **only** part of the tool
> that touches the network, and it is **disabled by default**. Run it **only**
> against database endpoints you own or are explicitly authorized to inspect.
> Unauthorized scanning may be illegal.

It is a *defensive* check: it opens a TCP connection to a target `host:port`,
reads any greeting banner the service volunteers, and fingerprints the engine.
It **never sends SQL, never attempts a login, and never sends any exploit or
injection payload** — it answers "is my DB port reachable, and what does it
announce itself as", the kind of check a defender runs on their own
infrastructure.

To run, you **must** supply **all** of:

- `--authorized` — an explicit consent flag asserting you are authorized.
- `--target-allowlist host[,host...]` — the scope. Any target not in this list
  is **refused and skipped**; there is no override.
- `--rate-limit <seconds>` — minimum delay between connection attempts
  (defaults to `1.0`).

```bash
# refused — no authorization (exit 2)
sqlsec probe 127.0.0.1:5432

# authorized check of your own database hosts, rate-limited
sqlsec probe db1.internal:5432 db2.internal:3306 \
    --authorized \
    --target-allowlist db1.internal,db2.internal \
    --rate-limit 2 --json
```

A loud authorized-use banner prints on every invocation. Targets outside the
allowlist are reported as `REFUSED` and are never connected to.

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
| SQL100 | critical | (taint) untrusted value reaches `execute`/`executemany` |
| SQL101 | critical | (taint) untrusted value reaches `executescript` |
| DEP001 | high | (deps) dependency has a known vulnerability in the bundled DB |

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

## Language ports

The **core line-level check** (SQL001 concatenation, SQL002 interpolation,
SQL003 `%`-formatting) is ported to three more ecosystems under
[`ports/`](ports/), so the same finding ids surface in Go, Rust, and TypeScript
codebases:

| Port | Path | Entry point |
|------|------|-------------|
| Go         | [`ports/go`](ports/go)     | `sqlsec.ScanText(text) []Finding` |
| Rust       | [`ports/rust`](ports/rust) | `sqlsec::scan_text(text) -> Vec<Finding>` |
| TypeScript | [`ports/ts`](ports/ts)     | `scanText(text): Finding[]` |

Each port has its own tests; the Go and Rust ports are built and tested on
GitHub runners by [`.github/workflows/ports.yml`](.github/workflows/ports.yml).
See [`ports/README.md`](ports/README.md).

## Bundled vulnerability database

Ships `sqlsec/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV
across 7 ecosystems) with detailed metadata; offline stdlib loader
`vulndb_local.VulnDB`, air-gap ready. It is **wired into `sqlsec deps`** (see
above), which audits a manifest / lockfile / SBOM against it entirely offline.

```python
from sqlsec.vulndb_local import VulnDB
db = VulnDB()
db.count()                      # 262351
db.by_cve("CVE-2021-44228")     # records for that CVE
db.by_package("requests")       # records affecting a package
```
