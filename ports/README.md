# sqlsec language ports

Polyglot ports of the **core sqlsec check** — a passive, offline heuristic that
flags unsafe SQL-query construction in source text. Each port implements the
three highest-signal rules from the Python reference so finding ids line up
across ecosystems:

| Rule   | Severity | Catches                                              |
|--------|----------|------------------------------------------------------|
| SQL001 | high     | SQL built by string concatenation with a variable    |
| SQL002 | high     | a value interpolated into SQL (f-string / template / format macro) |
| SQL003 | high     | SQL assembled with printf-style `%` formatting        |

All ports are **defensive / educational** only: they parse text, never execute
anything, and make no network calls.

| Port | Path | Entry point | Test command |
|------|------|-------------|--------------|
| Go         | `ports/go`   | `sqlsec.ScanText(text) []Finding` | `cd ports/go && go test ./...` |
| Rust       | `ports/rust` | `sqlsec::scan_text(text) -> Vec<Finding>` | `cd ports/rust && cargo test` |
| TypeScript | `ports/ts`   | `scanText(text): Finding[]` | `cd ports/ts && npm test` |

The Go and Rust ports are built and tested on GitHub runners by
`.github/workflows/ports.yml` (the maintainer's local box has no Go/Rust
toolchain). The TypeScript port's rule logic is verified locally and type-checked
in CI.

These ports cover the line-level construction check only. The full passive
feature set — AST taint analysis, the offline dependency/SBOM audit against the
bundled 262k-vuln database, SARIF output — and the authorization-gated active
probe live in the Python package.
