"""Command-line interface for sqlsec.

Subcommands:
  lint     scan .sql/.py files for unsafe query-construction patterns (PASSIVE)
  taint    AST data-flow analysis: trace untrusted input into SQL sinks (PASSIVE)
  deps     audit a manifest/lockfile/SBOM against the bundled offline vuln DB
           (PASSIVE -- no network)
  probe    ACTIVE, authorization-gated DB-endpoint reachability/banner check
           (OFF by default; requires --authorized + an allowlist + a rate limit)
  explain  describe a rule and its safe pattern
  train    interactive quiz from the authored lesson bank (--list to enumerate)

Passive subcommands (lint/taint/deps) are the safe default and touch no network.
The active probe is authorized-use-only. Defensive / educational scope only.
Standard library only. Maintainer: Cognis Digital.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Callable, Optional

from . import __version__
from . import deps as deps_mod
from . import lessons as lessons_mod
from . import probe as probe_mod
from . import rules as rules_mod
from . import taint as taint_mod
from .linter import gate_should_fail, scan_path
from .rules import Finding, severity_rank
from .sarif import build_sarif

SEVERITY_CHOICES = ("info", "low", "medium", "high", "critical")


# --- lint -----------------------------------------------------------------

def _format_table(findings: list[Finding]) -> str:
    if not findings:
        return "No unsafe patterns found."
    rows = []
    header = ("SEVERITY", "RULE", "LOCATION", "MESSAGE")
    rows.append(header)
    for f in findings:
        loc = f"{f.path}:{f.line}:{f.column}"
        rows.append((f.severity.upper(), f.rule_id, loc, f.message))
    widths = [max(len(r[i]) for r in rows) for i in range(len(header))]
    lines = []
    for idx, row in enumerate(rows):
        line = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        lines.append(line.rstrip())
        if idx == 0:
            lines.append("  ".join("-" * widths[i] for i in range(len(header))))
    return "\n".join(lines)


def _severity_counts(findings: list[Finding]) -> dict:
    counts = {s: 0 for s in SEVERITY_CHOICES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def cmd_lint(args, out=None, err=None) -> int:
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr
    target = args.target
    if not os.path.exists(target):
        print(f"error: path not found: {target}", file=err)
        return 2

    rule_set = rules_mod.all_rules()
    if args.select:
        wanted = {r.strip().upper() for r in args.select.split(",") if r.strip()}
        rule_set = [r for r in rule_set if r.rule_id in wanted]
        if not rule_set:
            print(f"error: no known rules in --select {args.select!r}", file=err)
            return 2

    findings = scan_path(target, rules=rule_set)

    if getattr(args, "sarif", False):
        print(json.dumps(build_sarif(findings), indent=2), file=out)
    elif args.json:
        payload = {
            "target": target,
            "tool": "sqlsec",
            "version": __version__,
            "summary": _severity_counts(findings),
            "count": len(findings),
            "findings": [f.as_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2), file=out)
    else:
        print(_format_table(findings), file=out)
        if findings:
            counts = _severity_counts(findings)
            summary = ", ".join(
                f"{counts[s]} {s}" for s in SEVERITY_CHOICES if counts[s]
            )
            print(f"\n{len(findings)} finding(s): {summary}", file=out)
            if args.verbose:
                print("\nRun 'sqlsec explain <RULE>' for the safe pattern.", file=out)

    if gate_should_fail(findings, args.fail_on):
        if not args.json and not getattr(args, "sarif", False):
            print(
                f"\nGate: findings at or above '{args.fail_on}' severity -> failing.",
                file=err,
            )
        return 1
    return 0


# --- taint ----------------------------------------------------------------

def cmd_taint(args, out=None, err=None) -> int:
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr
    target = args.target
    if not os.path.exists(target):
        print(f"error: path not found: {target}", file=err)
        return 2

    seed = not getattr(args, "explicit_only", False)
    findings = taint_mod.analyze_path(target, seed_params=seed)

    if getattr(args, "sarif", False):
        print(json.dumps(build_sarif(findings), indent=2), file=out)
    elif args.json:
        payload = {
            "target": target,
            "tool": "sqlsec",
            "mode": "taint",
            "version": __version__,
            "summary": _severity_counts(findings),
            "count": len(findings),
            "findings": [f.as_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2), file=out)
    else:
        print(_format_table(findings), file=out)
        if findings:
            counts = _severity_counts(findings)
            summary = ", ".join(
                f"{counts[s]} {s}" for s in SEVERITY_CHOICES if counts[s]
            )
            print(f"\n{len(findings)} tainted flow(s): {summary}", file=out)
            if args.verbose:
                print(
                    "\nEach finding traces an untrusted source to a SQL sink. "
                    "Run 'sqlsec explain SQL100' for the safe pattern.",
                    file=out,
                )

    if gate_should_fail(findings, args.fail_on):
        if not args.json and not getattr(args, "sarif", False):
            print(
                f"\nGate: flows at or above '{args.fail_on}' severity -> failing.",
                file=err,
            )
        return 1
    return 0


# --- deps (passive dependency / SBOM audit) -------------------------------

def cmd_deps(args, out=None, err=None) -> int:
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr
    target = args.target
    if not os.path.exists(target):
        print(f"error: path not found: {target}", file=err)
        return 2

    findings = deps_mod.audit_manifest_file(target)

    if getattr(args, "sarif", False):
        print(json.dumps(build_sarif(findings), indent=2), file=out)
    elif args.json:
        payload = {
            "target": target,
            "tool": "sqlsec",
            "mode": "deps",
            "version": __version__,
            "summary": _severity_counts(findings),
            "count": len(findings),
            "findings": [f.as_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2), file=out)
    else:
        print(_format_table(findings), file=out)
        if findings:
            counts = _severity_counts(findings)
            summary = ", ".join(
                f"{counts[s]} {s}" for s in SEVERITY_CHOICES if counts[s]
            )
            print(
                f"\n{len(findings)} vulnerable dependenc"
                f"{'y' if len(findings) == 1 else 'ies'}: {summary}",
                file=out,
            )
            if args.verbose:
                print(
                    "\nOffline name-match against the bundled OSV corpus. "
                    "Verify affected ranges against the upstream advisory.",
                    file=out,
                )

    if gate_should_fail(findings, args.fail_on):
        if not args.json and not getattr(args, "sarif", False):
            print(
                f"\nGate: dependencies at or above '{args.fail_on}' severity "
                f"-> failing.",
                file=err,
            )
        return 1
    return 0


# --- probe (ACTIVE, authorization-gated) ----------------------------------

def cmd_probe(args, out=None, err=None, connector=None, sleep=None) -> int:
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr

    # The loud authorized-use banner prints on every invocation of the active
    # capability, regardless of outcome.
    print(probe_mod.AUTHORIZED_USE_BANNER, file=err)

    allowlist = set()
    if args.target_allowlist:
        allowlist = {h.strip() for h in args.target_allowlist.split(",") if h.strip()}

    scope = probe_mod.Scope(
        authorized=bool(args.authorized),
        allowlist=frozenset(allowlist),
        rate_limit=args.rate_limit,
    )

    kwargs = {}
    if sleep is not None:
        kwargs["sleep"] = sleep
    try:
        results = probe_mod.probe_targets(
            args.targets,
            scope,
            timeout=args.timeout,
            default_port=args.default_port,
            connector=connector,
            **kwargs,
        )
    except probe_mod.AuthorizationError as exc:
        print(f"error: {exc}", file=err)
        return 2

    if args.json:
        payload = {
            "tool": "sqlsec",
            "mode": "probe",
            "version": __version__,
            "authorized": scope.authorized,
            "allowlist": sorted(scope.normalized_allowlist()),
            "rate_limit": scope.rate_limit,
            "count": len(results),
            "results": [r.as_dict() for r in results],
        }
        print(json.dumps(payload, indent=2), file=out)
    else:
        for r in results:
            if r.error and not r.reachable and "out of scope" in (r.error or ""):
                print(f"  {r.target}  REFUSED ({r.error})", file=out)
            elif r.reachable:
                eng = r.engine or "unknown engine"
                extra = f" -- banner: {r.banner}" if r.banner else ""
                print(f"  {r.target}  REACHABLE  [{eng}]{extra}", file=out)
            else:
                print(f"  {r.target}  unreachable ({r.error})", file=out)
        print(f"\n{len(results)} target(s) processed.", file=out)
    return 0


# --- explain --------------------------------------------------------------

def cmd_explain(args, out=None, err=None) -> int:
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr
    if args.rule_id is None:
        # List all rules.
        print("Available rules:\n", file=out)
        for rule in rules_mod.all_rules():
            print(f"  {rule.rule_id}  [{rule.severity:<8}] {rule.title}", file=out)
        print("\nData-flow (taint) rules:\n", file=out)
        for rid, meta in taint_mod.TAINT_RULES.items():
            print(f"  {rid}  [{meta['severity']:<8}] {meta['title']}", file=out)
        print("\nDependency-audit rules:\n", file=out)
        for rid, meta in deps_mod.DEP_RULES.items():
            print(f"  {rid}  [{meta['severity']:<8}] {meta['title']}", file=out)
        print("\nRun 'sqlsec explain <RULE-ID>' for details.", file=out)
        return 0

    # Data-flow + dependency rules live outside the regex rule set.
    extra_meta = dict(taint_mod.TAINT_RULES)
    extra_meta.update(deps_mod.DEP_RULES)
    tmeta = extra_meta.get(args.rule_id.upper())
    if tmeta is not None:
        rid = args.rule_id.upper()
        print(f"{rid}: {tmeta['title']}", file=out)
        print(f"Severity: {tmeta['severity']}", file=out)
        if rid.startswith("DEP"):
            print("Applies to: dependency manifests / lockfiles / SBOM "
                  "(offline DB audit)", file=out)
        else:
            print("Applies to: py (AST data-flow analysis)", file=out)
        print("", file=out)
        print("What it catches:", file=out)
        print(f"  {tmeta['description']}", file=out)
        print("", file=out)
        print("Safe pattern:", file=out)
        for line in tmeta["safe_pattern"].splitlines():
            print(f"  {line}", file=out)
        return 0

    rule = rules_mod.get_rule(args.rule_id)
    if rule is None:
        print(f"error: unknown rule id: {args.rule_id}", file=err)
        return 2

    print(f"{rule.rule_id}: {rule.title}", file=out)
    print(f"Severity: {rule.severity}", file=out)
    print(f"Applies to: {', '.join(rule.languages)}", file=out)
    print("", file=out)
    print("What it catches:", file=out)
    print(f"  {rule.description}", file=out)
    print("", file=out)
    print("Safe pattern:", file=out)
    for line in rule.safe_pattern.splitlines():
        print(f"  {line}", file=out)
    return 0


# --- train ----------------------------------------------------------------

def run_quiz(
    lessons_list,
    ask: Callable[[str, tuple], Optional[int]],
    out=None,
) -> "lessons_mod.QuizResult":
    """Pure-ish quiz driver.

    ``ask(prompt, choices)`` returns the chosen 0-based index, or None to abort.
    All input is funneled through ``ask`` so the loop is unit-testable without
    real stdin. Returns a QuizResult.
    """
    if out is None:
        out = sys.stdout
    result = lessons_mod.QuizResult()
    for lesson, question in lessons_mod.iter_questions(lessons_list):
        print(f"\n[{lesson.topic}] {lesson.title}", file=out)
        choice = ask(question.prompt, question.choices)
        if choice is None:
            break
        ok = result.record(question, choice)
        if ok:
            print("Correct.", file=out)
        else:
            correct_text = question.choices[question.answer_index]
            print(f"Not quite. Answer: {correct_text}", file=out)
        print(f"  Why: {question.rationale}", file=out)

    print(
        f"\nScore: {result.correct}/{result.total} ({result.score_pct:.0f}%)",
        file=out,
    )
    return result


def _make_console_ask(in_stream, out_stream) -> Callable[[str, tuple], Optional[int]]:
    def ask(prompt: str, choices: tuple) -> Optional[int]:
        print(f"\n{prompt}", file=out_stream)
        for i, choice in enumerate(choices, start=1):
            print(f"  {i}) {choice}", file=out_stream)
        while True:
            out_stream.write("Your answer (number, or 'q' to quit): ")
            out_stream.flush()
            raw = in_stream.readline()
            if raw == "":  # EOF
                return None
            raw = raw.strip().lower()
            if raw in ("q", "quit", "exit"):
                return None
            if raw.isdigit():
                idx = int(raw) - 1
                if 0 <= idx < len(choices):
                    return idx
            print("Please enter a valid choice number.", file=out_stream)

    return ask


def cmd_train(args, out=None, err=None, in_stream=None) -> int:
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr
    if args.list:
        print("Lesson topics:\n", file=out)
        for lesson in lessons_mod.LESSONS:
            n = len(lesson.questions)
            print(
                f"  {lesson.topic:<16} {lesson.title}  ({n} question{'s' if n != 1 else ''})",
                file=out,
            )
        print("\nRun 'sqlsec train --topic <topic>' or '--topic all'.", file=out)
        return 0

    selected = lessons_mod.select_lessons(args.topic)
    if not selected:
        print(
            f"error: unknown topic: {args.topic!r}. "
            f"Try one of: {', '.join(lessons_mod.topics())}, or 'all'.",
            file=err,
        )
        return 2

    if in_stream is None:
        in_stream = sys.stdin
    ask = _make_console_ask(in_stream, out)
    result = run_quiz(selected, ask, out=out)
    # Non-zero exit only on outright failure to engage (no questions answered).
    return 0 if result.total > 0 else 0


# --- parser ---------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqlsec",
        description=(
            "Defensive SQL-safety linter + trainer. Scans source for unsafe "
            "query construction and teaches parameterized-query safety. It does "
            "not execute attacks."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"sqlsec {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    p_lint = sub.add_parser(
        "lint", help="scan .sql/.py files for unsafe query-construction patterns"
    )
    p_lint.add_argument("target", help="file or directory to scan")
    p_lint.add_argument(
        "--json", action="store_true", help="emit findings as JSON"
    )
    p_lint.add_argument(
        "--sarif",
        action="store_true",
        help="emit findings as SARIF 2.1.0 (for GitHub code scanning / CI)",
    )
    p_lint.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        default=None,
        help="exit non-zero if any finding is at or above this severity",
    )
    p_lint.add_argument(
        "--select",
        default=None,
        help="comma-separated rule ids to run (default: all rules)",
    )
    p_lint.add_argument(
        "-v", "--verbose", action="store_true", help="print extra hints"
    )
    p_lint.set_defaults(func=cmd_lint)

    p_taint = sub.add_parser(
        "taint",
        help="AST data-flow analysis: trace untrusted input into SQL sinks",
    )
    p_taint.add_argument("target", help="python file or directory to analyze")
    p_taint.add_argument("--json", action="store_true", help="emit findings as JSON")
    p_taint.add_argument(
        "--sarif",
        action="store_true",
        help="emit findings as SARIF 2.1.0 (for GitHub code scanning / CI)",
    )
    p_taint.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        default=None,
        help="exit non-zero if any flow is at or above this severity",
    )
    p_taint.add_argument(
        "--explicit-only",
        action="store_true",
        help=(
            "only report flows that start at an explicit untrusted source "
            "(request data / input / env / argv); do not treat bare function "
            "parameters as tainted (higher precision, lower recall)"
        ),
    )
    p_taint.add_argument(
        "-v", "--verbose", action="store_true", help="print extra hints"
    )
    p_taint.set_defaults(func=cmd_taint)

    # --- deps (passive dependency / SBOM audit) ---------------------------
    p_deps = sub.add_parser(
        "deps",
        help=(
            "audit a manifest/lockfile/SBOM against the bundled offline "
            "vuln DB (PASSIVE -- no network)"
        ),
    )
    p_deps.add_argument(
        "target",
        help=(
            "dependency file to audit: requirements.txt, package.json, "
            "package-lock.json, Cargo.lock/toml, go.mod, or a CycloneDX SBOM"
        ),
    )
    p_deps.add_argument("--json", action="store_true", help="emit findings as JSON")
    p_deps.add_argument(
        "--sarif",
        action="store_true",
        help="emit findings as SARIF 2.1.0 (for GitHub code scanning / CI)",
    )
    p_deps.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        default=None,
        help="exit non-zero if any vulnerable dependency is at/above this severity",
    )
    p_deps.add_argument(
        "-v", "--verbose", action="store_true", help="print extra hints"
    )
    p_deps.set_defaults(func=cmd_deps)

    # --- probe (ACTIVE, authorization-gated) ------------------------------
    p_probe = sub.add_parser(
        "probe",
        help=(
            "ACTIVE: reachability/banner check of a DB endpoint you are "
            "AUTHORIZED to inspect (OFF by default; requires --authorized + "
            "--target-allowlist + a rate limit). Sends NO SQL/login/payloads."
        ),
    )
    p_probe.add_argument(
        "targets", nargs="+",
        help="one or more host[:port] targets (must be in --target-allowlist)",
    )
    p_probe.add_argument(
        "--authorized", action="store_true",
        help=(
            "REQUIRED consent flag asserting you are authorized to inspect the "
            "targets. Without it, the probe is refused."
        ),
    )
    p_probe.add_argument(
        "--target-allowlist", default=None,
        help=(
            "REQUIRED comma-separated scope of permitted hosts/IPs. Targets not "
            "in this list are refused and skipped."
        ),
    )
    p_probe.add_argument(
        "--rate-limit", dest="rate_limit", type=float, default=1.0,
        help="minimum seconds between connection attempts (default: 1.0)",
    )
    p_probe.add_argument(
        "--timeout", type=float, default=3.0,
        help="per-target connection timeout in seconds (default: 3.0)",
    )
    p_probe.add_argument(
        "--default-port", dest="default_port", type=int, default=5432,
        help="port to use when a target omits one (default: 5432 / PostgreSQL)",
    )
    p_probe.add_argument(
        "--json", action="store_true", help="emit results as JSON"
    )
    p_probe.set_defaults(func=cmd_probe)

    p_explain = sub.add_parser(
        "explain", help="describe a rule id and show its safe pattern"
    )
    p_explain.add_argument(
        "rule_id", nargs="?", default=None, help="rule id (e.g. SQL001); omit to list all"
    )
    p_explain.set_defaults(func=cmd_explain)

    p_train = sub.add_parser(
        "train", help="interactive SQL-safety quiz from the lesson bank"
    )
    p_train.add_argument(
        "--topic", default=None, help="lesson topic to quiz (or 'all')"
    )
    p_train.add_argument(
        "--list", action="store_true", help="list lesson topics and exit"
    )
    p_train.set_defaults(func=cmd_train)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
