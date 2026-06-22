"""Command-line interface for sqlsec.

Subcommands:
  lint     scan .sql/.py files for unsafe query-construction patterns
  taint    AST data-flow analysis: trace untrusted input into SQL sinks
  explain  describe a rule and its safe pattern
  train    interactive quiz from the authored lesson bank (--list to enumerate)

Defensive / educational scope only. Standard library only.
Maintainer: Cognis Digital.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Callable, Optional

from . import __version__
from . import lessons as lessons_mod
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
        print("\nRun 'sqlsec explain <RULE-ID>' for details.", file=out)
        return 0

    # Data-flow rules live in the taint module, not the regex rule set.
    tmeta = taint_mod.TAINT_RULES.get(args.rule_id.upper())
    if tmeta is not None:
        rid = args.rule_id.upper()
        print(f"{rid}: {tmeta['title']}", file=out)
        print(f"Severity: {tmeta['severity']}", file=out)
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
