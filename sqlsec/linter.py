"""File/directory scanning engine for sqlsec.

Walks .py and .sql sources, applies the authored rule set line by line, and
returns a list of Finding objects. Comment-only lines in Python are skipped so
the linter does not flag examples discussed in docstrings/comments... except
where a rule explicitly targets SQL comment sequences inside literals.

Original work by Cognis Digital.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional

from .rules import Finding, Rule, all_rules, severity_rank

SCANNABLE_EXTENSIONS = {".py": "py", ".sql": "sql"}


def _strip_python_line_comment(line: str) -> str:
    """Remove a trailing ``# ...`` comment that is outside any string.

    A tiny state machine: we only treat ``#`` as a comment when not inside a
    single- or double-quoted string. This prevents false positives where a rule
    pattern would otherwise match commentary, while still scanning the code part
    of the line.
    """
    out = []
    quote = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out)


def language_for(path: str) -> Optional[str]:
    _, ext = os.path.splitext(path)
    return SCANNABLE_EXTENSIONS.get(ext.lower())


def iter_source_files(target: str) -> Iterable[str]:
    """Yield scannable files under ``target`` (a file or a directory)."""
    if os.path.isfile(target):
        if language_for(target) is not None:
            yield target
        return
    for root, dirs, files in os.walk(target):
        # Skip common noise directories.
        dirs[:] = [
            d
            for d in dirs
            if d not in {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox"}
        ]
        for name in sorted(files):
            full = os.path.join(root, name)
            if language_for(full) is not None:
                yield full


def scan_text(
    text: str,
    path: str = "<string>",
    language: Optional[str] = None,
    rules: Optional[list[Rule]] = None,
) -> list[Finding]:
    """Scan raw source text and return findings.

    ``language`` ("py" or "sql") restricts which rules apply. When None it is
    inferred from the path extension and defaults to scanning everything.
    """
    if rules is None:
        rules = all_rules()
    if language is None:
        language = language_for(path)

    findings: list[Finding] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line
        if language == "py":
            line = _strip_python_line_comment(raw_line)
        if not line.strip():
            continue
        for rule in rules:
            if language is not None and language not in rule.languages:
                continue
            m = rule.match(line)
            if m is None:
                continue
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    message=rule.message,
                    path=path,
                    line=lineno,
                    column=m.start() + 1,
                    snippet=raw_line.strip()[:200],
                    suggestion=rule.safe_pattern,
                )
            )
    return findings


def scan_file(path: str, rules: Optional[list[Rule]] = None) -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return scan_text(text, path=path, language=language_for(path), rules=rules)


def scan_path(target: str, rules: Optional[list[Rule]] = None) -> list[Finding]:
    """Scan a file or recurse a directory. Returns all findings, sorted."""
    findings: list[Finding] = []
    for path in iter_source_files(target):
        findings.extend(scan_file(path, rules=rules))
    findings.sort(key=lambda f: (f.path, f.line, f.column, f.rule_id))
    return findings


def max_severity_rank(findings: Iterable[Finding]) -> int:
    rank = -1
    for f in findings:
        rank = max(rank, severity_rank(f.severity))
    return rank


def gate_should_fail(findings: Iterable[Finding], fail_on: Optional[str]) -> bool:
    """True when any finding is at or above the ``fail_on`` severity."""
    if not fail_on:
        return False
    threshold = severity_rank(fail_on)
    if threshold < 0:
        return False
    return max_severity_rank(findings) >= threshold
