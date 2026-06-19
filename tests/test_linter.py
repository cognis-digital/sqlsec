"""Linter engine, examples, and the --fail-on gate."""

import io
import os

import pytest

from sqlsec import cli
from sqlsec.linter import (
    gate_should_fail,
    max_severity_rank,
    scan_file,
    scan_path,
    scan_text,
)

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")


def test_vulnerable_example_has_many_findings():
    findings = scan_file(os.path.join(EXAMPLES, "vulnerable.py"))
    fired = {f.rule_id for f in findings}
    # The vulnerable sample exercises every rule that targets python.
    assert len(fired) >= 10, f"expected broad coverage, got {sorted(fired)}"


def test_safe_example_is_clean():
    findings = scan_file(os.path.join(EXAMPLES, "safe.py"))
    assert findings == [], f"safe.py should be clean, got {[f.rule_id for f in findings]}"


def test_python_comment_is_not_scanned():
    text = '# query = "SELECT * FROM t WHERE id = " + x\nx = 1\n'
    findings = scan_text(text, path="c.py", language="py")
    assert findings == []


def test_comment_after_code_still_scans_code():
    text = 'q = "SELECT * FROM t WHERE id = " + x  # trailing note\n'
    findings = scan_text(text, path="c.py", language="py")
    assert any(f.rule_id == "SQL001" for f in findings)


def test_scan_path_recurses_directory():
    findings = scan_path(EXAMPLES)
    paths = {os.path.basename(f.path) for f in findings}
    assert "vulnerable.py" in paths
    assert "safe.py" not in paths  # clean file contributes nothing


def test_findings_are_sorted():
    findings = scan_path(EXAMPLES)
    keys = [(f.path, f.line, f.column, f.rule_id) for f in findings]
    assert keys == sorted(keys)


def test_gate_should_fail_thresholds():
    findings = scan_file(os.path.join(EXAMPLES, "vulnerable.py"))
    assert gate_should_fail(findings, "high") is True
    assert gate_should_fail(findings, "critical") is True  # SQL005 is critical
    assert gate_should_fail(findings, None) is False


def test_gate_no_fail_when_below_threshold():
    text = 'cur.execute(prebuilt_query)\n'  # SQL009 = medium only
    findings = scan_text(text, path="m.py", language="py")
    assert max(f.severity for f in findings) == "medium"
    assert gate_should_fail(findings, "high") is False
    assert gate_should_fail(findings, "medium") is True


def test_lint_cli_exit_codes():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        target = os.path.join(EXAMPLES, "vulnerable.py")
        json = False
        fail_on = "high"
        select = None
        verbose = False

    rc = cli.cmd_lint(Args(), out=out, err=err)
    assert rc == 1  # gate trips on high+


def test_lint_cli_clean_exit_zero():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        target = os.path.join(EXAMPLES, "safe.py")
        json = False
        fail_on = "high"
        select = None
        verbose = False

    rc = cli.cmd_lint(Args(), out=out, err=err)
    assert rc == 0
    assert "No unsafe patterns found." in out.getvalue()


def test_lint_cli_json_output():
    import json as _json

    out, err = io.StringIO(), io.StringIO()

    class Args:
        target = os.path.join(EXAMPLES, "vulnerable.py")
        json = True
        fail_on = None
        select = None
        verbose = False

    rc = cli.cmd_lint(Args(), out=out, err=err)
    assert rc == 0
    payload = _json.loads(out.getvalue())
    assert payload["tool"] == "sqlsec"
    assert payload["count"] == len(payload["findings"])
    assert payload["count"] > 0


def test_lint_missing_path_returns_2():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        target = os.path.join(EXAMPLES, "does_not_exist.py")
        json = False
        fail_on = None
        select = None
        verbose = False

    assert cli.cmd_lint(Args(), out=out, err=err) == 2


def test_lint_select_restricts_rules():
    out, err = io.StringIO(), io.StringIO()
    import json as _json

    class Args:
        target = os.path.join(EXAMPLES, "vulnerable.py")
        json = True
        fail_on = None
        select = "SQL001"
        verbose = False

    cli.cmd_lint(Args(), out=out, err=err)
    payload = _json.loads(out.getvalue())
    assert {f["rule_id"] for f in payload["findings"]} == {"SQL001"}
