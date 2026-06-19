"""End-to-end CLI wiring: parser, explain, version."""

import io
import os

import pytest

from sqlsec import cli

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")


def test_main_no_command_prints_help():
    assert cli.main([]) == 0


def test_main_lint_subcommand(capsys):
    rc = cli.main(["lint", os.path.join(EXAMPLES, "safe.py")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No unsafe patterns found." in out


def test_main_lint_fail_on(capsys):
    rc = cli.main(["lint", os.path.join(EXAMPLES, "vulnerable.py"), "--fail-on", "high"])
    assert rc == 1


def test_explain_specific_rule():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        rule_id = "SQL001"

    rc = cli.cmd_explain(Args(), out=out, err=err)
    text = out.getvalue()
    assert rc == 0
    assert "SQL001" in text
    assert "Safe pattern:" in text
    assert "What it catches:" in text


def test_explain_lists_all_when_no_id():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        rule_id = None

    rc = cli.cmd_explain(Args(), out=out, err=err)
    assert rc == 0
    assert "SQL012" in out.getvalue()


def test_explain_unknown_rule():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        rule_id = "SQL999"

    rc = cli.cmd_explain(Args(), out=out, err=err)
    assert rc == 2
    assert "unknown rule" in err.getvalue()


def test_version_flag():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
