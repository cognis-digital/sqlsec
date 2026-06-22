"""CLI integration for `sqlsec taint` and the taint/explain/SARIF wiring."""

import io
import json as _json
import os

import pytest

from sqlsec import cli

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")
FLOW = os.path.join(EXAMPLES, "taint_flow.py")
SAFE = os.path.join(EXAMPLES, "taint_safe.py")


class _Args:
    def __init__(self, **kw):
        self.target = FLOW
        self.json = False
        self.sarif = False
        self.fail_on = None
        self.explicit_only = True
        self.verbose = False
        self.__dict__.update(kw)


def test_taint_table_output():
    out, err = io.StringIO(), io.StringIO()
    rc = cli.cmd_taint(_Args(), out=out, err=err)
    assert rc == 0
    text = out.getvalue()
    assert "SQL100" in text
    assert "tainted flow" in text


def test_taint_clean_file():
    out, err = io.StringIO(), io.StringIO()
    rc = cli.cmd_taint(_Args(target=SAFE), out=out, err=err)
    assert rc == 0
    assert "No unsafe patterns found." in out.getvalue()


def test_taint_missing_path():
    out, err = io.StringIO(), io.StringIO()
    rc = cli.cmd_taint(_Args(target="does_not_exist.py"), out=out, err=err)
    assert rc == 2
    assert "path not found" in err.getvalue()


def test_taint_json_output():
    out, err = io.StringIO(), io.StringIO()
    rc = cli.cmd_taint(_Args(json=True), out=out, err=err)
    assert rc == 0
    payload = _json.loads(out.getvalue())
    assert payload["tool"] == "sqlsec"
    assert payload["mode"] == "taint"
    assert payload["count"] == 9
    assert payload["count"] == len(payload["findings"])
    assert payload["summary"]["critical"] == 9


def test_taint_fail_on_gate_trips():
    out, err = io.StringIO(), io.StringIO()
    rc = cli.cmd_taint(_Args(fail_on="high"), out=out, err=err)
    assert rc == 1
    assert "Gate" in err.getvalue()


def test_taint_fail_on_gate_clean_file_passes():
    out, err = io.StringIO(), io.StringIO()
    rc = cli.cmd_taint(_Args(target=SAFE, fail_on="critical"), out=out, err=err)
    assert rc == 0


def test_taint_explicit_only_vs_seeded():
    # A file with only a bare-parameter flow: explicit-only sees nothing, the
    # default (seeded) mode flags it.
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "param.py")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(
                "def get(uid, cur):\n"
                "    cur.execute('SELECT * FROM u WHERE id=' + uid)\n"
            )
        out1 = io.StringIO()
        rc1 = cli.cmd_taint(
            _Args(target=p, explicit_only=True), out=out1, err=io.StringIO()
        )
        assert rc1 == 0
        assert "No unsafe patterns found." in out1.getvalue()

        out2 = io.StringIO()
        rc2 = cli.cmd_taint(
            _Args(target=p, explicit_only=False), out=out2, err=io.StringIO()
        )
        assert "SQL100" in out2.getvalue()


def test_taint_sarif_output():
    out, err = io.StringIO(), io.StringIO()
    rc = cli.cmd_taint(_Args(sarif=True), out=out, err=err)
    assert rc == 0
    doc = _json.loads(out.getvalue())
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert len(results) == 9
    rule_ids = {r["ruleId"] for r in results}
    assert "SQL100" in rule_ids
    # Every emitted result resolves to a declared rule descriptor.
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids <= declared


def test_taint_verbose_hint():
    out, err = io.StringIO(), io.StringIO()
    cli.cmd_taint(_Args(verbose=True), out=out, err=err)
    assert "explain SQL100" in out.getvalue()


# --- explain knows the taint rules ----------------------------------------

def test_explain_lists_taint_rules():
    out, err = io.StringIO(), io.StringIO()

    class A:
        rule_id = None

    cli.cmd_explain(A(), out=out, err=err)
    text = out.getvalue()
    assert "SQL100" in text
    assert "SQL101" in text
    assert "Data-flow" in text


@pytest.mark.parametrize("rid", ["SQL100", "SQL101", "sql100"])
def test_explain_taint_rule_detail(rid):
    out, err = io.StringIO(), io.StringIO()

    class A:
        rule_id = None

    a = A()
    a.rule_id = rid
    rc = cli.cmd_explain(a, out=out, err=err)
    assert rc == 0
    text = out.getvalue()
    assert rid.upper() in text
    assert "Safe pattern:" in text


# --- parser wiring --------------------------------------------------------

def test_parser_has_taint_subcommand():
    parser = cli.build_parser()
    args = parser.parse_args(["taint", "some/path", "--explicit-only", "--json"])
    assert args.command == "taint"
    assert args.target == "some/path"
    assert args.explicit_only is True
    assert args.json is True
    assert args.func is cli.cmd_taint


def test_taint_end_to_end_via_main(capsys):
    rc = cli.main(["taint", FLOW, "--explicit-only"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "SQL100" in captured.out


def test_taint_end_to_end_fail_on_via_main():
    rc = cli.main(["taint", FLOW, "--fail-on", "high"])
    assert rc == 1
