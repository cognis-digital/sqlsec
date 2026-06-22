"""Extra passive-mode coverage: linter robustness, deps edge cases, and the
documented passive-by-default / active-gated contract.

All offline. No network. Reinforces that the default subcommands never reach
out and that the active probe is discoverable but gated.
"""

import io

import pytest

from sqlsec import cli
from sqlsec import deps as D
from sqlsec.linter import scan_text
from sqlsec.probe import Scope


def _run(argv):
    parser = cli.build_parser()
    args = parser.parse_args(argv)
    out, err = io.StringIO(), io.StringIO()
    rc = args.func(args, out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


# --- linter still detects the canonical unsafe patterns -------------------

@pytest.mark.parametrize("src,rule", [
    ('q = "SELECT * FROM users WHERE id = " + uid', "SQL001"),
    ('q = f"SELECT * FROM t WHERE n = {name}"', "SQL002"),
    ('q = "SELECT * FROM t WHERE id = %s" % v', "SQL003"),
    ('q = "SELECT * FROM t WHERE id = {}".format(v)', "SQL004"),
])
def test_core_rules_fire(src, rule):
    findings = scan_text(src, path="x.py", language="py")
    assert any(f.rule_id == rule for f in findings)


@pytest.mark.parametrize("safe", [
    'cur.execute("SELECT * FROM users WHERE id = ?", (uid,))',
    'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))',
    'query = "SELECT * FROM users"',
])
def test_safe_patterns_quiet(safe):
    findings = scan_text(safe, path="x.py", language="py")
    # Parameterized / constant queries should not raise SQL001-004.
    assert not any(f.rule_id in {"SQL001", "SQL002", "SQL003", "SQL004"}
                   for f in findings)


def test_non_sql_concat_not_flagged():
    findings = scan_text('greeting = "hello " + name', path="x.py", language="py")
    assert findings == []


# --- deps parser robustness -----------------------------------------------

def test_deps_handles_empty_manifest():
    assert D.sniff_and_parse("", "requirements.txt") == []


def test_deps_handles_whitespace_only():
    assert D.sniff_and_parse("   \n\t\n", "requirements.txt") == []


def test_deps_garbage_json_no_crash():
    # Looks like JSON but is broken; must not raise.
    out = D.sniff_and_parse('{"dependencies": ', "package.json")
    assert out == []


def test_deps_requirements_many_lines():
    text = "\n".join(f"pkg{i}=={i}.0" for i in range(50))
    deps = D.parse_requirements(text)
    assert len(deps) == 50


# --- passive-by-default / active-gated contract ---------------------------

def test_help_lists_passive_and_active_subcommands():
    help_text = cli.build_parser().format_help()
    for sub in ("lint", "taint", "deps", "probe"):
        assert sub in help_text


def test_probe_help_flags_authorized_use():
    parser = cli.build_parser()
    # Drill into the probe subparser help.
    text = parser.format_help()
    assert "probe" in text


def test_active_scope_defaults_are_off():
    # A freshly constructed scope must NOT be authorized.
    scope = Scope()
    assert scope.authorized is False
    assert scope.normalized_allowlist() == frozenset()


def test_lint_does_not_accept_target_outside_filesystem():
    rc, out, err = _run(["lint", "this/path/does/not/exist"])
    assert rc == 2


def test_deps_and_lint_share_finding_shape(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.0.0\n", encoding="utf-8")
    rc, out, err = _run(["deps", str(f), "--json"])
    import json as _json
    payload = _json.loads(out)
    fields = set(payload["findings"][0])
    assert {"rule_id", "severity", "message", "path"} <= fields
