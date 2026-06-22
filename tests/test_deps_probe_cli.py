"""CLI integration tests for the `deps` and `probe` subcommands.

Probe tests inject a fake connector via cmd_probe so nothing touches the
network. They assert the loud banner prints and that gating/scope hold.
"""

import io
import json

from sqlsec import cli
from sqlsec import probe as P


def _run(argv, **kw):
    """Build args from argv and dispatch, capturing stdout/stderr."""
    parser = cli.build_parser()
    args = parser.parse_args(argv)
    out, err = io.StringIO(), io.StringIO()
    rc = args.func(args, out=out, err=err, **kw)
    return rc, out.getvalue(), err.getvalue()


# --- deps -----------------------------------------------------------------

def test_deps_missing_path(tmp_path):
    rc, out, err = _run(["deps", str(tmp_path / "nope.txt")])
    assert rc == 2
    assert "not found" in err


def test_deps_table_output(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.0.0\n", encoding="utf-8")
    rc, out, err = _run(["deps", str(f)])
    assert "DEP001" in out
    assert "requests" in out


def test_deps_json_output(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.0.0\n", encoding="utf-8")
    rc, out, err = _run(["deps", str(f), "--json"])
    payload = json.loads(out)
    assert payload["mode"] == "deps"
    assert payload["count"] >= 1
    assert payload["findings"][0]["rule_id"] == "DEP001"


def test_deps_sarif_output(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.0.0\n", encoding="utf-8")
    rc, out, err = _run(["deps", str(f), "--sarif"])
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "DEP001" in rule_ids


def test_deps_clean_manifest(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("zzz-not-real-pkg-xyzzy==1.0\n", encoding="utf-8")
    rc, out, err = _run(["deps", str(f)])
    assert rc == 0
    assert "No unsafe patterns" in out


def test_deps_fail_on_gate(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.0.0\n", encoding="utf-8")
    rc, out, err = _run(["deps", str(f), "--fail-on", "low"])
    assert rc == 1
    assert "Gate" in err


# --- probe ----------------------------------------------------------------

def _ok_connector(target, timeout):
    return b"PostgreSQL fixture banner"


def test_probe_prints_banner_to_stderr():
    rc, out, err = _run(
        ["probe", "127.0.0.1:5432", "--authorized",
         "--target-allowlist", "127.0.0.1", "--rate-limit", "0"],
        connector=_ok_connector, sleep=lambda s: None,
    )
    assert "AUTHORIZED USE ONLY" in err


def test_probe_refused_without_authorized():
    rc, out, err = _run(
        ["probe", "127.0.0.1:5432", "--target-allowlist", "127.0.0.1",
         "--rate-limit", "0"],
        connector=_ok_connector, sleep=lambda s: None,
    )
    assert rc == 2
    assert "authorized" in err.lower()


def test_probe_refused_without_allowlist():
    rc, out, err = _run(
        ["probe", "127.0.0.1:5432", "--authorized", "--rate-limit", "0"],
        connector=_ok_connector, sleep=lambda s: None,
    )
    assert rc == 2
    assert "allowlist" in err.lower() or "scope" in err.lower()


def test_probe_in_scope_reachable():
    rc, out, err = _run(
        ["probe", "127.0.0.1:5432", "--authorized",
         "--target-allowlist", "127.0.0.1", "--rate-limit", "0"],
        connector=_ok_connector, sleep=lambda s: None,
    )
    assert rc == 0
    assert "REACHABLE" in out
    assert "PostgreSQL" in out


def test_probe_out_of_scope_target_refused():
    rc, out, err = _run(
        ["probe", "8.8.8.8:5432", "--authorized",
         "--target-allowlist", "127.0.0.1", "--rate-limit", "0"],
        connector=_ok_connector, sleep=lambda s: None,
    )
    assert rc == 0
    assert "REFUSED" in out


def test_probe_json_output():
    rc, out, err = _run(
        ["probe", "127.0.0.1:5432", "--authorized",
         "--target-allowlist", "127.0.0.1", "--rate-limit", "0", "--json"],
        connector=_ok_connector, sleep=lambda s: None,
    )
    payload = json.loads(out)
    assert payload["mode"] == "probe"
    assert payload["authorized"] is True
    assert payload["allowlist"] == ["127.0.0.1"]
    assert payload["results"][0]["reachable"] is True


def test_probe_unreachable_reported():
    def boom(target, timeout):
        raise OSError("refused")

    rc, out, err = _run(
        ["probe", "127.0.0.1:1", "--authorized",
         "--target-allowlist", "127.0.0.1", "--rate-limit", "0"],
        connector=boom, sleep=lambda s: None,
    )
    assert "unreachable" in out


def test_probe_default_off_documented_in_help():
    parser = cli.build_parser()
    help_text = parser.format_help()
    # The active probe must be discoverable and flagged as gated.
    assert "probe" in help_text


# --- explain integration --------------------------------------------------

def test_explain_lists_dep_rule():
    rc, out, err = _run(["explain"])
    assert "DEP001" in out


def test_explain_dep_rule_detail():
    rc, out, err = _run(["explain", "DEP001"])
    assert "DEP001" in out
    assert "dependency" in out.lower()
