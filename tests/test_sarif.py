"""SARIF 2.1.0 export."""

import io
import json
import os

from sqlsec import cli
from sqlsec.linter import scan_file
from sqlsec.rules import all_rules
from sqlsec.sarif import build_sarif

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")


def _vuln_findings():
    return scan_file(os.path.join(EXAMPLES, "vulnerable.py"))


def test_sarif_top_level_shape():
    doc = build_sarif(_vuln_findings())
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_sarif_driver_lists_every_rule():
    doc = build_sarif([])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = {r["id"] for r in rules}
    from sqlsec.taint import TAINT_RULES

    # The catalog covers both the regex rule set and the data-flow (taint)
    # rules, so results from either engine resolve to a descriptor.
    expected = {r.rule_id for r in all_rules()} | set(TAINT_RULES)
    assert ids == expected
    # Each descriptor carries a level and a security-severity for GitHub.
    for r in rules:
        assert r["defaultConfiguration"]["level"] in {"note", "warning", "error"}
        assert "security-severity" in r["properties"]


def test_sarif_results_match_findings():
    findings = _vuln_findings()
    doc = build_sarif(findings)
    results = doc["runs"][0]["results"]
    assert len(results) == len(findings)
    first = results[0]
    assert first["ruleId"] == findings[0].rule_id
    region = first["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == findings[0].line
    assert region["startColumn"] == findings[0].column


def test_sarif_level_mapping():
    # high/critical -> error, medium -> warning, low/info -> note
    doc = build_sarif(_vuln_findings())
    levels = {
        r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]
    }
    assert levels["SQL005"] == "error"  # critical
    assert levels["SQL001"] == "error"  # high
    assert levels["SQL009"] == "warning"  # medium
    assert levels["SQL012"] == "note"  # low


def test_sarif_uri_is_forward_slash():
    doc = build_sarif(_vuln_findings())
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert "\\" not in uri


def test_cli_sarif_flag_emits_valid_json():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        target = os.path.join(EXAMPLES, "vulnerable.py")
        json = False
        sarif = True
        fail_on = None
        select = None
        verbose = False

    rc = cli.cmd_lint(Args(), out=out, err=err)
    assert rc == 0
    doc = json.loads(out.getvalue())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_cli_sarif_with_gate_still_emits_clean_sarif():
    # When --fail-on trips, the SARIF on stdout must stay parseable (the gate
    # message goes to stderr only for the table format).
    out, err = io.StringIO(), io.StringIO()

    class Args:
        target = os.path.join(EXAMPLES, "vulnerable.py")
        json = False
        sarif = True
        fail_on = "high"
        select = None
        verbose = False

    rc = cli.cmd_lint(Args(), out=out, err=err)
    assert rc == 1  # gate trips
    json.loads(out.getvalue())  # stdout is still valid SARIF
