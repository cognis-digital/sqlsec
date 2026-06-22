"""Every demo must actually produce the findings its SCENARIO advertises.

These are real-use-case fixtures under demos/. Each entry below pins the rule
ids that demo is expected to fire (or an empty set for the clean demo). This is
the guard against demo rot: if a rule or a demo changes, this test fails loudly.
"""

import os

import pytest

from sqlsec.linter import scan_path

DEMOS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")

# demo folder -> rule ids that MUST appear in its findings
EXPECTED = {
    "01-flask-user-search": {"SQL001", "SQL002"},
    "02-auth-review": {"SQL007", "SQL008", "SQL009"},
    "03-analytics-report": {"SQL001", "SQL004", "SQL009", "SQL011"},
    "04-legacy-stored-proc": {"SQL001", "SQL005"},
    "05-data-migration": {"SQL001", "SQL006", "SQL012"},
    "06-ecommerce-filter": {"SQL001", "SQL004", "SQL009", "SQL010"},
    "07-batch-etl": {"SQL003"},
    "08-clean-refactor": set(),  # the clean rewrite -> zero findings
    "09-orm-raw-escape": {"SQL006", "SQL009"},
    "10-ci-gate": {"SQL002", "SQL009"},
}


def test_demos_dir_exists():
    assert os.path.isdir(DEMOS)


@pytest.mark.parametrize("demo,expected", sorted(EXPECTED.items()))
def test_demo_fires_expected_rules(demo, expected):
    findings = scan_path(os.path.join(DEMOS, demo))
    fired = {f.rule_id for f in findings}
    if not expected:
        assert fired == set(), f"{demo} should be clean, got {sorted(fired)}"
    else:
        missing = expected - fired
        assert not missing, f"{demo} missing expected rules {sorted(missing)}"


@pytest.mark.parametrize("demo", sorted(EXPECTED))
def test_every_demo_has_a_scenario(demo):
    assert os.path.isfile(os.path.join(DEMOS, demo, "SCENARIO.md"))


def test_demos_cover_every_rule():
    """Across all demos, every authored rule should fire at least once."""
    from sqlsec.rules import all_rules

    fired = set()
    for demo in EXPECTED:
        fired |= {f.rule_id for f in scan_path(os.path.join(DEMOS, demo))}
    all_ids = {r.rule_id for r in all_rules()}
    assert all_ids <= fired, f"rules never demoed: {sorted(all_ids - fired)}"
