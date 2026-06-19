"""Each authored rule must fire on a bad sample and stay quiet on a safe one."""

import pytest

from sqlsec import rules as rules_mod
from sqlsec.linter import scan_text

# (rule_id, bad_line, safe_line, language)
CASES = [
    (
        "SQL001",
        'query = "SELECT * FROM users WHERE id = " + user_id',
        'cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "py",
    ),
    (
        "SQL002",
        'cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
        'cur.execute("SELECT * FROM users WHERE name = ?", (name,))',
        "py",
    ),
    (
        "SQL003",
        'cur.execute("SELECT * FROM users WHERE email = \'%s\'" % email)',
        'cur.execute("SELECT * FROM users WHERE email = ?", (email,))',
        "py",
    ),
    (
        "SQL004",
        'cur.execute("SELECT * FROM users WHERE role = \'{}\'".format(role))',
        'cur.execute("SELECT * FROM users WHERE role = ?", (role,))',
        "py",
    ),
    (
        "SQL005",
        "EXEC('SELECT * FROM ' + @table)",
        "EXEC sp_get_user @id = 5",
        "sql",
    ),
    (
        "SQL006",
        '"INSERT INTO log VALUES (1); DELETE FROM sessions WHERE u = 2"',
        '"INSERT INTO log VALUES (?)"',
        "py",
    ),
    (
        "SQL007",
        '"SELECT * FROM users WHERE name = \'\' OR \'1\'=\'1\'"',
        '"SELECT * FROM users WHERE name = ?"',
        "py",
    ),
    (
        "SQL008",
        '"SELECT * FROM users WHERE name = \'x\' -- comment"',
        '"SELECT * FROM users WHERE name = ?"',
        "py",
    ),
    (
        "SQL009",
        "cur.execute(prebuilt_query)",
        'cur.execute("SELECT 1", ())',
        "py",
    ),
    (
        "SQL010",
        '"SELECT * FROM products WHERE name LIKE \'%" + term + "%\'"',
        'cur.execute("SELECT * FROM products WHERE name LIKE ?", (pattern,))',
        "py",
    ),
    (
        "SQL011",
        '"SELECT * FROM " + table + " WHERE active = 1"',
        'cur.execute("SELECT id FROM users WHERE active = ?", (1,))',
        "py",
    ),
    (
        "SQL012",
        'cur.executescript("CREATE TABLE t (a);" + payload)',
        'conn.executescript(STATIC_MIGRATION)',
        "py",
    ),
]


@pytest.mark.parametrize("rule_id,bad,safe,lang", CASES)
def test_rule_fires_on_bad(rule_id, bad, safe, lang):
    findings = scan_text(bad, path="bad." + lang, language=lang)
    fired = {f.rule_id for f in findings}
    assert rule_id in fired, f"{rule_id} should fire on: {bad!r} (got {fired})"


@pytest.mark.parametrize("rule_id,bad,safe,lang", CASES)
def test_rule_quiet_on_safe(rule_id, bad, safe, lang):
    findings = scan_text(safe, path="safe." + lang, language=lang)
    fired = {f.rule_id for f in findings}
    assert rule_id not in fired, f"{rule_id} should NOT fire on: {safe!r} (got {fired})"


def test_every_rule_has_a_case():
    covered = {c[0] for c in CASES}
    defined = {r.rule_id for r in rules_mod.all_rules()}
    assert covered == defined, f"uncovered rules: {defined - covered}"


def test_rule_metadata_complete():
    for rule in rules_mod.all_rules():
        assert rule.title
        assert rule.description
        assert rule.safe_pattern
        assert rule.severity in rules_mod.SEVERITY_ORDER
        assert rule.message


def test_get_rule_case_insensitive():
    assert rules_mod.get_rule("sql001") is rules_mod.get_rule("SQL001")
    assert rules_mod.get_rule("nope") is None


def test_severity_rank_ordering():
    assert rules_mod.severity_rank("critical") > rules_mod.severity_rank("high")
    assert rules_mod.severity_rank("high") > rules_mod.severity_rank("low")
    assert rules_mod.severity_rank("bogus") == -1
