"""Tests for the passive dependency / SBOM audit (sqlsec.deps).

All offline. Parser tests use synthetic manifests; the DB cross-reference uses
a tiny in-memory fake VulnDB so they never depend on the bundled corpus
contents (a couple of integration tests do touch the real bundle).
"""

import json

import pytest

from sqlsec import deps as D
from sqlsec.deps import (
    Dependency,
    audit_dependencies,
    audit_manifest_text,
    parse_cargo,
    parse_cyclonedx,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_plain,
    parse_requirements,
    sniff_and_parse,
)


class FakeDB:
    """Minimal stand-in for VulnDB.by_package."""

    def __init__(self, table):
        # table: {name_lower: [records]}
        self.table = {k.lower(): v for k, v in table.items()}

    def by_package(self, name, ecosystem=None):
        recs = self.table.get((name or "").lower(), [])
        if ecosystem:
            return [r for r in recs if r.get("ecosystem", "").lower() == ecosystem.lower()]
        return recs


# --- requirements.txt -----------------------------------------------------

def test_parse_requirements_basic():
    deps = parse_requirements("requests==2.0.0\nflask>=1.0\nclick\n")
    names = {d.name for d in deps}
    assert names == {"requests", "flask", "click"}
    assert all(d.ecosystem == "PyPI" for d in deps)


def test_parse_requirements_pins_version():
    deps = parse_requirements("requests==2.28.1\n")
    assert deps[0].version == "2.28.1"


def test_parse_requirements_skips_comments_and_blanks():
    deps = parse_requirements("# a comment\n\n   \nfoo==1.0\n")
    assert [d.name for d in deps] == ["foo"]


def test_parse_requirements_skips_options_and_urls():
    text = "-r other.txt\n--hash=sha256:abc\nhttps://x/y.whl\nfoo==1\n"
    deps = parse_requirements(text)
    assert [d.name for d in deps] == ["foo"]


def test_parse_requirements_strips_extras():
    deps = parse_requirements("celery[redis]==5.0\n")
    assert deps[0].name == "celery"
    assert deps[0].version == "5.0"


def test_parse_requirements_strips_env_markers():
    deps = parse_requirements('foo==1.0 ; python_version < "3.8"\n')
    assert deps[0].name == "foo"
    assert deps[0].version == "1.0"


def test_parse_requirements_range_specifiers():
    deps = parse_requirements("foo~=1.4\nbar!=2.0\n")
    names = {d.name for d in deps}
    assert names == {"foo", "bar"}


# --- package.json / lock --------------------------------------------------

def test_parse_package_json_deps_and_dev():
    text = json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "~29.0.0"},
    })
    deps = parse_package_json(text)
    names = {d.name for d in deps}
    assert names == {"express", "jest"}
    assert all(d.ecosystem == "npm" for d in deps)


def test_parse_package_json_strips_range_prefix():
    deps = parse_package_json(json.dumps({"dependencies": {"left-pad": "^1.3.0"}}))
    assert deps[0].version == "1.3.0"


def test_parse_package_json_invalid_returns_empty():
    assert parse_package_json("{not json") == []


def test_parse_package_lock_v3_packages():
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/b": {"version": "1.0.0"},
        },
    })
    deps = parse_package_lock(text)
    names = {d.name for d in deps}
    assert "lodash" in names and "b" in names
    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.version == "4.17.20"


def test_parse_package_lock_v1_dependencies():
    text = json.dumps({
        "lockfileVersion": 1,
        "dependencies": {"minimist": {"version": "1.2.0"}},
    })
    deps = parse_package_lock(text)
    assert any(d.name == "minimist" and d.version == "1.2.0" for d in deps)


# --- cargo ----------------------------------------------------------------

def test_parse_cargo_lock():
    text = (
        '[[package]]\nname = "serde"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "tokio"\nversion = "1.20.0"\n'
    )
    deps = parse_cargo(text)
    names = {d.name for d in deps}
    assert names == {"serde", "tokio"}
    assert all(d.ecosystem == "crates.io" for d in deps)


def test_parse_cargo_toml_dependencies():
    text = '[package]\nname = "x"\n\n[dependencies]\nserde = "1.0"\nrand = "0.8"\n'
    deps = parse_cargo(text)
    names = {d.name for d in deps}
    assert names == {"serde", "rand"}


# --- go.mod ---------------------------------------------------------------

def test_parse_go_mod_block():
    text = (
        "module example.com/x\n\ngo 1.20\n\n"
        "require (\n"
        "\tgithub.com/gin-gonic/gin v1.9.0\n"
        "\tgithub.com/pkg/errors v0.9.1 // indirect\n"
        ")\n"
    )
    deps = parse_go_mod(text)
    names = {d.name for d in deps}
    assert "github.com/gin-gonic/gin" in names
    assert "github.com/pkg/errors" in names
    assert all(d.ecosystem == "Go" for d in deps)


def test_parse_go_mod_single_line():
    deps = parse_go_mod("require github.com/foo/bar v1.2.3\n")
    assert deps[0].name == "github.com/foo/bar"
    assert deps[0].version == "1.2.3"


# --- cyclonedx ------------------------------------------------------------

def test_parse_cyclonedx_components_and_purl_ecosystem():
    text = json.dumps({
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "requests", "version": "2.0.0", "purl": "pkg:pypi/requests@2.0.0"},
            {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
        ],
    })
    deps = parse_cyclonedx(text)
    eco = {d.name: d.ecosystem for d in deps}
    assert eco["requests"] == "PyPI"
    assert eco["lodash"] == "npm"


def test_parse_cyclonedx_invalid_returns_empty():
    assert parse_cyclonedx("nope") == []


# --- plain ----------------------------------------------------------------

def test_parse_plain_list():
    deps = parse_plain("foo\nbar==1.0\n# skip\n")
    names = {d.name for d in deps}
    assert names == {"foo", "bar"}


# --- sniffing -------------------------------------------------------------

def test_sniff_package_lock_by_content():
    text = json.dumps({"lockfileVersion": 2, "packages": {}})
    assert sniff_and_parse(text, "whatever.json") is not None


def test_sniff_requirements_by_name():
    deps = sniff_and_parse("foo==1.0\n", "requirements-dev.txt")
    assert deps[0].name == "foo"


def test_sniff_cargo_by_content():
    deps = sniff_and_parse('[[package]]\nname = "x"\nversion = "1"\n', "weird")
    assert deps[0].name == "x"


def test_sniff_go_mod_by_content():
    deps = sniff_and_parse("module example.com/x\nrequire foo v1\n", "anything")
    assert any(d.ecosystem == "Go" for d in deps)


def test_sniff_cyclonedx_by_content():
    text = json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "z"}]})
    deps = sniff_and_parse(text, "bom.json")
    assert deps[0].name == "z"


# --- audit (with fake DB) -------------------------------------------------

def _rec(rid, eco="PyPI", sev="HIGH", aliases=None):
    return {"id": rid, "ecosystem": eco, "severity": sev,
            "aliases": aliases or [], "packages": []}


def test_audit_flags_only_known_vulnerable():
    db = FakeDB({"badpkg": [_rec("GHSA-1")]})
    deps = [Dependency("badpkg", "1.0", "PyPI"), Dependency("safepkg", "1.0", "PyPI")]
    findings = audit_dependencies(deps, db=db)
    assert len(findings) == 1
    assert findings[0].name == "badpkg"


def test_audit_severity_picks_worst():
    db = FakeDB({"p": [_rec("a", sev="LOW"), _rec("b", sev="CRITICAL")]})
    findings = audit_dependencies([Dependency("p", None, "PyPI")], db=db)
    assert findings[0].severity() == "critical"


def test_audit_default_severity_when_unknown():
    db = FakeDB({"p": [_rec("a", sev="")]})
    findings = audit_dependencies([Dependency("p", None, "PyPI")], db=db)
    assert findings[0].severity() == "medium"


def test_audit_ecosystem_agnostic_fallback():
    # Record labelled npm; dep claims PyPI -> first lookup misses, fallback hits.
    db = FakeDB({"p": [_rec("a", eco="npm")]})
    findings = audit_dependencies([Dependency("p", None, "PyPI")], db=db)
    assert len(findings) == 1


def test_audit_empty_when_no_matches():
    db = FakeDB({})
    findings = audit_dependencies([Dependency("nope", None, None)], db=db)
    assert findings == []


def test_dep_finding_to_finding_shape():
    db = FakeDB({"p": [_rec("GHSA-x", aliases=["CVE-2021-1"])]})
    df = audit_dependencies([Dependency("p", "1.2", "PyPI")], db=db)[0]
    f = D.dep_finding_to_finding(df, "req.txt")
    assert f.rule_id == "DEP001"
    assert "p" in f.message
    assert "CVE-2021-1" in f.message or "GHSA-x" in f.message


def test_audit_manifest_text_end_to_end_with_fake_db():
    db = FakeDB({"requests": [_rec("GHSA-r")]})
    findings = audit_manifest_text("requests==2.0\nflask\n", "req.txt", db=db)
    assert len(findings) == 1
    assert findings[0].rule_id == "DEP001"


# --- integration with the REAL bundled DB ---------------------------------

@pytest.mark.parametrize("manifest", [
    "requests==2.0.0\n",
    json.dumps({"dependencies": {"lodash": "4.17.0"}}),
])
def test_real_db_returns_findings_for_known_vulnerable(manifest):
    findings = audit_manifest_text(manifest, "m")
    # requests and lodash both have many real OSV records in the bundle.
    assert len(findings) >= 1
    assert all(f.rule_id == "DEP001" for f in findings)


def test_real_db_clean_package_no_findings():
    # An obviously nonexistent name should match nothing.
    findings = audit_manifest_text("zzz-not-a-real-package-xyzzy==1\n", "m")
    assert findings == []
