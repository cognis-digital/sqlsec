"""Passive dependency / SBOM audit against the bundled offline vuln database.

This is a **passive** capability: it parses a dependency manifest, lockfile,
or SBOM that the user provides on disk and cross-references each package name
against the bundled ``cognis_vulndb.jsonl.gz`` (262k+ real OSV records). It
performs **no network access** and runs fully offline / air-gapped.

Supported inputs (format is sniffed from filename + content):

  * ``requirements.txt`` / pip freeze output  (PyPI)
  * ``package.json``                           (npm, from "dependencies")
  * ``package-lock.json``                      (npm, full lock tree)
  * ``Cargo.toml`` / ``Cargo.lock``            (crates.io)
  * ``go.mod``                                 (Go)
  * CycloneDX SBOM (``*.cdx.json`` / bom.json) (any ecosystem)
  * a plain newline list of ``name`` or ``name==version``

The result is a list of :class:`DepFinding` objects -- one per package that has
at least one matching record in the bundled DB -- which the CLI renders as a
table / JSON / SARIF, exactly like the linter findings.

Defensive / educational scope only. Standard library only. No fabricated data:
every match is a real record drawn from the bundled OSV corpus.

Original work by Cognis Digital.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Optional

from .rules import Finding
from .vulndb_local import VulnDB


@dataclass(frozen=True)
class Dependency:
    """A single declared dependency parsed from a manifest."""

    name: str
    version: Optional[str]
    ecosystem: Optional[str]  # "PyPI", "npm", "crates.io", "Go", or None


# --------------------------------------------------------------------------
# Manifest parsers (pure, offline, stdlib only).
# --------------------------------------------------------------------------

_REQ_LINE = re.compile(
    r"""^\s*([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([0-9][\w.\-+]*))?""",
)


def parse_requirements(text: str) -> list[Dependency]:
    """Parse a pip ``requirements.txt`` / freeze list."""
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # Drop environment markers / extras / urls.
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line or "://" in line:
            continue
        line = re.sub(r"\[[^\]]*\]", "", line)  # drop extras like name[foo]
        m = _REQ_LINE.match(line)
        if not m:
            continue
        deps.append(Dependency(m.group(1), m.group(2), "PyPI"))
    return deps


def parse_package_json(text: str) -> list[Dependency]:
    """Parse npm ``package.json`` dependency maps."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    deps: list[Dependency] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies",
                "peerDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, ver in block.items():
                v = ver if isinstance(ver, str) else None
                if v:
                    v = v.lstrip("^~>=< ").strip() or None
                deps.append(Dependency(name, v, "npm"))
    return deps


def parse_package_lock(text: str) -> list[Dependency]:
    """Parse npm ``package-lock.json`` (v1 ``dependencies`` or v2/3 ``packages``)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    deps: list[Dependency] = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for path, meta in pkgs.items():
            if not path or not isinstance(meta, dict):
                continue
            # "node_modules/foo" -> "foo"; nested "a/node_modules/b" -> "b".
            name = path.split("node_modules/")[-1]
            if name:
                deps.append(Dependency(name, meta.get("version"), "npm"))
    legacy = data.get("dependencies")
    if isinstance(legacy, dict):
        for name, meta in legacy.items():
            ver = meta.get("version") if isinstance(meta, dict) else None
            deps.append(Dependency(name, ver, "npm"))
    return deps


def parse_cargo(text: str) -> list[Dependency]:
    """Parse ``Cargo.lock`` ([[package]] blocks) or a Cargo.toml [dependencies]."""
    deps: list[Dependency] = []
    # Cargo.lock: [[package]] name = "x" \n version = "y"
    blocks = re.split(r"\[\[package\]\]", text)
    if len(blocks) > 1:
        for block in blocks[1:]:
            nm = re.search(r'name\s*=\s*"([^"]+)"', block)
            ver = re.search(r'version\s*=\s*"([^"]+)"', block)
            if nm:
                deps.append(
                    Dependency(nm.group(1), ver.group(1) if ver else None, "crates.io")
                )
        return deps
    # Cargo.toml [dependencies] table.
    in_deps = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_deps = "dependencies" in line
            continue
        if in_deps and "=" in line:
            name = line.split("=", 1)[0].strip()
            ver = re.search(r'"([^"]+)"', line)
            if name:
                deps.append(
                    Dependency(name, ver.group(1) if ver else None, "crates.io")
                )
    return deps


def parse_go_mod(text: str) -> list[Dependency]:
    """Parse a ``go.mod`` require directives (single-line and block forms)."""
    deps: list[Dependency] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        body = line
        if line.startswith("require "):
            body = line[len("require "):].strip()
        elif not in_block:
            continue
        body = body.split("//", 1)[0].strip()
        if not body:
            continue
        parts = body.split()
        if len(parts) >= 2:
            deps.append(Dependency(parts[0], parts[1].lstrip("v"), "Go"))
    return deps


def parse_cyclonedx(text: str) -> list[Dependency]:
    """Parse a CycloneDX SBOM ``components`` array."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    deps: list[Dependency] = []
    _eco = {
        "pypi": "PyPI", "npm": "npm", "cargo": "crates.io", "crates.io": "crates.io",
        "golang": "Go", "go": "Go", "maven": "Maven", "nuget": "NuGet",
        "gem": "RubyGems", "rubygems": "RubyGems",
    }
    for comp in data.get("components", []) or []:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name")
        if not name:
            continue
        eco = None
        purl = comp.get("purl") or ""
        m = re.match(r"pkg:([^/]+)/", purl)
        if m:
            eco = _eco.get(m.group(1).lower())
        deps.append(Dependency(name, comp.get("version"), eco))
    return deps


def parse_plain(text: str) -> list[Dependency]:
    """Parse a plain newline list of ``name`` or ``name==version``."""
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            deps.append(Dependency(m.group(1), m.group(2), None))
    return deps


def sniff_and_parse(text: str, filename: str = "") -> list[Dependency]:
    """Pick a parser from the filename / content and parse the manifest."""
    base = os.path.basename(filename).lower()
    if base == "package-lock.json" or '"lockfileVersion"' in text:
        return parse_package_lock(text)
    if base == "package.json":
        return parse_package_json(text)
    if base.endswith(("cargo.lock", "cargo.toml")) or "[[package]]" in text:
        return parse_cargo(text)
    if base == "go.mod" or text.lstrip().startswith("module "):
        return parse_go_mod(text)
    if base.endswith((".cdx.json", "bom.json")) or '"bomFormat"' in text \
            or '"components"' in text:
        return parse_cyclonedx(text)
    # Any JSON object carrying a dependency map is treated as package.json,
    # regardless of file extension (content sniffing).
    if '"dependencies"' in text or '"devDependencies"' in text:
        return parse_package_json(text)
    if base.startswith("requirements") or base.endswith(".txt") \
            or "==" in text or ">=" in text:
        return parse_requirements(text)
    return parse_plain(text)


# --------------------------------------------------------------------------
# Audit: cross-reference parsed deps against the bundled vuln DB.
# --------------------------------------------------------------------------

# Map an OSV CVSS-ish severity onto sqlsec's severity vocabulary.
_SEV_WORD = {
    "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
    "MEDIUM": "medium", "LOW": "low",
}


@dataclass(frozen=True)
class DepFinding:
    """One vulnerable dependency with its matching DB records."""

    name: str
    version: Optional[str]
    ecosystem: Optional[str]
    records: tuple  # tuple[dict, ...] of matching vuln records

    def severity(self) -> str:
        """Worst severity across the matching records (default 'medium')."""
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        best, best_rank = "medium", 2
        for r in self.records:
            raw = (r.get("severity") or "").upper()
            word = _SEV_WORD.get(raw)
            if word and order[word] > best_rank:
                best, best_rank = word, order[word]
        return best


def audit_dependencies(
    deps: list[Dependency],
    db: Optional[VulnDB] = None,
) -> list[DepFinding]:
    """Cross-reference each dependency against the bundled DB. Offline only."""
    if db is None:
        db = VulnDB()
    out: list[DepFinding] = []
    for dep in deps:
        records = db.by_package(dep.name, ecosystem=dep.ecosystem)
        if not records and dep.ecosystem:
            # Retry ecosystem-agnostic (DB ecosystem labels vary).
            records = db.by_package(dep.name)
        if records:
            out.append(
                DepFinding(
                    name=dep.name,
                    version=dep.version,
                    ecosystem=dep.ecosystem,
                    records=tuple(records),
                )
            )
    out.sort(key=lambda f: (f.name.lower(), f.ecosystem or ""))
    return out


def dep_finding_to_finding(df: DepFinding, path: str) -> Finding:
    """Adapt a DepFinding into the linter's Finding shape for unified output."""
    ids = sorted({r.get("id", "") for r in df.records if r.get("id")})
    aliases = sorted({
        a for r in df.records for a in (r.get("aliases") or []) if a
    })
    shown = (ids + aliases)[:6]
    ver = f"@{df.version}" if df.version else ""
    eco = f" [{df.ecosystem}]" if df.ecosystem else ""
    msg = (
        f"{df.name}{ver}{eco}: {len(df.records)} known vulnerabilit"
        f"{'y' if len(df.records) == 1 else 'ies'} in bundled DB "
        f"({', '.join(shown)}{', ...' if len(ids + aliases) > 6 else ''})"
    )
    return Finding(
        rule_id="DEP001",
        severity=df.severity(),
        message=msg,
        path=path,
        line=0,
        column=0,
        snippet=f"{df.name}{ver}",
        suggestion=(
            "Upgrade to a fixed release of this package. Review the listed "
            "advisories (CVE/GHSA) and confirm your pinned version is not in an "
            "affected range. This is an offline name-match against the bundled "
            "OSV corpus; verify ranges against the upstream advisory."
        ),
    )


def audit_manifest_text(text: str, filename: str = "<input>",
                        db: Optional[VulnDB] = None) -> list[Finding]:
    """Parse a manifest's text and return Finding rows for vulnerable deps."""
    deps = sniff_and_parse(text, filename)
    findings = [dep_finding_to_finding(df, filename)
                for df in audit_dependencies(deps, db=db)]
    findings.sort(key=lambda f: (f.path, f.snippet, f.rule_id))
    return findings


def audit_manifest_file(path: str, db: Optional[VulnDB] = None) -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return audit_manifest_text(text, filename=path, db=db)


# Rule metadata for `sqlsec explain` integration.
DEP_RULES = {
    "DEP001": {
        "severity": "high",
        "title": "Dependency has a known vulnerability in the bundled DB",
        "description": (
            "A package declared in the scanned manifest / lockfile / SBOM matches "
            "one or more real advisory records in the bundled offline OSV corpus "
            "(cognis_vulndb.jsonl.gz). The match is by package name (and ecosystem "
            "when known); confirm the affected version range against the upstream "
            "advisory before acting."
        ),
        "safe_pattern": (
            "Pin to a patched release and re-run the audit:\n"
            "    sqlsec deps requirements.txt --json\n"
            "Track advisories (CVE/GHSA) and keep lockfiles current."
        ),
    },
}
