"""SARIF 2.1.0 export for sqlsec findings.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard
consumed by GitHub code scanning, Azure DevOps, and most security dashboards.
Emitting it lets `sqlsec lint --sarif` drop straight into a code-scanning
upload step instead of bespoke JSON glue.

This module builds the SARIF document purely from the in-memory rule set and
findings; it performs no I/O and no network calls. Standard library only.

Original work by Cognis Digital.
"""

from __future__ import annotations

import os
from typing import Iterable

from . import __version__
from .rules import Finding, all_rules

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/cognis-digital/sqlsec"

# SARIF result.level is one of: none, note, warning, error.
# Map sqlsec severities onto that closed vocabulary.
_LEVEL_FOR_SEVERITY = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

# A numeric security-severity (0.0-10.0) drives GitHub's High/Medium/Low badge.
_SECURITY_SEVERITY = {
    "info": "1.0",
    "low": "3.0",
    "medium": "5.5",
    "high": "8.0",
    "critical": "9.5",
}


def _level_for(severity: str) -> str:
    return _LEVEL_FOR_SEVERITY.get(severity.lower(), "warning")


def _uri(path: str) -> str:
    """Normalize a filesystem path into a forward-slash relative SARIF URI."""
    rel = os.path.relpath(path).replace(os.sep, "/")
    return rel


def _rule_descriptors() -> list[dict]:
    """One reportingDescriptor per authored rule (the SARIF rules catalog)."""
    descriptors = []
    for rule in all_rules():
        descriptors.append(
            {
                "id": rule.rule_id,
                "name": "".join(w.capitalize() for w in rule.title.split()),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "helpUri": f"{INFORMATION_URI}#{rule.rule_id.lower()}",
                "help": {
                    "text": f"{rule.description}\n\nSafe pattern:\n{rule.safe_pattern}"
                },
                "defaultConfiguration": {"level": _level_for(rule.severity)},
                "properties": {
                    "tags": ["security", "sql-injection"],
                    "security-severity": _SECURITY_SEVERITY.get(
                        rule.severity.lower(), "5.0"
                    ),
                    "sqlsec-severity": rule.severity,
                },
            }
        )
    return descriptors


def _result_for(finding: Finding) -> dict:
    return {
        "ruleId": finding.rule_id,
        "level": _level_for(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(finding.path)},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                        "snippet": {"text": finding.snippet},
                    },
                }
            }
        ],
        "properties": {"sqlsec-severity": finding.severity},
    }


def build_sarif(findings: Iterable[Finding]) -> dict:
    """Build a complete SARIF 2.1.0 log document for the given findings."""
    findings = list(findings)
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sqlsec",
                        "informationUri": INFORMATION_URI,
                        "version": __version__,
                        "rules": _rule_descriptors(),
                    }
                },
                "results": [_result_for(f) for f in findings],
            }
        ],
    }
