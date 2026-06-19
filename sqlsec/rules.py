"""Authored SQL-safety rule set.

Each rule is a small heuristic over a single source line (with a little
surrounding context where noted). Rules are intentionally conservative: they
look for the construction patterns that lead to SQL injection rather than
trying to fully parse SQL. Every rule carries an id, a severity, a human
explanation, and a safe-pattern suggestion used by `sqlsec explain`.

All rules and copy here are original work by Cognis Digital.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


# Severity ordering, lowest -> highest. Used by the --fail-on gate.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    """A single linter finding tied to a file location."""

    rule_id: str
    severity: str
    message: str
    path: str
    line: int
    column: int
    snippet: str
    suggestion: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "suggestion": self.suggestion,
        }


@dataclass(frozen=True)
class Rule:
    """An authored detection rule.

    ``pattern`` is matched against each (lightly normalized) source line. A rule
    only fires when ``pattern`` matches AND the optional ``guard`` callable
    returns True for the raw line. The guard lets a rule require SQL-ish context
    so it stays quiet on unrelated string building.
    """

    rule_id: str
    severity: str
    title: str
    description: str
    safe_pattern: str
    pattern: re.Pattern
    message: str
    languages: tuple = ("py", "sql")
    guard: Optional[Callable[[str], bool]] = field(default=None)

    def match(self, line: str) -> Optional[re.Match]:
        m = self.pattern.search(line)
        if not m:
            return None
        if self.guard is not None and not self.guard(line):
            return None
        return m


# --- shared helpers -------------------------------------------------------

# Tokens that strongly suggest a string is a SQL statement.
_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|"
    r"CREATE\s+TABLE|ALTER\s+TABLE|FROM|WHERE|VALUES|JOIN|UNION|"
    r"TRUNCATE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)


def _looks_like_sql(line: str) -> bool:
    """True when the line plausibly contains a SQL fragment."""
    return _SQL_KEYWORDS.search(line) is not None


def _has_sql_string(line: str) -> bool:
    """True when there is a quoted string on the line that looks like SQL."""
    for m in re.finditer(r"""(['"]).*?\1""", line):
        if _SQL_KEYWORDS.search(m.group(0)):
            return True
    # Also catch lines that are clearly a continuation of a SQL string.
    return _looks_like_sql(line)


# --- the authored rule set ------------------------------------------------

RULES: list[Rule] = [
    Rule(
        rule_id="SQL001",
        severity="high",
        title="String concatenation builds a SQL query",
        description=(
            "A SQL string is assembled with the '+' operator and a variable. "
            "User-controlled values spliced directly into the query text let an "
            "attacker change the statement's meaning, which is the classic SQL "
            "injection vector."
        ),
        safe_pattern=(
            "Use a parameterized query and let the driver bind values:\n"
            '    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        ),
        # "..." + var   OR   var + "..."   where the literal looks SQL-ish
        pattern=re.compile(
            r"""(['"]).*?\1\s*\+\s*\w|"""
            r"""\w\s*\+\s*(['"]).*?\2""",
        ),
        message="SQL query built by string concatenation with a variable",
        languages=("py", "sql"),
        guard=_has_sql_string,
    ),
    Rule(
        rule_id="SQL002",
        severity="high",
        title="f-string interpolates a value into SQL",
        description=(
            "An f-string places a Python expression directly inside SQL text. "
            "The interpolated value is not escaped or bound, so any quote or "
            "clause in it becomes part of the executed statement."
        ),
        safe_pattern=(
            "Keep the SQL static and pass values as parameters:\n"
            '    cur.execute("SELECT * FROM t WHERE name = %s", (name,))'
        ),
        pattern=re.compile(
            r"""f(['"]).*?\{[^}]+\}.*?\1""",
            re.IGNORECASE,
        ),
        message="f-string interpolation of a value into a SQL statement",
        languages=("py",),
        guard=lambda line: _SQL_KEYWORDS.search(line) is not None,
    ),
    Rule(
        rule_id="SQL003",
        severity="high",
        title="printf-style % formatting builds SQL",
        description=(
            "A SQL string uses %-formatting (\"... %s ...\" % value) to inject a "
            "value. This is string substitution, not parameter binding, and is "
            "vulnerable in exactly the same way as concatenation."
        ),
        safe_pattern=(
            "Pass the value to execute() as a bound parameter instead of "
            "formatting it in:\n"
            '    cur.execute("... WHERE id = %s", (value,))'
        ),
        pattern=re.compile(
            r"""(['"]).*?%[sd].*?\1\s*%\s*[\w(]""",
        ),
        message="SQL string assembled with %-formatting",
        languages=("py",),
        guard=_has_sql_string,
    ),
    Rule(
        rule_id="SQL004",
        severity="high",
        title=".format() builds a SQL query",
        description=(
            "str.format() substitutes values into the SQL text before the driver "
            "ever sees it, so the values are not bound and can alter the query."
        ),
        safe_pattern=(
            "Use placeholders supported by your driver (?, %s, :name) and bind "
            "the values rather than calling .format() on the SQL."
        ),
        pattern=re.compile(
            r"""(['"]).*?\{.*?\}.*?\1\s*\.\s*format\s*\(""",
        ),
        message="SQL string built with str.format()",
        languages=("py",),
        guard=_has_sql_string,
    ),
    Rule(
        rule_id="SQL005",
        severity="critical",
        title="Dynamic EXEC / EXECUTE of assembled SQL",
        description=(
            "A dynamically built string is handed to EXEC/EXECUTE (or "
            "sp_executesql / EXECUTE IMMEDIATE). Executing assembled SQL text "
            "turns any unsanitized input into arbitrary statements."
        ),
        safe_pattern=(
            "Avoid dynamic SQL where possible. When unavoidable, parameterize "
            "the dynamic statement (e.g. sp_executesql with @params) and never "
            "concatenate user input into the executed text."
        ),
        pattern=re.compile(
            # EXEC/EXECUTE/EXECUTE IMMEDIATE/sp_executesql as a SQL keyword
            # (not the Python ".execute(" method, hence the negative lookbehind
            # for a preceding '.') followed by a concatenated argument.
            r"""(?<![.\w])(EXEC(\s+IMMEDIATE|UTE\s+IMMEDIATE)?|sp_executesql)"""
            r"""\b\s*\(?\s*"""
            r"""(@?\w+\s*(\+|\|\|)|['"].*?(\+|\|\|))""",
            re.IGNORECASE,
        ),
        message="Dynamic execution of a concatenated SQL string",
        languages=("py", "sql"),
    ),
    Rule(
        rule_id="SQL006",
        severity="medium",
        title="Stacked / multi-statement query",
        description=(
            "Two statements are packed into one query string separated by ';'. "
            "If any part is built from input, an attacker can append a second "
            "statement (e.g. '; DROP TABLE ...'). Most drivers should run one "
            "statement per execute() call."
        ),
        safe_pattern=(
            "Split the work into separate execute() calls and parameterize each "
            "one. Do not allow a trailing ';' plus another statement in a single "
            "query string."
        ),
        pattern=re.compile(
            r"""(['"]).*?;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|"""
            r"""TRUNCATE|GRANT|REVOKE)\b.*?\1""",
            re.IGNORECASE,
        ),
        message="Multiple SQL statements stacked in one string",
        languages=("py", "sql"),
    ),
    Rule(
        rule_id="SQL007",
        severity="high",
        title="Tautology-style OR condition in literal SQL",
        description=(
            "The literal contains an always-true comparison such as OR '1'='1' "
            "or OR 1=1. In source this is usually a copied injection payload or a "
            "test of a vulnerable path; it should never ship in real query text."
        ),
        safe_pattern=(
            "Remove the tautology and filter with bound parameters. Authorization "
            "must be enforced in the WHERE clause with parameters, not literals."
        ),
        pattern=re.compile(
            r"""\bOR\b\s*(['"]?)\s*(\d+|\w+)\s*\1\s*=\s*(['"]?)\s*\2\s*\3""",
            re.IGNORECASE,
        ),
        message="Always-true (tautology) condition embedded in SQL",
        languages=("py", "sql"),
    ),
    Rule(
        rule_id="SQL008",
        severity="medium",
        title="Comment-out sequence inside a SQL literal",
        description=(
            "A SQL literal contains a comment introducer (-- or /* or #). In "
            "injection these truncate the rest of a statement. Inside a built "
            "query string this is a strong smell of a copied payload or an "
            "attempt to neutralize trailing clauses."
        ),
        safe_pattern=(
            "Do not place comment sequences in query text built from input. Use "
            "parameters so the structure of the statement is fixed in code."
        ),
        pattern=re.compile(
            r"""(['"]).*?(--\s|/\*|\#\s).*?\1""",
        ),
        message="SQL comment sequence embedded inside a query literal",
        languages=("py", "sql"),
        guard=_has_sql_string,
    ),
    Rule(
        rule_id="SQL009",
        severity="medium",
        title="execute() called with a single pre-built string",
        description=(
            "execute()/executemany() is called with one argument that is a "
            "variable or an expression rather than a literal plus a params "
            "tuple. If that string was assembled from input it is unsafe; the "
            "params argument is missing."
        ),
        safe_pattern=(
            "Always pass parameters as the second argument:\n"
            '    cur.execute(QUERY, (value1, value2))'
        ),
        pattern=re.compile(
            r"""\.\s*execute(many)?\s*\(\s*[A-Za-z_]\w*\s*\)""",
        ),
        message="execute() called with a pre-built query and no parameters",
        languages=("py",),
    ),
    Rule(
        rule_id="SQL010",
        severity="low",
        title="LIKE pattern concatenated with a value",
        description=(
            "A LIKE clause concatenates a value and wildcards into the SQL text. "
            "Besides injection risk, this also breaks if the value contains % or "
            "_; the pattern should be a bound parameter."
        ),
        safe_pattern=(
            "Bind the whole pattern as a parameter:\n"
            "    cur.execute(\"... WHERE name LIKE ?\", (f'%{term}%',))\n"
            "(building the wildcard string in Python, then binding it)."
        ),
        pattern=re.compile(
            r"""\bLIKE\b\s*['"][^'"]*['"]?\s*\+\s*\w|"""
            r"""\bLIKE\b\s*['"]?\s*\+\s*\w""",
            re.IGNORECASE,
        ),
        message="LIKE pattern built by concatenation",
        languages=("py", "sql"),
    ),
    Rule(
        rule_id="SQL011",
        severity="medium",
        title="Identifier (table/column) interpolated into SQL",
        description=(
            "A table or column name is interpolated after FROM/JOIN/INTO/UPDATE. "
            "Placeholders cannot bind identifiers, so this is often done with "
            "string building; if the identifier comes from input it must be "
            "validated against an allow-list."
        ),
        safe_pattern=(
            "Validate identifiers against a fixed allow-list of known table / "
            "column names, then build the query from the vetted constant — never "
            "from raw input."
        ),
        pattern=re.compile(
            r"""\b(FROM|JOIN|INTO|UPDATE)\b\s*(['"]?)\s*\+\s*\w|"""
            r"""\b(FROM|JOIN|INTO|UPDATE)\b\s*\{[^}]+\}""",
            re.IGNORECASE,
        ),
        message="Table/column identifier interpolated into SQL",
        languages=("py", "sql"),
    ),
    Rule(
        rule_id="SQL012",
        severity="low",
        title="cursor.executescript() with built input",
        description=(
            "executescript() (sqlite3) runs an entire script and does not accept "
            "parameters. Passing a string assembled from input runs every "
            "statement in it, including any an attacker appended."
        ),
        safe_pattern=(
            "Reserve executescript() for trusted, static migration text. For "
            "data operations use execute() with bound parameters."
        ),
        pattern=re.compile(
            r"""\.\s*executescript\s*\(\s*[A-Za-z_]\w*\s*\+|"""
            r"""\.\s*executescript\s*\(\s*f?(['"])""",
        ),
        message="executescript() called with assembled/dynamic text",
        languages=("py",),
    ),
]


_RULES_BY_ID = {r.rule_id: r for r in RULES}


def get_rule(rule_id: str) -> Optional[Rule]:
    """Return a rule by id (case-insensitive), or None."""
    return _RULES_BY_ID.get(rule_id.upper())


def all_rules() -> list[Rule]:
    return list(RULES)


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.lower(), -1)
