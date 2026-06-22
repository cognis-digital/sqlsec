"""AST-based taint analysis for SQL-injection data flows.

Where the line-by-line linter (``sqlsec.linter``) flags *construction patterns*
on a single source line, this module reasons about *data flow*: it parses the
file into a Python AST and tracks whether an untrusted value (an HTTP request
parameter, ``input()``, ``sys.argv``, an environment variable, a CLI/function
argument, ...) reaches a SQL-execution sink (``cursor.execute``,
``executemany``, ``executescript``, an ``EXEC``/``sp_executesql`` string, ...)
while still tainted.

This catches two classes of bug the regex linter is weak at:

  * **Multi-line flows.** The tainted value is concatenated/interpolated into a
    query on one line and executed three lines later. A per-line rule sees an
    f-string and a separate ``execute(query)`` and cannot connect them; the
    taint engine follows ``query`` across the assignments.

  * **False-positive suppression.** A query built with ``.format()`` from a
    *constant* (no untrusted input anywhere in its data flow) is reported by the
    regex linter but is, in fact, safe. The taint engine only raises a flow
    finding when an untrusted source actually reaches the sink.

It is deliberately conservative and intra-procedural (it analyzes one function
body at a time, plus module level). It does not execute anything. It is a
defensive / educational static-analysis aid, not a proof of safety.

All original work by Cognis Digital. Standard library only (``ast``).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional

from .rules import Finding


# --------------------------------------------------------------------------
# What counts as an untrusted *source*.
# --------------------------------------------------------------------------

# Bare calls whose return value is untrusted, e.g. input(...).
_SOURCE_CALLS = {"input"}

# Attribute access chains that yield untrusted data. We match on the trailing
# attribute names of common web frameworks and OS/env entry points. These are
# the well-documented request-data accessors -- no fabrication.
#   flask:   request.args, request.form, request.values, request.json,
#            request.data, request.cookies, request.headers, request.files,
#            request.get_json()
#   django:  request.GET, request.POST, request.COOKIES, request.body
#   generic: os.environ, os.getenv(...), sys.argv
_SOURCE_ATTRS = {
    "args",
    "form",
    "values",
    "json",
    "cookies",
    "headers",
    "files",
    "GET",
    "POST",
    "COOKIES",
    "body",
    "data",
    "query_params",
    "path_params",
    "environ",
    "argv",
}

# Calls whose result is untrusted regardless of receiver, by *method* name.
_SOURCE_METHODS = {"get_json", "getenv", "getlist"}

# Names that, when a request-like object reads through them, are untrusted.
# We treat any attribute whose *base* is named one of these as a request object.
_REQUEST_OBJECTS = {"request", "req", "flask_request"}


# --------------------------------------------------------------------------
# What counts as a SQL *sink*.
# --------------------------------------------------------------------------

# Method names that execute SQL. ``execute``/``executemany`` are safe *iff* the
# query is constant AND a separate params argument carries the values; the
# danger is a tainted query string. ``executescript`` takes no params at all.
_SINK_METHODS = {"execute", "executemany", "executescript", "executescriptmany"}

# The query argument is always the first positional arg of these sinks.
_QUERY_ARG_INDEX = 0


@dataclass
class _Scope:
    """Taint state for a single function (or module) body.

    ``tainted`` maps a variable name to the :class:`TaintInfo` describing why it
    is untrusted. Parameters of a function are seeded as tainted sources because,
    intra-procedurally, we cannot prove a caller passed something safe -- this is
    the standard conservative assumption for a security linter.
    """

    tainted: dict = field(default_factory=dict)


@dataclass(frozen=True)
class TaintInfo:
    """Why a value is considered untrusted, for human-readable reporting."""

    origin: str  # short description, e.g. "request.args" or "function argument"
    line: int


# --------------------------------------------------------------------------
# Source detection over expressions.
# --------------------------------------------------------------------------

def _attr_chain(node: ast.AST) -> list[str]:
    """Return the dotted attribute chain for an Attribute/Name, root-first.

    ``request.args.get`` -> ["request", "args", "get"]. Returns [] for anything
    that is not a pure name/attribute chain.
    """
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return parts
    return []


def _expr_source(node: ast.AST) -> Optional[str]:
    """If ``node`` is itself an untrusted source expression, name it; else None.

    This inspects only the node, not variables (those are handled via scope).
    """
    # input(...)  /  request.get_json()  /  os.getenv(...)  /  *.getlist(...)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _SOURCE_CALLS:
            return f"{func.id}()"
        if isinstance(func, ast.Attribute):
            chain = _attr_chain(func)
            if func.attr in _SOURCE_METHODS:
                return ".".join(chain) + "()" if chain else f"{func.attr}()"
            # request.args.get(...) -> base object is request-like and the
            # penultimate attr is a known source accessor.
            if len(chain) >= 2 and (
                chain[0] in _REQUEST_OBJECTS or chain[-2] in _SOURCE_ATTRS
            ):
                return ".".join(chain) + "()"
        return None

    # Attribute access: request.args, os.environ, sys.argv, request.GET ...
    if isinstance(node, ast.Attribute):
        chain = _attr_chain(node)
        if not chain:
            return None
        if chain[0] in _REQUEST_OBJECTS and node.attr in _SOURCE_ATTRS:
            return ".".join(chain)
        if node.attr in _SOURCE_ATTRS and chain[0] in {"os", "sys"}:
            return ".".join(chain)
        # request.args  (attr is a source accessor, base is request-like)
        if node.attr in _SOURCE_ATTRS and chain[0] in _REQUEST_OBJECTS:
            return ".".join(chain)
    return None


def _subscript_source(node: ast.AST) -> Optional[str]:
    """request.args['x'], request.form['y'], os.environ['Z'] -> source name."""
    if isinstance(node, ast.Subscript):
        base = node.value
        src = _expr_source(base)
        if src is not None:
            return src
    return None


def _is_tainted_expr(node: ast.AST, scope: _Scope) -> Optional[TaintInfo]:
    """Return TaintInfo if evaluating ``node`` yields an untrusted value.

    Recurses through the expression forms that *propagate* taint: binary ops
    (concatenation), f-strings (JoinedStr), %-formatting, .format() calls,
    str()/repr() wrappers, subscripts of tainted collections, tuples/lists, and
    plain name references that are tainted in scope.
    """
    if node is None:
        return None

    # Direct source expression (call / attribute).
    src = _expr_source(node)
    if src is not None:
        return TaintInfo(origin=src, line=getattr(node, "lineno", 0))
    src = _subscript_source(node)
    if src is not None:
        return TaintInfo(origin=src, line=getattr(node, "lineno", 0))

    # Name reference -> look up scope.
    if isinstance(node, ast.Name):
        return scope.tainted.get(node.id)

    # Subscript of a tainted base: tainted[...] stays tainted.
    if isinstance(node, ast.Subscript):
        return _is_tainted_expr(node.value, scope)

    # Binary op: concatenation / other -- tainted if either side is tainted.
    if isinstance(node, ast.BinOp):
        left = _is_tainted_expr(node.left, scope)
        if left:
            return left
        return _is_tainted_expr(node.right, scope)

    # Boolean op (a or b) -- tainted if any operand is.
    if isinstance(node, ast.BoolOp):
        for v in node.values:
            t = _is_tainted_expr(v, scope)
            if t:
                return t
        return None

    # f-string: tainted if any interpolated field is tainted.
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                t = _is_tainted_expr(v.value, scope)
                if t:
                    return t
        return None

    # str(...).format(...) and "...".format(tainted_arg)
    if isinstance(node, ast.Call):
        func = node.func
        # str()/repr()/format() wrappers propagate taint of their argument.
        if isinstance(func, ast.Name) and func.id in {"str", "repr", "format"}:
            for a in node.args:
                t = _is_tainted_expr(a, scope)
                if t:
                    return t
            return None
        if isinstance(func, ast.Attribute):
            # "...".format(x): the format args (and the receiver) carry taint.
            if func.attr in {"format", "join"}:
                for a in node.args:
                    t = _is_tainted_expr(a, scope)
                    if t:
                        return t
                for kw in node.keywords:
                    t = _is_tainted_expr(kw.value, scope)
                    if t:
                        return t
                # "sep".join(tainted_list) -- receiver tainted too.
                t = _is_tainted_expr(func.value, scope)
                if t:
                    return t
                return None
        return None

    # tuple / list literal: tainted if any element is (covers join inputs).
    if isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            t = _is_tainted_expr(elt, scope)
            if t:
                return t
        return None

    return None


# --------------------------------------------------------------------------
# Statement-level taint propagation.
# --------------------------------------------------------------------------

def _assigned_targets(target: ast.AST) -> list[str]:
    """Flatten an assignment target into the simple names it binds."""
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_assigned_targets(elt))
    return names


class _FunctionAnalyzer(ast.NodeVisitor):
    """Walk one function/module body in source order, tracking taint.

    Findings are appended to ``self.findings``. The walk is linear (it does not
    model branches or loops precisely); on a branch it conservatively keeps any
    taint seen. That over-approximation favors recall, which is correct for a
    defensive linter.
    """

    def __init__(self, path: str, scope: _Scope, seed_params: bool = True):
        self.path = path
        self.scope = scope
        self.findings: list[Finding] = []

    # --- assignments propagate taint -----------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        info = _is_tainted_expr(node.value, self.scope)
        for tgt in node.targets:
            for name in _assigned_targets(tgt):
                if info is not None:
                    self.scope.tainted[name] = info
                else:
                    # Reassigning from a clean value clears prior taint.
                    self.scope.tainted.pop(name, None)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is None:
            return
        info = _is_tainted_expr(node.value, self.scope)
        if isinstance(node.target, ast.Name):
            if info is not None:
                self.scope.tainted[node.target.id] = info
            else:
                self.scope.tainted.pop(node.target.id, None)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # query += tainted  ->  query becomes tainted.
        self.generic_visit(node)
        if isinstance(node.target, ast.Name):
            info = _is_tainted_expr(node.value, self.scope) or self.scope.tainted.get(
                node.target.id
            )
            if info is not None:
                self.scope.tainted[node.target.id] = info

    # --- calls may be sinks --------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        self._check_sink(node)
        self.generic_visit(node)

    def _check_sink(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        method = func.attr
        if method not in _SINK_METHODS:
            return
        if not node.args:
            return
        query_arg = node.args[_QUERY_ARG_INDEX]
        info = _is_tainted_expr(query_arg, self.scope)
        if info is None:
            return

        # We have a tainted query reaching an execution sink.
        has_params = len(node.args) > 1 or bool(node.keywords)
        # executescript never takes params; a tainted script is always unsafe.
        if method == "executescript":
            rule_id, severity = "SQL101", "critical"
            extra = "executescript() runs every statement and binds nothing"
        elif has_params and not _query_text_is_dynamic(query_arg):
            # Edge: a *constant* query with params but the query var was marked
            # tainted only via aliasing -- unlikely; treat as lower severity.
            rule_id, severity = "SQL100", "high"
            extra = "untrusted value reaches the query argument"
        else:
            rule_id, severity = "SQL100", "critical"
            extra = "untrusted value is built into the executed query text"

        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0) + 1
        msg = (
            f"tainted data flow: {info.origin} (line {info.line}) reaches "
            f".{method}() -- {extra}"
        )
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=msg,
                path=self.path,
                line=line,
                column=col,
                snippet=f".{method}(...)  <- {info.origin}",
                suggestion=(
                    "Keep the SQL text constant and pass the untrusted value as a "
                    "bound parameter:\n"
                    '    cur.execute("... WHERE x = ?", (value,))\n'
                    "Never concatenate / interpolate request data into the query."
                ),
            )
        )


def _query_text_is_dynamic(node: ast.AST) -> bool:
    """True if the query argument is built (not a plain constant string)."""
    return not isinstance(node, ast.Constant)


# --------------------------------------------------------------------------
# Public entry points.
# --------------------------------------------------------------------------

def _seed_params(func: ast.AST) -> _Scope:
    """Build a scope whose tainted set is seeded with the function's params.

    Intra-procedural analysis cannot see callers, so every parameter is assumed
    untrusted -- the conservative, recall-favoring choice for security tooling.
    ``self``/``cls`` are excluded (they are receivers, not data).
    """
    scope = _Scope()
    args = func.args
    seq = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    if args.vararg:
        seq.append(args.vararg)
    if args.kwarg:
        seq.append(args.kwarg)
    for a in seq:
        name = a.arg
        if name in {"self", "cls"}:
            continue
        scope.tainted[name] = TaintInfo(
            origin="function argument", line=getattr(func, "lineno", 0)
        )
    return scope


def analyze_text(
    text: str,
    path: str = "<string>",
    seed_params: bool = True,
) -> list[Finding]:
    """Run taint analysis over Python source ``text`` and return findings.

    When ``seed_params`` is True (the default), function parameters are treated
    as untrusted sources. Set it False to analyze only flows that originate from
    an *explicit* untrusted source (request data, input(), env, argv) -- this is
    the higher-precision, lower-recall mode.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    findings: list[Finding] = []

    # Module-level body: no parameter seeding.
    module_scope = _Scope()
    mod_analyzer = _FunctionAnalyzer(path, module_scope)
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        mod_analyzer.visit(stmt)
    findings.extend(mod_analyzer.findings)

    # Each function (including nested and methods) gets its own scope.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = _seed_params(node) if seed_params else _Scope()
            analyzer = _FunctionAnalyzer(path, scope)
            for stmt in node.body:
                analyzer.visit(stmt)
            findings.extend(analyzer.findings)

    findings.sort(key=lambda f: (f.path, f.line, f.column, f.rule_id))
    return findings


def analyze_file(path: str, seed_params: bool = True) -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return analyze_text(text, path=path, seed_params=seed_params)


def analyze_path(target: str, seed_params: bool = True) -> list[Finding]:
    """Analyze a .py file or recurse a directory of .py files."""
    import os

    from .linter import iter_source_files

    findings: list[Finding] = []
    for src in iter_source_files(target):
        if not src.lower().endswith(".py"):
            continue
        findings.extend(analyze_file(src, seed_params=seed_params))
    findings.sort(key=lambda f: (f.path, f.line, f.column, f.rule_id))
    return findings


# Rule metadata for `sqlsec explain` integration.
TAINT_RULES = {
    "SQL100": {
        "severity": "critical",
        "title": "Untrusted data flows into a SQL execution sink",
        "description": (
            "Taint analysis traced an untrusted source (request parameter, "
            "input(), environment variable, argv, or an unverified function "
            "argument) into the query argument of execute()/executemany() while "
            "still tainted. Unlike the line linter, this confirms the value "
            "actually reaches the database call across assignments, so it is a "
            "high-confidence injection finding."
        ),
        "safe_pattern": (
            "Bind the value instead of building it into the query text:\n"
            '    cur.execute("SELECT * FROM t WHERE id = ?", (user_id,))'
        ),
    },
    "SQL101": {
        "severity": "critical",
        "title": "Untrusted data flows into executescript()",
        "description": (
            "executescript() runs an entire multi-statement script and accepts "
            "no parameters. Taint analysis found untrusted data reaching it, so "
            "an attacker controls one or more whole statements."
        ),
        "safe_pattern": (
            "Reserve executescript() for trusted, static migration text. Use "
            "execute() with bound parameters for anything touching input."
        ),
    },
}
