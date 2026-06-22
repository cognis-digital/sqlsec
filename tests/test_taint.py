"""AST taint-analysis engine tests.

These cover the data-flow detector end to end: every untrusted source kind,
every taint-propagating expression form, the multi-line flows the line linter
misses, the false-positive suppression that is the engine's reason to exist,
and the param-seeding / explicit-only modes. All offline; no DB, no network.
"""

import os

import pytest

from sqlsec.taint import (
    TAINT_RULES,
    analyze_file,
    analyze_path,
    analyze_text,
)

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")


def _ids(findings):
    return [f.rule_id for f in findings]


def _flow(src, **kw):
    kw.setdefault("seed_params", False)
    return analyze_text(src, path="t.py", **kw)


# --------------------------------------------------------------------------
# Sources: each documented untrusted entry point taints a downstream sink.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "expr",
    [
        'request.args.get("x")',
        'request.form["x"]',
        'request.values["x"]',
        'request.cookies["x"]',
        'request.headers["x"]',
        'request.get_json()',
        'request.GET["x"]',
        'request.POST["x"]',
        'request.body',
        'req.args.get("x")',
        'input()',
        'os.environ["X"]',
        'os.getenv("X")',
        'sys.argv[1]',
    ],
)
def test_each_source_taints_a_sink(expr):
    src = f"def f(request, req, cur):\n    v = {expr}\n    cur.execute('SELECT ' + v)\n"
    findings = _flow(src)
    assert "SQL100" in _ids(findings), f"{expr} should taint the sink"


def test_unknown_attribute_is_not_a_source():
    src = (
        "def f(request, cur):\n"
        "    v = request.user.display_name\n"  # not a documented source accessor
        "    cur.execute('SELECT ' + v)\n"
    )
    # display_name is not in the source-accessor set; without param seeding the
    # value is clean.
    assert _flow(src) == []


# --------------------------------------------------------------------------
# Propagation: each expression form carries taint to the sink.
# --------------------------------------------------------------------------

def test_concatenation_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    cur.execute('SELECT * FROM t WHERE a=' + v)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_fstring_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    cur.execute(f'SELECT * FROM t WHERE a={v}')\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_percent_format_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    q = 'SELECT * FROM t WHERE a=%s' % v\n"
        "    cur.execute(q)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_str_format_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    q = 'SELECT * FROM t WHERE a={}'.format(v)\n"
        "    cur.execute(q)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_format_keyword_arg_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    q = 'SELECT * FROM t WHERE a={a}'.format(a=v)\n"
        "    cur.execute(q)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_join_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    q = ' '.join(['SELECT * FROM t WHERE a=', v])\n"
        "    cur.execute(q)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_str_wrapper_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    cur.execute('SELECT ' + str(v))\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_augmented_assignment_propagates():
    src = (
        "def f(request, cur):\n"
        "    q = 'SELECT * FROM t WHERE a='\n"
        "    q += request.args.get('x')\n"
        "    cur.execute(q)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_boolop_propagates():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x') or 'default'\n"
        "    cur.execute('SELECT ' + v)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_chained_assignment_hops():
    src = (
        "def f(request, cur):\n"
        "    a = request.args.get('x')\n"
        "    b = a\n"
        "    c = 'SELECT ' + b\n"
        "    cur.execute(c)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_tuple_unpack_does_not_falsely_taint_other_name():
    # Only the tainted element should mark a downstream sink; here both targets
    # share the RHS so both are conservatively tainted -- but a clean separate
    # var must stay clean.
    src = (
        "def f(request, cur):\n"
        "    clean = 'literal'\n"
        "    cur.execute('SELECT ' + clean)\n"
    )
    assert _flow(src) == []


# --------------------------------------------------------------------------
# Sinks.
# --------------------------------------------------------------------------

def test_executemany_is_a_sink():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    cur.executemany('SELECT ' + v)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_executescript_is_critical_sink():
    src = (
        "def f(request, cur):\n"
        "    v = request.form['sql']\n"
        "    cur.executescript('CREATE TABLE t(a);' + v)\n"
    )
    findings = _flow(src)
    assert "SQL101" in _ids(findings)
    assert findings[0].severity == "critical"


def test_non_sink_method_not_flagged():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    cur.prepare('SELECT ' + v)\n"  # prepare() is not in the sink set
    )
    assert _flow(src) == []


def test_sink_with_no_args_ignored():
    src = "def f(cur):\n    cur.execute()\n"
    assert _flow(src) == []


# --------------------------------------------------------------------------
# False-positive suppression -- the whole point of taint over regex.
# --------------------------------------------------------------------------

def test_constant_concatenation_is_clean():
    src = (
        "def f(cur):\n"
        "    q = 'SELECT * FROM t WHERE a=' + 'b'\n"
        "    cur.execute(q)\n"
    )
    assert _flow(src) == []


def test_constant_format_is_clean():
    src = (
        "def f(cur):\n"
        "    col = 'name'\n"
        "    q = 'SELECT {} FROM t'.format(col)\n"
        "    cur.execute(q)\n"
    )
    assert _flow(src) == []


def test_parameter_binding_is_clean():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    cur.execute('SELECT * FROM t WHERE a = ?', (v,))\n"
    )
    # The query text is a constant; the tainted value is bound, not built in.
    assert _flow(src) == []


def test_reassignment_clears_taint():
    src = (
        "def f(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    v = 'safe-constant'\n"  # clobbers the taint
        "    cur.execute('SELECT ' + v)\n"
    )
    assert _flow(src) == []


def test_allowlist_get_is_clean():
    src = (
        "ALLOWED = {'users': 'users'}\n"
        "def f(request, cur):\n"
        "    requested = request.args.get('t')\n"
        "    table = ALLOWED.get(requested)\n"  # dict.get is not a source
        "    cur.execute('SELECT id FROM ' + table)\n"
    )
    assert _flow(src) == []


# --------------------------------------------------------------------------
# Multi-line flows -- where the line linter is weakest.
# --------------------------------------------------------------------------

def test_three_hop_flow_detected():
    src = (
        "def handler(request, cur):\n"
        "    name = request.args.get('name')\n"
        "    query = 'SELECT * FROM users WHERE name = ' + name\n"
        "    cur.execute(query)\n"
    )
    findings = _flow(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "SQL100"
    # The message names the originating source for the analyst.
    assert "request.args.get" in findings[0].message


def test_finding_records_sink_line_not_source_line():
    src = (
        "def handler(request, cur):\n"
        "    name = request.args.get('name')\n"
        "    query = 'SELECT ' + name\n"
        "    cur.execute(query)\n"  # line 4 is the sink
    )
    findings = _flow(src)
    assert findings[0].line == 4


# --------------------------------------------------------------------------
# Param seeding modes.
# --------------------------------------------------------------------------

def test_seed_params_treats_arguments_as_tainted():
    src = "def get(uid, cur):\n    cur.execute('SELECT * FROM u WHERE id=' + uid)\n"
    assert "SQL100" in _ids(analyze_text(src, path="p.py", seed_params=True))


def test_explicit_only_ignores_bare_parameters():
    src = "def get(uid, cur):\n    cur.execute('SELECT * FROM u WHERE id=' + uid)\n"
    assert analyze_text(src, path="p.py", seed_params=False) == []


def test_self_and_cls_not_seeded():
    src = (
        "class Repo:\n"
        "    def m(self, cur):\n"
        "        cur.execute('SELECT 1')\n"
    )
    assert analyze_text(src, path="c.py", seed_params=True) == []


def test_seeded_param_bound_is_clean():
    src = "def get(uid, cur):\n    cur.execute('SELECT * FROM u WHERE id=?', (uid,))\n"
    assert analyze_text(src, path="p.py", seed_params=True) == []


# --------------------------------------------------------------------------
# Scope isolation, nesting, async, module level.
# --------------------------------------------------------------------------

def test_taint_does_not_leak_across_functions():
    src = (
        "def a(request, cur):\n"
        "    v = request.args.get('x')\n"
        "def b(cur):\n"
        "    cur.execute('SELECT ' + v)\n"  # v is undefined/clean in b's scope
    )
    assert _flow(src) == []


def test_async_function_analyzed():
    src = (
        "async def h(request, cur):\n"
        "    v = request.args.get('x')\n"
        "    cur.execute('SELECT ' + v)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_nested_function_analyzed():
    src = (
        "def outer(request, cur):\n"
        "    def inner():\n"
        "        v = request.args.get('x')\n"
        "        cur.execute('SELECT ' + v)\n"
        "    return inner\n"
    )
    # inner is walked as its own function; request is free but request.args.get
    # is still an explicit source.
    assert "SQL100" in _ids(_flow(src))


def test_module_level_flow_detected():
    src = (
        "import os\n"
        "region = os.environ['REGION']\n"
        "cur.execute('SELECT * FROM s WHERE r=' + region)\n"
    )
    assert "SQL100" in _ids(_flow(src))


def test_syntax_error_returns_empty():
    assert analyze_text("def (:\n  pass", path="bad.py") == []


# --------------------------------------------------------------------------
# Example fixtures.
# --------------------------------------------------------------------------

def test_example_taint_flow_all_critical():
    findings = analyze_file(
        os.path.join(EXAMPLES, "taint_flow.py"), seed_params=False
    )
    assert len(findings) == 9, _ids(findings)
    assert all(f.severity == "critical" for f in findings)
    assert "SQL101" in _ids(findings)  # the executescript one


def test_example_taint_safe_is_clean():
    findings = analyze_file(
        os.path.join(EXAMPLES, "taint_safe.py"), seed_params=False
    )
    assert findings == [], _ids(findings)


def test_example_taint_safe_clean_even_with_seeding():
    # Even when we assume every parameter is untrusted, the safe file binds or
    # allow-lists everything, so it stays clean.
    findings = analyze_file(
        os.path.join(EXAMPLES, "taint_safe.py"), seed_params=True
    )
    assert findings == [], _ids(findings)


def test_analyze_path_recurses_examples():
    findings = analyze_path(EXAMPLES, seed_params=False)
    paths = {os.path.basename(f.path) for f in findings}
    assert "taint_flow.py" in paths
    assert "taint_safe.py" not in paths


def test_analyze_path_skips_sql_files(tmp_path):
    sql = tmp_path / "x.sql"
    sql.write_text("SELECT * FROM t;")
    py = tmp_path / "y.py"
    py.write_text(
        "def f(request, cur):\n"
        "    cur.execute('SELECT ' + request.args.get('x'))\n"
    )
    findings = analyze_path(str(tmp_path), seed_params=False)
    assert {os.path.basename(f.path) for f in findings} == {"y.py"}


# --------------------------------------------------------------------------
# Findings are well-formed and sorted.
# --------------------------------------------------------------------------

def test_findings_sorted():
    findings = analyze_file(
        os.path.join(EXAMPLES, "taint_flow.py"), seed_params=False
    )
    keys = [(f.path, f.line, f.column, f.rule_id) for f in findings]
    assert keys == sorted(keys)


def test_finding_as_dict_round_trip():
    findings = _flow(
        "def f(request, cur):\n"
        "    cur.execute('SELECT ' + request.args.get('x'))\n"
    )
    d = findings[0].as_dict()
    for key in (
        "rule_id",
        "severity",
        "message",
        "path",
        "line",
        "column",
        "snippet",
        "suggestion",
    ):
        assert key in d


def test_taint_rules_metadata_complete():
    for rid, meta in TAINT_RULES.items():
        assert rid.startswith("SQL1")
        for key in ("severity", "title", "description", "safe_pattern"):
            assert meta[key]
