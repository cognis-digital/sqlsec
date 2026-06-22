"""Safe counterparts to taint_flow.py.

Every function either binds the untrusted value as a parameter, or routes
identifiers through a fixed allow-list so untrusted input never reaches the
query *text*. ``sqlsec taint`` should produce NO findings here -- including for
the .format() case, which the line linter would (conservatively) flag but which
is provably safe because the formatted value is a constant.
"""

import os


ALLOWED_TABLES = {"users": "users", "products": "products"}


def multi_line_param(request, cur):
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = ?"
    cur.execute(query, (name,))


def fstring_constant(cur):
    # f-string, but every field is a constant -- no taint reaches the sink.
    limit = 100
    query = f"SELECT * FROM users LIMIT {limit}"
    cur.execute(query)


def format_constant(cur):
    # .format() of a constant -> safe. The taint engine does NOT flag this,
    # which is the precision win over the line linter.
    column = "name"  # chosen in code, not from input
    query = "SELECT {} FROM users".format(column)
    cur.execute(query)


def allowlisted_identifier(request, cur):
    requested = request.args.get("table")
    table = ALLOWED_TABLES.get(requested)
    if table is None:
        raise ValueError("unknown table")
    # ``table`` is now a vetted constant from the allow-list, not input.
    query = "SELECT id FROM " + table + " WHERE active = ?"
    cur.execute(query, (1,))


def env_then_param(cur):
    region = os.environ["REGION"]
    cur.execute("SELECT * FROM sites WHERE region = ?", (region,))


def static_script(cur):
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, region TEXT);
        """
    )
