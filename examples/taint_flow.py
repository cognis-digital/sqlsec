"""DEMONSTRATION ONLY -- intentionally unsafe SQL *data flows*.

Unlike examples/vulnerable.py (single-line construction anti-patterns), this
file exercises ``sqlsec taint``: each function lets an untrusted source reach a
SQL execution sink *across one or more assignments*. A per-line regex linter
cannot connect the source to the sink here; the AST taint engine can.

Do NOT copy these into real code. Safe counterparts live in taint_safe.py.
"""

import os
import sys


def multi_line_concat(request, cur):
    # request.args.get -> name -> query -> execute. Three hops.
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)


def fstring_after_assignment(request, cur):
    role = request.form["role"]
    query = f"SELECT * FROM users WHERE role = '{role}'"
    cur.execute(query)


def format_flow(request, cur):
    table = request.args.get("table")
    query = "SELECT * FROM {} WHERE active = 1".format(table)
    cur.execute(query)


def input_source(cur):
    # input() is untrusted.
    user = input()
    cur.execute("SELECT * FROM users WHERE id = " + user)


def env_source(cur):
    region = os.environ["REGION"]
    q = "SELECT * FROM sites WHERE region = '" + region + "'"
    cur.execute(q)


def argv_source(cur):
    cur.execute("SELECT * FROM logs WHERE host = '" + sys.argv[1] + "'")


def augmented_assignment(request, cur):
    where = "WHERE name = '"
    where += request.args.get("name")
    query = "SELECT * FROM users " + where + "'"
    cur.execute(query)


def script_sink(request, cur):
    payload = request.form["sql"]
    cur.executescript("CREATE TABLE staging (a TEXT);" + payload)


def getenv_call(cur):
    region = os.getenv("REGION")
    cur.execute("SELECT * FROM sites WHERE region = '" + region + "'")
