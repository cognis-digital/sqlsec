"""The parameterized rewrite of demo 01 (flask-user-search).

This is the GOOD version: it lints clean (zero findings). Use it side by side
with demo 01 to show the before/after, and as a target for the CI gate in
demo 10. The SQL text is fixed in code; every value is a bound parameter, and
the one identifier (sort column) is mapped through a fixed allow-list.
"""

from flask import request
import sqlite3


def search_users(conn):
    term = request.args.get("q", "")
    cur = conn.cursor()
    # Build the wildcard pattern in Python, then BIND it as a value.
    pattern = f"%{term}%"
    cur.execute("SELECT id, email FROM users WHERE email LIKE ?", (pattern,))
    return cur.fetchall()


def user_by_status(conn):
    status = request.args.get("status", "active")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE status = ?", (status,))
    return cur.fetchall()


# A fixed allow-list is how you safely choose an identifier from input. Map the
# input to a whole pre-written, constant query string -- no value from the
# request ever touches the SQL text.
_SORTED_QUERIES = {
    "email": "SELECT id, email FROM users ORDER BY email",
    "created": "SELECT id, email FROM users ORDER BY created_at",
    "name": "SELECT id, email FROM users ORDER BY display_name",
}


def users_sorted(conn, sort_key):
    query = _SORTED_QUERIES.get(sort_key, _SORTED_QUERIES["email"])
    cur = conn.cursor()
    cur.execute(query, ())
    return cur.fetchall()
