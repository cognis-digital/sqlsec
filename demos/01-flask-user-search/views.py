"""Flask user-search endpoint pulled from a support-portal code review.

DEMONSTRATION ONLY. This file is intentionally unsafe so `sqlsec lint` has
something to detect. Do not copy these patterns into real code.
"""

from flask import request
import sqlite3


def search_users(conn):
    # The free-text box on /admin/users is passed straight into the query.
    term = request.args.get("q", "")
    cur = conn.cursor()
    cur.execute(f"SELECT id, email FROM users WHERE email LIKE '%{term}%'")
    return cur.fetchall()


def user_by_status(conn):
    status = request.args.get("status", "active")
    cur = conn.cursor()
    # Status comes from a dropdown today, but the value is still glued in.
    cur.execute("SELECT * FROM users WHERE status = '" + status + "'")
    return cur.fetchall()
