"""Authentication handler from a legacy intranet app, flagged in audit.

DEMONSTRATION ONLY. Intentionally unsafe. The tautology and comment sequence
below are the textbook shape of an auth-bypass payload that someone pasted in
to "test" the login path and never removed.
"""

import sqlite3


def check_login(conn, username, password):
    cur = conn.cursor()
    # Built straight from the form fields -- this is the vulnerable path.
    query = (
        "SELECT * FROM accounts WHERE user = '"
        + username
        + "' AND pass = '"
        + password
        + "'"
    )
    cur.execute(query)
    return cur.fetchone() is not None


def debug_probe(conn, username):
    cur = conn.cursor()
    # Left-over manual test of the bypass: tautology + comment truncation.
    cur.execute("SELECT * FROM accounts WHERE user = '' OR '1'='1' -- '")
    return cur.fetchall()
