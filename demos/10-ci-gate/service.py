"""A service module as it would arrive in a pull request.

DEMONSTRATION ONLY. Intentionally unsafe. This demo is about the CI workflow,
not a single rule: the file carries one HIGH finding (f-string) and one MEDIUM
finding (pre-built execute), so you can watch `--fail-on` flip the exit code
and `--sarif` produce an upload for code scanning.
"""

import sqlite3


def order_total(conn, order_id):
    cur = conn.cursor()
    cur.execute(f"SELECT sum(amount) FROM line_items WHERE order_id = {order_id}")
    row = cur.fetchone()
    return row[0] if row else 0


def run_report(conn, report_sql):
    cur = conn.cursor()
    cur.execute(report_sql)
    return cur.fetchall()
