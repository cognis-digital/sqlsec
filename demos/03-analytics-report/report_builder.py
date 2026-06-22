"""Ad-hoc analytics report builder used by the data team.

DEMONSTRATION ONLY. Intentionally unsafe. The dimension/table name comes from a
UI selector and is interpolated as an identifier -- placeholders cannot bind
identifiers, so the team reached for string building and got it wrong.
"""

import psycopg2


def rows_for_table(conn, source_table):
    cur = conn.cursor()
    # source_table is one of a fixed set in the UI, but nothing enforces it here.
    query = "SELECT count(*) FROM " + source_table + " GROUP BY day"
    cur.execute(query)
    return cur.fetchall()


def report_from_table(conn, table, region):
    cur = conn.cursor()
    # Table name chosen in a dropdown, region typed by the analyst.
    cur.execute("SELECT * FROM {} WHERE region = '{}'".format(table, region))
    return cur.fetchall()
