"""One-off SQLite data-migration script from an ops runbook.

DEMONSTRATION ONLY. Intentionally unsafe. executescript() runs every statement
in the text it is given and accepts no parameters, so feeding it an assembled
string (here, a tenant name spliced into DDL) runs whatever ends up in it.
"""

import sqlite3


def provision_tenant(conn, tenant_slug):
    cur = conn.cursor()
    # tenant_slug came from a CSV of new sign-ups -- not validated.
    ddl = "CREATE TABLE tenant_" + tenant_slug + "_log (id INTEGER, msg TEXT);"
    cur.executescript(ddl)


def seed_from_template(conn, seed_sql):
    cur = conn.cursor()
    # The "template" is read from a file path passed on the command line.
    cur.executescript(seed_sql + "; INSERT INTO meta VALUES ('seeded');")
