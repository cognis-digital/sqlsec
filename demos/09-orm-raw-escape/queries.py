"""ORM project that drops to raw SQL for a few "fast path" queries.

DEMONSTRATION ONLY. Intentionally unsafe. Teams that use an ORM are often safe
by default, then reintroduce injection in the handful of places they escape to
raw SQL. Here a raw execute() takes a pre-built string with no params, and an
audit query stacks a second statement.
"""

from django.db import connection


def fast_lookup(prebuilt_query):
    with connection.cursor() as cur:
        # Someone assembled `prebuilt_query` upstream and passed it straight in.
        cur.execute(prebuilt_query)
        return cur.fetchall()


def purge_and_log(cur, account_id):
    # Two statements in one string: an attacker who controls account_id can
    # append their own statement after the ';'.
    cur.execute("DELETE FROM tokens WHERE acct = 1; DELETE FROM audit WHERE acct = 1")
