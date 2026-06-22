"""Nightly ETL job that loads a partner feed into the warehouse.

DEMONSTRATION ONLY. Intentionally unsafe. The job uses printf-style
%-formatting to build the WHERE clause from the partner id and the run date,
both of which arrive in the job config -- string substitution, not binding.
"""

import psycopg2


def load_partner(conn, partner_id, run_date):
    cur = conn.cursor()
    # partner_id and run_date come from the scheduler's job parameters.
    cur.execute(
        "DELETE FROM staging WHERE partner = '%s' AND load_date = '%s'"
        % (partner_id, run_date)
    )


def upsert_metric(conn, metric_name, value):
    cur = conn.cursor()
    cur.execute("UPDATE metrics SET value = %d WHERE name = '%s'" % (value, metric_name))
