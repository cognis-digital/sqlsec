"""DEMONSTRATION ONLY -- intentionally unsafe SQL construction.

Every function below contains a query-building anti-pattern that `sqlsec lint`
should flag. Do NOT copy these into real code. The matching safe versions live
in safe.py. This file exists so the linter has something to detect.
"""

import sqlite3


def get_user_concat(conn, user_id):
    # SQL001: string concatenation builds the query
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cur.execute(query)
    return cur.fetchall()


def get_user_fstring(conn, name):
    # SQL002: f-string interpolates the value into SQL
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()


def get_user_percent(conn, email):
    # SQL003: printf-style % formatting
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = '%s'" % email)
    return cur.fetchall()


def get_user_format(conn, role):
    # SQL004: str.format() builds the SQL
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE role = '{}'".format(role))
    return cur.fetchall()


def run_dynamic(cur, table):
    # SQL005: dynamic EXEC of concatenated SQL
    cur.execute("EXEC('SELECT * FROM ' + " + repr(table) + ")")


def stacked(cur, name):
    # SQL006: stacked / multi-statement query
    cur.execute("INSERT INTO log VALUES ('x'); DELETE FROM sessions WHERE u = 'a'")


def tautology(cur):
    # SQL007: always-true condition embedded in SQL
    cur.execute("SELECT * FROM users WHERE name = '' OR '1'='1'")


def commented(cur, name):
    # SQL008: SQL comment sequence inside a literal
    cur.execute("SELECT * FROM users WHERE name = 'x' -- drop the rest")


def prebuilt(cur, prebuilt_query):
    # SQL009: execute() with a single pre-built string, no params
    cur.execute(prebuilt_query)


def like_concat(cur, term):
    # SQL010: LIKE pattern built by concatenation
    cur.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")


def dynamic_identifier(cur, table):
    # SQL011: identifier interpolated into SQL
    cur.execute("SELECT * FROM " + table + " WHERE active = 1")


def script(cur, payload):
    # SQL012: executescript with assembled text
    cur.executescript("CREATE TABLE t (a);" + payload)
