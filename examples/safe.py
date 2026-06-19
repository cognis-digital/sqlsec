"""Safe counterparts to vulnerable.py.

Every function uses parameterized queries or validated allow-lists. `sqlsec
lint` should produce NO findings for this file. Use these as the patterns to
follow in real code.
"""

import sqlite3

# Allow-list of identifiers we are willing to interpolate. Identifiers cannot be
# bound as parameters, so we map untrusted input to a known-safe constant.
ALLOWED_TABLES = {"users": "users", "products": "products"}
ALLOWED_SORT = {"name": "name", "created": "created_at"}


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()


def get_user_by_name(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()


def get_user_by_email(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchall()


def insert_then_clean(conn, value, user):
    # Two separate, parameterized statements -- never stacked in one string.
    cur = conn.cursor()
    cur.execute("INSERT INTO log VALUES (?)", (value,))
    cur.execute("DELETE FROM sessions WHERE u = ?", (user,))
    conn.commit()


def search_products(conn, term):
    cur = conn.cursor()
    # Build the wildcard pattern in Python, then bind the whole thing.
    pattern = f"%{term}%"
    cur.execute("SELECT * FROM products WHERE name LIKE ?", (pattern,))
    return cur.fetchall()


def select_from_allowed(conn, table_request):
    # Identifier comes from an allow-list, not from raw input. Placeholders
    # cannot bind identifiers, so we map untrusted input to a fixed, known-safe
    # query constant chosen entirely in code -- input never reaches the SQL.
    queries = {
        "users": "SELECT id FROM users WHERE active = ?",
        "products": "SELECT id FROM products WHERE active = ?",
    }
    query = queries.get(table_request)
    if query is None:
        raise ValueError("unknown table")
    cur = conn.cursor()
    return cur.execute(query, (1,)).fetchall()


def setup_schema(conn):
    # Static, trusted migration text -- no input involved.
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT);
        """
    )
