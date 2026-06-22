"""Product-catalog filtering for an e-commerce storefront.

DEMONSTRATION ONLY. Intentionally unsafe. The keyword search builds a LIKE
pattern by concatenation, and the category filter uses str.format() -- both
splice shopper input into the query text instead of binding it.
"""

import mysql.connector


def search_catalog(conn, keyword):
    cur = conn.cursor()
    # Keyword from the storefront search bar.
    cur.execute("SELECT * FROM products WHERE title LIKE '%" + keyword + "%'")
    return cur.fetchall()


def by_category(conn, category, max_price):
    cur = conn.cursor()
    # Category from a facet link, max_price from a slider widget.
    sql = "SELECT * FROM products WHERE category = '{}' AND price <= {}".format(
        category, max_price
    )
    cur.execute(sql)
    return cur.fetchall()
