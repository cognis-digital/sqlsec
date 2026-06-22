# Demo 04 — Legacy T-SQL stored procedure (dynamic SQL)

**Where this came from.** A database security review of a SQL Server app. The
`dbo.GetOrders` procedure takes a customer name plus a caller-chosen sort column
and filter, concatenates them into a string, and runs it with `EXEC()`. This is
a raw `.sql` file — `sqlsec` scans SQL sources, not just Python.

**What to expect.** Three findings:

- `SQL005` (**critical**) — `EXEC('... ' + @CustomerName + ...)` runs an
  assembled string. The `@Filter` parameter is the worst part: it is dropped in
  as a whole clause, so a caller can inject arbitrary boolean logic.
- `SQL001` (high) × 2 — the concatenation that builds the dynamic statement.

**Run it.**

```bash
sqlsec lint demos/04-legacy-stored-proc/get_orders.sql
```

**How to act.** Avoid dynamic SQL where you can. When it is unavoidable (e.g. a
genuinely dynamic ORDER BY), parameterize the values with `sp_executesql` and
validate the sort column against a fixed list:

```sql
DECLARE @order NVARCHAR(100) =
    CASE @SortColumn WHEN 'date' THEN 'OrderDate' ELSE 'OrderId' END;
EXEC sp_executesql
    N'SELECT * FROM Orders WHERE CustomerName = @c',
    N'@c NVARCHAR(100)', @c = @CustomerName;
```

Never concatenate `@Filter`-style free text into the statement.
