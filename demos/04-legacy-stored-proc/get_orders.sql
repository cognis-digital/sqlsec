-- Legacy T-SQL stored procedure flagged during a database security review.
-- DEMONSTRATION ONLY. Intentionally unsafe: it concatenates the caller-supplied
-- @SortColumn and @Filter into a string and runs it with dynamic EXEC, so any
-- value passed in becomes part of the executed statement.

CREATE PROCEDURE dbo.GetOrders
    @CustomerName NVARCHAR(100),
    @SortColumn   NVARCHAR(50),
    @Filter       NVARCHAR(200)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX);

    SET @sql = 'SELECT * FROM Orders WHERE CustomerName = ''' + @CustomerName + '''';
    SET @sql = @sql + ' AND ' + @Filter + ' ORDER BY ' + @SortColumn;

    -- Running the assembled string directly is the critical dynamic-SQL sink.
    EXEC('SELECT * FROM Orders WHERE CustomerName = ''' + @CustomerName + '''');
    EXEC(@sql);
END
