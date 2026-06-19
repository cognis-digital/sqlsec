"""sqlsec - a defensive SQL-safety linter and trainer.

Scans SQL strings and source files for unsafe query-construction patterns
(string concatenation, f-string interpolation, dynamic EXEC, stacked queries,
missing parameterization) and ships an interactive trainer that quizzes the
user on SQL-injection safety and parameterized queries.

Defensive / educational scope only. It does not execute attacks.

Maintainer: Cognis Digital
License: COCL 1.0
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
