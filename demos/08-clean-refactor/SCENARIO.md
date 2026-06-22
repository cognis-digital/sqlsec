# Demo 08 — The clean rewrite (zero findings)

**Where this came from.** The parameterized rewrite of [demo 01](../01-flask-user-search/).
This is the **after** picture: same three operations, written safely.

**What to expect.** Nothing. The file lints clean:

```
No unsafe patterns found.
```

That is the point — use it side by side with demo 01 to show the before/after,
and as a positive control proving the linter stays quiet on idiomatic safe code
(few false positives).

**Run it.**

```bash
sqlsec lint demos/08-clean-refactor
sqlsec lint demos/08-clean-refactor --fail-on info   # still exits 0
```

**What makes it safe.**

- LIKE pattern: built in Python, then **bound** as one parameter.
- Status value: bound, not concatenated.
- Sort column (an *identifier*, which can't be bound): the input key is mapped
  to a whole pre-written, constant query string through a fixed allow-list, so
  no request value ever reaches the SQL text.
