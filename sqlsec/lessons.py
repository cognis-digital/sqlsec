"""Authored lesson + quiz bank for the sqlsec trainer.

A small set of original lessons on SQL-injection safety and parameterized
queries. Each lesson carries a short teaching note and one or more multiple
choice questions. The interactive loop logic is kept pure (no input()) so it is
unit-testable; the CLI wires real input/output around it.

All lesson copy and questions are original work by Cognis Digital.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Question:
    prompt: str
    choices: tuple  # tuple[str, ...]
    answer_index: int
    rationale: str

    def is_correct(self, choice_index: int) -> bool:
        return choice_index == self.answer_index


@dataclass(frozen=True)
class Lesson:
    topic: str
    title: str
    note: str
    questions: tuple = field(default_factory=tuple)  # tuple[Question, ...]


LESSONS: list[Lesson] = [
    Lesson(
        topic="basics",
        title="What SQL injection actually is",
        note=(
            "SQL injection happens when input is treated as part of a query's "
            "*structure* instead of as *data*. If a value can introduce a quote, "
            "a clause, or a second statement, the attacker controls the query. "
            "The fix is to keep the SQL text fixed in code and send values "
            "separately as bound parameters."
        ),
        questions=(
            Question(
                prompt="What is the root cause of a SQL injection vulnerability?",
                choices=(
                    "The database is too old to patch",
                    "Input is concatenated into the query structure instead of bound as data",
                    "The table has too many columns",
                    "The connection is not encrypted",
                ),
                answer_index=1,
                rationale=(
                    "Injection is about input crossing from data into the "
                    "statement's structure. Binding values keeps that boundary."
                ),
            ),
            Question(
                prompt="Which single technique prevents the most SQL injection?",
                choices=(
                    "Hiding error messages",
                    "Renaming tables",
                    "Parameterized (bound) queries",
                    "A longer connection timeout",
                ),
                answer_index=2,
                rationale=(
                    "Parameterized queries send the SQL and the values "
                    "separately, so values can never change the statement."
                ),
            ),
        ),
    ),
    Lesson(
        topic="parameterize",
        title="Parameterized queries vs string building",
        note=(
            "A parameterized query uses placeholders (?, %s, or :name depending "
            "on the driver) in static SQL text, and passes the values as a "
            "separate sequence or mapping to execute(). The driver binds them, "
            "escaping is automatic and correct, and the query structure cannot "
            "change. Never build the SQL with +, %, .format(), or an f-string."
        ),
        questions=(
            Question(
                prompt='Which call is safe in sqlite3?',
                choices=(
                    'cur.execute("SELECT * FROM t WHERE id = " + uid)',
                    'cur.execute(f"SELECT * FROM t WHERE id = {uid}")',
                    'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))',
                    'cur.execute("SELECT * FROM t WHERE id = %s" % uid)',
                ),
                answer_index=2,
                rationale=(
                    "Only the placeholder + params tuple binds the value; the "
                    "other three splice it into the SQL text."
                ),
            ),
            Question(
                prompt="What is the second argument to execute() used for?",
                choices=(
                    "A comment describing the query",
                    "The values to bind to the placeholders",
                    "The name of the table",
                    "A timeout in seconds",
                ),
                answer_index=1,
                rationale=(
                    "execute(sql, params) binds params to the placeholders in "
                    "sql. That separation is what makes it safe."
                ),
            ),
        ),
    ),
    Lesson(
        topic="identifiers",
        title="Why placeholders cannot bind table/column names",
        note=(
            "Bound parameters only work for *values*, not for identifiers like "
            "table or column names or for keywords like ASC/DESC. If you must "
            "pick an identifier from input, validate it against a fixed "
            "allow-list of known names and use the vetted constant in the SQL — "
            "do not concatenate raw input as an identifier."
        ),
        questions=(
            Question(
                prompt="A sort column comes from a query string. Safest approach?",
                choices=(
                    "Concatenate the column name into the ORDER BY clause",
                    "Map the input through an allow-list of permitted columns",
                    "Wrap the column name in quotes",
                    "Pass the column name as a bound parameter",
                ),
                answer_index=1,
                rationale=(
                    "Identifiers can't be bound. An allow-list maps untrusted "
                    "input to a known-safe constant before it touches the SQL."
                ),
            ),
        ),
    ),
    Lesson(
        topic="dynamic",
        title="Dynamic SQL and EXEC",
        note=(
            "Dynamic SQL builds a statement at runtime and runs it with EXEC / "
            "sp_executesql / EXECUTE IMMEDIATE. It is occasionally necessary, but "
            "concatenating input into the executed text is one of the most "
            "dangerous patterns there is. When dynamic SQL is unavoidable, "
            "parameterize the dynamic statement and never splice in raw input."
        ),
        questions=(
            Question(
                prompt="When is dynamic EXEC of a concatenated string acceptable?",
                choices=(
                    "Whenever it is more convenient",
                    "When the input is from a trusted admin",
                    "Essentially never with raw input; parameterize the dynamic statement",
                    "When wrapped in a transaction",
                ),
                answer_index=2,
                rationale=(
                    "Trust and transactions do not stop injection. Parameterize "
                    "the dynamic statement instead of concatenating input."
                ),
            ),
        ),
    ),
    Lesson(
        topic="stacked",
        title="Stacked queries and the trailing semicolon",
        note=(
            "A stacked query packs more than one statement into a single string "
            "separated by ';'. If part of that string is attacker-controlled, "
            "they can append '; DROP TABLE ...'. Run one statement per execute() "
            "call and never allow a trailing statement to be appended to a query "
            "built from input."
        ),
        questions=(
            Question(
                prompt="Why are stacked queries risky?",
                choices=(
                    "They run slower",
                    "An attacker can append an extra statement after a ';'",
                    "They use more memory",
                    "They cannot be logged",
                ),
                answer_index=1,
                rationale=(
                    "A ';' lets a second statement ride along; if any part is "
                    "from input, the attacker chooses that statement."
                ),
            ),
        ),
    ),
    Lesson(
        topic="defense-in-depth",
        title="Layers beyond parameterization",
        note=(
            "Parameterized queries are the primary defense. Around them: apply "
            "least-privilege database accounts so a compromised query can do "
            "little, validate and constrain input types, use allow-lists for "
            "identifiers, and avoid leaking detailed SQL errors to users. These "
            "layers reduce blast radius but do not replace binding values."
        ),
        questions=(
            Question(
                prompt="Which is a defense-in-depth layer, NOT a replacement for binding?",
                choices=(
                    "Least-privilege database accounts",
                    "Treating input as part of the SQL structure",
                    "Disabling all logging",
                    "Using one shared admin account everywhere",
                ),
                answer_index=0,
                rationale=(
                    "Least privilege limits damage if something slips through, "
                    "but parameterized queries remain the main control."
                ),
            ),
        ),
    ),
]


def topics() -> list[str]:
    return [lesson.topic for lesson in LESSONS]


def get_lesson(topic: str):
    for lesson in LESSONS:
        if lesson.topic == topic.lower():
            return lesson
    return None


def select_lessons(topic: str | None = None) -> list[Lesson]:
    """Return the lessons to quiz. None/'all' selects every lesson."""
    if topic is None or topic.lower() == "all":
        return list(LESSONS)
    lesson = get_lesson(topic)
    return [lesson] if lesson else []


@dataclass
class QuizResult:
    total: int = 0
    correct: int = 0
    details: list = field(default_factory=list)  # list[tuple[Question, int, bool]]

    def record(self, question: Question, choice_index: int) -> bool:
        ok = question.is_correct(choice_index)
        self.total += 1
        if ok:
            self.correct += 1
        self.details.append((question, choice_index, ok))
        return ok

    @property
    def score_pct(self) -> float:
        if self.total == 0:
            return 0.0
        return 100.0 * self.correct / self.total


def iter_questions(lessons: list[Lesson]):
    """Yield (lesson, question) pairs across the selected lessons."""
    for lesson in lessons:
        for question in lesson.questions:
            yield lesson, question
