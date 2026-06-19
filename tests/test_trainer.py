"""Lesson bank loads, and the quiz loop is testable without real input()."""

import io

from sqlsec import cli
from sqlsec import lessons as lessons_mod
from sqlsec.cli import run_quiz


def test_lesson_bank_loads():
    assert len(lessons_mod.LESSONS) >= 5
    for lesson in lessons_mod.LESSONS:
        assert lesson.topic
        assert lesson.title
        assert lesson.note
        assert len(lesson.questions) >= 1
        for q in lesson.questions:
            assert len(q.choices) >= 2
            assert 0 <= q.answer_index < len(q.choices)
            assert q.rationale


def test_topics_unique():
    topics = lessons_mod.topics()
    assert len(topics) == len(set(topics))


def test_select_lessons_all_and_specific():
    assert len(lessons_mod.select_lessons("all")) == len(lessons_mod.LESSONS)
    assert len(lessons_mod.select_lessons(None)) == len(lessons_mod.LESSONS)
    one = lessons_mod.select_lessons("basics")
    assert len(one) == 1 and one[0].topic == "basics"
    assert lessons_mod.select_lessons("nope") == []


def test_run_quiz_all_correct():
    lessons = lessons_mod.select_lessons("all")

    def ask(prompt, choices):
        # Always answer correctly by reading the bank.
        for lesson, q in lessons_mod.iter_questions(lessons):
            if q.prompt == prompt:
                return q.answer_index
        return 0

    out = io.StringIO()
    result = run_quiz(lessons, ask, out=out)
    assert result.total == result.correct
    assert result.score_pct == 100.0
    assert "100%" in out.getvalue()


def test_run_quiz_all_wrong():
    lessons = lessons_mod.select_lessons("basics")

    def ask(prompt, choices):
        for lesson, q in lessons_mod.iter_questions(lessons):
            if q.prompt == prompt:
                return (q.answer_index + 1) % len(q.choices)
        return 0

    out = io.StringIO()
    result = run_quiz(lessons, ask, out=out)
    assert result.correct == 0
    assert result.total > 0


def test_run_quiz_abort_midway():
    lessons = lessons_mod.select_lessons("all")

    def ask(prompt, choices):
        return None  # quit immediately

    out = io.StringIO()
    result = run_quiz(lessons, ask, out=out)
    assert result.total == 0


def test_console_ask_parses_input():
    lessons = lessons_mod.select_lessons("basics")
    # Provide one valid answer per question, then EOF.
    n_questions = sum(len(l.questions) for l in lessons)
    instream = io.StringIO("\n".join(["1"] * n_questions) + "\n")
    out = io.StringIO()

    class Args:
        list = False
        topic = "basics"

    rc = cli.cmd_train(Args(), out=out, in_stream=instream)
    assert rc == 0
    assert "Score:" in out.getvalue()


def test_console_ask_rejects_then_accepts():
    ask = cli._make_console_ask(io.StringIO("bogus\n9\n2\n"), io.StringIO())
    # 'bogus' invalid, '9' out of range, '2' -> index 1
    idx = ask("pick", ("a", "b", "c"))
    assert idx == 1


def test_console_ask_quit():
    ask = cli._make_console_ask(io.StringIO("q\n"), io.StringIO())
    assert ask("pick", ("a", "b")) is None


def test_train_list():
    out = io.StringIO()

    class Args:
        list = True
        topic = None

    rc = cli.cmd_train(Args(), out=out)
    assert rc == 0
    for topic in lessons_mod.topics():
        assert topic in out.getvalue()


def test_train_unknown_topic():
    out, err = io.StringIO(), io.StringIO()

    class Args:
        list = False
        topic = "nonexistent"

    rc = cli.cmd_train(Args(), out=out, err=err, in_stream=io.StringIO(""))
    assert rc == 2
