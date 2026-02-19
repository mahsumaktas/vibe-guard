"""Tests for SQL injection detection."""
import tempfile
from pathlib import Path
from vibe_guard.rules.sqli import scan_file


def make_temp_file(content: str, suffix: str = ".py") -> Path:
    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w",
                                     encoding="utf-8", delete=False) as f:
        f.write(content)
        return Path(f.name)


# === Positive detection ===

def test_detects_string_concat():
    f = make_temp_file('query = "SELECT * FROM users WHERE id = " + user_id\n')
    findings = scan_file(f)
    assert len(findings) > 0


def test_detects_fstring_sql():
    f = make_temp_file('query = f"SELECT * FROM {table_name}"\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "sql_fstring" for fi in findings)


def test_detects_cursor_execute_concat():
    f = make_temp_file('cursor.execute("SELECT * FROM users WHERE name = " + name)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "cursor_execute_concat" for fi in findings)


def test_detects_cursor_execute_fstring():
    f = make_temp_file('cursor.execute(f"DELETE FROM {table}")\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "cursor_execute_fstring" for fi in findings)


def test_detects_percent_format():
    f = make_temp_file('sql = "SELECT * FROM users WHERE id = %s" % user_id\n')
    findings = scan_file(f)
    assert len(findings) > 0


def test_detects_format_method():
    f = make_temp_file('sql = "SELECT * FROM users WHERE name = {}".format(name)\n')
    findings = scan_file(f)
    assert len(findings) > 0


# === False positive avoidance ===

def test_safe_parameterized_query():
    """Parameterized queries are safe."""
    f = make_temp_file('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n')
    findings = scan_file(f)
    # The query itself has no concatenation - should not flag
    risky = [fi for fi in findings if fi.severity == "critical"]
    assert len(risky) == 0


def test_safe_literal_sql():
    """Static SQL without user input is safe."""
    f = make_temp_file('cursor.execute("SELECT COUNT(*) FROM users")\n')
    findings = scan_file(f)
    risky = [fi for fi in findings if fi.severity == "critical"]
    assert len(risky) == 0


def test_comment_not_flagged():
    f = make_temp_file('# SELECT * FROM users WHERE id = " + user_id -- injection\n')
    findings = scan_file(f)
    assert len(findings) == 0


def test_markdown_file_skipped():
    """Markdown files should be skipped."""
    f = make_temp_file('Use `SELECT * FROM users WHERE id = " + id` carefully\n', suffix=".md")
    findings = scan_file(f)
    assert findings == []


def test_all_findings_have_filename():
    f = make_temp_file('q = "SELECT * FROM " + table\n')
    findings = scan_file(f)
    for fi in findings:
        assert fi.filename
        assert fi.line_number > 0
