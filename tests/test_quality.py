"""Tests for code quality rule detection."""
import tempfile
from pathlib import Path
from vibe_guard.rules.quality import scan_file


def make_temp_file(content: str, suffix: str = ".py", prefix: str = "test_code_") -> Path:
    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w",
                                     encoding="utf-8", delete=False,
                                     prefix=prefix) as f:
        f.write(content)
        return Path(f.name)


# === Positive detection ===

def test_detects_bare_except():
    f = make_temp_file('try:\n    risky()\nexcept:\n    pass\n', prefix="prod_code_")
    findings = scan_file(f)
    assert any(fi.rule_id == "bare_except" for fi in findings)


def test_detects_silent_exception():
    f = make_temp_file('try:\n    risky()\nexcept Exception:\n    pass\n', prefix="prod_code_")
    findings = scan_file(f)
    assert any(fi.rule_id == "silent_exception" for fi in findings)


def test_detects_hardcoded_localhost():
    f = make_temp_file('url = "http://localhost:8080/api"\n')
    findings = scan_file(f)
    assert any(fi.rule_id == "hardcoded_localhost" for fi in findings)


def test_detects_hardcoded_127():
    f = make_temp_file('DB_HOST = "http://127.0.0.1:5432"\n')
    findings = scan_file(f)
    assert any(fi.rule_id == "hardcoded_localhost" for fi in findings)


def test_detects_excessive_prints(tmp_path):
    """6+ print statements in a non-test file should trigger warning."""
    content = "".join(f'print("debug {i}")\n' for i in range(7))
    f = tmp_path / "prodcode.py"
    f.write_text(content)
    findings = scan_file(f)
    assert any(fi.rule_id == "excessive_print_statements" for fi in findings)


# === False positive avoidance ===

def test_no_flag_in_test_file():
    """print() in test files should not trigger."""
    # make_temp_file uses prefix starting with "test_code_" so filename has "test"
    f = make_temp_file('print("debug")\nprint("more")\n' * 4)
    # Default prefix "test_code_" contains "test" - so prints should not be flagged
    findings = scan_file(f)
    assert not any(fi.rule_id == "excessive_print_statements" for fi in findings)


def test_few_todos_no_flag():
    """Less than 5% TODO ratio should not flag."""
    lines = ["x = 1\n"] * 100 + ["# TODO: fix this\n"] * 3
    f = make_temp_file("".join(lines))
    findings = scan_file(f)
    assert not any(fi.rule_id == "high_todo_ratio" for fi in findings)


def test_high_todo_ratio_flag():
    """More than 5% TODO ratio should flag."""
    lines = ["x = 1\n"] * 10 + ["# TODO: fix this\n"] * 5  # 5/15 = 33%
    f = make_temp_file("".join(lines))
    findings = scan_file(f)
    assert any(fi.rule_id == "high_todo_ratio" for fi in findings)


def test_proper_exception_handling():
    """Proper exception handling should not be flagged."""
    code = 'try:\n    risky()\nexcept ValueError as e:\n    logger.error(e)\n    raise\n'
    f = make_temp_file(code, prefix="prod_code_")
    findings = scan_file(f)
    assert not any(fi.rule_id == "bare_except" for fi in findings)


def test_markdown_not_scanned():
    """Non-Python/JS files should return no findings."""
    f = make_temp_file("# TODO: fix everything\nexcept:\n    pass", suffix=".md")
    findings = scan_file(f)
    assert findings == []


def test_severity_info_for_localhost():
    f = make_temp_file('url = "http://localhost:3000"\n')
    findings = scan_file(f)
    localhost_findings = [fi for fi in findings if fi.rule_id == "hardcoded_localhost"]
    assert all(fi.severity == "info" for fi in localhost_findings)
