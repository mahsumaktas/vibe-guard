import tempfile, os
from vibe_guard.rules.quality import scan_file

def test_detects_silent_exception():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('try:\n    1/0\nexcept:\n    pass\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'silent_exception' for f in findings)

def test_detects_todo_comment():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# TODO: Fix this later\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'high_todo_ratio' for f in findings)

def test_detects_print_statement():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('print("debug")\n')
        name = f.name
    findings = scan_file(name)
    # This is also a directory-level rule, so we will test the threshold there
    assert not any(f.rule_id == 'excessive_print' for f in findings)


def test_detects_hardcoded_localhost():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('url = "http://localhost:8000"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_localhost' for f in findings)

def test_detects_hardcoded_localhost_ip():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('url = "http://127.0.0.1:8000"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_localhost' for f in findings)


def test_no_false_positive_for_good_exception_handling():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('try:\n    1/0\nexcept ZeroDivisionError as e:\n    print(e)\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert not any(f.rule_id == 'silent_exception' for f in findings)

def test_high_todo_ratio():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# TODO: 1\n# TODO: 2\n# TODO: 3\n' + '\n'*50)
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'high_todo_ratio' for f in findings)

def test_excessive_print_usage():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('print(1)\n' * 11)
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'excessive_print' for f in findings)
    
def test_print_in_test_file_is_ok():
    with tempfile.NamedTemporaryFile(mode='w', suffix='_test.py', delete=False) as f:
        f.write('print(1)\n' * 11)
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert not any(f.rule_id == 'excessive_print' for f in findings)

def test_vibe_ignore_comment():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('except: # vibe-ignore\n    pass\n')
        f.write('url = "http://localhost:8000" # vibe-ignore\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0

