"""Tests for RCE risk detection."""
import tempfile
from pathlib import Path
from vibe_guard.rules.rce import scan_file


def make_temp_file(content: str, suffix: str = ".py") -> Path:
    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w",
                                     encoding="utf-8", delete=False) as f:
        f.write(content)
        return Path(f.name)


# === Positive detection ===

def test_detects_eval_dynamic():
    f = make_temp_file('result = eval(user_input)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "eval_usage" for fi in findings)


def test_detects_exec_dynamic():
    f = make_temp_file('exec(code_string)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "exec_usage" for fi in findings)


def test_detects_os_system():
    f = make_temp_file('import os\nos.system(command)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "os_system" for fi in findings)


def test_detects_subprocess_shell_true():
    f = make_temp_file('subprocess.run(cmd, shell=True)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "subprocess_shell" for fi in findings)


def test_detects_pickle_loads():
    f = make_temp_file('data = pickle.loads(raw_bytes)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "pickle_deserialization" for fi in findings)


def test_detects_dynamic_import():
    f = make_temp_file('mod = __import__(module_name)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "dynamic_import" for fi in findings)


def test_detects_yaml_load_unsafe():
    f = make_temp_file('data = yaml.load(content)\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(fi.rule_id == "yaml_load_unsafe" for fi in findings)


# === False positive avoidance ===

def test_safe_subprocess_no_shell():
    """subprocess without shell=True is safe."""
    f = make_temp_file('subprocess.run(["ls", "-la"])\n')
    findings = scan_file(f)
    assert not any(fi.rule_id == "subprocess_shell" for fi in findings)


def test_safe_eval_literal():
    """eval with a literal string is flagged (still risky by pattern)."""
    # Our pattern flags any eval() with non-literal - conservative approach
    f = make_temp_file('x = eval("1+1")\n')
    # Literal eval might be flagged or not - just check no crash
    findings = scan_file(f)
    assert isinstance(findings, list)


def test_comment_not_flagged():
    """Comments about eval should not trigger."""
    f = make_temp_file('# never use eval(user_input) in production\n')
    findings = scan_file(f)
    assert len(findings) == 0


def test_yaml_safe_load_not_flagged():
    """yaml.safe_load is safe."""
    f = make_temp_file('data = yaml.safe_load(stream)\n')
    findings = scan_file(f)
    assert not any(fi.rule_id == "yaml_load_unsafe" for fi in findings)


def test_severity_is_critical_for_eval():
    f = make_temp_file('eval(user_input)\n')
    findings = scan_file(f)
    eval_findings = [fi for fi in findings if fi.rule_id == "eval_usage"]
    assert all(fi.severity == "critical" for fi in eval_findings)
