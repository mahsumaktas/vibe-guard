import os
import pytest
from vibe_guard.rules import hardcoded, rce, sqli

def test_ignore_specific_rule(tmp_path):
    d = tmp_path / "subdir"
    d.mkdir()
    f = d / "test.py"
    # This line has both hardcoded secret and RCE risk, but we only ignore rce_risk
    # We use a multi-line string for clarity
    content = 'key = "sk-12345678901234567890123456789012" # vibe-ignore: rce_risk\neval(input()) # vibe-ignore: rce_risk'
    f.write_text(content)
    
    findings = hardcoded.scan_file(str(f))
    # hardcoded_secret should still be found on line 1
    assert any(fn.rule_id == "hardcoded_secret" for fn in findings)
    
    findings_rce = rce.scan_file(str(f))
    # rce_risk should be ignored on both lines
    assert not any(fn.rule_id == "rce_risk" for fn in findings_rce)

def test_ignore_multiple_rules(tmp_path):
    f = tmp_path / "test.py"
    f.write_text('eval("SELECT * FROM users") # vibe-ignore: rce_risk, sql_injection')
    
    assert not any(fn.rule_id == "rce_risk" for fn in rce.scan_file(str(f)))
    assert not any(fn.rule_id == "sql_injection" for fn in sqli.scan_file(str(f)))

def test_ignore_all(tmp_path):
    f = tmp_path / "test.py"
    f.write_text('eval(input()) # vibe-ignore')
    
    assert not any(fn.rule_id == "rce_risk" for fn in rce.scan_file(str(f)))
