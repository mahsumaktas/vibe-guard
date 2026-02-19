from vibe_guard.scorer import calculate_vibe_score, score_label, score_emoji
from vibe_guard.rules.hardcoded import Finding

def test_calculate_vibe_score_no_findings():
    assert calculate_vibe_score([]) == 100

def test_calculate_vibe_score_one_critical():
    findings = [Finding("test", "critical", "file.py", 1, "line", "desc")]
    assert calculate_vibe_score(findings) == 80

def test_calculate_vibe_score_multiple_critical():
    findings = [Finding("test", "critical", "file.py", i, "line", "desc") for i in range(3)]
    assert calculate_vibe_score(findings) == 40

def test_calculate_vibe_score_many_critical_cap():
    findings = [Finding("test", "critical", "file.py", i, "line", "desc") for i in range(10)]
    assert calculate_vibe_score(findings) == 40 # capped at 60 penalty

def test_calculate_vibe_score_one_warning():
    findings = [Finding("test", "warning", "file.py", 1, "line", "desc")]
    assert calculate_vibe_score(findings) == 95

def test_calculate_vibe_score_multiple_warnings():
    findings = [Finding("test", "warning", "file.py", i, "line", "desc") for i in range(4)]
    assert calculate_vibe_score(findings) == 80

def test_calculate_vibe_score_many_warnings_cap():
    findings = [Finding("test", "warning", "file.py", i, "line", "desc") for i in range(10)]
    assert calculate_vibe_score(findings) == 80 # capped at 20 penalty

def test_calculate_vibe_score_one_info():
    findings = [Finding("test", "info", "file.py", 1, "line", "desc")]
    assert calculate_vibe_score(findings) == 99

def test_calculate_vibe_score_multiple_infos():
    findings = [Finding("test", "info", "file.py", i, "line", "desc") for i in range(5)]
    assert calculate_vibe_score(findings) == 95
    
def test_calculate_vibe_score_many_infos_cap():
    findings = [Finding("test", "info", "file.py", i, "line", "desc") for i in range(10)]
    assert calculate_vibe_score(findings) == 95 # capped at 5 penalty

def test_calculate_vibe_score_mixed():
    findings = [
        Finding("test", "critical", "file.py", 1, "line", "desc"),
        Finding("test", "warning", "file.py", 2, "line", "desc"),
        Finding("test", "info", "file.py", 3, "line", "desc"),
    ]
    assert calculate_vibe_score(findings) == 100 - 20 - 5 - 1

def test_score_label():
    assert score_label(95) == "Safe"
    assert score_label(85) == "OK"
    assert score_label(65) == "Review needed"
    assert score_label(45) == "Unsafe"
    assert score_label(0) == "Unsafe"

def test_score_emoji():
    assert score_emoji(95) == "✅"
    assert score_emoji(85) == "🟡"
    assert score_emoji(65) == "⚠️"
    assert score_emoji(45) == "🔴"
    assert score_emoji(0) == "🔴"
