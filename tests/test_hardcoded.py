"""Tests for hardcoded credential detection."""
import tempfile
from pathlib import Path
from vibe_guard.rules.hardcoded import scan_file


def test_detects_openai_key():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write('api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"\n')
        f.flush()
        findings = scan_file(Path(f.name))
    assert len(findings) > 0
    assert findings[0].severity == "CRITICAL"


def test_no_false_positive():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write('api_key = os.environ.get("OPENAI_API_KEY")\n')
        f.flush()
        findings = scan_file(Path(f.name))
    assert len(findings) == 0


def test_vibe_score_perfect():
    from vibe_guard.scorer import calculate_score
    assert calculate_score([]) == 100
