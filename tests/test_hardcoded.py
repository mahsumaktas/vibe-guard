"""Tests for hardcoded credential detection."""
import tempfile
from pathlib import Path
import pytest
from vibe_guard.rules.hardcoded import scan_file, calculate_entropy, Finding


# --- Helper ---
def make_temp_file(content: str, suffix: str = ".py") -> Path:
    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w",
                                     encoding="utf-8", delete=False) as f:
        f.write(content)
        return Path(f.name)


# === Positive detection tests ===

def test_detects_openai_key():
    f = make_temp_file('api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(finding.severity == "critical" for finding in findings)


def test_detects_github_token():
    f = make_temp_file('token = "ghp_' + 'A' * 36 + '"\n')
    findings = scan_file(f)
    assert len(findings) > 0
    rule_ids = [finding.rule_id for finding in findings]
    assert "github_token" in rule_ids


def test_detects_aws_access_key():
    f = make_temp_file('key = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(f.rule_id == "aws_access_key" for f in findings)


def test_detects_hardcoded_password():
    f = make_temp_file('password = "supersecret123"\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(f.severity == "critical" for f in findings)


def test_detects_hardcoded_secret():
    f = make_temp_file('api_key = "my_super_secret_api_key"\n')
    findings = scan_file(f)
    assert len(findings) > 0


def test_detects_slack_token():
    f = make_temp_file('bot_token = "xoxb-1234567890-1234567890-' + 'a' * 24 + '"\n')
    findings = scan_file(f)
    assert len(findings) > 0


def test_detects_stripe_live_key():
    f = make_temp_file('stripe_key = "sk_live_' + 'a' * 24 + '"\n')
    findings = scan_file(f)
    assert len(findings) > 0
    assert any(f.rule_id == "stripe_live_key" for f in findings)


def test_detects_private_key_header():
    f = make_temp_file('key_data = """-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n"""\n')
    findings = scan_file(f)
    assert len(findings) > 0


# === False positive avoidance tests ===

def test_no_false_positive_env_var_lookup():
    """os.environ lookup is NOT a hardcoded secret."""
    f = make_temp_file('api_key = os.environ.get("OPENAI_API_KEY")\n')
    findings = scan_file(f)
    # Should not flag env var lookups
    assert not any(f.rule_id == "hardcoded_secret" for f in findings)


def test_no_false_positive_process_env():
    """process.env lookup in JS is safe."""
    f = make_temp_file('const key = process.env.API_KEY;\n', suffix=".js")
    findings = scan_file(f)
    assert not any(f.rule_id == "hardcoded_secret" for f in findings)


def test_no_false_positive_comment():
    """Comments should not trigger findings."""
    f = make_temp_file('# password = "example"\n')
    findings = scan_file(f)
    assert len(findings) == 0


def test_no_false_positive_short_string():
    """Short password-looking strings should not necessarily trigger."""
    f = make_temp_file('# minimum password length is 8\nminLen = 8\n')
    findings = scan_file(f)
    # No critical findings
    assert not any(f.severity == "critical" for f in findings)


# === Entropy tests ===

def test_entropy_low_string():
    assert calculate_entropy("aaaaaaaaaa") < 1.0


def test_entropy_high_random():
    # Random-looking string should have high entropy
    s = "aB3$xY7qZ1mN9pR2wK5jL8hV4tG6fD0eC"
    assert calculate_entropy(s) > 4.0


def test_entropy_empty():
    assert calculate_entropy("") == 0.0


def test_entropy_uniform():
    # All unique chars = max entropy
    s = "abcdefghijklmnop"
    assert calculate_entropy(s) == pytest.approx(4.0, abs=0.1)


# === Vibe Score tests ===

def test_vibe_score_perfect():
    from vibe_guard.scorer import calculate_vibe_score
    assert calculate_vibe_score([]) == 100


def test_vibe_score_one_critical():
    from vibe_guard.scorer import calculate_vibe_score
    findings = [Finding("test", "critical", "f.py", 1, "x", "desc")]
    assert calculate_vibe_score(findings) == 80


def test_vibe_score_cap():
    """Score should not go below 0 even with many findings."""
    from vibe_guard.scorer import calculate_vibe_score
    findings = [Finding("test", "critical", "f.py", i, "x", "desc") for i in range(20)]
    score = calculate_vibe_score(findings)
    assert score >= 0


def test_vibe_score_label():
    from vibe_guard.scorer import score_label
    assert score_label(100) == "Safe"
    assert score_label(90) == "Safe"
    assert score_label(75) == "OK"
    assert score_label(55) == "Review"
    assert score_label(30) == "Unsafe"


# === File type tests ===

def test_binary_file_skipped():
    """Binary files should return no findings."""
    f = Path(tempfile.mktemp(suffix=".png"))
    f.write_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR')
    findings = scan_file(f)
    assert findings == []
