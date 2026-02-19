import tempfile, os
from vibe_guard.rules.hardcoded import scan_file, scan_directory, calculate_entropy

def test_detects_api_key_in_variable():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('API_KEY = "a_very_long_and_secretive_api_key_string"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_secret' and f.description == 'Hardcoded API key' for f in findings)

def test_detects_password_in_variable():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('password = "mySuperSecretPassword123!"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_secret' and f.description == 'Hardcoded password' for f in findings)

def test_detects_secret_token_in_variable():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('SECRET = "a_super_secret_token_of_at_least_16_chars"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_secret' and f.description == 'Hardcoded secret/token' for f in findings)

def test_detects_openai_api_key():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('openai.api_key = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_secret' and f.description == 'OpenAI API key' for f in findings)

def test_detects_github_personal_access_token():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_secret' and f.description == 'GitHub Personal Access Token' for f in findings)
    
def test_detects_slack_bot_token():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('SLACK_TOKEN = "xoxb-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_secret' and f.description == 'Slack Bot Token' for f in findings)

def test_detects_aws_secret_access_key():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('aws_secret_access_key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'hardcoded_secret' and f.description == 'AWS Secret Access Key' for f in findings)

def test_high_entropy_string_detected():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('random_string = "AbcDefGhiJklMnoPqrStuVwxYz1234567890+/"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'high_entropy_string' for f in findings)

def test_no_false_positive_in_comment():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# API_KEY = "a_very_long_and_secretive_api_key_string"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0
    
def test_no_false_positive_in_example_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('API_KEY = "example_key_for_testing"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0

def test_scan_file_not_found():
    findings = scan_file("non_existent_file.py")
    assert len(findings) == 0

def test_entropy_calculation():
    assert calculate_entropy("abc") > 1.5
    assert calculate_entropy("aaa") == 0.0
    assert calculate_entropy("") == 0.0

def test_scan_directory():
    with tempfile.TemporaryDirectory() as tempdir:
        with open(os.path.join(tempdir, "secrets.py"), "w") as f:
            f.write('password = "mySuperSecretPassword123!"\n')
        
        with open(os.path.join(tempdir, "no_secrets.py"), "w") as f:
            f.write('password = "ok"\n')

        findings = scan_directory(tempdir)
        assert len(findings) == 1
        assert findings[0].rule_id == 'hardcoded_secret'

def test_false_positive_short_strings():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('pwd = "short"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0

def test_entropy_with_placeholders():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('key = "your_api_key_here"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert not any(f.rule_id == 'high_entropy_string' for f in findings)