import tempfile, os
from vibe_guard.rules.rce import scan_file

def test_detects_eval():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('result = eval(user_input)\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'rce_risk' and f.description == 'eval() usage - remote code execution risk' for f in findings)

def test_detects_exec():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('exec(user_input)\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'rce_risk' and f.description == 'exec() usage - code execution risk' for f in findings)

def test_detects_os_system():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import os\nos.system("ls")\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'rce_risk' and f.description == 'os.system() - shell injection risk' for f in findings)

def test_detects_subprocess_with_shell_true():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import subprocess\nsubprocess.run("ls", shell=True)\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'rce_risk' and f.description == 'subprocess with shell=True - injection risk' for f in findings)

def test_detects_dynamic_import():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('module = __import__("os")\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'rce_risk' and f.description == 'Dynamic import - potential code injection' for f in findings)

def test_detects_pickle_load():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import pickle\npickle.load(f)\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'rce_risk' and f.description == 'pickle.load() - arbitrary code execution risk' for f in findings)

def test_detects_yaml_load():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import yaml\nyaml.load(stream)\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert any(f.rule_id == 'rce_risk' and f.description == 'yaml.load() without Loader - use yaml.safe_load()' for f in findings)

def test_no_false_positive_in_comment():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# eval() is dangerous\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0

def test_no_false_positive_in_string():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = "eval is a function"\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0

def test_subprocess_shell_false_is_safe():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import subprocess\nsubprocess.run("ls", shell=False)\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0

def test_vibe_ignore_comment():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('result = eval(user_input) # vibe-ignore\n')
        name = f.name
    findings = scan_file(name)
    os.unlink(name)
    assert len(findings) == 0