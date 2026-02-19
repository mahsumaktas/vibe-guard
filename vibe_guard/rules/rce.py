"""Detect Remote Code Execution (RCE) risk patterns."""
import re
from pathlib import Path
from typing import List
from .hardcoded import Finding


# RCE patterns: (regex, rule_id, severity, description)
RCE_PATTERNS = [
    # eval() with non-literal argument
    (r'\beval\s*\((?!["\'])', "eval_usage", "critical",
     "eval() with dynamic argument - potential code execution"),
    # exec() with non-literal argument
    (r'\bexec\s*\((?!["\'])', "exec_usage", "critical",
     "exec() with dynamic argument - potential code execution"),
    # os.system()
    (r'\bos\.system\s*\(', "os_system", "critical",
     "os.system() usage - potential shell injection"),
    # subprocess with shell=True
    (r'\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True', "subprocess_shell", "critical",
     "subprocess called with shell=True - potential shell injection"),
    # __import__()
    (r'\b__import__\s*\(', "dynamic_import", "warning",
     "__import__() usage - dynamic module loading"),
    # compile() with exec mode
    (r'\bcompile\s*\([^,]+,\s*[^,]+,\s*["\']exec["\']', "compile_exec", "warning",
     "compile() with 'exec' mode - potential code execution"),
    # pickle.loads() - arbitrary code execution
    (r'\bpickle\.loads?\s*\(', "pickle_deserialization", "critical",
     "pickle.loads() - deserialization can execute arbitrary code"),
    # yaml.load() without Loader
    (r'\byaml\.load\s*\([^,)]+\)', "yaml_load_unsafe", "warning",
     "yaml.load() without explicit Loader - use yaml.safe_load()"),
    # marshal.loads()
    (r'\bmarshal\.loads?\s*\(', "marshal_loads", "critical",
     "marshal.loads() - arbitrary code execution risk"),
    # popen variants
    (r'\bos\.popen\s*\(', "os_popen", "critical",
     "os.popen() - potential shell injection"),
    (r'\bpopen\s*\(', "popen_call", "warning",
     "popen() call - potential shell injection"),
]

# Lines that are likely safe (documentation, comments about patterns)
SAFE_CONTEXTS = [
    r'#.*eval',
    r'#.*exec',
    r'"""',
    r"'''",
]


def scan_file(filepath) -> List[Finding]:
    """Scan a file for RCE risk patterns."""
    filepath = Path(filepath)
    findings: List[Finding] = []

    skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                       '.woff', '.woff2', '.ttf', '.pdf', '.zip', '.gz',
                       '.tar', '.lock', '.bin', '.exe'}
    if filepath.suffix.lower() in skip_extensions:
        return []

    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []

    filename = str(filepath)
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip pure comment lines
        if stripped.startswith('#') or stripped.startswith('//'):
            continue

        for pattern, rule_id, severity, description in RCE_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    filename=filename,
                    line_number=line_no,
                    line_content=line.strip()[:120],
                    description=description,
                ))
                break  # one finding per line

    return findings
