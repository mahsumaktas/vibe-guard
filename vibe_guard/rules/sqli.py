import re
from pathlib import Path
from typing import List
from .hardcoded import Finding

SQLI_PATTERNS = [
    (r'(?i)cursor\.execute\s*\([^)]*\+', "critical", "SQL execute with string concatenation"),
    (r'(?i)cursor\.execute\s*\(\s*f["\']', "critical", "SQL execute with f-string - injection risk"),
    (r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE).{0,50}["\']?\s*\+\s*\w+', "critical", "SQL string concatenation - injection risk"),
    (r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.{0,30}%s.*%\s*\w+', "warning", "SQL with % formatting - use parameterized queries"),
]

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
    except (IOError, OSError):
        return findings
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        for pattern, severity, desc in SQLI_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id="sql_injection",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description=desc
                ))
                break
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    for p in Path(path).rglob('*.py'):
        if '.git' not in str(p):
            findings.extend(scan_file(str(p)))
    return findings
