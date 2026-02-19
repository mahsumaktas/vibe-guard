import re
from pathlib import Path
from typing import List
from .hardcoded import Finding

RCE_PATTERNS = [
    (r'\beval\s*\(', "critical", "eval() usage - remote code execution risk"),
    (r'\bexec\s*\(', "critical", "exec() usage - code execution risk"),
    (r'os\.system\s*\(', "critical", "os.system() - shell injection risk"),
    (r'subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True', "critical", "subprocess with shell=True - injection risk"),
    (r'__import__\s*\(', "warning", "Dynamic import - potential code injection"),
    (r'pickle\.loads?\s*\(', "warning", "pickle.load() - arbitrary code execution risk"),
    (r'yaml\.load\s*\([^,)]*\)', "warning", "yaml.load() without Loader - use yaml.safe_load()"),
]

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        for pattern, severity, desc in RCE_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id="rce_risk",
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
