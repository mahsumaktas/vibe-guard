import re
from pathlib import Path
from typing import List
from ..models import Finding
from .common import should_ignore, is_excluded_dir

INSECURE_PATTERNS = [
    (r'(?i)Access-Control-Allow-Origin\s*:\s*\*', "warning", "Overly permissive CORS: allows any domain"),
    (r'console\.log\s*\(\s*process\.env\s*\)', "critical", "Environment variables logged to console"),
    (r'verify\s*=\s*False', "critical", "SSL certificate verification disabled (verify=False)"),
    (r'tls_reject_unauthorized\s*=\s*(0|false)', "critical", "Node.js TLS rejection disabled"),
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
        if stripped.startswith('#') or stripped.startswith('//'):
            continue

        for pattern, severity, desc in INSECURE_PATTERNS:
            if re.search(pattern, line):
                if should_ignore(line, "insecure_default"):
                    continue
                findings.append(Finding(
                    rule_id="insecure_default",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description=desc
                ))
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx'}
    for p in Path(path).rglob('*'):
        if p.is_file() and p.suffix in extensions and not is_excluded_dir(str(p)):
            findings.extend(scan_file(str(p)))
    return findings
