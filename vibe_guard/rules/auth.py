import re
from pathlib import Path
from typing import List
from ..models import Finding
from .common import should_ignore, is_excluded_dir

AUTH_PATTERNS = [
    # JWT Vulnerabilities
    (r'(?i)["\']alg["\']\s*:\s*["\']none["\']', "critical", "JWT: Algorithm 'none' is completely insecure and bypasses signature validation"),
    (r'(?i)jwt\.sign\([^,]+,\s*["\'](secret|12345|test|password)["\']', "critical", "JWT: Signed with a very weak, hardcoded secret"),
    
    # Insecure Cookies
    (r'(?i)res\.cookie\([^,]+,\s*[^,]+,\s*\{\s*(?!.*httpOnly).*\}', "warning", "Cookie: Set without 'httpOnly' flag, vulnerable to XSS"),
    (r'(?i)res\.cookie\([^,]+,\s*[^,]+,\s*\{\s*(?!.*secure).*\}', "warning", "Cookie: Set without 'secure' flag, can be intercepted over HTTP"),
    
    # NextAuth / Generic Auth
    (r'(?i)NEXTAUTH_SECRET\s*=\s*["\'](secret|test|12345)["\']', "critical", "NextAuth: Extremely weak default secret used"),
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

        for pattern, severity, desc in AUTH_PATTERNS:
            if re.search(pattern, line):
                if should_ignore(line, "auth_misconfig"):
                    continue
                findings.append(Finding(
                    rule_id="auth_misconfig",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description=desc
                ))
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    extensions = {'.js', '.ts', '.jsx', '.tsx', '.py', '.env'}
    for p in Path(path).rglob('*'):
        if p.is_file() and p.suffix in extensions and not is_excluded_dir(str(p)):
            findings.extend(scan_file(str(p)))
    return findings
