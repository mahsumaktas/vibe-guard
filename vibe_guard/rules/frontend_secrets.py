import re
from pathlib import Path
from typing import List
from ..models import Finding
from .common import should_ignore

# Detect patterns where sensitive names are exposed via frontend public prefixes
FRONTEND_PREFIXES = r'(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)'
SENSITIVE_NAMES = r'(SECRET|KEY|PASSWORD|TOKEN|AUTH|API_KEY|PRIVATE|DATABASE_URL|DB_URL)'

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

        # Look for things like NEXT_PUBLIC_DATABASE_URL or VITE_STRIPE_SECRET_KEY
        pattern = f"{FRONTEND_PREFIXES}.*{SENSITIVE_NAMES}"
        if re.search(pattern, line, re.IGNORECASE):
            if should_ignore(line, "frontend_secret_leak"):
                continue
            findings.append(Finding(
                rule_id="frontend_secret_leak",
                severity="critical",
                filename=filepath,
                line_number=i,
                line_content=stripped[:100],
                description="Client-side secret leak: Sensitive variable exposed to frontend bundle"
            ))
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.env', '.yml', '.yaml', '.json'}
    for p in Path(path).rglob('*'):
        if p.is_file() and p.suffix in extensions and '.git' not in str(p) and 'node_modules' not in str(p):
            findings.extend(scan_file(str(p)))
    return findings
