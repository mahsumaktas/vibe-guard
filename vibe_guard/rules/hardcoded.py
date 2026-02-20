import re
import math
from typing import List
from pathlib import Path
from ..models import Finding
from .common import should_ignore

CREDENTIAL_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{32,}', "critical", "OpenAI API key"),
    (r'ghp_[a-zA-Z0-9]{36}', "critical", "GitHub Personal Access Token"),
    (r'xoxb-[a-zA-Z0-9\-]{50,}', "critical", "Slack Bot Token"),
    (r'(?i)aws_secret_access_key\s*=\s*["\']?([a-zA-Z0-9/+]{40})["\']?', "critical", "AWS Secret Access Key"),
    (r'(?i)(api[_-]?key|apikey)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "critical", "Hardcoded API key"),
    (r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\']{8,})["\']', "critical", "Hardcoded password"),
    (r'(?i)(secret|token)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "critical", "Hardcoded secret/token"),
    (r'([a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9]{27})', "critical", "Discord Bot Token"), # Add discord token
    (r'(?i)vercel_.*_token\s*=\s*["\']([a-zA-Z0-9_\-]{24,})["\']', "critical", "Vercel Access Token"),
    (r'(?i)railway_token\s*=\s*["\']([a-zA-Z0-9_\-]{30,})["\']', "critical", "Railway Access Token"),
    (r'(?i)cloudflare_api_token\s*=\s*["\']([a-zA-Z0-9_\-]{40,})["\']', "critical", "Cloudflare API Token"),
]

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())

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
        if any(w in line.lower() for w in ['example', 'test', 'placeholder', 'your_']):
            continue

        for pattern, severity, desc in CREDENTIAL_PATTERNS:
            if re.search(pattern, line):
                if should_ignore(line, "hardcoded_secret"):
                    continue
                findings.append(Finding(
                    rule_id="hardcoded_secret",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description=desc
                ))
                break
        # High entropy string detection
        tokens = re.findall(r'["\']([a-zA-Z0-9+/=_\-]{20,})["\']', line)
        for token in tokens:
            if calculate_entropy(token) > 4.5:
                if should_ignore(line, "high_entropy_string"):
                    continue
                findings.append(Finding(
                    rule_id="high_entropy_string",
                    severity="warning",
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description=f"High entropy string detected (entropy={calculate_entropy(token):.2f})"
                ))
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    extensions = {'.py', '.js', '.ts', '.env', '.yml', '.yaml', '.json', '.sh'}
    for p in Path(path).rglob('*'):
        if p.is_file() and p.suffix in extensions and '.git' not in str(p):
            findings.extend(scan_file(str(p)))
    return findings
