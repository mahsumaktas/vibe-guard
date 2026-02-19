import re
import math
from dataclasses import dataclass
from typing import List
from pathlib import Path

@dataclass
class Finding:
    rule_id: str
    severity: str  # "critical" | "warning" | "info"
    filename: str
    line_number: int
    line_content: str
    description: str

CREDENTIAL_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{32,}', "critical", "OpenAI API key"),
    (r'ghp_[a-zA-Z0-9]{36}', "critical", "GitHub Personal Access Token"),
    (r'xoxb-[a-zA-Z0-9\-]{50,}', "critical", "Slack Bot Token"),
    (r'(?i)aws_secret_access_key\s*=\s*["\']?([a-zA-Z0-9/+]{40})["\']?', "critical", "AWS Secret Access Key"),
    (r'(?i)(api[_-]?key|apikey)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "critical", "Hardcoded API key"),
    (r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\']{8,})["\']', "critical", "Hardcoded password"),
    (r'(?i)(secret|token)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "critical", "Hardcoded secret/token"),
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
        if "# vibe-ignore" in line:
            continue
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue
        if any(w in line.lower() for w in ['example', 'test', 'placeholder', 'your_']):
            continue

        for pattern, severity, desc in CREDENTIAL_PATTERNS:
            if re.search(pattern, line):
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
