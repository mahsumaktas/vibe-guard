"""Detect hardcoded credentials and API keys."""
import re
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class Finding:
    rule_id: str         # "hardcoded_secret", "high_entropy_string", etc.
    severity: str        # "critical" | "warning" | "info"
    filename: str
    line_number: int
    line_content: str    # relevant line (truncated)
    description: str


# Patterns: (regex, rule_id, severity, description)
SECRET_PATTERNS = [
    # OpenAI API keys
    (r'sk-[a-zA-Z0-9]{32,}', "openai_api_key", "critical",
     "OpenAI API key detected"),
    # OpenAI project keys
    (r'sk-proj-[a-zA-Z0-9\-_]{40,}', "openai_project_key", "critical",
     "OpenAI project API key detected"),
    # GitHub tokens
    (r'ghp_[a-zA-Z0-9]{36}', "github_token", "critical",
     "GitHub personal access token detected"),
    (r'gho_[a-zA-Z0-9]{36}', "github_oauth_token", "critical",
     "GitHub OAuth token detected"),
    (r'ghs_[a-zA-Z0-9]{36}', "github_app_token", "critical",
     "GitHub App token detected"),
    # Slack tokens
    (r'xoxb-[0-9\-a-zA-Z]{50,}', "slack_bot_token", "critical",
     "Slack bot token detected"),
    (r'xoxa-[0-9\-a-zA-Z]{50,}', "slack_app_token", "critical",
     "Slack app token detected"),
    # AWS keys
    (r'AKIA[0-9A-Z]{16}', "aws_access_key", "critical",
     "AWS Access Key ID detected"),
    (r'(?i)aws_secret_access_key\s*=\s*["\'][^"\']{20,}["\']', "aws_secret_key", "critical",
     "AWS Secret Access Key detected"),
    # Google API keys
    (r'AIza[0-9A-Za-z\-_]{35}', "google_api_key", "critical",
     "Google API key detected"),
    # Stripe keys
    (r'sk_live_[0-9a-zA-Z]{24,}', "stripe_live_key", "critical",
     "Stripe live secret key detected"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "stripe_live_pk", "warning",
     "Stripe live publishable key detected"),
    # Generic patterns - password/secret assignments
    (r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']', "hardcoded_password", "critical",
     "Hardcoded password detected"),
    (r'(?i)(?:secret|api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']', "hardcoded_secret", "critical",
     "Hardcoded secret/API key detected"),
    (r'(?i)(?:token|auth_token|access_token)\s*=\s*["\'][a-zA-Z0-9\-_\.]{20,}["\']', "hardcoded_token", "warning",
     "Hardcoded token detected"),
    # Private key headers
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "private_key", "critical",
     "Private key material detected"),
]

# Variables that suggest env var usage (false positive avoidance)
ENV_VAR_PATTERNS = [
    r'os\.environ',
    r'os\.getenv',
    r'process\.env',
    r'getenv\(',
    r'environ\.get\(',
    r'config\[',
    r'\$\{',
    r'\$[A-Z_]+',
]


def calculate_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_env_var_reference(line: str) -> bool:
    """Return True if the line uses env var lookup (not hardcoded)."""
    for pattern in ENV_VAR_PATTERNS:
        if re.search(pattern, line):
            return True
    return False


def _check_high_entropy(line: str, line_no: int, filename: str) -> List[Finding]:
    """Detect high-entropy strings that may be secrets."""
    findings = []
    # Find quoted strings of 20+ chars
    for match in re.finditer(r'["\']([A-Za-z0-9+/=\-_\.]{20,})["\']', line):
        candidate = match.group(1)
        entropy = calculate_entropy(candidate)
        if entropy > 4.5:
            findings.append(Finding(
                rule_id="high_entropy_string",
                severity="warning",
                filename=filename,
                line_number=line_no,
                line_content=line.strip()[:120],
                description=f"High entropy string detected (entropy={entropy:.2f}): possible secret",
            ))
            break  # one finding per line is enough
    return findings


def scan_file(filepath) -> List[Finding]:
    """Scan a file for hardcoded credentials."""
    filepath = Path(filepath)
    findings: List[Finding] = []

    # Skip binary and non-text files
    skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                       '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip',
                       '.gz', '.tar', '.lock', '.bin', '.exe'}
    if filepath.suffix.lower() in skip_extensions:
        return []

    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []

    filename = str(filepath)
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        # Skip comments (Python, JS, shell)
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
            continue

        # Skip env var references (not hardcoded)
        if _is_env_var_reference(line):
            continue

        # Check known secret patterns
        for pattern, rule_id, severity, description in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    filename=filename,
                    line_number=line_no,
                    line_content=line.strip()[:120],
                    description=description,
                ))
                break  # one finding per line per category

        # Check high entropy strings
        if not any(f.line_number == line_no and f.rule_id != "high_entropy_string"
                   for f in findings):
            findings.extend(_check_high_entropy(line, line_no, filename))

    return findings
