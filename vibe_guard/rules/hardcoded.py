"""Detect hardcoded credentials and API keys."""
import re
from dataclasses import dataclass
from pathlib import Path

SECRET_PATTERNS = [
    (r'["\']?(sk-[a-zA-Z0-9]{32,})["\']?', "OpenAI API key"),
    (r'["\']?(AIza[0-9A-Za-z\-_]{35})["\']?', "Google API key"),
    (r'["\']?(ghp_[a-zA-Z0-9]{36})["\']?', "GitHub token"),
    (r'(?i)(password|passwd|secret|api_key)\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded credential"),
    (r'(?i)(token)\s*=\s*["\'][a-zA-Z0-9\-_\.]{20,}["\']', "Hardcoded token"),
]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    snippet: str


def scan_file(file_path: Path) -> list[Finding]:
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        for line_no, line in enumerate(content.splitlines(), 1):
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule=label,
                        severity="CRITICAL",
                        file=str(file_path),
                        line=line_no,
                        snippet=line.strip()[:80],
                    ))
    except Exception:
        pass
    return findings
