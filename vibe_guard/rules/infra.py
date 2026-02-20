import re
from pathlib import Path
from typing import List
from ..models import Finding
from .common import should_ignore, is_excluded_dir

INFRA_PATTERNS = [
    # GitHub Actions
    (r'(?i)permissions\s*:\s*write-all', "critical", "GitHub Actions: 'write-all' permissions grant excessive repo access"),
    (r'(?i)on\s*:\s*\[?\s*pull_request_target\s*\]?', "critical", "GitHub Actions: 'pull_request_target' can execute malicious code from forks with elevated privileges"),
    
    # Terraform / Cloud
    (r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]', "warning", "Terraform: Security group open to the world (0.0.0.0/0)"),
]

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
    except (IOError, OSError):
        return findings
    
    filename_lower = Path(filepath).name.lower()
    
    # Docker specific checks
    if 'dockerfile' in filename_lower:
        has_user_directive = False
        for i, line in enumerate(lines, 1):
            if re.match(r'(?i)^\s*USER\s+[a-zA-Z0-9_-]+', line):
                has_user_directive = True
        
        if not has_user_directive and len(lines) > 0:
            findings.append(Finding(
                rule_id="docker_root_user",
                severity="warning",
                filename=filepath,
                line_number=1,
                line_content="",
                description="Dockerfile missing USER directive, defaults to root execution"
            ))

    # General regex checks
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue

        for pattern, severity, desc in INFRA_PATTERNS:
            if re.search(pattern, line):
                if should_ignore(line, "infra_misconfig"):
                    continue
                findings.append(Finding(
                    rule_id="infra_misconfig",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description=desc
                ))
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    # Include yml/yaml for GitHub actions, tf for Terraform, and Dockerfiles
    extensions = {'.yml', '.yaml', '.tf'}
    for p in Path(path).rglob('*'):
        if p.is_file() and not is_excluded_dir(str(p)):
            if p.suffix in extensions or 'dockerfile' in p.name.lower():
                findings.extend(scan_file(str(p)))
    return findings
