import re
from pathlib import Path
from typing import List
from .hardcoded import Finding

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings
    
    total = len(lines)
    todo_count = 0
    print_count = 0
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Silent exception
        if re.match(r'except\s*(Exception|:|\w+Error)?\s*:', stripped):
            next_lines = [lines[j].strip() for j in range(i, min(i+2, total))]
            if any(l in ('pass', '') for l in next_lines):
                findings.append(Finding(
                    rule_id="silent_exception",
                    severity="warning",
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description="Silent exception - errors are swallowed silently"
                ))
        
        # TODO/FIXME tracking
        if re.search(r'\b(TODO|FIXME|HACK|XXX)\b', line, re.IGNORECASE):
            todo_count += 1
        
        # print() in non-test files
        if re.match(r'\s*print\s*\(', line) and 'test' not in filepath.lower():
            print_count += 1
        
        # Hardcoded localhost
        if re.search(r'["\']https?://(?:localhost|127\.0\.0\.1)', line):
            findings.append(Finding(
                rule_id="hardcoded_localhost",
                severity="info",
                filename=filepath,
                line_number=i,
                line_content=stripped[:100],
                description="Hardcoded localhost URL - use config/env var"
            ))
    
    if total > 0 and todo_count / total > 0.05:
        findings.append(Finding(
            rule_id="high_todo_ratio",
            severity="info",
            filename=filepath,
            line_number=1,
            line_content="",
            description=f"High TODO ratio: {todo_count}/{total} lines ({todo_count/total*100:.1f}%)"
        ))
    
    if print_count > 10:
        findings.append(Finding(
            rule_id="excessive_print",
            severity="info",
            filename=filepath,
            line_number=1,
            line_content="",
            description=f"Excessive print() usage: {print_count} calls - use logging"
        ))
    
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    for p in Path(path).rglob('*.py'):
        if '.git' not in str(p):
            findings.extend(scan_file(str(p)))
    return findings