import re
from pathlib import Path
from typing import List
from ..models import Finding
from .common import should_ignore, is_excluded_dir

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
            if not should_ignore(line, "silent_exception"):
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
            if not should_ignore(line, "high_todo_ratio"):
                todo_count += 1
        
        # print() or console.log() in non-test files
        if (re.match(r'\s*print\s*\(', line) or re.match(r'\s*console\.log\s*\(', line)) and 'test' not in filepath.lower():
            if not should_ignore(line, "excessive_print"):
                print_count += 1
        
        # Hardcoded localhost
        if re.search(r'["\']https?://(?:localhost|127\.0\.0\.1)', line):
            if not should_ignore(line, "hardcoded_localhost"):
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
            description=f"Excessive print/log usage: {print_count} calls - use proper logging"
        ))
    
    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx'}
    for p in Path(path).rglob('*'):
        if p.is_file() and p.suffix in extensions and not is_excluded_dir(str(p)):
            findings.extend(scan_file(str(p)))
    return findings