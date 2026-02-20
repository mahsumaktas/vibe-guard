import re
from pathlib import Path
from typing import List
from ..models import Finding
from .common import should_ignore

SUPABASE_PATTERNS = [
    # Look for usage of service_role key in frontend/client context
    (r'(?i)supabase_service_role(?:_key)?\s*=\s*["\']([^"\']+)["\']', "critical", "Supabase service_role key exposed. Bypasses all RLS."),
    # Look for permissive RLS in SQL
    (r'(?i)create\s+policy.*using\s*\(\s*true\s*\)', "warning", "Overly permissive Supabase RLS policy (USING (true))"),
    # Missing WITH CHECK in insert/update policies
    (r'(?i)create\s+policy.*for\s+(?:insert|update|all)(?:(?!with\s+check).)*;', "warning", "Supabase RLS policy missing WITH CHECK clause"),
]

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
    except (IOError, OSError):
        return findings
    
    # Check line-by-line for service_role keys
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('--') or stripped.startswith('//'):
            continue

        for pattern, severity, desc in SUPABASE_PATTERNS[:1]: # Check only single-line patterns
            if re.search(pattern, line):
                if should_ignore(line, "supabase_misconfig"):
                    continue
                findings.append(Finding(
                    rule_id="supabase_misconfig",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:100],
                    description=desc
                ))
                
    # Multi-line checks for SQL policies
    if filepath.endswith('.sql'):
        # Very basic check for permissive policies across the whole file
        if re.search(SUPABASE_PATTERNS[1][0], content):
             findings.append(Finding(
                    rule_id="supabase_misconfig",
                    severity="warning",
                    filename=filepath,
                    line_number=1,
                    line_content="",
                    description="Overly permissive Supabase RLS policy detected (USING (true))"
                ))

    return findings

def scan_directory(path: str) -> List[Finding]:
    findings = []
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.sql', '.env'}
    for p in Path(path).rglob('*'):
        if p.is_file() and p.suffix in extensions and '.git' not in str(p) and 'node_modules' not in str(p):
            findings.extend(scan_file(str(p)))
    return findings
