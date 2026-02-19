"""Detect SQL injection risk patterns."""
import re
from pathlib import Path
from typing import List
from .hardcoded import Finding


# SQL injection patterns: (regex, rule_id, severity, description)
SQLI_PATTERNS = [
    # cursor.execute with concatenation (check before generic SQL patterns)
    (r"(?i)(?:cursor|conn|connection|db)\s*\.\s*execute\s*\([^)]*\+[^)]*\)", "cursor_execute_concat", "critical",
     "cursor.execute() with string concatenation - injection risk"),
    # cursor.execute with f-string
    (r"(?i)(?:cursor|conn|connection|db)\s*\.\s*execute\s*\(\s*f[\"']", "cursor_execute_fstring", "critical",
     "cursor.execute() with f-string - injection risk"),
    # cursor.execute with % formatting
    (r'(?i)(?:cursor|conn|connection|db)\s*\.\s*execute\s*\(.*%\s*\w', "cursor_execute_format", "warning",
     "cursor.execute() with % formatting - use parameterized queries"),
    # ORM raw() with variables
    (r'(?i)\.raw\s*\(\s*["\'][^"\']*["\'\s]*\+', "orm_raw_concat", "critical",
     "ORM .raw() query with concatenation - injection risk"),
    (r'(?i)\.raw\s*\(\s*f["\']', "orm_raw_fstring", "critical",
     "ORM .raw() query with f-string - injection risk"),
    # f-string SQL queries
    (r'(?i)f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s.*\{', "sql_fstring", "critical",
     "SQL query in f-string with variable interpolation - injection risk"),
    # .format() on SQL string
    (r'(?i)["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s[^"\']*["\']\.format\s*\(', "sql_format_method", "critical",
     "SQL query using .format() - injection risk"),
    # % formatting SQL queries
    (r'(?i)["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s.*["\'\s]*%\s*(?:\(|\w)', "sql_percent_format", "critical",
     "SQL query with % string formatting - injection risk"),
    # String concatenation with SQL keywords
    (r'(?i)["\']?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s[^"\']*["\'\s]*\s*\+', "sql_concat", "critical",
     "SQL query built with string concatenation - injection risk"),
    # Raw SQL with user-controlled variables
    (r'(?i)(?:WHERE|AND|OR)\s+\w+\s*=\s*["\']?\s*\+', "sql_where_concat", "critical",
     "SQL WHERE clause with string concatenation - injection risk"),
]


def scan_file(filepath) -> List[Finding]:
    """Scan a file for SQL injection patterns."""
    filepath = Path(filepath)
    findings: List[Finding] = []

    skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                       '.woff', '.woff2', '.ttf', '.pdf', '.zip', '.gz',
                       '.tar', '.lock', '.bin', '.exe', '.md', '.txt'}
    if filepath.suffix.lower() in skip_extensions:
        return []

    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []

    filename = str(filepath)
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comment lines
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
            continue

        for pattern, rule_id, severity, description in SQLI_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    filename=filename,
                    line_number=line_no,
                    line_content=line.strip()[:120],
                    description=description,
                ))
                break  # one finding per line

    return findings
