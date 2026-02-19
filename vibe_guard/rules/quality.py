"""Detect code quality issues."""
import re
from pathlib import Path
from typing import List
from .hardcoded import Finding


def scan_file(filepath) -> List[Finding]:
    """Scan a file for code quality issues."""
    filepath = Path(filepath)
    findings: List[Finding] = []

    skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                       '.woff', '.woff2', '.ttf', '.pdf', '.zip', '.gz',
                       '.tar', '.lock', '.bin', '.exe', '.md'}
    if filepath.suffix.lower() in skip_extensions:
        return []

    # Only scan Python files for now
    if filepath.suffix not in {'.py', '.js', '.ts', '.jsx', '.tsx'}:
        return []

    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []

    filename = str(filepath)
    lines = content.splitlines()
    total_lines = len(lines)

    # --- Per-line analysis ---
    todo_count = 0
    print_count = 0

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()

        # 1. Bare except clauses
        if re.match(r'^except\s*:\s*$', stripped) or re.match(r'^except\s*:\s*#', stripped):
            findings.append(Finding(
                rule_id="bare_except",
                severity="warning",
                filename=filename,
                line_number=line_no,
                line_content=line.strip()[:120],
                description="Bare 'except:' clause catches all exceptions including KeyboardInterrupt",
            ))

        # 2. Silent exception handlers: except ...: pass
        elif re.match(r'^except\s*(?:\w+(?:\s*,\s*\w+)*)?\s*:\s*$', stripped):
            # Check next line for pass
            if line_no < total_lines:
                next_line = lines[line_no].strip()  # line_no is 0-based index of next
                if next_line in ('pass', 'pass  # noqa', '...'):
                    findings.append(Finding(
                        rule_id="silent_exception",
                        severity="warning",
                        filename=filename,
                        line_number=line_no,
                        line_content=line.strip()[:120],
                        description="Silent exception handler with 'pass' - exceptions are swallowed",
                    ))

        # 3. TODO/FIXME/HACK/XXX markers
        if re.search(r'\b(?:TODO|FIXME|HACK|XXX)\b', line, re.IGNORECASE):
            todo_count += 1

        # 4. print() in Python files (not in test files)
        if filepath.suffix == '.py' and 'test' not in filepath.name.lower():
            if re.match(r'^print\s*\(', stripped) or re.search(r'[^_a-z]print\s*\(', stripped):
                print_count += 1

        # 5. Hardcoded localhost/127.0.0.1 URLs
        if re.search(r'["\']https?://(?:localhost|127\.0\.0\.1)(?::\d+)?', line):
            findings.append(Finding(
                rule_id="hardcoded_localhost",
                severity="info",
                filename=filename,
                line_number=line_no,
                line_content=line.strip()[:120],
                description="Hardcoded localhost URL - use environment variable for server address",
            ))

    # --- File-level analysis ---

    # TODO/FIXME ratio > 5%
    if total_lines > 10 and todo_count / total_lines > 0.05:
        findings.append(Finding(
            rule_id="high_todo_ratio",
            severity="info",
            filename=filename,
            line_number=1,
            line_content=f"File has {todo_count} TODO/FIXME markers in {total_lines} lines",
            description=f"High TODO/FIXME ratio ({todo_count}/{total_lines} = {todo_count/total_lines:.0%}) - many unfinished items",
        ))

    # Many print() statements (>5 in a non-test file)
    if print_count > 5:
        findings.append(Finding(
            rule_id="excessive_print_statements",
            severity="info",
            filename=filename,
            line_number=1,
            line_content=f"File has {print_count} print() calls",
            description=f"{print_count} print() statements found - consider using proper logging",
        ))

    return findings
