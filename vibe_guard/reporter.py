"""Generate markdown reports from findings."""
from typing import List
from .rules.hardcoded import Finding
from .scorer import calculate_vibe_score, score_emoji, score_label
from collections import defaultdict

FIX_HINTS = {
    "hardcoded_secret": "Move to environment variable or secrets manager",
    "high_entropy_string": "Review if this is a credential, move to env var if so",
    "rce_risk": "Use subprocess with shell=False and argument lists instead",
    "sql_injection": "Use parameterized queries: cursor.execute('SELECT ? FROM ?', (val,))",
    "silent_exception": "Log the exception: except Exception as e: logger.error(e)",
    "hardcoded_localhost": "Use environment variable: os.getenv('API_URL', 'http://localhost:8000')",
    "high_todo_ratio": "Address TODOs or move them to GitHub Issues",
    "excessive_print": "Replace print() with logging module",
}

def generate_markdown_report(findings: List[Finding], scan_path: str) -> str:
    score = calculate_vibe_score(findings)
    critical = [f for f in findings if f.severity == "critical"]
    warnings = [f for f in findings if f.severity == "warning"]
    infos = [f for f in findings if f.severity == "info"]
    
    lines = [
        f"# vibe-guard Security Report",
        f"",
        f"**Scan path:** `{scan_path}`  ",
        f"**Vibe Score:** {score_emoji(score)} **{score}/100** — {score_label(score)}",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {len(critical)} |",
        f"| 🟡 Warning | {len(warnings)} |",
        f"| 🔵 Info | {len(infos)} |",
        f"| **Total** | **{len(findings)}** |",
        f"",
    ]
    
    # Group by file
    by_file = defaultdict(list)
    for f in findings:
        by_file[f.filename].append(f)
    
    if findings:
        lines.append("## Findings")
        lines.append("")
        for fname, file_findings in sorted(by_file.items()):
            lines.append(f"### `{fname}`")
            lines.append("")
            for f in sorted(file_findings, key=lambda x: x.line_number):
                icon = "🔴" if f.severity == "critical" else "🟡" if f.severity == "warning" else "🔵"
                lines.append(f"- {icon} **Line {f.line_number}** — {f.description}")
                hint = FIX_HINTS.get(f.rule_id)
                if hint:
                    lines.append(f"  > 💡 Fix: {hint}")
            lines.append("")
    else:
        lines.append("## ✅ No issues found!")
        lines.append("")
    
    return "
".join(lines)
