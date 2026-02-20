"""Generate markdown reports from findings."""
from typing import List
from .models import Finding
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
    "frontend_secret_leak": "Remove the public prefix (e.g. NEXT_PUBLIC_) so it's not bundled in the client code",
    "insecure_default": "Fix the insecure shortcut (e.g. restrict CORS, remove verify=False, don't log process.env)",
    "supabase_misconfig": "Keep service_role safe on backend. Enforce RLS with auth.uid() and WITH CHECK clauses.",
    "docker_root_user": "Add a 'USER node' or 'USER nonroot' directive before running the app",
    "infra_misconfig": "Fix the excessive infrastructure permission (e.g. restrict write-all, avoid 0.0.0.0/0)",
    "auth_misconfig": "Use strong environment secrets and secure cookie flags (HttpOnly, Secure)",
}

def generate_progress_bar(score: int) -> str:
    total_blocks = 10
    filled_blocks = round(score / 10)
    empty_blocks = total_blocks - filled_blocks
    
    color = "🟩" if score >= 90 else "🟨" if score >= 70 else "🟧" if score >= 50 else "🟥"
    return (color * filled_blocks) + ("⬜" * empty_blocks)

def generate_markdown_report(findings: List[Finding], scan_path: str) -> str:
    score = calculate_vibe_score(findings)
    critical = [f for f in findings if f.severity == "critical"]
    warnings = [f for f in findings if f.severity == "warning"]
    infos = [f for f in findings if f.severity == "info"]
    
    progress_bar = generate_progress_bar(score)
    
    lines = [
        f"# 🛡️ Vibe-Guard Security Report",
        f"",
        f"**Scan path:** `{scan_path}`  ",
        f"**Vibe Score:** {score_emoji(score)} **{score}/100** — {score_label(score)}",
        f"**Health:** {progress_bar}",
        f"",
        f"### 📊 Summary",
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
        lines.append("## 🔍 Detailed Findings")
        lines.append("")
        for fname, file_findings in sorted(by_file.items()):
            lines.append(f"### 📄 `{fname}`")
            lines.append("")
            for f in sorted(file_findings, key=lambda x: x.line_number):
                icon = "🔴" if f.severity == "critical" else "🟡" if f.severity == "warning" else "🔵"
                lines.append(f"#### {icon} Line {f.line_number}: {f.description}")
                lines.append(f"```python\n{f.line_content}\n```")
                hint = FIX_HINTS.get(f.rule_id)
                if hint:
                    lines.append(f"> 💡 **Fix:** {hint}")
                lines.append("")
            lines.append("---")
            lines.append("")
    else:
        lines.append("## ✅ All Clear!")
        lines.append("No security issues were found. Excellent vibe coding!")
        lines.append("")
    
    return "\n".join(lines)
