from typing import List
from .rules.hardcoded import Finding

def calculate_vibe_score(findings: List[Finding]) -> int:
    penalty = 0
    critical = sum(1 for f in findings if f.severity == "critical")
    warning = sum(1 for f in findings if f.severity == "warning")
    info = sum(1 for f in findings if f.severity == "info")
    
    penalty += min(critical * 20, 60)
    penalty += min(warning * 5, 20)
    penalty += min(info * 1, 5)
    
    return max(0, 100 - penalty)

def score_label(score: int) -> str:
    if score >= 90:
        return "Safe"
    elif score >= 70:
        return "OK"
    elif score >= 50:
        return "Review needed"
    else:
        return "Unsafe"

def score_emoji(score: int) -> str:
    if score >= 90:
        return "✅"
    elif score >= 70:
        return "🟡"
    elif score >= 50:
        return "⚠️"
    else:
        return "🔴"