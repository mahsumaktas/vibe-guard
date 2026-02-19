"""Calculate the Vibe Score (0-100) based on findings."""
from typing import List
from .rules.hardcoded import Finding


# Penalty caps per severity
SEVERITY_PENALTY = {
    "critical": 20,
    "warning": 5,
    "info": 1,
}

SEVERITY_CAPS = {
    "critical": 60,
    "warning": 20,
    "info": 5,
}

# Legacy uppercase support
SEVERITY_PENALTY_UPPER = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "WARNING": 5,
    "INFO": 1,
}


def calculate_vibe_score(findings: List[Finding]) -> int:
    """Returns 0-100 Vibe Score based on findings.

    Scoring:
        Critical finding: -20 points each (max -60 total)
        Warning finding:  -5 points each  (max -20 total)
        Info finding:     -1 point each   (max -5 total)
        Minimum score:    0
    """
    penalty_by_severity: dict = {"critical": 0, "warning": 0, "info": 0}

    for finding in findings:
        sev = finding.severity.lower()
        # Normalize legacy severities
        if sev in ("high",):
            sev = "critical"
        elif sev in ("medium", "low"):
            sev = "warning"

        if sev in penalty_by_severity:
            penalty_by_severity[sev] += SEVERITY_PENALTY.get(sev, 1)

    # Apply caps
    total_penalty = 0
    for sev, penalty in penalty_by_severity.items():
        cap = SEVERITY_CAPS.get(sev, 10)
        total_penalty += min(penalty, cap)

    return max(0, 100 - total_penalty)


def score_label(score: int) -> str:
    """Returns emoji label for score.

    90+ : Safe
    70+ : OK
    50+ : Review
    <50 : Unsafe
    """
    if score >= 90:
        return "Safe"
    elif score >= 70:
        return "OK"
    elif score >= 50:
        return "Review"
    else:
        return "Unsafe"


def score_emoji(score: int) -> str:
    """Returns emoji for score."""
    if score >= 90:
        return ""
    elif score >= 70:
        return ""
    elif score >= 50:
        return "⚠️"
    else:
        return ""


# Legacy compatibility
def calculate_score(findings: List[Finding]) -> int:
    """Legacy function - use calculate_vibe_score instead."""
    return calculate_vibe_score(findings)
