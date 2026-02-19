"""Calculate the Vibe Score (0-100) based on findings."""
from vibe_guard.rules.hardcoded import Finding

SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}


def calculate_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 5) for f in findings)
    return max(0, 100 - penalty)
