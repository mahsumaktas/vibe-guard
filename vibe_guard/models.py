from dataclasses import dataclass

@dataclass
class Finding:
    rule_id: str
    severity: str  # "critical" | "warning" | "info"
    filename: str
    line_number: int
    line_content: str
    description: str
