import re

def should_ignore(line: str, rule_id: str) -> bool:
    """
    Checks if a line should be ignored for a specific rule.
    Supported formats:
    - # vibe-ignore (ignores all rules on this line)
    - # vibe-ignore: rule1, rule2 (ignores only specific rules)
    """
    if "# vibe-ignore" not in line:
        return False
    
    # Extract everything after # vibe-ignore
    # We use a regex that handles both cases
    match = re.search(r'# vibe-ignore(?::\s*(.*))?', line)
    if match:
        specific_rules_str = match.group(1)
        if specific_rules_str:
            ignored_rules = [r.strip() for r in specific_rules_str.split(',')]
            return rule_id in ignored_rules
        else:
            # Generic # vibe-ignore (no colon or nothing after colon) ignores all
            return True
            
    return False
