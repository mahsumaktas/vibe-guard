import re

EXCLUDED_DIRS = {
    'node_modules', '.git', '.venv', 'venv', 'env', '.env', 
    'dist', 'build', '.next', '.nuxt', 'coverage', '.cache'
}

def is_excluded_dir(path_str: str) -> bool:
    path_parts = path_str.replace('\\', '/').split('/')
    return any(part in EXCLUDED_DIRS for part in path_parts)

def should_ignore(line: str, rule_id: str) -> bool:
    """
    Checks if a line should be ignored for a specific rule.
    Supported formats:
    - # vibe-ignore (Python, Ruby, Shell)
    - // vibe-ignore (JS, TS, C, Java)
    - /* vibe-ignore */ (CSS, JS blocks)
    - <!-- vibe-ignore --> (HTML, Markdown)
    """
    if "vibe-ignore" not in line:
        return False
    
    # Extract everything after vibe-ignore, ignoring closing comment tags like */ or -->
    match = re.search(r'vibe-ignore(?::\s*([a-zA-Z0-9_,\s]*))?', line)
    if match:
        specific_rules_str = match.group(1)
        if specific_rules_str:
            # Clean up trailing comment syntax
            specific_rules_str = specific_rules_str.replace('*/', '').replace('-->', '').strip()
            ignored_rules = [r.strip() for r in specific_rules_str.split(',')]
            return rule_id in ignored_rules
        else:
            return True
            
    return False

