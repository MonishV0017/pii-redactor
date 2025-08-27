import re
from pyredact.regex_patterns import REGEX_PATTERNS

def find_pii(text: str, types_to_scan: list[str] | None = None) -> list:
    found_pii = []
    
    patterns_to_use = REGEX_PATTERNS
    if types_to_scan:
        # Filter the patterns to only include the ones requested by the user
        patterns_to_use = {
            key: REGEX_PATTERNS[key] for key in types_to_scan if key in REGEX_PATTERNS
        }

    for pii_type, pattern in patterns_to_use.items():
        matches = re.findall(pattern, text)
        for match in matches:
            found_pii.append({
                'type': pii_type,
                'value': match
            })
            
    return found_pii