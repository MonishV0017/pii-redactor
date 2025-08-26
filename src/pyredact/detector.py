import re
from .regex_patterns import REGEX_PATTERNS

def find_pii(text: str) -> list:
    found_pii = []
    
    for pii_type, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            found_pii.append({
                'type': pii_type,
                'value': match
            })
            
    return found_pii