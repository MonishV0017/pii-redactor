import re
from pyredact.regex_patterns import REGEX_PATTERNS

def find_pii(text: str, types_to_scan: list[str] | None = None) -> list:
    all_matches = []
    
    patterns_to_use = REGEX_PATTERNS
    if types_to_scan:
        patterns_to_use = {
            key: REGEX_PATTERNS[key] for key in types_to_scan if key in REGEX_PATTERNS
        }

    # Step 1: Find all possible matches for all patterns
    for pii_type, pattern in patterns_to_use.items():
        for match in re.finditer(pattern, text):
            all_matches.append({
                'type': pii_type,
                'value': match.group(0),
                'start': match.start(),
                'end': match.end()
            })

    if not all_matches:
        return []

    # Step 2: Sort matches by their starting position
    all_matches.sort(key=lambda x: x['start'])

    # Step 3: Resolve overlaps, keeping the longest match
    final_results = []
    if all_matches:
        current_match = all_matches[0]
        for next_match in all_matches[1:]:
            # If the next match is completely inside the current one, ignore it
            if next_match['end'] <= current_match['end']:
                continue
            # If there's no overlap, the current match is final
            elif next_match['start'] >= current_match['end']:
                final_results.append(current_match)
                current_match = next_match
            # If there is an overlap, prioritize the longer one
            else:
                if (current_match['end'] - current_match['start']) >= (next_match['end'] - next_match['start']):
                    # Current match is longer or equal, so we keep it and ignore the start of the next one
                    pass
                else:
                    # Next match is longer, so it becomes the new current match
                    final_results.append(current_match)
                    current_match = next_match
        final_results.append(current_match)
    
    # Return a simplified list without start/end positions
    return [{'type': p['type'], 'value': p['value']} for p in final_results]