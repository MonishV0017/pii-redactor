REGEX_PATTERNS = {
    'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'AADHAAR': r'\b\d{4}\s?\d{4}\s?\d{4}\b',
    'PAN_CARD': r'\b[A-Z]{5}\d{4}[A-Z]\b',
    'CREDIT_CARD': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'INDIAN_MOBILE': r'\b(?:\+91|0)?[-\s]?[6-9]\d{9}\b',
    'VOTER_ID': r'\b[A-Z]{3}\d{7}\b',
    'DRIVING_LICENSE': r'\b[A-Z]{2}[-\s]?\d{2}[-\s]?\d{4}[-\s]?\d{7}\b',
}