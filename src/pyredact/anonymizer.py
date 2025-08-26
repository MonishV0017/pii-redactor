def anonymize_email(email: str) -> str:
    user, domain = email.split('@')
    return f"{user[0]}***@{domain}"

def anonymize_credit_card(card: str) -> str:
    clean_card = card.replace(' ', '').replace('-', '')
    return f"{'*' * (len(clean_card) - 4)}{clean_card[-4:]}"

def anonymize_aadhaar(aadhaar: str) -> str:
    clean_aadhaar = aadhaar.replace(' ', '').replace('-', '')
    return f"{clean_aadhaar[:4]}-XXXX-{clean_aadhaar[-4:]}"

def anonymize_pan_card(pan: str) -> str:
    return 'X' * len(pan)
    
def anonymize_indian_mobile(mobile: str) -> str:
    clean_mobile = mobile.replace(' ', '').replace('-', '').replace('+91', '')
    if len(clean_mobile) > 4:
        return f"{clean_mobile[:2]}******{clean_mobile[-2:]}"
    return 'X' * len(mobile)

def anonymize_voter_id(voter_id: str) -> str:
    return 'X' * len(voter_id)

def anonymize_driving_license(license_num: str) -> str:
    parts = license_num.replace('-', ' ').split()
    if len(parts) > 1:
        parts[-1] = 'X' * len(parts[-1])
        return '-'.join(parts)
    return 'X' * len(license_num)

ANONYMIZATION_RULES = {
    'EMAIL': anonymize_email,
    'CREDIT_CARD': anonymize_credit_card,
    'AADHAAR': anonymize_aadhaar,
    'PAN_CARD': anonymize_pan_card,
    'INDIAN_MOBILE': anonymize_indian_mobile,
    'VOTER_ID': anonymize_voter_id,
    'DRIVING_LICENSE': anonymize_driving_license,
}

def anonymize_pii(pii_type: str, pii_value: str) -> str:
    anonymizer_func = ANONYMIZATION_RULES.get(pii_type)
    if anonymizer_func:
        return anonymizer_func(pii_value)
    return pii_value