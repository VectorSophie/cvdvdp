import re

PATTERNS = [
    ("cookie_header", re.compile(r"(?i)cookie:\s*\S+")),
    ("auth_bearer", re.compile(r"(?i)(authorization:\s*)?bearer\s+[a-z0-9._~+/=-]+")),
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("phone_kr", re.compile(r"01[016789]-?\d{3,4}-?\d{4}")),
    ("rrn_kr", re.compile(r"\d{6}-?[1-4]\d{6}")),
    ("high_entropy_token", re.compile(r"\b[A-Za-z0-9_-]{32,}\b")),
]


def redact(text: str) -> str:
    result = text
    for label, pattern in PATTERNS:
        result = pattern.sub(f"[REDACTED:{label}]", result)
    return result


def contains_sensitive(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in PATTERNS)
