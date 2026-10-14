"""
WAF Detection Rules
Detects SQL Injection, XSS, Path Traversal, and Command Injection patterns.
Each rule returns the matched pattern so we can show WHY it was blocked.
"""

import re

# Rule sets — each entry is (name, pattern)
SQL_RULES = [
    ("SQL Injection", r"' OR '1'='1"),
    ("SQL Injection", r"' OR 1=1"),
    ("SQL Injection", r"UNION\s+SELECT"),
    ("SQL Injection", r"DROP\s+TABLE"),
    ("SQL Injection", r"INSERT\s+INTO"),
    ("SQL Injection", r"DELETE\s+FROM"),
    ("SQL Injection", r"--\s"),
    ("SQL Injection", r";\s*DROP"),
    ("SQL Injection", r"1\s*=\s*1"),
]

XSS_RULES = [
    ("XSS", r"<script"),
    ("XSS", r"</script>"),
    ("XSS", r"javascript:"),
    ("XSS", r"onerror\s*="),
    ("XSS", r"onload\s*="),
    ("XSS", r"<iframe"),
    ("XSS", r"alert\s*\("),
    ("XSS", r"document\.cookie"),
]

TRAVERSAL_RULES = [
    ("Path Traversal", r"\.\./"),
    ("Path Traversal", r"\.\.\\"),
    ("Path Traversal", r"%2e%2e%2f"),
    ("Path Traversal", r"%252e%252e"),
    ("Path Traversal", r"/etc/passwd"),
    ("Path Traversal", r"c:\\windows"),
]

CMD_RULES = [
    ("Command Injection", r";\s*cat\s"),
    ("Command Injection", r"\|\s*ls\s"),
    ("Command Injection", r"`.*`"),
    ("Command Injection", r"\$\(.*\)"),
    ("Command Injection", r";\s*rm\s"),
]

ALL_RULES = SQL_RULES + XSS_RULES + TRAVERSAL_RULES + CMD_RULES


def inspect(payload: str):
    """
    Inspect payload against all rules.
    Returns (attack_type, matched_rule) or (None, None) if safe.
    """
    if not payload:
        return None, None

    for name, pattern in ALL_RULES:
        if re.search(pattern, payload, re.IGNORECASE):
            return name, pattern

    return None, None


def detect_attack(payload: str):
    """Backward-compatible wrapper."""
    attack, _ = inspect(payload)
    return attack