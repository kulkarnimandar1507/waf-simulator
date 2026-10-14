"""
WAF Middleware
Intercepts every request, inspects for attacks, logs ALL requests.
"""

import sqlite3
from datetime import datetime
from flask import request
from .rules import inspect

# In-memory brute force tracker
FAILED_LOGINS = {}
BRUTE_FORCE_THRESHOLD = 5


def _log_request_row(ip, method, path, payload, verdict, attack_type, matched_rule):
    conn = sqlite3.connect('instance/waf.db')
    c = conn.cursor()
    c.execute(
        """INSERT INTO request_log
           (ip, method, path, payload, verdict, attack_type, matched_rule, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ip, method, path, payload[:300], verdict,
         attack_type or "-", matched_rule or "-",
         datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def _log_attack_row(ip, attack_type, payload, path):
    conn = sqlite3.connect('instance/waf.db')
    c = conn.cursor()
    c.execute(
        """INSERT INTO attack_logs (ip, attack_type, payload, path, timestamp)
           VALUES (?, ?, ?, ?, ?)""",
        (ip, attack_type, payload[:300], path, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def log_request(ip, method, path, payload, verdict, attack_type, matched_rule):
    """Log to BOTH tables."""
    try:
        _log_request_row(ip, method, path, payload, verdict, attack_type, matched_rule)
        if verdict and verdict.startswith('BLOCKED') and attack_type:
            _log_attack_row(ip, attack_type, payload, path)
    except Exception as e:
        print(f"[WAF] Log error: {e}")


def reset_brute_force(ip=None):
    """Reset the brute force counter for a specific IP, or all IPs."""
    global FAILED_LOGINS
    if ip:
        FAILED_LOGINS[ip] = 0
    else:
        FAILED_LOGINS = {}


def waf_check():
    """
    Called before every request.
    Returns (attack_type, matched_rule) if blocked, else (None, None).

    Order of inspection:
      1. Payload inspection (SQLi, XSS, Path Traversal) — most specific
      2. Brute force check — falls back only if no payload attack found
    """
    ip = request.remote_addr
    method = request.method
    path = request.path

    # -------------------------------------------------
    # 1. PAYLOAD INSPECTION FIRST (SQLi, XSS, etc.)
    # -------------------------------------------------
    parts = [request.full_path]
    for key, value in request.args.items():
        parts.append(f"{key}={value}")
    for key, value in request.form.items():
        parts.append(f"{key}={value}")
    for key, value in request.headers.items():
        if key.lower() in ('user-agent', 'referer'):
            parts.append(f"{key}={value}")

    combined = " ".join(parts)
    attack_type, matched_rule = inspect(combined)

    if attack_type:
        print(f"[WAF] 🚫 BLOCKED  | {ip} | {method} {path} | {attack_type} (matched: {matched_rule})")
        log_request(ip, method, path, combined, "BLOCKED", attack_type, matched_rule)
        return attack_type, matched_rule

    # -------------------------------------------------
    # 2. BRUTE FORCE CHECK (only if no payload attack)
    # -------------------------------------------------
    if method == 'POST' and path in ('/login', '/site/login'):
        attempts = FAILED_LOGINS.get(ip, 0)
        if attempts >= BRUTE_FORCE_THRESHOLD:
            print(f"[WAF] 🚫 BLOCKED  | {ip} | {method} {path} | Brute Force (attempts: {attempts})")
            log_request(ip, method, path, f"Brute force ({attempts} attempts)",
                        "BLOCKED", "Brute Force", f"{BRUTE_FORCE_THRESHOLD}+ failed logins")
            return "Brute Force", f"{BRUTE_FORCE_THRESHOLD}+ failed logins"

    # -------------------------------------------------
    # 3. ALLOWED
    # -------------------------------------------------
    print(f"[WAF] ✅ ALLOWED  | {ip} | {method} {path}")
    log_request(ip, method, path, combined, "ALLOWED", None, None)
    return None, None