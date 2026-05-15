# remediation_advice.py


def get_remediation(vuln_type: str) -> dict:
    """
    Return a remediation info dictionary for a given vulnerability type.

    Structure:
    {
        "description": "...",
        "remediation": ["step 1", "step 2", ...],
        "severity": "high" | "critical" | "medium" | "low" | "unknown"
    }
    """
    if vuln_type == "XSS":
        return {
            "description": (
                "Cross-Site Scripting (XSS) allows attackers to inject malicious "
                "scripts into web pages viewed by other users."
            ),
            "remediation": [
                "Validate and sanitize all user input on both client and server side.",
                "Use proper output encoding when inserting untrusted data into HTML, "
                "JavaScript, or attributes.",
                "Avoid using innerHTML with untrusted data; use safe DOM APIs instead.",
                "Implement a strong Content Security Policy (CSP) to limit script execution.",
            ],
            "severity": "high",
        }

    elif vuln_type == "SQL Injection":
        return {
            "description": (
                "SQL Injection allows attackers to manipulate SQL queries, which can "
                "lead to unauthorized access, data leakage, or data modification."
            ),
            "remediation": [
                "Always use parameterized queries (prepared statements) for database access.",
                "Never concatenate raw user input directly into SQL queries.",
                "Use ORM libraries instead of building SQL by hand where possible.",
                "Implement least-privilege database accounts.",
                "Validate and sanitize all user input.",
            ],
            "severity": "critical",
        }

    elif vuln_type == "Security Headers":
        return {
            "description": (
                "Missing or misconfigured HTTP security headers can make the application "
                "more vulnerable to attacks like XSS, clickjacking, and man-in-the-middle."
            ),
            "remediation": [
                "Configure Content-Security-Policy (CSP) to restrict sources of scripts "
                "and other resources.",
                "Set X-Content-Type-Options: nosniff.",
                "Set X-Frame-Options or use frame-ancestors in CSP.",
                "Set Referrer-Policy.",
                "Enable HTTP Strict-Transport-Security (HSTS).",
            ],
            "severity": "medium",
        }

    elif vuln_type == "CSRF":
        return {
            "description": (
                "Cross-Site Request Forgery (CSRF) tricks a victim's browser into "
                "performing unwanted actions on an application where the victim is authenticated."
            ),
            "remediation": [
                "Use anti-CSRF tokens in all state-changing requests.",
                "Validate tokens server-side and bind them to user sessions.",
                "Use SameSite cookies for session cookies where possible.",
                "Require re-authentication for critical operations.",
            ],
            "severity": "medium",
        }

    elif vuln_type == "Directory Listing":
        return {
            "description": (
                "Directory listing allows attackers to see files and folders in a web "
                "directory, which may reveal sensitive information or backup files."
            ),
            "remediation": [
                "Disable directory browsing in your web server configuration.",
                "Use index files (index.html, index.php) to prevent listings.",
                "Avoid storing sensitive files in web-accessible directories.",
            ],
            "severity": "medium",
        }

    elif vuln_type == "Insecure Transport":
        return {
            "description": (
                "Using plain HTTP means data is sent without encryption and can be "
                "intercepted or modified in transit."
            ),
            "remediation": [
                "Serve the application exclusively over HTTPS.",
                "Obtain and configure a valid TLS certificate.",
                "Redirect all HTTP traffic to HTTPS.",
                "Use HSTS to enforce HTTPS usage.",
            ],
            "severity": "high",
        }

    elif vuln_type == "Weak TLS":
        return {
            "description": (
                "Weak TLS configuration (e.g., missing HSTS) can allow downgrade or "
                "man-in-the-middle attacks."
            ),
            "remediation": [
                "Enable HTTP Strict-Transport-Security (HSTS) with an appropriate max-age.",
                "Use modern TLS versions (TLS 1.2+).",
                "Disable obsolete protocols and weak cipher suites.",
            ],
            "severity": "medium",
        }

    elif vuln_type == "Open Redirect":
        return {
            "description": (
                "Open redirect vulnerabilities allow attackers to redirect users to "
                "malicious sites using your application's URLs."
            ),
            "remediation": [
                "Avoid redirecting to user-controlled URLs.",
                "Maintain a whitelist of allowed redirect targets.",
                "Validate and normalize redirect URLs before using them.",
            ],
            "severity": "medium",
        }

    elif vuln_type == "Sensitive Info Disclosure":
        return {
            "description": (
                "Leaking sensitive information (passwords, tokens, API keys, stack traces) "
                "in responses can help attackers compromise the application."
            ),
            "remediation": [
                "Remove debug/error messages from production responses.",
                "Avoid returning stack traces or internal identifiers to clients.",
                "Scan source code and responses for hard-coded secrets.",
                "Use centralized error handling/logging instead of exposing details.",
            ],
            "severity": "high",
        }

    elif vuln_type == "Clickjacking":
        return {
            "description": (
                "Clickjacking allows an attacker to trick users into clicking on something "
                "different from what they perceive, typically by framing your site."
            ),
            "remediation": [
                "Set X-Frame-Options to DENY or SAMEORIGIN.",
                "Alternatively, use the frame-ancestors directive in CSP.",
                "Avoid allowing your application to be embedded in untrusted iframes.",
            ],
            "severity": "medium",
        }

    elif vuln_type == "Cookie Security":
        return {
            "description": (
                "Missing Secure/HttpOnly/SameSite flags on cookies can make them easier "
                "to steal or misuse."
            ),
            "remediation": [
                "Mark session cookies as Secure and HttpOnly.",
                "Set SameSite=Lax or Strict where applicable.",
                "Avoid storing sensitive data directly in cookies.",
            ],
            "severity": "medium",
        }

    else:
        return {
            "description": "No specific remediation information available for this vulnerability type.",
            "remediation": [
                "Identify the exact vulnerability category.",
                "Consult the OWASP Top 10 and relevant OWASP Cheat Sheets for best practices.",
            ],
            "severity": "unknown",
        }