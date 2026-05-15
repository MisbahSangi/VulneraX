import json
import time
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import requests
from colorama import Fore, init
from urllib.parse import urljoin, urlparse

from . crawler import get_all_links, get_all_forms
from .logger import log_scan_summary, log_vulnerability
from .payloads import SQLI_PAYLOADS, XSS_PAYLOADS
from .pdf_exporter import generate_pdf_report
from .remediation_advice import get_remediation

# Initialize colorama for colored console output
init(autoreset=True)

# Base dirs
BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SAFE_LOG_FILE = REPORTS_DIR / "vulnerability_log.txt"
CONFIG_PATH = BASE_DIR / "config" / "settings.json"


def load_config() -> Dict:
    """
    Load configuration from config/settings.json with sane defaults.
    """
    cfg = {
        "crawler": {
            "max_pages": 30,
            "max_depth": 3,
            "request_timeout": 10,
        },
        "scan": {
            "max_scan_time_seconds": 300,
        },
        "checks": {
            "xss": True,
            "sqli":  True,
            "security_headers": True,
            "csrf": True,
            "directory_listing": True,
            "weak_tls": True,
            "open_redirect": True,
            "sensitive_info": True,
            "clickjacking": True,
            "cookie_security":  True,
        },
    }
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        for section in ("crawler", "scan", "checks"):
            if section in user_cfg: 
                cfg[section]. update(user_cfg. get(section, {}))
    except Exception: 
        # If file missing or invalid, keep defaults
        pass
    return cfg


_CONFIG = load_config()
_REQUEST_TIMEOUT:  int = _CONFIG["crawler"]["request_timeout"]
_MAX_SCAN_TIME: int = _CONFIG["scan"]["max_scan_time_seconds"]
_DEFAULT_CHECKS: Dict[str, bool] = _CONFIG["checks"]


def _timed_out(start_time:  float) -> bool:
    return (time.time() - start_time) > _MAX_SCAN_TIME


ProgressCallback = Optional[Callable[[str, Optional[int], Optional[str]], None]]


def _log_console_and_progress(
    msg: str,
    progress_callback: ProgressCallback,
    percent: Optional[int] = None,
    phase: Optional[str] = None,
) -> None:
    """
    Helper to print to console and optionally call the UI progress callback.
    """
    print(msg)
    if progress_callback:
        progress_callback(msg, percent, phase)


# ---------------------------------------------------------------------------
# Helper for forms
# ---------------------------------------------------------------------------


def submit_form(form, url: str, payload: str) -> Optional[requests.Response]:
    """
    Send the form with a test payload. 
    Returns the HTTP response or None on error.
    """
    action = form.get("action")
    method = form.get("method", "get").lower()
    post_url = urljoin(url, action)

    inputs = form.find_all("input")
    data:  Dict[str, str] = {}

    for input_tag in inputs:
        name = input_tag. get("name")
        if name:
            data[name] = payload

    print(f"\n[*] Submitting to {post_url} with payload:  {payload}")

    try:
        if method == "post": 
            return requests.post(post_url, data=data, timeout=_REQUEST_TIMEOUT)
        else:
            return requests.get(post_url, params=data, timeout=_REQUEST_TIMEOUT)
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def scan_xss(url: str, findings:  List[Dict], log: ProgressCallback) -> None:
    _log_console_and_progress(f"--- Scanning for XSS on {url} ---", log, None, "xss")
    forms = get_all_forms(url)

    for form in forms:
        for payload in XSS_PAYLOADS: 
            res = submit_form(form, url, payload)
            if res and payload in res.text:
                _log_console_and_progress(
                    f"[XSS] Detected on {url} with payload: {payload}", log, None, "xss"
                )
                log_vulnerability("XSS", url, payload)
                advice = get_remediation("XSS")

                findings.append(
                    {
                        "type":  "XSS",
                        "url": url,
                        "parameter": None,
                        "severity": advice. get("severity", "high"),
                        "evidence": f"Reflected payload: {payload}",
                    }
                )
                break


def scan_sqli(url: str, findings:  List[Dict], log: ProgressCallback) -> None:
    _log_console_and_progress(
        f"--- Scanning for SQL Injection on {url} ---", log, None, "sqli"
    )
    forms = get_all_forms(url)

    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
    ]

    for form in forms:
        for payload in SQLI_PAYLOADS:
            res = submit_form(form, url, payload)
            if not res:
                continue

            text_lower = res.text. lower()
            for error in sql_errors:
                if error in text_lower: 
                    _log_console_and_progress(
                        f"[SQLi] Detected on {url} with payload:  {payload}", log, None, "sqli"
                    )
                    log_vulnerability("SQL Injection", url, payload)
                    advice = get_remediation("SQL Injection")

                    findings.append(
                        {
                            "type": "SQL Injection",
                            "url": url,
                            "parameter": None,
                            "severity":  advice.get("severity", "high"),
                            "evidence":  (
                                f"Error pattern found in response: '{error}' "
                                f"with payload: {payload}"
                            ),
                        }
                    )
                    break


def scan_security_headers(
    url: str,
    findings: List[Dict],
    reported_hosts: Dict[str, Set[str]],
    log: ProgressCallback,
) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in reported_hosts["security_headers"]: 
        return

    _log_console_and_progress(
        f"--- Scanning for Security Headers on {url} ---", log, None, "security_headers"
    )

    try:
        try:
            res = requests.head(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
            if res.status_code >= 400:
                res = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
        except Exception:
            res = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        _log_console_and_progress(
            f"[! ] Failed to fetch headers from {url}: {e}", log, None, "security_headers"
        )
        return

    headers = {k.lower(): v for k, v in res.headers.items()}

    required_headers = {
        "content-security-policy":  "Helps mitigate XSS and data injection attacks.",
        "x-content-type-options": "Prevents MIME-sniffing, helps block some attacks.",
        "x-frame-options": "Mitigates clickjacking by controlling framing.",
        "referrer-policy": "Controls how much referrer data is sent.",
        "strict-transport-security":  "Enforces HTTPS (HSTS) for the domain.",
    }

    missing:  List[Tuple[str, str]] = []
    for header_name, desc in required_headers. items():
        if header_name not in headers:
            missing.append((header_name, desc))

    if not missing:
        _log_console_and_progress(
            f"[+] Security headers look OK on {url}", log, None, "security_headers"
        )
        return

    missing_list = ", ".join([name for name, _ in missing])
    evidence_lines = [f"Missing header: {name} – {desc}" for name, desc in missing]

    high_risk = any(
        name in ("content-security-policy", "strict-transport-security")
        for name, _ in missing
    )
    severity = "high" if high_risk else "medium"

    _log_console_and_progress(
        f"[!! ] Security header issues detected on host {host}", log, None, "security_headers"
    )
    for line in evidence_lines: 
        _log_console_and_progress("    " + line, log)

    log_vulnerability("Security Headers", url, f"Missing:  {missing_list}")
    findings.append(
        {
            "type": "Security Headers",
            "url":  url,
            "parameter": None,
            "severity": severity,
            "evidence": "; ".join(evidence_lines),
        }
    )
    reported_hosts["security_headers"].add(host)


def scan_csrf(url: str, findings: List[Dict], log: ProgressCallback) -> None:
    _log_console_and_progress(
        f"--- Scanning for CSRF Protections on {url} ---", log, None, "csrf"
    )
    forms = get_all_forms(url)

    for form in forms:
        method = (form.get("method") or "GET").upper()
        if method != "POST":
            continue

        inputs = form.find_all("input")
        has_token = False

        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(
                key in name
                for key in ("csrf", "xsrf", "token", "anti_forgery", "__requestverificationtoken")
            ):
                has_token = True
                break

        if not has_token:
            evidence = "POST form without apparent CSRF token parameter."
            _log_console_and_progress(
                f"[!! ] Possible CSRF issue on {url}", log, None, "csrf"
            )
            log_vulnerability("CSRF", url, evidence)
            advice = get_remediation("CSRF")

            findings.append(
                {
                    "type": "CSRF",
                    "url": url,
                    "parameter": None,
                    "severity":  advice.get("severity", "medium"),
                    "evidence": evidence,
                }
            )


def scan_directory_listing(url: str, findings: List[Dict], log: ProgressCallback) -> None:
    _log_console_and_progress(
        f"--- Scanning for Directory Listing on {url} ---", log, None, "directory_listing"
    )
    parsed = urlparse(url)
    path = parsed.path or "/"

    if not path. endswith("/"):
        return

    try:
        res = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        _log_console_and_progress(
            f"[!] Failed to request {url} for directory listing: {e}",
            log,
            None,
            "directory_listing",
        )
        return

    text = res.text. lower()
    indicators = [
        "index of /",
        "directory listing for",
        "parent directory",
    ]

    for marker in indicators:
        if marker in text: 
            evidence = f"Page content contains marker: '{marker}'"
            _log_console_and_progress(
                f"[!! ] Possible directory listing on {url}", log, None, "directory_listing"
            )
            log_vulnerability("Directory Listing", url, evidence)
            advice = get_remediation("Directory Listing")

            findings.append(
                {
                    "type": "Directory Listing",
                    "url":  url,
                    "parameter": None,
                    "severity": advice.get("severity", "medium"),
                    "evidence": evidence,
                }
            )
            break


def scan_weak_tls(
    url: str,
    findings: List[Dict],
    reported_hosts: Dict[str, Set[str]],
    log: ProgressCallback,
) -> None:
    _log_console_and_progress(
        f"--- Scanning for Weak TLS / Insecure Transport on {url} ---",
        log,
        None,
        "weak_tls",
    )
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if parsed.scheme == "http":
        if host in reported_hosts["insecure_transport"]:
            return

        evidence = "Site is served over HTTP; traffic is not encrypted."
        _log_console_and_progress(
            f"[!!] Insecure transport (HTTP) on {url}", log, None, "weak_tls"
        )
        log_vulnerability("Insecure Transport", url, evidence)
        advice = get_remediation("Insecure Transport")

        findings.append(
            {
                "type": "Insecure Transport",
                "url": url,
                "parameter": None,
                "severity": advice. get("severity", "high"),
                "evidence": evidence,
            }
        )
        reported_hosts["insecure_transport"].add(host)
        return

    if parsed.scheme == "https":
        if host in reported_hosts["weak_tls"]:
            return

        try:
            res = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
        except Exception as e:
            _log_console_and_progress(
                f"[!] Failed to check TLS headers on {url}: {e}", log, None, "weak_tls"
            )
            return

        headers = {k.lower(): v for k, v in res.headers.items()}
        if "strict-transport-security" not in headers:
            evidence = "HTTPS in use, but Strict-Transport-Security (HSTS) header is missing."
            _log_console_and_progress(
                f"[! ] Missing HSTS on host {host}", log, None, "weak_tls"
            )
            log_vulnerability("Weak TLS", url, evidence)
            advice = get_remediation("Weak TLS")

            findings.append(
                {
                    "type":  "Weak TLS",
                    "url": url,
                    "parameter":  None,
                    "severity": advice. get("severity", "medium"),
                    "evidence": evidence,
                }
            )
            reported_hosts["weak_tls"].add(host)


def scan_open_redirect(url: str, findings: List[Dict], log: ProgressCallback) -> None:
    _log_console_and_progress(
        f"--- Scanning for Open Redirect patterns on {url} ---",
        log,
        None,
        "open_redirect",
    )
    parsed_base = urlparse(url)
    base_netloc = parsed_base.netloc

    links = get_all_links(url)
    for link in links:
        parsed = urlparse(link)
        if parsed. netloc and parsed.netloc != base_netloc: 
            q = (parsed.query or "").lower()
            if any(key in q for key in ("redirect=", "url=", "next=", "return=", "dest=")):
                evidence = f"Link with external target and redirect-like parameter:  {link}"
                _log_console_and_progress(
                    f"[!!] Potential open redirect pattern on {url}",
                    log,
                    None,
                    "open_redirect",
                )
                log_vulnerability("Open Redirect", url, evidence)
                advice = get_remediation("Open Redirect")

                findings.append(
                    {
                        "type":  "Open Redirect",
                        "url": url,
                        "parameter": None,
                        "severity": advice.get("severity", "medium"),
                        "evidence": evidence,
                    }
                )
                break


def scan_sensitive_info(url: str, findings: List[Dict], log: ProgressCallback) -> None:
    _log_console_and_progress(
        f"--- Scanning for Sensitive Info Disclosure on {url} ---",
        log,
        None,
        "sensitive_info",
    )
    try:
        res = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e: 
        _log_console_and_progress(
            f"[!] Failed to request {url} for sensitive info: {e}",
            log,
            None,
            "sensitive_info",
        )
        return

    text_lower = res.text.lower()

    keywords = [
        "password",
        "passwd",
        "api_key",
        "api-key",
        "access_token",
        "secret_key",
        "private key",
        "begin rsa private key",
        "stack trace",
        "traceback (most recent call last)",
    ]

    hits = [kw for kw in keywords if kw. lower() in text_lower]
    if hits:
        evidence = f"Response contains potentially sensitive keyword(s): {', '.join(set(hits))}"
        _log_console_and_progress(
            f"[!!] Possible sensitive info disclosure on {url}",
            log,
            None,
            "sensitive_info",
        )
        log_vulnerability("Sensitive Info Disclosure", url, evidence)
        advice = get_remediation("Sensitive Info Disclosure")

        findings.append(
            {
                "type": "Sensitive Info Disclosure",
                "url": url,
                "parameter": None,
                "severity":  advice.get("severity", "high"),
                "evidence": evidence,
            }
        )


def scan_clickjacking(
    url: str,
    findings: List[Dict],
    reported_hosts: Dict[str, Set[str]],
    log: ProgressCallback,
) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in reported_hosts["clickjacking"]:
        return

    _log_console_and_progress(
        f"--- Scanning for Clickjacking Protections on {url} ---",
        log,
        None,
        "clickjacking",
    )
    try:
        res = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        _log_console_and_progress(
            f"[! ] Failed to request {url} for clickjacking:  {e}",
            log,
            None,
            "clickjacking",
        )
        return

    headers = {k.lower(): v for k, v in res.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")

    protected = False
    if xfo: 
        protected = True
    elif "frame-ancestors" in csp. lower():
        protected = True

    if not protected:
        evidence = "No X-Frame-Options header or CSP frame-ancestors directive detected."
        _log_console_and_progress(
            f"[!!] Possible clickjacking risk on host {host}",
            log,
            None,
            "clickjacking",
        )
        log_vulnerability("Clickjacking", url, evidence)
        advice = get_remediation("Clickjacking")

        findings.append(
            {
                "type": "Clickjacking",
                "url": url,
                "parameter":  None,
                "severity": advice.get("severity", "medium"),
                "evidence": evidence,
            }
        )

    reported_hosts["clickjacking"].add(host)


def scan_cookie_security(
    url: str,
    findings: List[Dict],
    reported_hosts: Dict[str, Set[str]],
    log: ProgressCallback,
) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in reported_hosts["cookie_security"]:
        return

    _log_console_and_progress(
        f"--- Scanning for Cookie Security Flags on {url} ---",
        log,
        None,
        "cookie_security",
    )
    try:
        res = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e: 
        _log_console_and_progress(
            f"[!] Failed to request {url} for cookies: {e}",
            log,
            None,
            "cookie_security",
        )
        return

    set_cookie_headers = res. headers.get("Set-Cookie")
    cookies_to_check:  List[SimpleCookie] = []

    if set_cookie_headers: 
        cookie = SimpleCookie()
        cookie.load(set_cookie_headers)
        for morsel in cookie.values():
            cookies_to_check.append(morsel)

    if not cookies_to_check:
        reported_hosts["cookie_security"].add(host)
        return

    issues:  List[str] = []
    for c in cookies_to_check:
        name = c.key
        attrs = str(c).lower()
        if "httponly" not in attrs:
            issues.append(f"Cookie '{name}' missing HttpOnly flag.")
        if "secure" not in attrs and parsed.scheme == "https":
            issues.append(f"Cookie '{name}' missing Secure flag over HTTPS.")

    if issues: 
        evidence = "; ".join(issues)
        _log_console_and_progress(
            f"[!!] Cookie security issues on host {host}",
            log,
            None,
            "cookie_security",
        )
        log_vulnerability("Cookie Security", url, evidence)
        advice = get_remediation("Cookie Security")

        findings.append(
            {
                "type": "Cookie Security",
                "url":  url,
                "parameter": None,
                "severity": advice.get("severity", "medium"),
                "evidence": evidence,
            }
        )

    reported_hosts["cookie_security"].add(host)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_scan(
    target_url: str,
    enabled_checks: Optional[Dict[str, bool]] = None,
    progress_callback: ProgressCallback = None,
) -> Tuple[List[Dict], Dict]: 
    """
    Main entry point for web UI or CLI. 

    enabled_checks:  per-check boolean flags. 
    progress_callback: function(msg, percent, phase) for UI progress.
    Returns (findings, summary).
    """
    def log(msg: str, pct: Optional[int] = None, phase: Optional[str] = None) -> None:
        _log_console_and_progress(msg, progress_callback, pct, phase)

    findings: List[Dict] = []
    checks = _DEFAULT_CHECKS.copy()
    if enabled_checks:
        checks.update(enabled_checks)

    if not target_url:
        log("[!] No target URL provided to run_scan()", 0, "idle")
        return findings, {"total": 0, "by_type": {}}

    log(f"[*] Starting scan for {target_url}", 5, "init")
    start_time = time. time()

    log("Discovering links...", 10, "discover")
    links = get_all_links(target_url)
    for link in links: 
        print(Fore.GREEN + link)

    if not links:
        links = {target_url}

    total_links = len(links) or 1

    reported_hosts:  Dict[str, Set[str]] = {
        "weak_tls": set(),
        "insecure_transport":  set(),
        "security_headers": set(),
        "clickjacking": set(),
        "cookie_security": set(),
    }

    log("--- Scanning All Discovered Links ---", 15, "scanning")

    link_index = 0
    for link in links: 
        if _timed_out(start_time):
            log("[!] Max scan time exceeded, stopping further checks.", 90, "timeout")
            break

        link_index += 1
        link_pct = 15 + int(70 * (link_index / total_links))
        log(f"Scanning link:  {link}", link_pct, "scanning")

        if checks. get("weak_tls", True):
            scan_weak_tls(link, findings, reported_hosts, log)
        if checks.get("security_headers", True):
            scan_security_headers(link, findings, reported_hosts, log)
        if checks.get("clickjacking", True):
            scan_clickjacking(link, findings, reported_hosts, log)
        if checks.get("cookie_security", True):
            scan_cookie_security(link, findings, reported_hosts, log)
        if checks.get("csrf", True):
            scan_csrf(link, findings, log)
        if checks.get("directory_listing", True):
            scan_directory_listing(link, findings, log)
        if checks.get("open_redirect", True):
            scan_open_redirect(link, findings, log)
        if checks.get("sensitive_info", True):
            scan_sensitive_info(link, findings, log)
        if checks.get("xss", True):
            scan_xss(link, findings, log)
        if checks.get("sqli", True):
            scan_sqli(link, findings, log)

    # Build summary with by_type, by_severity, and by_type_and_severity
    summary = {
        "total": len(findings),
        "by_type": {},
        "by_severity": {},
        "by_type_and_severity": {},
    }

    for finding in findings:
        t = finding. get("type", "Unknown")
        s = (finding.get("severity") or "unknown").lower()

        # by_type
        summary["by_type"][t] = summary["by_type"].get(t, 0) + 1

        # by_severity
        summary["by_severity"][s] = summary["by_severity"].get(s, 0) + 1

        # by_type_and_severity
        if t not in summary["by_type_and_severity"]: 
            summary["by_type_and_severity"][t] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low":  0,
                "info": 0,
            }
        if s in summary["by_type_and_severity"][t]:
            summary["by_type_and_severity"][t][s] += 1

    log_scan_summary(target_url, len(findings))

    if not findings:
        with SAFE_LOG_FILE. open("a", encoding="utf-8") as lf:
            lf.write(f"[{target_url}] ✅ Website is safe.  No vulnerabilities found.\n")

    try:
        log("Generating PDF report...", 95, "report")
        generate_pdf_report(findings=findings, summary=summary, target_url=target_url)
    except Exception as e: 
        log(f"[!] Failed to generate PDF report:  {e}", 95, "report")

    log("Scan complete.", 100, "done")
    return findings, summary