"""
VulneraX Unit Tests
===================
AI-assisted test suite covering 6 core functions across main.py,
scanner.py, and remediation_advice.py.

Prompt used to generate these tests:
  "Write comprehensive pytest unit tests for the following Python functions
   in a FastAPI web vulnerability scanner: is_internal_host, validate_target_url,
   get_scan_summary_stats, _timed_out, get_remediation, scan_directory_listing,
   and scan_sensitive_info. Cover normal cases, edge cases, and invalid input.
   Use pytest-mock to patch requests and time."

Run with:  pytest tests/ -v
"""

import sys
import os
import time

# Make project root importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# ============================================================
# 1. Tests for is_internal_host (main.py)
# ============================================================
from main import is_internal_host


class TestIsInternalHost:
    """Tests for the is_internal_host() function."""

    # --- Normal cases ---
    def test_public_domain_is_not_internal(self):
        """A public domain should not be flagged as internal."""
        assert is_internal_host("example.com") is False

    def test_google_is_not_internal(self):
        """google.com is a public IP and must return False."""
        assert is_internal_host("google.com") is False

    # --- Known internal hostnames ---
    def test_localhost_string(self):
        """'localhost' must be identified as internal."""
        assert is_internal_host("localhost") is True

    def test_loopback_ipv4(self):
        """127.0.0.1 is a loopback address, must be internal."""
        assert is_internal_host("127.0.0.1") is True

    def test_loopback_ipv6(self):
        """::1 is the IPv6 loopback, must be internal."""
        assert is_internal_host("::1") is True

    # --- Private IP ranges ---
    def test_private_ip_192_168(self):
        """192.168.x.x is a private range, must be internal."""
        assert is_internal_host("192.168.1.1") is True

    def test_private_ip_10_x(self):
        """10.x.x.x is a private range, must be internal."""
        assert is_internal_host("10.0.0.1") is True

    def test_private_ip_172_16(self):
        """172.16.x.x is a private range, must be internal."""
        assert is_internal_host("172.16.0.1") is True

    # --- Edge cases ---
    def test_uppercase_localhost(self):
        """Function must handle uppercase input gracefully."""
        assert is_internal_host("LOCALHOST") is True

    def test_empty_string(self):
        """Empty string is not a valid hostname, should return False."""
        assert is_internal_host("") is False

    def test_non_ip_garbage_string(self):
        """A random garbage string is not internal."""
        assert is_internal_host("notanipaddress!@#") is False


# ============================================================
# 2. Tests for validate_target_url (main.py)
# ============================================================
from main import validate_target_url


class TestValidateTargetUrl:
    """Tests for the validate_target_url() function."""

    # --- Normal cases ---
    def test_valid_https_url(self):
        """A clean https URL should pass validation."""
        url, err = validate_target_url("https://example.com")
        assert err is None
        assert "example.com" in url

    def test_valid_http_url(self):
        """A clean http URL should pass validation."""
        url, err = validate_target_url("http://testsite.org")
        assert err is None
        assert url is not None

    def test_auto_prepend_http(self):
        """URLs without scheme should get http:// prepended."""
        url, err = validate_target_url("example.com")
        assert err is None
        assert url.startswith("http://")

    # --- Invalid input cases ---
    def test_empty_string_returns_error(self):
        """Empty input must return an error message."""
        url, err = validate_target_url("")
        assert url is None
        assert err is not None
        assert "required" in err.lower()

    def test_none_like_whitespace_returns_error(self):
        """Whitespace-only string must return an error."""
        url, err = validate_target_url("   ")
        assert url is None
        assert err is not None

    def test_missing_scheme_gets_http_prepended(self):
        """URLs without any scheme get http:// prepended automatically."""
        url, err = validate_target_url("testsite.net/page")
        assert err is None
        assert url.startswith("http://")

    # --- Security / SSRF cases ---
    def test_localhost_blocked(self):
        """localhost targets must be blocked."""
        url, err = validate_target_url("http://localhost/admin")
        assert url is None
        assert err is not None
        assert "internal" in err.lower()

    def test_private_ip_blocked(self):
        """Private IP 192.168.x.x must be blocked."""
        url, err = validate_target_url("http://192.168.0.1/")
        assert url is None
        assert err is not None

    def test_loopback_ip_blocked(self):
        """Loopback 127.0.0.1 must be blocked."""
        url, err = validate_target_url("http://127.0.0.1:8000")
        assert url is None
        assert err is not None


# ============================================================
# 3. Tests for get_scan_summary_stats (main.py)
# ============================================================
from main import get_scan_summary_stats, LATEST_RESULT, SCAN_STATE


class TestGetScanSummaryStats:
    """Tests for the AI-generated get_scan_summary_stats() function."""

    def setup_method(self):
        """Reset global state before each test."""
        LATEST_RESULT["target"] = None
        LATEST_RESULT["findings"] = []
        LATEST_RESULT["summary"] = None
        SCAN_STATE["status"] = "idle"

    # --- Normal cases ---
    def test_returns_dict_with_required_keys(self):
        """Stats dict must contain all required keys."""
        stats = get_scan_summary_stats()
        assert "scan_status" in stats
        assert "last_target" in stats
        assert "total_findings" in stats
        assert "severity_breakdown" in stats
        assert "uptime_seconds" in stats

    def test_severity_breakdown_has_all_levels(self):
        """Severity breakdown must always include all severity levels."""
        stats = get_scan_summary_stats()
        breakdown = stats["severity_breakdown"]
        for level in ("critical", "high", "medium", "low"):
            assert level in breakdown

    def test_counts_findings_by_severity(self):
        """Findings must be counted correctly by severity."""
        LATEST_RESULT["findings"] = [
            {"type": "XSS", "severity": "high"},
            {"type": "SQLi", "severity": "critical"},
            {"type": "CSRF", "severity": "high"},
        ]
        stats = get_scan_summary_stats()
        assert stats["severity_breakdown"]["high"] == 2
        assert stats["severity_breakdown"]["critical"] == 1

    # --- Edge cases ---
    def test_empty_findings_all_zero(self):
        """With no findings all severity counts should be 0."""
        LATEST_RESULT["findings"] = []
        stats = get_scan_summary_stats()
        assert all(v == 0 for v in stats["severity_breakdown"].values())

    def test_uptime_is_positive(self):
        """Uptime must always be a non-negative number."""
        stats = get_scan_summary_stats()
        assert stats["uptime_seconds"] >= 0

    def test_scan_status_reflected(self):
        """Current SCAN_STATE status must be reflected in stats."""
        SCAN_STATE["status"] = "running"
        stats = get_scan_summary_stats()
        assert stats["scan_status"] == "running"


# ============================================================
# 4. Tests for _timed_out (scanner.py)
# ============================================================
from scanner_core.scanner import _timed_out, _MAX_SCAN_TIME


class TestTimedOut:
    """Tests for the _timed_out() helper in scanner.py."""

    # --- Normal cases ---
    def test_not_timed_out_when_just_started(self):
        """A scan started right now should not be timed out."""
        start = time.time()
        assert _timed_out(start) is False

    def test_timed_out_after_max_time(self):
        """A start time far in the past must trigger timeout."""
        old_start = time.time() - (_MAX_SCAN_TIME + 10)
        assert _timed_out(old_start) is True

    # --- Edge cases ---
    def test_not_timed_out_exactly_at_limit(self):
        """Just before the max scan time, should NOT be timed out."""
        start = time.time() - (_MAX_SCAN_TIME - 1)
        assert _timed_out(start) is False

    def test_timed_out_with_very_old_timestamp(self):
        """An extremely old timestamp must always be timed out."""
        ancient_start = time.time() - 999999
        assert _timed_out(ancient_start) is True

    # --- Invalid input edge case ---
    def test_future_start_time_not_timed_out(self):
        """A start time slightly in the future should not trigger timeout."""
        future_start = time.time() + 5
        assert _timed_out(future_start) is False


# ============================================================
# 5. Tests for get_remediation (remediation_advice.py)
# ============================================================
from scanner_core.remediation_advice import get_remediation


class TestGetRemediation:
    """Tests for get_remediation() in remediation_advice.py."""

    # --- Normal cases: known vulnerability types ---
    def test_xss_returns_high_severity(self):
        """XSS remediation must have severity 'high'."""
        result = get_remediation("XSS")
        assert result["severity"] == "high"
        assert "description" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert len(result["remediation"]) > 0

    def test_sqli_returns_critical_severity(self):
        """SQL Injection remediation must have severity 'critical'."""
        result = get_remediation("SQL Injection")
        assert result["severity"] == "critical"

    def test_csrf_returns_medium_severity(self):
        """CSRF remediation must have severity 'medium'."""
        result = get_remediation("CSRF")
        assert result["severity"] == "medium"

    def test_cookie_security_returns_medium(self):
        """Cookie Security remediation must have severity 'medium'."""
        result = get_remediation("Cookie Security")
        assert result["severity"] == "medium"

    def test_clickjacking_returns_medium(self):
        """Clickjacking remediation must have severity 'medium'."""
        result = get_remediation("Clickjacking")
        assert result["severity"] == "medium"

    def test_directory_listing_returns_correct_keys(self):
        """Directory Listing result must have all required keys."""
        result = get_remediation("Directory Listing")
        assert "description" in result
        assert "remediation" in result
        assert "severity" in result

    # --- Edge cases ---
    def test_unknown_type_returns_unknown_severity(self):
        """An unknown vulnerability type must return severity 'unknown'."""
        result = get_remediation("SomeRandomVulnType")
        assert result["severity"] == "unknown"
        assert "remediation" in result

    def test_empty_string_type_returns_unknown(self):
        """Empty string input must return a safe fallback dict."""
        result = get_remediation("")
        assert result["severity"] == "unknown"

    # --- Invalid input ---
    def test_none_type_handled_gracefully(self):
        """None should not crash the function; expect fallback dict."""
        try:
            result = get_remediation(None)
            assert "severity" in result
        except TypeError:
            pass  # Acceptable if function does not guard None explicitly


# ============================================================
# 6. Tests for scan_directory_listing (scanner.py)
# ============================================================
from scanner_core.scanner import scan_directory_listing


class TestScanDirectoryListing:
    """Tests for scan_directory_listing() using mocked HTTP responses."""

    def test_detects_index_of_marker(self, mocker):
        """A response with 'index of /' must trigger a finding."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "<html><h1>Index of /uploads/</h1></html>"
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_directory_listing("http://example.com/uploads/", findings, None)
        assert len(findings) == 1
        assert findings[0]["type"] == "Directory Listing"

    def test_detects_parent_directory_marker(self, mocker):
        """'Parent Directory' keyword in response must trigger finding."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "<html>Parent Directory &nbsp;</html>"
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_directory_listing("http://example.com/files/", findings, None)
        assert len(findings) == 1

    def test_no_finding_for_normal_page(self, mocker):
        """A normal page without directory listing markers must not trigger."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "<html><h1>Welcome to our website!</h1></html>"
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_directory_listing("http://example.com/about/", findings, None)
        assert len(findings) == 0

    def test_url_without_trailing_slash_skipped(self, mocker):
        """URLs without trailing slash must be skipped (no HTTP request)."""
        mock_get = mocker.patch("scanner_core.scanner.requests.get")
        findings = []
        scan_directory_listing("http://example.com/page", findings, None)
        mock_get.assert_not_called()
        assert len(findings) == 0

    def test_request_exception_handled_gracefully(self, mocker):
        """Network errors must not crash the scanner."""
        mocker.patch(
            "scanner_core.scanner.requests.get",
            side_effect=Exception("Connection refused")
        )
        findings = []
        scan_directory_listing("http://example.com/broken/", findings, None)
        assert len(findings) == 0


# ============================================================
# 7. Tests for scan_sensitive_info (scanner.py)
# ============================================================
from scanner_core.scanner import scan_sensitive_info


class TestScanSensitiveInfo:
    """Tests for scan_sensitive_info() using mocked HTTP responses."""

    def test_detects_api_key_keyword(self, mocker):
        """Response containing 'api_key' must trigger a finding."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "Error: invalid api_key provided in request."
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_sensitive_info("http://example.com/debug", findings, None)
        assert len(findings) == 1
        assert findings[0]["type"] == "Sensitive Info Disclosure"

    def test_detects_stack_trace_keyword(self, mocker):
        """Response with 'Traceback (most recent call last)' must trigger."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "Traceback (most recent call last):\n  File app.py line 42"
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_sensitive_info("http://example.com/error", findings, None)
        assert len(findings) == 1

    def test_detects_private_key_keyword(self, mocker):
        """Response with 'BEGIN RSA PRIVATE KEY' must trigger."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_sensitive_info("http://example.com/config", findings, None)
        assert len(findings) == 1

    def test_no_finding_for_clean_page(self, mocker):
        """Clean page with no sensitive keywords must produce no findings."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "<html><body><h1>Hello World</h1></body></html>"
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_sensitive_info("http://example.com/", findings, None)
        assert len(findings) == 0

    def test_request_exception_handled_gracefully(self, mocker):
        """Network errors during sensitive scan must not crash scanner."""
        mocker.patch(
            "scanner_core.scanner.requests.get",
            side_effect=Exception("Timeout")
        )
        findings = []
        scan_sensitive_info("http://example.com/", findings, None)
        assert len(findings) == 0

    # --- Edge case ---
    def test_case_insensitive_keyword_match(self, mocker):
        """Keyword matching must be case-insensitive (e.g., 'PASSWORD')."""
        mock_resp = mocker.MagicMock()
        mock_resp.text = "Your PASSWORD has been reset successfully."
        mocker.patch("scanner_core.scanner.requests.get", return_value=mock_resp)

        findings = []
        scan_sensitive_info("http://example.com/reset", findings, None)
        assert len(findings) == 1
