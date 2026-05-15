"""
Shared pytest fixtures for VulneraX unit tests.
"""
import pytest


@pytest.fixture
def sample_findings():
    """Return a realistic list of scan findings for testing."""
    return [
        {
            "type": "XSS",
            "url": "http://example.com/search",
            "parameter": None,
            "severity": "high",
            "evidence": "Reflected payload: <script>alert(1)</script>",
        },
        {
            "type": "SQL Injection",
            "url": "http://example.com/login",
            "parameter": None,
            "severity": "critical",
            "evidence": "Error pattern found: you have an error in your sql syntax",
        },
        {
            "type": "Directory Listing",
            "url": "http://example.com/uploads/",
            "parameter": None,
            "severity": "medium",
            "evidence": "Page content contains marker: 'index of /'",
        },
    ]


@pytest.fixture
def mock_requests_get(mocker):
    """Factory fixture to mock requests.get with a custom response."""
    def _make_mock(text="", status_code=200, headers=None):
        mock_resp = mocker.MagicMock()
        mock_resp.status_code = status_code
        mock_resp.text = text
        mock_resp.headers = headers or {}
        return mock_resp
    return _make_mock
