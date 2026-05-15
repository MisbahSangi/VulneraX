from fastapi import FastAPI, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import json
import time
from typing import Optional, Any, Dict

from scanner_core.scanner import run_scan

app = FastAPI(title="VulneraX", description="Web Vulnerability Scanner", version="1.0.0")

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
PDF_REPORT_PATH = REPORTS_DIR / "vulnerability_report.pdf"
LOG_PATH = REPORTS_DIR / "vulnerability_log.txt"
CONFIG_PATH = BASE_DIR / "config" / "settings.json"

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SCAN_STATE = {
    "status": "idle",
    "progress": 0,
    "phase": "idle",
    "log": [],
    "last_target": None,
}

LATEST_RESULT = {
    "target": None,
    "findings": [],
    "summary": None,
    "checks": {},
}

# Track app start time for uptime reporting
_APP_START_TIME = time.time()


def reset_scan_state(target: Optional[str] = None) -> None:
    SCAN_STATE["status"] = "running"
    SCAN_STATE["progress"] = 0
    SCAN_STATE["phase"] = "starting"
    SCAN_STATE["log"] = []
    SCAN_STATE["last_target"] = target


def append_log_line(msg: str, percent: Optional[int] = None, phase: Optional[str] = None) -> None:
    msg = msg.strip()
    if msg:
        SCAN_STATE["log"].append(msg)
        if len(SCAN_STATE["log"]) > 200:
            SCAN_STATE["log"] = SCAN_STATE["log"][-200:]
    if percent is not None:
        SCAN_STATE["progress"] = max(0, min(100, int(percent)))
    if phase:
        SCAN_STATE["phase"] = phase


def mark_scan_done() -> None:
    SCAN_STATE["status"] = "done"
    if SCAN_STATE["progress"] < 100:
        SCAN_STATE["progress"] = 100
    if SCAN_STATE["phase"] != "done":
        SCAN_STATE["phase"] = "done"


def load_default_checks() -> dict:
    defaults = {
        "xss": True,
        "sqli": True,
        "security_headers": True,
        "csrf": True,
        "directory_listing": True,
        "weak_tls": True,
        "open_redirect": True,
        "sensitive_info": True,
        "clickjacking": True,
        "cookie_security": True,
    }
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as f:
            cfg = json.load(f)
        checks = cfg.get("checks", {})
        defaults.update(checks)
    except Exception:
        pass
    return defaults


def is_internal_host(hostname: str) -> bool:
    """
    Return True if hostname resolves to a localhost or private/internal IP.
    Prevents SSRF by blocking scans against internal infrastructure.
    """
    hostname = hostname.lower().strip()
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback:
            return True
    except ValueError:
        pass
    return False


def validate_target_url(raw_url: str):
    """
    Validate and sanitize a user-supplied target URL.
    Returns (clean_url, None) on success or (None, error_message) on failure.
    """
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return None, "Target URL is required."
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "http://" + raw_url
    try:
        parsed = urlparse(raw_url)
    except Exception:
        return None, "Invalid URL format."
    if parsed.scheme not in ("http", "https"):
        return None, "Only http:// and https:// URLs are allowed."
    if not parsed.netloc:
        return None, "Target URL must include a valid hostname."
    hostname = parsed.hostname or ""
    if is_internal_host(hostname):
        return None, "Scanning internal addresses (localhost/private IPs) is not allowed."
    return parsed.geturl(), None


def read_scan_history(limit: int = 10):
    history = []
    if not LOG_PATH.exists():
        return history
    with LOG_PATH.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    for line in reversed(lines):
        line = line.strip()
        if not line.startswith("[") or "->" not in line:
            continue
        try:
            ts_part, rest = line.split("]", 1)
            ts = ts_part.lstrip("[")
            rest = rest.strip()
            if "->" not in rest:
                continue
            url_part, findings_part = rest.split("->", 1)
            url = url_part.strip()
            findings_text = findings_part.strip()
            history.append({
                "timestamp": ts,
                "target": url,
                "summary": findings_text,
            })
            if len(history) >= limit:
                break
        except ValueError:
            continue
    history.reverse()
    return history


# ---------------------------------------------------------------------------
# AI-GENERATED: get_scan_summary_stats() — helper for the /api/health endpoint
# Prompt used: "Generate a helper function that returns scan statistics from
# LATEST_RESULT and SCAN_STATE for a health/status API endpoint."
# ---------------------------------------------------------------------------
def get_scan_summary_stats() -> Dict[str, Any]:
    """
    Aggregate current scan state and latest result into a single stats dict.
    Used by the /api/health endpoint to expose application status at a glance.
    """
    findings = LATEST_RESULT.get("findings") or []
    summary = LATEST_RESULT.get("summary") or {}

    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev = (finding.get("severity") or "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    uptime_seconds = round(time.time() - _APP_START_TIME)

    return {
        "scan_status": SCAN_STATE.get("status", "idle"),
        "last_target": LATEST_RESULT.get("target"),
        "total_findings": summary.get("total", 0),
        "severity_breakdown": severity_counts,
        "uptime_seconds": uptime_seconds,
    }


def background_scan(target_url: str, checks_state: dict) -> None:
    def progress_cb(msg: str, pct: Optional[int], phase: Optional[str]):
        append_log_line(msg, pct, phase)

    findings, summary = run_scan(
        target_url,
        enabled_checks=checks_state,
        progress_callback=progress_cb,
    )
    mark_scan_done()
    LATEST_RESULT["target"] = target_url
    LATEST_RESULT["findings"] = findings
    LATEST_RESULT["summary"] = summary
    LATEST_RESULT["checks"] = checks_state.copy()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    history = read_scan_history(limit=10)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "target_url": LATEST_RESULT["target"],
            "findings": LATEST_RESULT["findings"],
            "summary": LATEST_RESULT["summary"],
            "error": None,
            "checks": load_default_checks(),
            "history": history,
            "severity_filter": "all",
        },
    )


@app.post("/scan")
async def post_scan(
    background_tasks: BackgroundTasks,
    target_url: str = Form(...),
    severity_filter: str = Form("all"),
    check_xss: str | None = Form(None),
    check_sqli: str | None = Form(None),
    check_security_headers: str | None = Form(None),
    check_csrf: str | None = Form(None),
    check_directory_listing: str | None = Form(None),
    check_weak_tls: str | None = Form(None),
    check_open_redirect: str | None = Form(None),
    check_sensitive_info: str | None = Form(None),
    check_clickjacking: str | None = Form(None),
    check_cookie_security: str | None = Form(None),
):
    clean_url, error = validate_target_url(target_url)
    checks_state = {
        "xss": check_xss is not None,
        "sqli": check_sqli is not None,
        "security_headers": check_security_headers is not None,
        "csrf": check_csrf is not None,
        "directory_listing": check_directory_listing is not None,
        "weak_tls": check_weak_tls is not None,
        "open_redirect": check_open_redirect is not None,
        "sensitive_info": check_sensitive_info is not None,
        "clickjacking": check_clickjacking is not None,
        "cookie_security": check_cookie_security is not None,
    }
    if error:
        return JSONResponse({"ok": False, "error": error}, status_code=400)
    reset_scan_state(clean_url)
    background_tasks.add_task(background_scan, clean_url, checks_state)
    return JSONResponse({
        "ok": True,
        "target_url": clean_url,
        "severity_filter": severity_filter,
    })


@app.get("/scan-status")
async def scan_status():
    return JSONResponse({
        "status": SCAN_STATE["status"],
        "progress": SCAN_STATE["progress"],
        "phase": SCAN_STATE["phase"],
        "log_lines": SCAN_STATE["log"],
        "target": SCAN_STATE["last_target"],
    })


@app.post("/cancel-scan")
async def cancel_scan():
    global SCAN_STATE
    SCAN_STATE["status"] = "idle"
    SCAN_STATE["progress"] = 0
    SCAN_STATE["phase"] = "Cancelled"
    SCAN_STATE["log"] = []
    return JSONResponse({"ok": True, "message": "Scan cancelled"})


@app.get("/last-results")
async def last_results() -> JSONResponse:
    global LATEST_RESULT
    data: Dict[str, Any] = {
        "target_url": LATEST_RESULT.get("target"),
        "findings": LATEST_RESULT.get("findings") or [],
        "summary": LATEST_RESULT.get("summary") or {},
        "history": read_scan_history(limit=10),
    }
    summary = data["summary"] or {}
    if "by_type" not in summary or summary.get("by_type") is None:
        summary["by_type"] = {}
    data["summary"] = summary
    return JSONResponse(data)


@app.get("/download-report")
async def download_report():
    if not PDF_REPORT_PATH.exists():
        return HTMLResponse(
            "<h3>No PDF report found. Run a scan first.</h3>",
            status_code=404,
        )
    return FileResponse(
        path=str(PDF_REPORT_PATH),
        media_type="application/pdf",
        filename="vulnerability_report.pdf",
    )


# ---------------------------------------------------------------------------
# AI-GENERATED ENDPOINT: /api/health
# Prompt used: "Add a /api/health GET endpoint to this FastAPI app that returns
# application status, uptime, current scan state, and last scan summary stats.
# Make it production-ready with proper response structure."
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health_check() -> JSONResponse:
    """
    Health check endpoint for monitoring and CI/CD deployment verification.
    Returns app status, uptime, and last scan statistics.
    """
    stats = get_scan_summary_stats()
    return JSONResponse({
        "status": "ok",
        "app": "VulneraX",
        "version": "1.0.0",
        **stats,
    })
