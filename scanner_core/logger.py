from datetime import datetime
from pathlib import Path

# Base directory = directory one level above scanner_core (project root)
BASE_DIR = Path(__file__).resolve().parent.parent

# Reports directory (ensure it exists)
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = REPORTS_DIR / "vulnerability_log.txt"


def log_vulnerability(vuln_type: str, url: str, payload: str) -> None:
    """
    Append a vulnerability entry to the log file (detailed block format).
    """
    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write("----- Vulnerability Found -----\n")
        file.write(f"Time: {datetime.now()}\n")
        file.write(f"Type: {vuln_type}\n")
        file.write(f"URL: {url}\n")
        file.write(f"Payload: {payload}\n")
        file.write("-------------------------------\n\n")


def log_scan_summary(target_url: str, findings_count: int) -> None:
    """
    Append a simple one-line summary of a scan, for history.

    Format:
      [YYYY-MM-DD HH:MM:SS] TARGET_URL -> FINDINGS_COUNT findings
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {target_url} -> {findings_count} findings\n"
    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(line)