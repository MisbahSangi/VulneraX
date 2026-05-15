# VulneraX — Web Vulnerability Scanner

A FastAPI-based web vulnerability scanner that detects XSS, SQL Injection, CSRF, Directory Listing, Clickjacking, Insecure Transport, Weak TLS, Sensitive Info Disclosure, Open Redirect, and Cookie Security issues.

---

## Tech Stack
- **Backend:** FastAPI + Uvicorn
- **Scanner:** requests, BeautifulSoup4
- **PDF Reports:** ReportLab
- **Testing:** pytest, pytest-mock
- **Linting:** flake8
- **CI/CD:** GitHub Actions
- **Deployment:** Render

---

## Local Setup

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/VulneraX.git
cd VulneraX/project_root

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000 in your browser.

---

## Running Unit Tests

```bash
cd project_root
pytest tests/ -v
```

**Test coverage (35 tests across 7 functions):**

| Function | File | Cases |
|---|---|---|
| `is_internal_host` | main.py | 11 tests |
| `validate_target_url` | main.py | 9 tests |
| `get_scan_summary_stats` | main.py | 6 tests |
| `_timed_out` | scanner.py | 5 tests |
| `get_remediation` | remediation_advice.py | 9 tests |
| `scan_directory_listing` | scanner.py | 5 tests |
| `scan_sensitive_info` | scanner.py | 6 tests |

---

## CI/CD Pipeline

GitHub Actions pipeline defined in `.github/workflows/ci-cd.yml`:

```
Push to main
    ↓
[1] LINT      → flake8 (max-line-length: 120)
    ↓
[2] TEST      → pytest tests/ -v
    ↓
[3] BUILD     → Docker image build + health check verification
    ↓
[4] DEPLOY    → Trigger Render deploy hook (main branch only)
```

---

## Deployment (Render)

1. Push code to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect GitHub repo
4. Set:
   - **Build Command:** `pip install -r project_root/requirements.txt`
   - **Start Command:** `cd project_root && uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Copy Deploy Hook URL → add as `RENDER_DEPLOY_HOOK_URL` in GitHub Secrets
6. Auto-deploy on every push to main ✅

**Live URL:** https://vulnerax.onrender.com

---

## AI Features Added

### 1. `get_scan_summary_stats()` (main.py)
AI-generated helper function that aggregates scan state + latest results into a single stats dictionary. Used by the `/api/health` endpoint.

### 2. `GET /api/health` endpoint (main.py)
AI-generated production-ready health check endpoint returning app version, uptime, scan status, and severity breakdown.

### 3. Refactored `load_default_checks()` (main.py)
AI-assisted refactoring — added explicit return type hint, improved exception handling with specific error recovery, and added inline documentation for clarity.

---

## AI Prompts Used

See `AI_Prompts_Used.txt` for full list of prompts used during development.

---

## Project Structure

```
VulneraX/
├── project_root/
│   ├── main.py                        ← FastAPI app (AI additions marked)
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── render.yaml
│   ├── .gitignore
│   ├── scanner_core/
│   │   ├── scanner.py                 ← 10 vulnerability scanners
│   │   ├── crawler.py
│   │   ├── payloads.py
│   │   ├── remediation_advice.py
│   │   └── pdf_exporter.py
│   ├── tests/
│   │   ├── conftest.py                ← Shared fixtures
│   │   └── test_vulnerax.py          ← 35 unit tests
│   └── .github/
│       └── workflows/
│           └── ci-cd.yml             ← lint → test → build → deploy
├── Deployment_URL.txt
└── README.md
```
