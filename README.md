---
title: VulneraX
emoji: 🔍
colorFrom: red
colorTo: gray
sdk: docker
app_port: 8000
pinned: false
---

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
- **Deployment:** Hugging Face Spaces (Docker)

---

## Local Setup

```bash
git clone https://github.com/MisbahSangi/VulneraX.git
cd VulneraX
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

---

## Running Unit Tests

```bash
pytest tests/ -v
```

**51 tests across 7 functions — all passing.**

---

## CI/CD Pipeline

```
Push to main
    ↓
[1] LINT   → flake8
[2] TEST   → pytest (51 tests)
[3] BUILD  → Docker image + health check
[4] DEPLOY → Hugging Face Spaces (auto push)
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Main scanner UI |
| `/scan` | POST | Start a vulnerability scan |
| `/scan-status` | GET | Live scan progress |
| `/api/health` | GET | Health check (AI-generated) |
| `/last-results` | GET | Last scan results |
| `/download-report` | GET | Download PDF report |
