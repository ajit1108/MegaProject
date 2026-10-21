# AI-Based Sensitive Data Detection and Privacy Classification System

> **Final Year Engineering Project — 2026**
> A complete, locally-running privacy intelligence platform built with HTML5 + CSS3 + Vanilla JS + Python FastAPI + MongoDB.

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Features](#2-features)
3. [Technology Stack](#3-technology-stack)
4. [Architecture](#4-architecture)
5. [Prerequisites](#5-prerequisites)
6. [Installation](#6-installation)
7. [Running the Application](#7-running-the-application)
8. [Using the Application](#8-using-the-application)
9. [Running Tests](#9-running-tests)
10. [API Documentation](#10-api-documentation)
11. [Project Structure](#11-project-structure)
12. [Risk Scoring Formula](#12-risk-scoring-formula)
13. [Privacy Classification Rules](#13-privacy-classification-rules)
14. [Limitations](#14-limitations)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Project Overview

This system detects sensitive information in uploaded documents before they are shared with external AI services or cloud platforms. It provides:

- **Text extraction** from PDF, DOCX, TXT, PNG, JPG, JPEG
- **OCR** for scanned documents and images (requires Tesseract)
- **Sensitive-data detection** using Regex patterns + spaCy NLP
- **Privacy classification** into four levels: Public, Internal, Confidential, Restricted
- **Privacy risk scoring** on a transparent 0–100 scale
- **Data sanitization** (redaction or masking)
- **Privacy Gateway** to inspect text before external transmission
- **Reports and analytics** from real scan data
- **Full user authentication** with JWT

---

## 2. Features

| Module | Status |
|--------|--------|
| User Registration & Login (JWT) | ✅ Complete |
| Dashboard with real statistics | ✅ Complete |
| Document Upload (PDF/DOCX/TXT/PNG/JPG) | ✅ Complete |
| PDF Text Extraction (PyMuPDF) | ✅ Complete |
| DOCX Text Extraction (python-docx) | ✅ Complete |
| TXT Processing | ✅ Complete |
| OCR for images & scanned PDFs (Tesseract) | ✅ Complete |
| Text Preprocessing | ✅ Complete |
| Regex Detection (Email/Phone/Aadhaar/PAN/IP/Card/API keys) | ✅ Complete |
| NLP Named-Entity Recognition (spaCy) | ✅ Complete (optional) |
| Privacy Classification (4 levels) | ✅ Complete |
| Privacy Risk Scoring (0–100) | ✅ Complete |
| Data Sanitization (redact & mask modes) | ✅ Complete |
| Sanitization Verification Re-scan | ✅ Complete |
| Sanitized TXT Download | ✅ Complete |
| Privacy Gateway | ✅ Complete |
| Reports & Analytics | ✅ Complete |
| CSV Export | ✅ Complete |
| Analysis History | ✅ Complete |
| Audit Logging | ✅ Complete |
| Unit Tests | ✅ Complete |

---

## 3. Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Python 3.11+, FastAPI, Uvicorn |
| Database | MongoDB (local or Atlas) |
| NLP | spaCy en_core_web_sm |
| Document Processing | PyMuPDF, python-docx |
| OCR | Tesseract, pytesseract, Pillow |
| Authentication | JWT (python-jose), bcrypt (passlib) |

---

## 4. Architecture

```
User Browser (HTML/CSS/JS)
         │
         │  HTTP/REST (JSON)
         ▼
   FastAPI Backend (Python)
         │
    ┌────┴────────────────────┐
    │                         │
    ▼                         ▼
MongoDB Database       Document Processing
(users, documents,       │
 analyses, audits)       ├─ Text Extraction (PyMuPDF / python-docx)
                         ├─ OCR (Tesseract / pytesseract)
                         ├─ Preprocessing
                         ├─ Detection (Regex + spaCy NLP)
                         ├─ Classification (4 privacy levels)
                         ├─ Risk Scoring (0–100)
                         └─ Sanitization (redact / mask)
```

---

## 5. Prerequisites

Install the following before setup:

### 5.1 Python 3.11+
Download from https://www.python.org/downloads/

Verify: `python --version`

### 5.2 MongoDB (local development)
Download Community Edition from https://www.mongodb.com/try/download/community

Or use a **free MongoDB Atlas** cluster (cloud) — see step 6.4.

Start local MongoDB:
```
mongod --dbpath C:\data\db
```

### 5.3 Tesseract OCR (for image/scanned PDF processing)

Download the Windows installer from:
https://github.com/UB-Mannheim/tesseract/wiki

Default install path: `C:\Program Files\Tesseract-OCR\tesseract.exe`

Verify: `tesseract --version`

Set in `.env`:
```
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

---

## 6. Installation

### 6.1 Clone / place the project
```
cd d:\Ajit\Megaproject\sensitive-data-detection
```

### 6.2 Create and activate virtual environment
```powershell
python -m venv venv
venv\Scripts\activate
```

### 6.3 Install Python dependencies
```powershell
pip install -r requirements.txt
```

### 6.4 Download the spaCy model
```powershell
python -m spacy download en_core_web_sm
```

> **Note:** If spaCy model download fails, detection still works using Regex only. The application reports reduced NLP capability clearly.

### 6.5 Configure environment variables

Copy the example and edit:
```powershell
copy .env.example .env
```

Edit `.env`:
```env
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=sensitive_data_detection
SECRET_KEY=your-long-random-secret-key-here
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

For **MongoDB Atlas** (cloud):
```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
```

### 6.6 Create upload directory
```powershell
mkdir uploads
```

---

## 7. Running the Application

### 7.1 Start MongoDB (if using local)
```powershell
mongod --dbpath C:\data\db
```

### 7.2 Activate the virtual environment
```powershell
cd d:\Ajit\Megaproject\sensitive-data-detection
venv\Scripts\activate
```

### 7.3 Start the FastAPI server
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 7.4 Open the application

Open your browser and go to:
```
http://127.0.0.1:8000
```

The FastAPI server serves both the API and the HTML frontend.

### 7.5 API Documentation (Swagger UI)
```
http://127.0.0.1:8000/docs
```

---

## 8. Using the Application

1. **Register** — Create an account at `/register.html`
2. **Login** — Sign in at `/login.html`
3. **Upload** — Go to Upload & Scan, drag-drop or select a file, click Upload
4. **Analyse** — Click "Run Analysis" after upload
5. **View Results** — See detected entities, risk score, classification breakdown
6. **Sanitize** — Choose Redact or Mask mode, click Sanitize
7. **Download** — Download the sanitized TXT file
8. **Privacy Gateway** — Paste any text and inspect it before external sharing
9. **Reports** — View aggregate statistics and export CSV
10. **History** — Browse and filter past analyses

---

## 9. Running Tests

```powershell
# Activate virtual environment first
venv\Scripts\activate

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_detection.py -v

# Run with coverage (optional: pip install pytest-cov)
pytest tests/ --cov=app -v
```

### Test Results (expected)
All tests pass on a correctly configured system:
- `test_detection.py` — 20+ tests for detection, classification, risk scoring, sanitization
- `test_auth.py` — 8 tests for authentication, JWT, and password hashing

> **Note:** `test_auth.py` integration tests that hit the database require MongoDB to be running. Detection/classification/scoring/sanitization tests are fully local (no DB required).

---

## 10. API Documentation

Full interactive docs at: `http://127.0.0.1:8000/docs`

Key endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | Register new account |
| POST | /api/auth/login | Login, get JWT token |
| GET  | /api/auth/me | Get current user |
| GET  | /api/dashboard/stats | Dashboard statistics |
| POST | /api/documents/upload | Upload document |
| GET  | /api/documents | List documents |
| DELETE | /api/documents/{id} | Delete document |
| POST | /api/analysis/analyze/{doc_id} | Run analysis |
| GET  | /api/analysis/{id} | Get analysis results |
| GET  | /api/analysis/history | Analysis history |
| POST | /api/analysis/{id}/sanitize | Sanitize document |
| GET  | /api/analysis/{id}/sanitized-download | Download sanitized TXT |
| POST | /api/privacy-gateway/inspect | Gateway inspection |
| GET  | /api/reports/summary | Report summary |
| GET  | /api/reports/export | CSV export |
| GET  | /api/health | System health check |

---

## 11. Project Structure

```
sensitive-data-detection/
│
├── app/
│   ├── main.py                    # FastAPI app, lifespan, routes
│   ├── config.py                  # Settings from .env
│   ├── database.py                # MongoDB connection + indexes
│   │
│   ├── routes/
│   │   ├── auth.py                # Register, login, /me
│   │   ├── dashboard.py           # Stats endpoint
│   │   ├── documents.py           # Upload, list, delete
│   │   ├── analysis.py            # Analyse, results, sanitize, download
│   │   ├── privacy_gateway.py     # Gateway inspect endpoint
│   │   └── reports.py             # Summary + CSV export
│   │
│   ├── services/
│   │   ├── text_extraction.py     # PDF/DOCX/TXT/OCR extraction
│   │   ├── preprocessing.py       # Text normalization
│   │   ├── detection_engine.py    # Regex + spaCy detection
│   │   ├── classification.py      # 4-level privacy classification
│   │   ├── risk_scoring.py        # 0–100 risk score algorithm
│   │   ├── sanitization.py        # Redact and mask engine
│   │   └── document_service.py    # Full pipeline orchestrator
│   │
│   ├── models/
│   │   └── schemas.py             # Pydantic request/response models
│   │
│   ├── security/
│   │   └── authentication.py      # JWT, bcrypt, FastAPI dependencies
│   │
│   └── utils/
│       └── file_validation.py     # Upload validation (MIME, size, ext)
│
├── frontend/
│   ├── index.html                 # Landing page
│   ├── login.html                 # Login
│   ├── register.html              # Registration
│   ├── dashboard.html             # Dashboard
│   ├── upload.html                # Upload & scan
│   ├── documents.html             # Documents list
│   ├── analysis.html              # Analysis results + sanitization
│   ├── history.html               # Analysis history
│   ├── privacy-gateway.html       # Privacy gateway
│   ├── reports.html               # Reports & analytics
│   ├── profile.html               # User profile & health status
│   ├── css/style.css              # Complete design system
│   └── js/
│       ├── api.js                 # API client + token management
│       ├── auth.js                # Auth guards, sidebar, toast
│       ├── dashboard.js           # Dashboard charts & stats
│       ├── analysis.js            # Results, highlights, sanitization
│       ├── documents.js           # Shared helpers
│       └── reports.js             # Reports charts & export
│
├── tests/
│   ├── conftest.py                # Shared fixtures
│   ├── test_detection.py          # Detection, classification, scoring, sanitization
│   └── test_auth.py               # Auth, JWT, password hashing
│
├── uploads/                       # Uploaded files (gitignored)
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variable template
├── .gitignore
└── README.md
```

---

## 12. Risk Scoring Formula

The risk score is calculated deterministically:

```
For each detection:
    points = CLASS_RISK_POINTS[privacy_class]
    effective_points = points × (0.5 ^ repetition_count_for_same_type)
    raw_score += effective_points

score = min(raw_score / 50, 1.0) × 100
score = round(score, 1)
```

**Class risk points:**
- Restricted: 5.0 pts
- Confidential: 3.0 pts
- Internal: 1.0 pts
- Public: 0.0 pts

**Diminishing returns:** Each additional detection of the same entity type contributes 50% of the previous one, preventing score inflation from repeated matches.

**Risk levels:**
- 0–29: Low Risk
- 30–59: Medium Risk
- 60–100: High Risk

---

## 13. Privacy Classification Rules

| Entity Type | Classification | Reason |
|-------------|---------------|--------|
| PASSWORD, API_KEY | Restricted | Credential enabling unauthorized access |
| AADHAAR, PAN | Restricted | Government ID requiring maximum protection |
| CREDIT_CARD | Restricted | Payment card data |
| EMAIL, PHONE | Confidential | Personal contact information |
| IP_ADDRESS, DATE_OF_BIRTH | Confidential | May identify individuals |
| PERSON_NAME | Confidential | PII (NLP detected) |
| ORGANIZATION, LOCATION | Internal | Business context information |
| DATE | Public | General date reference |

---

## 14. Limitations

1. **NLP detection is probabilistic** — spaCy en_core_web_sm may miss entities or produce false positives. Combined with regex for better coverage.
2. **OCR quality depends on image clarity** — low-resolution or handwritten documents may not extract well.
3. **Aadhaar / PAN patterns** are structural matches only. Validity is not verified.
4. **Sanitization is not a legal guarantee** — the system applies configured detection patterns. Novel or unusual sensitive data formats may not be detected.
5. **Password-protected PDFs** are not supported.
6. **No external AI integration** by default — the Privacy Gateway runs entirely locally.

---

## 15. Troubleshooting

### MongoDB connection failed
- Ensure `mongod` is running: `mongod --dbpath C:\data\db`
- Check `MONGODB_URI` in `.env`

### spaCy model not found
```powershell
python -m spacy download en_core_web_sm
```
Detection still works with regex only if spaCy model is missing.

### Tesseract not found
- Install from: https://github.com/UB-Mannheim/tesseract/wiki
- Set `TESSERACT_CMD` in `.env` to the full path

### Port 8000 already in use
```powershell
uvicorn app.main:app --reload --port 8001
```

### ImportError: No module named 'fitz'
```powershell
pip install PyMuPDF
```

### File upload fails with 422
- Check file size (max 20 MB by default)
- Check file type (PDF, DOCX, TXT, PNG, JPG, JPEG only)

### Frontend shows blank / 404
- Make sure you access `http://127.0.0.1:8000` not `file://...`
- FastAPI serves the frontend — the browser must connect to the running server.

---

*This project was built as a final-year engineering project demonstrating practical application of AI, NLP, and privacy engineering principles.*
