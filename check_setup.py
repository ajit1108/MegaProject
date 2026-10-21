"""
check_setup.py — Quick setup verification script.
Run with: python check_setup.py
"""
import sys
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

print("=" * 60)
print("  SensitiveDataDetector -- Setup Verification")
print("=" * 60)
errors = []

# Python version
major, minor = sys.version_info[:2]
status = "[OK]" if (major == 3 and minor >= 11) else "[X] (need 3.11+)"
print(f"\n[{'OK' if major==3 and minor>=11 else '!!'}] Python {major}.{minor}  {status}")
if not (major == 3 and minor >= 11):
    errors.append("Python 3.11+ required.")

checks = [
    ("fastapi",        "FastAPI"),
    ("uvicorn",        "Uvicorn"),
    ("pymongo",        "PyMongo"),
    ("pydantic",       "Pydantic"),
    ("jose",           "python-jose (JWT)"),
    ("bcrypt",         "bcrypt"),
    ("multipart",      "python-multipart"),
    ("aiofiles",       "aiofiles"),
]

for module, name in checks:
    try:
        __import__(module)
        print(f"[OK] {name}")
    except ImportError:
        print(f"[!!] {name}  — NOT installed")
        errors.append(f"{name} not installed.")

# Optional
print("\n--- Optional (graceful degradation if missing) ---")

try:
    try:
        import pymupdf as fitz
    except ImportError:
        import fitz
    print("[OK] PyMuPDF (PDF extraction)")
except Exception:
    print("[--] PyMuPDF -- not installed (PDF support disabled)")

try:
    import docx
    print(f"[OK] python-docx (DOCX extraction)")
except ImportError:
    print("[--] python-docx — not installed (DOCX support disabled)")

try:
    import spacy
    try:
        nlp = spacy.load("en_core_web_sm")
        print("[OK] spaCy + en_core_web_sm model (NLP detection)")
    except OSError:
        print("[--] spaCy installed BUT en_core_web_sm not found")
        print("     Run: python -m spacy download en_core_web_sm")
except ImportError:
    print("[--] spaCy — not installed (NLP detection disabled, Regex still works)")

try:
    import pytesseract
    from PIL import Image
    print("[OK] pytesseract + Pillow (OCR)")
    try:
        ver = pytesseract.get_tesseract_version()
        print(f"[OK] Tesseract v{ver}")
    except Exception:
        print("[--] Tesseract binary not found — set TESSERACT_CMD in .env")
except ImportError:
    print("[--] pytesseract/Pillow — not installed (OCR disabled)")

# MongoDB
print("\n--- Connectivity ---")
try:
    from pymongo import MongoClient
    from dotenv import load_dotenv
    import os
    load_dotenv()
    uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    client = MongoClient(uri, serverSelectionTimeoutMS=3000)
    client.admin.command("ping")
    print(f"[OK] MongoDB reachable at {uri}")
    client.close()
except Exception as e:
    print(f"[!!] MongoDB NOT reachable — {e}")
    errors.append("MongoDB connection failed.")

# Summary
print("\n" + "=" * 60)
if errors:
    print(f"  [X]  {len(errors)} issue(s) found:")
    for e in errors:
        print(f"     * {e}")
    print("\n  Fix the issues above, then run the server:")
else:
    print("  [OK]  All core checks passed!")
    print("\n  Start the server:")
print("     uvicorn app.main:app --reload --host 127.0.0.1 --port 8000")
print("=" * 60)
