# ============================================================
# tests/test_format_sanitization.py
# Verification of Image Processing & Format-Preserving Sanitization
# Covers all 12 specified test cases:
# 1. PNG with email + phone
# 2. JPG with name + ID
# 3. JPEG with multi-entities
# 4. Text-based PDF
# 5. Scanned PDF (image-only pages)
# 6. DOCX with sensitive values in paragraphs and tables
# 7. TXT with email and phone
# 8. Image with no readable text
# 9. Corrupted image upload
# 10. Rotated image with EXIF orientation
# 11. Unsupported file extension
# 12. Cross-user sanitization attempt security
# ============================================================
import io
import os
import pytest
from PIL import Image, ImageDraw
import pymupdf as fitz
from docx import Document
from fastapi.testclient import TestClient
from bson import ObjectId

from app.main import app
from app.services.text_extraction import extract_text
from app.services.detection_engine import detect
from app.services.sanitization import sanitize_file, sanitize
from app.database import get_db, connect_db, close_db
from app.security.authentication import create_access_token, hash_password


@pytest.fixture(autouse=True, scope="module")
def init_test_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


client = TestClient(app)


# ── Helpers to synthesize test files in memory ──────────────

def create_text_image(text_lines: list[str], fmt: str = "PNG") -> bytes:
    """Create a crisp image containing specific lines of text using true-type font."""
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except Exception:
        font = ImageFont.load_default(size=24) if hasattr(ImageFont, "load_default") else None

    width = 800
    height = 80 + len(text_lines) * 60
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    y = 35
    for line in text_lines:
        draw.text((40, y), line, fill=(0, 0, 0), font=font)
        y += 55
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def create_test_pdf(text_lines: list[str]) -> bytes:
    """Create a standard text-based PDF."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    y = 72
    for line in text_lines:
        page.insert_text((72, y), line, fontsize=12)
        y += 24
    buf = doc.tobytes()
    doc.close()
    return buf


def create_scanned_pdf(text_lines: list[str]) -> bytes:
    """Create a scanned PDF containing a rasterized image of text."""
    img_bytes = create_text_image(text_lines, "PNG")
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    rect = fitz.Rect(50, 50, 545, 400)
    page.insert_image(rect, stream=img_bytes)
    buf = doc.tobytes()
    doc.close()
    return buf


def create_test_docx(paragraphs: list[str], table_cells: list[str]) -> bytes:
    """Create a DOCX file with text in paragraphs and a table."""
    doc = Document()
    doc.add_heading("Confidential Document", 0)
    for p in paragraphs:
        doc.add_paragraph(p)
    if table_cells:
        table = doc.add_table(rows=1, cols=len(table_cells))
        for idx, text in enumerate(table_cells):
            table.rows[0].cells[idx].text = text
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ── Test Cases ───────────────────────────────────────────────

class TestFormatPreservingSanitization:

    def test_case_1_png_email_and_phone(self):
        """1. PNG image with email + phone: OCR extracts text, detects, sanitizes pixels to valid PNG."""
        img_bytes = create_text_image(["Contact: john.doe@example.com", "Phone: 9876543210"], fmt="PNG")
        extraction = extract_text(img_bytes, "contact.png")
        assert extraction.success is True
        assert extraction.used_ocr is True
        assert "john.doe@example.com" in extraction.text

        detections = [
            {"entity_type": "EMAIL", "matched_value": "john.doe@example.com", "start": 0, "end": 20},
            {"entity_type": "PHONE_IN", "matched_value": "9876543210", "start": 25, "end": 35},
        ]

        sanitized_bytes, sanitized_name, mime_type = sanitize_file(
            img_bytes, "contact.png", detections, mode="redact"
        )
        assert sanitized_name == "contact_sanitized.png"
        assert mime_type == "image/png"
        # Verify result is a valid PNG image
        sanitized_img = Image.open(io.BytesIO(sanitized_bytes))
        assert sanitized_img.format == "PNG"
        assert sanitized_img.size[0] > 0

    def test_case_2_jpg_name_and_id(self):
        """2. JPG image with sensitive name & PAN ID: sanitizes to valid JPEG."""
        jpg_bytes = create_text_image(["Taxpayer: Ramesh Sharma", "PAN: ABCDE1234F"], fmt="JPEG")
        extraction = extract_text(jpg_bytes, "card.jpg")
        assert extraction.success is True
        assert extraction.used_ocr is True

        detections = [
            {"entity_type": "PAN", "matched_value": "ABCDE1234F", "start": 0, "end": 10},
        ]
        sanitized_bytes, sanitized_name, mime_type = sanitize_file(
            jpg_bytes, "card.jpg", detections, mode="redact"
        )
        assert sanitized_name == "card_sanitized.jpg"
        assert mime_type == "image/jpeg"
        sanitized_img = Image.open(io.BytesIO(sanitized_bytes))
        assert sanitized_img.format == "JPEG"

    def test_case_3_jpeg_multi_entities(self):
        """3. JPEG with multi-entities (email, phone, PAN)."""
        jpeg_bytes = create_text_image([
            "Official Document",
            "Email: alert@domain.com",
            "PAN: BKZPK9988L",
            "Call: 9811122233"
        ], fmt="JPEG")
        detections = [
            {"entity_type": "EMAIL", "matched_value": "alert@domain.com", "start": 0, "end": 16},
            {"entity_type": "PAN", "matched_value": "BKZPK9988L", "start": 20, "end": 30},
            {"entity_type": "PHONE_IN", "matched_value": "9811122233", "start": 35, "end": 45},
        ]
        sanitized_bytes, sanitized_name, mime_type = sanitize_file(
            jpeg_bytes, "record.jpeg", detections, mode="mask"
        )
        assert sanitized_name == "record_sanitized.jpeg"
        assert mime_type == "image/jpeg"
        sanitized_img = Image.open(io.BytesIO(sanitized_bytes))
        assert sanitized_img.format == "JPEG"

    def test_case_4_text_based_pdf(self):
        """4. Text-based PDF: redactions permanently remove underlying glyphs & text."""
        pdf_bytes = create_test_pdf([
            "Invoice #1042",
            "Customer email: billing@megacorp.com",
            "Tax ID: ABCDE1234F",
        ])
        extraction = extract_text(pdf_bytes, "invoice.pdf")
        assert extraction.success is True
        assert "billing@megacorp.com" in extraction.text

        detections = [
            {"entity_type": "EMAIL", "matched_value": "billing@megacorp.com", "start": 0, "end": 21},
            {"entity_type": "PAN", "matched_value": "ABCDE1234F", "start": 30, "end": 40},
        ]
        sanitized_bytes, sanitized_name, mime_type = sanitize_file(
            pdf_bytes, "invoice.pdf", detections, mode="redact"
        )
        assert sanitized_name == "invoice_sanitized.pdf"
        assert mime_type == "application/pdf"

        # Verify underlying text was eliminated from sanitized PDF
        doc = fitz.open(stream=sanitized_bytes, filetype="pdf")
        sanitized_text = doc[0].get_text("text")
        doc.close()
        assert "billing@megacorp.com" not in sanitized_text
        assert "ABCDE1234F" not in sanitized_text

    def test_case_5_scanned_pdf(self):
        """5. Scanned PDF: OCR fallback detects text, sanitization outputs valid PDF."""
        scanned_bytes = create_scanned_pdf([
            "Confidential Scanned Memo",
            "Target email: secret@agency.gov",
        ])
        extraction = extract_text(scanned_bytes, "scanned_memo.pdf")
        assert extraction.success is True
        assert extraction.used_ocr is True
        assert "secret@agency.gov" in extraction.text

        detections = [
            {"entity_type": "EMAIL", "matched_value": "secret@agency.gov", "start": 0, "end": 17},
        ]
        sanitized_bytes, sanitized_name, mime_type = sanitize_file(
            scanned_bytes, "scanned_memo.pdf", detections, mode="redact"
        )
        assert sanitized_name == "scanned_memo_sanitized.pdf"
        assert mime_type == "application/pdf"
        doc = fitz.open(stream=sanitized_bytes, filetype="pdf")
        assert len(doc) == 1
        doc.close()

    def test_case_6_docx_paragraphs_and_tables(self):
        """6. DOCX with sensitive values in body paragraphs and tables."""
        docx_bytes = create_test_docx(
            paragraphs=["Confidential employee: admin@company.org"],
            table_cells=["Cell 1: Phone 9876543210", "Cell 2: PAN ABCDE1234F"]
        )
        extraction = extract_text(docx_bytes, "employee_info.docx")
        assert extraction.success is True
        assert "admin@company.org" in extraction.text
        assert "9876543210" in extraction.text

        detections = [
            {"entity_type": "EMAIL", "matched_value": "admin@company.org", "start": 0, "end": 17},
            {"entity_type": "PHONE_IN", "matched_value": "9876543210", "start": 20, "end": 30},
            {"entity_type": "PAN", "matched_value": "ABCDE1234F", "start": 35, "end": 45},
        ]
        sanitized_bytes, sanitized_name, mime_type = sanitize_file(
            docx_bytes, "employee_info.docx", detections, mode="redact"
        )
        assert sanitized_name == "employee_info_sanitized.docx"
        assert "wordprocessingml" in mime_type

        # Verify sanitized DOCX content
        doc = Document(io.BytesIO(sanitized_bytes))
        full_p_text = " ".join([p.text for p in doc.paragraphs])
        assert "admin@company.org" not in full_p_text
        assert "[EMAIL_REDACTED]" in full_p_text

        table_text = " ".join([cell.text for row in doc.tables[0].rows for cell in row.cells])
        assert "9876543210" not in table_text
        assert "[PHONE_REDACTED]" in table_text

    def test_case_7_txt_sanitization(self):
        """7. TXT with email and phone."""
        txt_bytes = b"Hello, reach me at user@test.com or call 9123456789."
        extraction = extract_text(txt_bytes, "notes.txt")
        assert extraction.success is True

        detections = [
            {"entity_type": "EMAIL", "matched_value": "user@test.com", "start": 19, "end": 32},
            {"entity_type": "PHONE_IN", "matched_value": "9123456789", "start": 41, "end": 51},
        ]
        sanitized_bytes, sanitized_name, mime_type = sanitize_file(
            txt_bytes, "notes.txt", detections, mode="redact"
        )
        assert sanitized_name == "notes_sanitized.txt"
        assert mime_type == "text/plain; charset=utf-8"
        text = sanitized_bytes.decode("utf-8")
        assert "user@test.com" not in text
        assert "[EMAIL_REDACTED]" in text
        assert "[PHONE_REDACTED]" in text

    def test_case_8_image_no_readable_text(self):
        """8. Image with no readable text returns clean warnings and 0 detections without crashing."""
        blank_img = Image.new("RGB", (300, 300), color=(200, 200, 200))
        buf = io.BytesIO()
        blank_img.save(buf, format="PNG")
        extraction = extract_text(buf.getvalue(), "blank.png")
        assert extraction.success is True
        assert extraction.text == ""
        assert len(extraction.warnings) > 0
        assert "No readable text" in extraction.warnings[0]

    def test_case_9_corrupted_image_validation(self):
        """9. Corrupted image upload is rejected with 400 error."""
        db = get_db()
        user = db.users.find_one() or {"_id": ObjectId()}
        token = create_access_token(data={"sub": str(user["_id"])})

        corrupted_bytes = b"NOT_A_REAL_PNG_HEADER_DATA_12345"
        resp = client.post(
            "/api/documents/upload",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("corrupt.png", corrupted_bytes, "image/png")},
        )
        assert resp.status_code == 400
        assert "corrupted or invalid" in resp.json()["detail"].lower()

    def test_case_10_rotated_image_exif(self):
        """10. Rotated image with EXIF orientation handled properly."""
        img = Image.new("RGB", (400, 150), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.text((20, 50), "Rotation test text", fill=(0, 0, 0))
        exif = img.getexif()
        exif[0x0112] = 6  # Orientation: 90 CW
        buf = io.BytesIO()
        img.save(buf, format="JPEG", exif=exif)

        extraction = extract_text(buf.getvalue(), "rotated.jpg")
        assert extraction.success is True
        assert extraction.used_ocr is True

    def test_case_11_unsupported_file_extension(self):
        """11. Unsupported file extension is rejected with 400 error."""
        db = get_db()
        user = db.users.find_one() or {"_id": ObjectId()}
        token = create_access_token(data={"sub": str(user["_id"])})

        resp = client.post(
            "/api/documents/upload",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
        )
        assert resp.status_code == 400
        assert "not supported" in resp.json()["detail"].lower()

    def test_case_12_cross_user_sanitization_security(self):
        """12. Cross-user sanitization attempt is blocked with 404 security guard."""
        db = get_db()
        user_a_id = db.users.insert_one({"email": "user_a@test.com", "role": "analyst"}).inserted_id
        user_b_id = db.users.insert_one({"email": "user_b@test.com", "role": "analyst"}).inserted_id

        token_b = create_access_token(data={"sub": str(user_b_id)})

        # Create analysis owned by user A
        analysis_id = db.analyses.insert_one({
            "user_id": user_a_id,
            "document_name": "user_a_doc.txt",
            "extracted_text": "email@usera.com",
            "detections": [],
            "sanitization_status": "not_sanitized",
        }).inserted_id

        # User B attempts to sanitize User A's analysis
        resp = client.post(
            f"/api/analysis/{analysis_id}/sanitize",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

        # Clean up test records
        db.analyses.delete_one({"_id": analysis_id})
        db.users.delete_one({"_id": user_a_id})
        db.users.delete_one({"_id": user_b_id})
