# ============================================================
# tests/test_pages.py
# Page-count and page-reference preservation through extraction
# ============================================================
import io
import os

import pymupdf as fitz
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app
from app.services.text_extraction import extract_text, page_for_offset
from app.services.detection_engine import detect
from app.database import get_db, connect_db
from app.security.authentication import create_access_token, hash_password

client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def init_test_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


def _pdf_with_pages(pages: list[str]) -> bytes:
    doc = fitz.open()
    for text in pages:
        page = doc.new_page(width=595, height=842)
        if text:
            page.insert_text((72, 72), text, fontsize=12)
    data = doc.tobytes()
    doc.close()
    return data


class TestPdfPageSpans:
    def test_page_count_includes_blank_pages(self):
        result = extract_text(_pdf_with_pages(["Alpha", "", "Beta"]), "three.pdf")
        assert result.success is True
        assert result.page_count == 3
        assert [p for _, _, p in result.page_spans] == [1, 3]

    def test_offsets_stay_aligned_with_text(self):
        result = extract_text(_pdf_with_pages(["Cover notes", "PAN: ABCDE1234F"]), "pan.pdf")
        pan = [d for d in detect(result.text) if d.entity_type == "PAN"]
        assert len(pan) == 1
        assert result.text[pan[0].start:pan[0].end] == "ABCDE1234F"
        assert page_for_offset(result.page_spans, pan[0].start) == 2

    def test_empty_pdf_reports_no_spans(self):
        result = extract_text(_pdf_with_pages(["", ""]), "blank.pdf")
        assert result.success is True
        assert result.page_count == 2
        assert result.page_spans == []

    def test_txt_is_single_page(self):
        result = extract_text(b"PAN: ABCDE1234F", "note.txt")
        assert result.page_count == 1
        assert result.page_spans == [(0, len(result.text), 1)]

    def test_offset_past_last_span_maps_to_last_page(self):
        spans = [(0, 5, 1), (7, 12, 3)]
        assert page_for_offset(spans, 11) == 3
        assert page_for_offset(spans, 99) == 3
        assert page_for_offset([], 99) == 1


class TestPdfPageInApiResponse:
    def test_analysis_reports_source_page_and_page_count(self):
        db = get_db()
        user_id = db.users.insert_one({
            "email": f"pages_{ObjectId()}@example.com",
            "hashed_password": hash_password("TestPass123!"),
            "role": "user",
        }).inserted_id
        token = create_access_token(data={"sub": str(user_id)})
        headers = {"Authorization": f"Bearer {token}"}

        content = _pdf_with_pages(["Quarterly cover", "Contact: aisha.k@corp.com"])
        doc_id = analysis_id = None
        try:
            upload = client.post(
                "/api/documents/upload",
                headers=headers,
                files={"file": ("report.pdf", content, "application/pdf")},
            )
            assert upload.status_code == 201, upload.text
            doc_id = upload.json()["id"]

            analysed = client.post(f"/api/analysis/analyze/{doc_id}", headers=headers)
            assert analysed.status_code == 200, analysed.text
            body = analysed.json()
            analysis_id = body["id"]

            assert body["page_count"] == 2
            email = [d for d in body["detections"] if d["entity_type"] == "EMAIL"]
            assert email and email[0]["page"] == 2
        finally:
            if analysis_id:
                db.analyses.delete_one({"_id": ObjectId(analysis_id)})
            if doc_id:
                doc = db.documents.find_one({"_id": ObjectId(doc_id)})
                if doc:
                    path = doc.get("file_path")
                    if path and os.path.exists(path):
                        os.remove(path)
                    db.documents.delete_one({"_id": ObjectId(doc_id)})
            db.users.delete_one({"_id": user_id})
