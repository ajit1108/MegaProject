# ============================================================
# tests/test_pseudonymization.py
# Pseudonymization, encrypted mapping, restoration, cleanup
# ============================================================
import os

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, connect_db
from app.security.authentication import create_access_token, hash_password
from app.services.detection_engine import detect
from app.services.pseudonymization import (
    build_pseudonyms,
    load_mapping,
    restore_text,
)
from app.services.sanitization import sanitize

client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def init_test_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


def _dets(text: str) -> list[dict]:
    return [d.__dict__ for d in detect(text)]


class TestPseudonymUnit:
    def test_same_value_gets_same_token(self):
        text = "Email a@corp.com and again a@corp.com."
        dets = _dets(text)
        spans, values, entries = build_pseudonyms("a" * 24, dets)
        emails = [d for d in dets if d["entity_type"] == "EMAIL"]
        assert len(emails) == 2
        tokens = {spans[(d["start"], d["end"])] for d in emails}
        assert len(tokens) == 1
        assert len([e for e in entries if e["entity_type"] == "EMAIL"]) == 1

    def test_mapping_has_no_plaintext(self):
        dets = _dets("Contact aisha.k@corp.com or 9876543210.")
        _, _, entries = build_pseudonyms("b" * 24, dets)
        blob = repr(entries)
        assert "aisha.k@corp.com" not in blob
        assert "9876543210" not in blob
        assert all(e["ciphertext"] and e["token"] for e in entries)

    def test_roundtrip_restore(self):
        text = "Contact aisha.k@corp.com or 9876543210."
        dets = _dets(text)
        spans, _, entries = build_pseudonyms("c" * 24, dets)
        sanitized = sanitize(text, dets, mode="pseudonymize", replacements=spans)
        assert "aisha.k@corp.com" not in sanitized
        assert "9876543210" not in sanitized
        restored, replaced = restore_text(sanitized, entries)
        assert restored == text
        assert replaced >= 2

    def test_tokens_differ_across_analyses(self):
        dets = _dets("Email a@corp.com")
        spans1, _, _ = build_pseudonyms("1" * 24, dets)
        spans2, _, _ = build_pseudonyms("2" * 24, dets)
        assert list(spans1.values()) != list(spans2.values())

    def test_remove_mode_drops_spans(self):
        text = "Email a@corp.com now."
        dets = _dets(text)
        assert sanitize(text, dets, mode="remove") == "Email  now."


class TestPseudonymApi:
    @staticmethod
    def _make_user(db) -> tuple:
        uid = db.users.insert_one({
            "email": f"pseudo_{ObjectId()}@example.com",
            "hashed_password": hash_password("TestPass123!"),
            "role": "user",
        }).inserted_id
        return uid, {"Authorization": f"Bearer {create_access_token(data={'sub': str(uid)})}"}

    @staticmethod
    def _upload_and_analyse(headers, content: bytes, filename="note.txt"):
        upload = client.post(
            "/api/documents/upload",
            headers=headers,
            files={"file": (filename, content, "text/plain")},
        )
        assert upload.status_code == 201, upload.text
        doc_id = upload.json()["id"]
        analysed = client.post(f"/api/analysis/analyze/{doc_id}", headers=headers)
        assert analysed.status_code == 200, analysed.text
        return doc_id, analysed.json()["id"]

    def test_pseudonymize_restore_and_audit(self):
        db = get_db()
        uid, headers = self._make_user(db)
        content = b"Email aisha.k@corp.com or call 9876543210.\n"
        doc_id = analysis_id = None
        try:
            doc_id, analysis_id = self._upload_and_analyse(headers, content)

            original_path = db.documents.find_one({"_id": ObjectId(doc_id)})["file_path"]
            with open(original_path, "rb") as f:
                original_hash = f.read()

            resp = client.post(
                f"/api/analysis/{analysis_id}/sanitize?mode=pseudonymize", headers=headers
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            clean = body["sanitized_text"]
            assert "aisha.k@corp.com" not in clean
            assert "9876543210" not in clean
            assert body["mode"] == "pseudonymize"
            assert body["pseudonym_count"] == 2
            assert body["remaining_detections"] == 0

            stored = db.pseudonym_maps.find_one({"analysis_id": ObjectId(analysis_id)})
            assert stored and len(stored["entries"]) == 2
            assert "aisha.k@corp.com" not in repr(stored["entries"])

            sanitized_doc = db.sanitized_documents.find_one(
                {"analysis_id": ObjectId(analysis_id), "user_id": uid}
            )
            assert sanitized_doc and sanitized_doc["mode"] == "pseudonymize"
            assert sanitized_doc["pseudonymized"] is True

            # Reloading the analysis page must recover the stored output and flags.
            reloaded = client.get(f"/api/analysis/{analysis_id}", headers=headers)
            assert reloaded.status_code == 200
            detail = reloaded.json()
            assert detail["sanitization_mode"] == "pseudonymize"
            assert detail["pseudonymized"] is True
            assert detail["sanitized_text"] == clean

            restored = client.post(
                f"/api/analysis/{analysis_id}/restore", headers=headers
            )
            assert restored.status_code == 200, restored.text
            stored_analysis = db.analyses.find_one({"_id": ObjectId(analysis_id)})
            assert restored.json()["restored_text"] == stored_analysis["extracted_text"]
            assert "aisha.k@corp.com" in restored.json()["restored_text"]
            assert "9876543210" in restored.json()["restored_text"]
            assert restored.json()["tokens_restored"] >= 2

            audit = db.audit_logs.find_one(
                {"user_id": uid, "action": "restore", "analysis_id": analysis_id}
            )
            assert audit is not None

            with open(original_path, "rb") as f:
                assert f.read() == original_hash  # originals are never modified
        finally:
            self._cleanup(db, uid, doc_id, analysis_id)

    def test_restore_without_mapping_is_rejected(self):
        db = get_db()
        uid, headers = self._make_user(db)
        doc_id = analysis_id = None
        try:
            doc_id, analysis_id = self._upload_and_analyse(
                headers, b"Email someone@corp.com\n"
            )
            resp = client.post(
                f"/api/analysis/{analysis_id}/sanitize?mode=redact", headers=headers
            )
            assert resp.status_code == 200
            resp = client.post(f"/api/analysis/{analysis_id}/restore", headers=headers)
            assert resp.status_code == 400
        finally:
            self._cleanup(db, uid, doc_id, analysis_id)

    def test_cross_user_restore_is_blocked(self):
        db = get_db()
        uid, headers = self._make_user(db)
        other_uid, other_headers = self._make_user(db)
        doc_id = analysis_id = None
        try:
            doc_id, analysis_id = self._upload_and_analyse(
                headers, b"Email owner@corp.com\n"
            )
            client.post(f"/api/analysis/{analysis_id}/sanitize?mode=pseudonymize", headers=headers)
            resp = client.post(
                f"/api/analysis/{analysis_id}/restore", headers=other_headers
            )
            assert resp.status_code == 404
        finally:
            self._cleanup(db, uid, doc_id, analysis_id)
            self._cleanup(db, other_uid, None, None)

    @staticmethod
    def _cleanup(db, uid, doc_id, analysis_id):
        if analysis_id:
            a = db.analyses.find_one({"_id": ObjectId(analysis_id)}) or {}
            sanitized = db.sanitized_documents.find_one(
                {"analysis_id": ObjectId(analysis_id)}
            ) or {}
            for path in (a.get("sanitized_file_path"), sanitized.get("sanitized_file_path")):
                if path and os.path.isfile(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
            db.analyses.delete_one({"_id": ObjectId(analysis_id)})
            db.sanitized_documents.delete_many({"analysis_id": ObjectId(analysis_id)})
            db.pseudonym_maps.delete_many({"analysis_id": ObjectId(analysis_id)})
        if doc_id:
            doc = db.documents.find_one({"_id": ObjectId(doc_id)})
            if doc:
                path = doc.get("file_path")
                if path and os.path.isfile(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                db.documents.delete_one({"_id": ObjectId(doc_id)})
        db.audit_logs.delete_many({"user_id": uid})
        db.users.delete_one({"_id": uid})
