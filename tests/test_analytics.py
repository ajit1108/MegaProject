# ============================================================
# tests/test_analytics.py
# Analytics/audit derived from real MongoDB rows; RBAC isolation.
# ============================================================
import json
import os

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, connect_db
from app.security.authentication import create_access_token, hash_password

client = TestClient(app)

DOC = (
    "Contact priya.sharma@corp.com or 9876543210 for details. "
    "Her Aadhaar is 4321 8765 2109 and the deployment region is Pune."
)


@pytest.fixture(autouse=True, scope="module")
def init_test_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


def _make_user(db, tag="an", role="user") -> tuple:
    uid = db.users.insert_one({
        "name": f"Analytics {tag}",
        "email": f"{tag}_{ObjectId()}@example.com",
        "hashed_password": hash_password("TestPass@123"),
        "role": role,
    }).inserted_id
    return uid, {"Authorization": f"Bearer {create_access_token(data={'sub': str(uid)})}"}


def _upload_analyse(headers, content: bytes = DOC.encode(), name="analytics.txt") -> tuple:
    upload = client.post(
        "/api/documents/upload", headers=headers,
        files={"file": (name, content, "text/plain")},
    )
    assert upload.status_code == 201, upload.text
    doc_id = upload.json()["id"]
    analysed = client.post(f"/api/analysis/analyze/{doc_id}", headers=headers)
    assert analysed.status_code == 200, analysed.text
    return doc_id, analysed.json()["id"]


def _cleanup(db, uid, doc_id=None, analysis_id=None):
    if analysis_id:
        oid = ObjectId(analysis_id)
        for row in db.sanitized_documents.find({"analysis_id": oid}):
            path = row.get("sanitized_file_path")
            if path and os.path.isfile(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        db.sanitized_documents.delete_many({"analysis_id": oid})
        db.pseudonym_maps.delete_many({"analysis_id": str(oid)})
        db.rag_chunks.delete_many({"analysis_id": oid})
        db.analyses.delete_one({"_id": oid})
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
    db.rag_conversations.delete_many({"user_id": uid})
    db.audit_logs.delete_many({"user_id": uid})
    db.users.delete_one({"_id": uid})


def _seed_activity(db, headers) -> tuple:
    """Upload, analyse, sanitize, inspect through the gateway, query RAG."""
    doc_id, analysis_id = _upload_analyse(headers)

    sanitized = client.post(
        f"/api/analysis/{analysis_id}/sanitize?mode=mask", headers=headers
    )
    assert sanitized.status_code == 200, sanitized.text

    gateway = client.post("/api/privacy-gateway/inspect", headers=headers, json={
        "text": "Reach priya.sharma@corp.com or 9876543210 immediately.",
        "allow_forward": True,
    })
    assert gateway.status_code == 200, gateway.text

    rag = client.post("/api/rag/query", headers=headers, json={
        "question": "Where is the deployment region?"
    })
    assert rag.status_code == 200, rag.text

    return doc_id, analysis_id


class TestUserAnalytics:
    def test_summary_reflects_real_activity(self):
        db = get_db()
        uid, headers = _make_user(db)
        doc_id = analysis_id = None
        try:
            doc_id, analysis_id = _seed_activity(db, headers)

            res = client.get("/api/analytics/summary", headers=headers)
            assert res.status_code == 200, res.text
            body = res.json()

            assert body["documents"] == 1
            assert body["analyses"] == 1
            assert body["total_detections"] >= 3
            assert body["sanitized_documents"] == 1
            assert body["sanitization_modes"] == {"mask": 1}
            assert body["gateway_inspections"] == 1
            assert body["rag_conversations"] == 1
            assert body["rag_queries"] == 1

            assert sum(body["risk_distribution"].values()) == 1
            assert sum(body["class_distribution"].values()) == body["total_detections"]
            assert sum(body["category_distribution"].values()) == body["total_detections"]
            assert sum(body["method_distribution"].values()) == body["total_detections"]
            assert body["top_entity_types"]
            assert body["audit_action_counts"].get("sanitize") == 1
            assert body["recent_activity"]

            # Aggregates expose types and counts, never raw values.
            blob = json.dumps(body)
            assert "priya.sharma@corp.com" not in blob
            assert "9876543210" not in blob
            assert "4321 8765 2109" not in blob
        finally:
            _cleanup(db, uid, doc_id, analysis_id)

    def test_summary_is_empty_for_new_user(self):
        db = get_db()
        uid, headers = _make_user(db, "an_new")
        try:
            body = client.get("/api/analytics/summary", headers=headers).json()
            assert body["documents"] == 0
            assert body["analyses"] == 0
            assert body["total_detections"] == 0
            assert body["risk_distribution"] == {}
            assert body["recent_activity"] == []
        finally:
            _cleanup(db, uid)

    def test_summary_requires_authentication(self):
        assert client.get("/api/analytics/summary").status_code == 401
        assert client.get("/api/analytics/audit").status_code == 401


class TestUserAudit:
    def test_audit_returns_only_own_events_without_emails(self):
        db = get_db()
        owner, owner_headers = _make_user(db, "an_owner")
        other, other_headers = _make_user(db, "an_other")
        try:
            client.post("/api/privacy-gateway/inspect", headers=other_headers,
                        json={"text": "Mail priya.sharma@corp.com"})
            client.post("/api/privacy-gateway/inspect", headers=owner_headers,
                        json={"text": "Mail priya.sharma@corp.com"})

            # Audit rows may carry an account email in nofield; feed must drop it.
            db.audit_logs.insert_one({
                "user_id": owner, "action": "login_failed",
                "email": "priya.sharma@corp.com",
                "status": "failure",
            })

            res = client.get("/api/analytics/audit", headers=owner_headers)
            assert res.status_code == 200, res.text
            events = res.json()["events"]
            assert events
            assert all(ev.get("user_id") == str(owner) for ev in events)
            assert all("email" not in ev for ev in events)
            assert "priya.sharma@corp.com" not in json.dumps(events)

            other_events = client.get(
                "/api/analytics/audit", headers=other_headers
            ).json()["events"]
            assert all(ev.get("user_id") == str(other) for ev in other_events)

            filtered = client.get(
                "/api/analytics/audit?action=login_failed", headers=owner_headers
            ).json()["events"]
            assert len(filtered) == 1
            assert filtered[0]["action"] == "login_failed"
        finally:
            _cleanup(db, owner)
            _cleanup(db, other)

    def test_audit_pagination(self):
        db = get_db()
        uid, headers = _make_user(db, "an_page")
        try:
            db.audit_logs.insert_many([
                {"user_id": uid, "action": "page_test", "seq": i}
                for i in range(3)
            ])
            first = client.get(
                "/api/analytics/audit?action=page_test&skip=0&limit=1", headers=headers
            ).json()
            second = client.get(
                "/api/analytics/audit?action=page_test&skip=1&limit=1", headers=headers
            ).json()
            assert len(first["events"]) == 1
            assert len(second["events"]) == 1
            assert first["events"][0]["seq"] != second["events"][0]["seq"]
            assert client.get(
                "/api/analytics/audit?limit=0", headers=headers
            ).status_code == 422
        finally:
            _cleanup(db, uid)


class TestAdminAnalytics:
    def test_non_admin_is_forbidden(self):
        db = get_db()
        uid, headers = _make_user(db, "an_user")
        try:
            for path in ("/api/admin/analytics", "/api/admin/audit", "/api/admin/users"):
                assert client.get(path, headers=headers).status_code == 403, path
        finally:
            _cleanup(db, uid)

    def test_admin_sees_global_totals(self):
        db = get_db()
        user, user_headers = _make_user(db, "an_plain")
        admin, admin_headers = _make_user(db, "an_admin", role="admin")
        doc_id = analysis_id = None
        try:
            doc_id, analysis_id = _seed_activity(db, user_headers)
            own = client.get("/api/analytics/summary", headers=user_headers).json()

            res = client.get("/api/admin/analytics", headers=admin_headers)
            assert res.status_code == 200, res.text
            body = res.json()

            assert body["users"] >= 2
            assert body["documents"] >= own["documents"]
            assert body["analyses"] >= own["analyses"]
            assert body["total_detections"] >= own["total_detections"]
            assert body["gateway_inspections"] >= own["gateway_inspections"]
            assert body["rag_queries"] >= own["rag_queries"]
            assert body["top_entity_types"]
            assert body["risk_distribution"]

            scoped = client.get(
                f"/api/admin/audit?user_id={user}", headers=admin_headers
            )
            assert scoped.status_code == 200
            events = scoped.json()["events"]
            assert events and all(ev.get("user_id") == str(user) for ev in events)

            bad = client.get("/api/admin/audit?user_id=not-an-id", headers=admin_headers)
            assert bad.status_code == 400

            users = client.get("/api/admin/users", headers=admin_headers)
            assert users.status_code == 200
            rows = users.json()
            assert rows
            assert all("password_hash" not in row and "hashed_password" not in row
                       for row in rows)
        finally:
            _cleanup(db, user, doc_id, analysis_id)
            _cleanup(db, admin)
