# ============================================================
# tests/test_gateway.py
# Privacy gateway policy decisions, modes, response inspection
# ============================================================
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, connect_db
from app.security.authentication import create_access_token, hash_password

client = TestClient(app)

HIGH_RISK = (
    "My Aadhaar 4321 8765 2109, PAN ABCDE1234F, passport M1234567, "
    "bank account 1234567890123456, IFSC SBIN0001234, "
    "card 4111 1111 1111 1111, password hunter2, "
    "api_key = sk-abc123def456ghi789jkl012"
)
LOW_RISK = "The report is ready for review."


@pytest.fixture(autouse=True, scope="module")
def init_test_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


def _headers(db) -> tuple:
    uid = db.users.insert_one({
        "name": "Gateway User",
        "email": f"gw_{ObjectId()}@example.com",
        "hashed_password": hash_password("TestPass@123"),
        "role": "user",
    }).inserted_id
    return uid, {"Authorization": f"Bearer {create_access_token(data={'sub': str(uid)})}"}


def _inspect(headers, text, **kwargs):
    payload = {"text": text, **kwargs}
    return client.post("/api/privacy-gateway/inspect", headers=headers, json=payload)


class TestGatewayPolicy:
    def test_requires_authentication(self):
        assert client.post(
            "/api/privacy-gateway/inspect", json={"text": LOW_RISK}
        ).status_code == 401

    def test_low_risk_can_be_forwarded_when_allowed(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            res = _inspect(headers, LOW_RISK, allow_forward=True)
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["blocked"] is False
            assert body["permit_forward"] is True
            assert body["decision"] == "allowed"
            assert body["sanitized_text"] == LOW_RISK
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})

    def test_high_risk_is_blocked_by_default(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            res = _inspect(headers, HIGH_RISK, allow_forward=True)
            assert res.status_code == 200
            body = res.json()
            assert body["risk_level"] == "High Risk"
            assert body["blocked"] is True
            assert body["permit_forward"] is False
            assert body["decision"] == "blocked"
            assert any("Blocked by policy" in w for w in body["warnings"])
            assert "ABCDE1234F" not in body["sanitized_text"]
            assert body["class_summary"]
            assert body["category_summary"]["Government Identification"] >= 1
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})

    def test_high_risk_without_block_flag_is_sanitized_only(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            body = _inspect(
                headers, HIGH_RISK, allow_forward=True, block_high_risk=False
            ).json()
            assert body["blocked"] is False
            assert body["permit_forward"] is False
            assert body["decision"] == "sanitized_only"
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})

    def test_audit_record_written_without_text(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            body = _inspect(headers, "Contact 9876543210", allow_forward=False).json()
            audit = db.audit_logs.find_one(
                {"user_id": uid, "action": "gateway_inspect", "gateway_id": body["gateway_id"]}
            )
            assert audit is not None
            assert "9876543210" not in repr(audit)
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})


class TestGatewayModes:
    def test_mask_mode_masks_phone(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            body = _inspect(headers, "Call 9876543210 today", mode="mask").json()
            assert body["mode"] == "mask"
            assert "9876543210" not in body["sanitized_text"]
            assert "3210" in body["sanitized_text"]
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})

    def test_pseudonymize_mode_replaces_with_token(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            body = _inspect(headers, "Email aisha.k@corp.com", mode="pseudonymize").json()
            assert body["mode"] == "pseudonymize"
            assert "aisha.k@corp.com" not in body["sanitized_text"]
            assert "[EMAIL_" in body["sanitized_text"]
            assert body["decision"] == "sanitized_only"
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})

    def test_invalid_mode_falls_back_to_redact(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            body = _inspect(headers, "Email aisha.k@corp.com", mode="delete-everything").json()
            assert body["mode"] == "redact"
            assert "[EMAIL_REDACTED]" in body["sanitized_text"]
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})


class TestGatewayResponseInspection:
    def test_leaked_value_in_external_response_is_flagged(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            body = _inspect(
                headers,
                "Contact aisha.k@corp.com for details.",
                allow_forward=False,
                inspect_response="Sure — the address is aisha.k@corp.com.",
            ).json()
            inspection = body["response_inspection"]
            assert inspection is not None
            assert inspection["safe"] is False
            assert inspection["leaked_from_input"] >= 1
            assert "EMAIL" in inspection["entity_types"]
            assert "aisha.k@corp.com" not in inspection["sanitized_response"]
            assert any("External response contains" in w for w in body["warnings"])
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})

    def test_clean_external_response_is_safe(self):
        db = get_db()
        uid, headers = _headers(db)
        try:
            body = _inspect(
                headers,
                "Contact aisha.k@corp.com for details.",
                inspect_response="The report was approved yesterday.",
            ).json()
            assert body["response_inspection"]["safe"] is True
            assert body["response_inspection"]["leaked_from_input"] == 0
        finally:
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})
