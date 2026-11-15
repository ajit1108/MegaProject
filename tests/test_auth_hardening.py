# ============================================================
# tests/test_auth_hardening.py
# Logout revocation, login throttling, role guards
# ============================================================
import pytest
from datetime import datetime, timezone
from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, connect_db
from app.security.authentication import (
    hash_password,
    require_admin,
    create_access_token,
    decode_token,
)
from app.services import login_throttle

client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def init_test_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


def _make_user(email: str, role: str = "user") -> ObjectId:
    return get_db().users.insert_one({
        "name": "Auth Test",
        "email": email,
        "password_hash": hash_password("TestPass@123"),
        "role": role,
        "created_at": datetime.now(timezone.utc),
    }).inserted_id


class TestLogoutRevocation:
    def test_logout_invalidates_token(self):
        db = get_db()
        email = f"logout_{ObjectId()}@example.com"
        uid = _make_user(email)
        try:
            login = client.post("/api/auth/login", json={
                "email": email, "password": "TestPass@123"
            })
            assert login.status_code == 200, login.text
            token = login.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            assert client.get("/api/auth/me", headers=headers).status_code == 200

            out = client.post("/api/auth/logout", headers=headers)
            assert out.status_code == 200, out.text

            assert client.get("/api/auth/me", headers=headers).status_code == 401
            assert db.token_denylist.find_one({"jti": decode_token(token)["jti"]})
            assert db.audit_logs.find_one({"user_id": uid, "action": "logout"})
        finally:
            db.token_denylist.delete_many({"user_id": uid})
            db.audit_logs.delete_many({"user_id": uid})
            db.users.delete_one({"_id": uid})

    def test_missing_token_is_rejected(self):
        assert client.get("/api/auth/me").status_code == 401


class TestLoginThrottling:
    def test_repeated_failures_lock_account(self):
        db = get_db()
        email = f"throttle_{ObjectId()}@example.com"
        uid = _make_user(email)
        key = login_throttle.attempt_key(email, "testclient")
        try:
            for _ in range(login_throttle.MAX_ATTEMPTS):
                res = client.post("/api/auth/login", json={
                    "email": email, "password": "WrongPass@123"
                })
                assert res.status_code == 401

            blocked = client.post("/api/auth/login", json={
                "email": email, "password": "TestPass@123"
            })
            assert blocked.status_code == 429
            assert "Retry-After" in blocked.headers

            # Correct password after the window is cleared works again.
            db.login_attempts.delete_one({"_id": key})
            ok = client.post("/api/auth/login", json={
                "email": email, "password": "TestPass@123"
            })
            assert ok.status_code == 200
        finally:
            db.login_attempts.delete_one({"_id": key})
            db.audit_logs.delete_many({"$or": [{"user_id": uid}, {"email": email}]})
            db.users.delete_one({"_id": uid})

    def test_successful_login_clears_failures(self):
        db = get_db()
        email = f"throttle_ok_{ObjectId()}@example.com"
        uid = _make_user(email)
        key = login_throttle.attempt_key(email, "testclient")
        try:
            client.post("/api/auth/login", json={"email": email, "password": "bad"})
            assert db.login_attempts.find_one({"_id": key})
            ok = client.post("/api/auth/login", json={"email": email, "password": "TestPass@123"})
            assert ok.status_code == 200
            assert db.login_attempts.find_one({"_id": key}) is None
        finally:
            db.login_attempts.delete_one({"_id": key})
            db.audit_logs.delete_many({"$or": [{"user_id": uid}, {"email": email}]})
            db.users.delete_one({"_id": uid})


class TestRoleGuard:
    def test_admin_passes(self):
        assert require_admin({"_id": ObjectId(), "role": "admin"})["role"] == "admin"

    def test_non_admin_blocked(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            require_admin({"_id": ObjectId(), "role": "user"})
        assert exc.value.status_code == 403
