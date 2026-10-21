# ============================================================
# tests/test_auth.py — Auth endpoint integration tests
# ============================================================
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app
from app.security.authentication import hash_password

client = TestClient(app)

MOCK_USER = {
    "_id": MagicMock(str=lambda: "507f1f77bcf86cd799439011"),
    "name": "Test User",
    "email": "test@example.com",
    "password_hash": hash_password("TestPass@123"),
    "role": "user",
}


class TestRegistration:
    def test_register_missing_fields(self):
        res = client.post("/api/auth/register", json={"name": "", "email": "", "password": ""})
        assert res.status_code in (400, 422)

    def test_register_weak_password(self):
        res = client.post("/api/auth/register", json={
            "name": "Test", "email": "t@t.com", "password": "123"
        })
        assert res.status_code == 422

    def test_register_invalid_email(self):
        res = client.post("/api/auth/register", json={
            "name": "Test", "email": "notanemail", "password": "ValidPass@123"
        })
        assert res.status_code == 422


class TestLogin:
    def test_login_invalid_credentials(self):
        with patch("app.routes.auth.get_db") as mock_db:
            mock_db.return_value.users.find_one.return_value = None
            mock_db.return_value.audit_logs.insert_one.return_value = None
            res = client.post("/api/auth/login", json={
                "email": "nobody@example.com", "password": "Wrong@123"
            })
            assert res.status_code == 401

    def test_login_missing_fields(self):
        res = client.post("/api/auth/login", json={"email": "x@x.com"})
        assert res.status_code == 422


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        h = hash_password("MyPassword@123")
        assert h != "MyPassword@123"
        assert len(h) > 20

    def test_verify_correct_password(self):
        from app.security.authentication import verify_password
        h = hash_password("TestPassword@456")
        assert verify_password("TestPassword@456", h) is True

    def test_verify_wrong_password(self):
        from app.security.authentication import verify_password
        h = hash_password("TestPassword@456")
        assert verify_password("WrongPassword", h) is False


class TestJWT:
    def test_create_and_decode_token(self):
        from app.security.authentication import create_access_token, decode_token
        token = create_access_token({"sub": "user123"})
        payload = decode_token(token)
        assert payload["sub"] == "user123"

    def test_invalid_token_raises(self):
        from app.security.authentication import decode_token, CREDENTIALS_EXCEPTION
        with pytest.raises(Exception):
            decode_token("not.a.valid.token")
