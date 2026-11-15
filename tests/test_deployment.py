# ============================================================
# tests/test_deployment.py — Production guards and health probes
# ============================================================
import asyncio

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.database import connect_db
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def init_test_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


def test_health_reports_database_status():
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["database"] == "ok"
    assert body["status"] == "ok"
    assert body["external_ai_enabled"] is False


def test_cors_origins_are_configurable():
    assert Settings(cors_origins="*").cors_origin_list == ["*"]
    origins = Settings(cors_origins="https://a.example, https://b.example").cors_origin_list
    assert origins == ["https://a.example", "https://b.example"]
    assert Settings(app_env="production").is_production
    assert not Settings(app_env="development").is_production


def test_production_default_secret_is_rejected(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(
        main_module, "get_settings",
        lambda: Settings(app_env="production", secret_key="change-this-secret-key"),
    )

    async def boot():
        async with main_module.lifespan(app):
            pass

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        asyncio.run(boot())
