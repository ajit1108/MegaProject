# ============================================================
# tests/conftest.py — Shared pytest fixtures
# ============================================================
import pytest
from app.services.detection_engine import Detection


@pytest.fixture
def sample_detection_email():
    return Detection(
        entity_type="EMAIL", matched_value="test@example.com",
        start=0, end=16, detection_method="regex", confidence=0.97
    )

@pytest.fixture
def sample_detection_pan():
    return Detection(
        entity_type="PAN", matched_value="ABCDE1234F",
        start=0, end=10, detection_method="regex", confidence=0.85
    )

@pytest.fixture
def sample_enriched_detection():
    return {
        "entity_type":    "EMAIL",
        "matched_value":  "test@example.com",
        "privacy_class":  "Confidential",
        "risk_points":    3.0,
        "start":          0,
        "end":            16,
    }
