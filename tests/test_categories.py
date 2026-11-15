# ============================================================
# tests/test_categories.py
# Data-category layer and labelled identifier detection
# ============================================================
from types import SimpleNamespace

from app.services.detection_engine import detect
from app.services.classification import (
    DATA_CATEGORIES,
    CATEGORY_CONTACT,
    CATEGORY_CREDENTIALS,
    CATEGORY_EMPLOYMENT,
    CATEGORY_FINANCIAL,
    CATEGORY_GENERAL,
    CATEGORY_GOVERNMENT_ID,
    CATEGORY_LOCATION,
    CATEGORY_MEDICAL,
    CATEGORY_PII,
    category_summary,
    data_category,
)


def _cat(entity_type: str) -> str:
    return data_category(SimpleNamespace(entity_type=entity_type))


class TestLabelledIdentifiers:
    def test_employee_id_detected_with_label(self):
        hits = detect("Employee ID: EMP-10234")
        emp = [h for h in hits if h.entity_type == "EMPLOYEE_ID"]
        assert len(emp) == 1
        assert emp[0].matched_value == "EMP-10234"

    def test_customer_id_detected_with_label(self):
        hits = detect("Customer code CUST/88120 was updated.")
        cust = [h for h in hits if h.entity_type == "CUSTOMER_ID"]
        assert len(cust) == 1
        assert cust[0].matched_value == "CUST/88120"

    def test_unlabelled_number_is_not_an_identifier(self):
        hits = detect("Order number 10234 was shipped.")
        assert not [h for h in hits if h.entity_type in ("EMPLOYEE_ID", "CUSTOMER_ID")]

    def test_identifier_needs_explicit_id_word(self):
        hits = detect("The employee arrived at 10234.")
        assert not [h for h in hits if h.entity_type == "EMPLOYEE_ID"]

    def test_degenerate_identifier_rejected(self):
        hits = detect("Employee ID: 000000")
        assert not [h for h in hits if h.entity_type == "EMPLOYEE_ID"]

    def test_identifier_offsets_point_at_value(self):
        text = "Staff no: 45012 is active."
        hit = [h for h in detect(text) if h.entity_type == "EMPLOYEE_ID"][0]
        assert text[hit.start:hit.end] == "45012"


class TestCategoryMapping:
    def test_all_ten_categories_declared(self):
        assert len(DATA_CATEGORIES) == 10
        assert len(set(DATA_CATEGORIES)) == 10

    def test_representative_mappings(self):
        assert _cat("PERSON_NAME") == CATEGORY_PII
        assert _cat("CUSTOMER_ID") == CATEGORY_PII
        assert _cat("EMAIL") == CATEGORY_CONTACT
        assert _cat("PHONE_IN") == CATEGORY_CONTACT
        assert _cat("BANK_ACCOUNT") == CATEGORY_FINANCIAL
        assert _cat("MEDICATION") == CATEGORY_MEDICAL
        assert _cat("AADHAAR_FORMAT") == CATEGORY_GOVERNMENT_ID
        assert _cat("PAN") == CATEGORY_GOVERNMENT_ID
        assert _cat("EMPLOYEE_ID") == CATEGORY_EMPLOYMENT
        assert _cat("API_KEY") == CATEGORY_CREDENTIALS
        assert _cat("GEO_POLITICAL") == CATEGORY_LOCATION
        assert _cat("IP_ADDRESS") == CATEGORY_GENERAL

    def test_unknown_entity_is_general(self):
        assert _cat("SOMETHING_NEW") == CATEGORY_GENERAL

    def test_category_summary_counts(self):
        dets = [
            {"category": CATEGORY_CONTACT},
            {"category": CATEGORY_CONTACT},
            {"category": CATEGORY_FINANCIAL},
            {"entity_type": "PAN"},
        ]
        summary = category_summary(dets)
        assert summary[CATEGORY_CONTACT] == 2
        assert summary[CATEGORY_FINANCIAL] == 1
        assert summary[CATEGORY_GENERAL] == 1

    def test_detect_pipeline_assigns_categories(self):
        text = "Write to aisha.k@corp.com, PAN ABCDE1234F, patient has diabetes."
        categories = {d.entity_type: data_category(d) for d in detect(text)}
        assert categories["EMAIL"] == CATEGORY_CONTACT
        assert categories["PAN"] == CATEGORY_GOVERNMENT_ID
        assert categories["MEDICAL_CONDITION"] == CATEGORY_MEDICAL
