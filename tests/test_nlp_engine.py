# ============================================================
# tests/test_nlp_engine.py
# Tests for the hybrid NLP detection engine:
#   - every sensitive entity family, Indian formats
#   - contextual sentences and false-positive traps
#   - offset integrity after normalisation
#   - confidence-aware, duplicate-safe risk scoring
#   - end-to-end upload -> analyse -> sanitize -> download
# ============================================================
import io
import os
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.database import get_db, connect_db
from app.security.authentication import create_access_token
from app.services.classification import classify
from app.services.detection_engine import Detection, detect
from app.services.preprocessing import preprocess, preprocess_with_offsets
from app.services.risk_scoring import calculate_risk, _level
from app.services.sanitization import protect_preview, sanitize
from app.routes.analysis import _masked_text_preview

client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def init_db():
    try:
        connect_db()
    except Exception:
        pass
    yield


def spans(text: str) -> list[Detection]:
    return detect(text)


def types(text: str) -> set[str]:
    return {d.entity_type for d in spans(text)}


def find(text: str, entity_type: str) -> list[str]:
    return [d.matched_value for d in spans(text) if d.entity_type == entity_type]


# ── Contextual sentences from the specification ─────────────
class TestContextualSentences:
    def test_my_name_is(self):
        found = find("My name is Ajit Birajdar.", "PERSON_NAME")
        assert "Ajit Birajdar" in found

    def test_contact_email(self):
        assert find("Contact me at ajit@example.com.", "EMAIL") == ["ajit@example.com"]

    def test_aadhaar_sentence(self):
        assert find("My Aadhaar number is 2345 6789 0124.", "AADHAAR") == ["2345 6789 0124"]

    def test_bank_account_mention_without_number(self):
        assert "BANK_ACCOUNT" not in types("My bank account number is mentioned below.")

    def test_date_of_birth(self):
        assert find("Date of birth: 12/05/2003.", "DATE_OF_BIRTH") == ["12/05/2003"]

    def test_registered_mobile(self):
        assert find("My registered mobile number is 9876543210.", "PHONE_IN") == ["9876543210"]

    def test_patient_has_diabetes(self):
        assert find("The patient has diabetes.", "MEDICAL_CONDITION") == ["diabetes"]

    def test_employee_salary(self):
        assert find("The employee receives a monthly salary of 45000.", "FINANCIAL_VALUE") == ["45000"]

    def test_ordinary_numbers_not_flagged(self):
        assert types("There are 12 items in 2024 and 3 boxes on the shelf.") == set()

    def test_joining_date_not_dob(self):
        assert "DATE_OF_BIRTH" not in types("Joining Date: 01/04/2021")


# ── Label-independent detection (no field label required) ───
class TestLabelIndependentDetection:
    @pytest.mark.parametrize("text", [
        "Ajit Birajdar is developing a project.",
        "My friend Ajit Birajdar visited Kolhapur.",
        "Ajit Birajdar is studying computer science.",
        "My friend is named Sneha Patil.",
        "Rahul Sharma works at the company.",
        "Priya visited Mumbai yesterday.",
    ])
    def test_person_names_in_sentences(self, text):
        found = find(text, "PERSON_NAME")
        assert found, f"no person detected in {text!r}"

    def test_person_offset_exact(self):
        text = "Ajit Birajdar is developing a project."
        det = next(d for d in spans(text) if d.entity_type == "PERSON_NAME")
        assert text[det.start:det.end] == det.matched_value == "Ajit Birajdar"

    @pytest.mark.parametrize("text", [
        "Contact me at ajit@example.com.",
        "Send the report to ajit@example.com tomorrow.",
        "Mail ajit@example.com for details.",
    ])
    def test_email_anywhere(self, text):
        assert find(text, "EMAIL") == ["ajit@example.com"]

    @pytest.mark.parametrize("value", [
        "+91 9876543210", "9876543210", "09876543210",
        "+91-98765-43210", "+91 98765 43210",
    ])
    def test_phone_anywhere(self, value):
        assert value in find(f"Call me on {value}.", "PHONE_IN")

    @pytest.mark.parametrize("text, expected", [
        ("I live at 123 MG Road, Kolhapur.", "123 MG Road, Kolhapur"),
        ("She stays in Shivaji Nagar, Pune.", "Shivaji Nagar, Pune"),
        ("The office is located near Rankala Lake, Kolhapur.", "Rankala Lake, Kolhapur"),
    ])
    def test_address_in_sentence(self, text, expected):
        assert find(text, "ADDRESS") == [expected]

    def test_address_offsets_exact(self):
        text = "I live at 123 MG Road, Kolhapur."
        det = next(d for d in spans(text) if d.entity_type == "ADDRESS")
        assert text[det.start:det.end] == "123 MG Road, Kolhapur"

    @pytest.mark.parametrize("text, expected", [
        ("I was born on 12 May 2003.", "12 May 2003"),
        ("I was born 12 May 2003.", "12 May 2003"),
        ("Her birthday is 15/08/2001.", "15/08/2001"),
        ("Her birthday is 2001-08-15.", "2001-08-15"),
    ])
    def test_dob_without_label(self, text, expected):
        assert find(text, "DATE_OF_BIRTH") == [expected]

    def test_medical_paragraph(self):
        text = "The patient has diabetes and hypertension."
        assert find(text, "MEDICAL_CONDITION") == ["diabetes", "hypertension"]

    def test_medical_treatment_sentence(self):
        assert find("He is receiving treatment for cancer.", "MEDICAL_CONDITION") == ["cancer"]

    def test_financial_in_sentence(self):
        assert find("The employee earns 45000 per month.", "FINANCIAL_VALUE") == ["45000"]
        assert find("Her account balance is 50000.", "FINANCIAL_VALUE") == ["50000"]

    def test_person_and_org_without_labels(self):
        text = "Ajit works at ABC Technologies."
        assert "Ajit" in find(text, "PERSON_NAME")
        assert find(text, "ORGANIZATION") == ["ABC Technologies"]

    def test_location_with_locative_grammar(self):
        text = "Ajit lives in Kolhapur Maharashtra."
        assert "Ajit" in find(text, "PERSON_NAME")
        assert find(text, "LOCATION") == ["Kolhapur", "Maharashtra"]

    def test_aadhaar_sentence_invalid_checksum_but_cued(self):
        assert find("My Aadhaar number is 1234 5678 9012.", "AADHAAR_FORMAT") == ["1234 5678 9012"]

    @pytest.mark.parametrize("text", [
        "There are 12 items in 2024 and 3 boxes on the shelf.",
        "My name is not important. The Patient Report is confidential.",
        "The agreement was signed on 12/05/2023.",
        "Order number 1234 5678 9012 was shipped.",
        "Toll free: 1800-123-4567.",
        "Invoice number 4500 was paid in 2023.",
    ])
    def test_negative_sentences_stay_clean(self, text):
        assert spans(text) == [], [(d.entity_type, d.matched_value) for d in spans(text)]

    def test_unlabelled_values_are_sanitized(self):
        text = "I live at 123 MG Road, Kolhapur and my email is ajit@example.com."
        detections = [d.to_dict() for d in spans(text)]
        cleaned = sanitize(text, detections, mode="redact")
        assert "123 MG Road, Kolhapur" not in cleaned
        assert "ajit@example.com" not in cleaned
        assert "[ADDRESS_REDACTED]" in cleaned
        assert "[EMAIL_REDACTED]" in cleaned

    def test_masked_preview_keeps_offsets_for_highlighting(self):
        text = "I live at 123 MG Road, Kolhapur and my email is ajit@example.com."
        detections = [d.to_dict() for d in spans(text)]
        preview = _masked_text_preview(text, detections)
        assert len(preview) == len(text)
        assert "ajit@example.com" not in preview
        assert "Kolhapur" not in preview
        for det in detections:
            fragment = preview[det["start"]:det["end"]]
            assert set(fragment) <= {"*", " "}, fragment

    def test_detection_is_separate_from_classification(self):
        text = "Ajit works at ABC Technologies."
        dets = spans(text)
        person = next(d for d in dets if d.entity_type == "PERSON_NAME")
        org = next(d for d in dets if d.entity_type == "ORGANIZATION")
        assert classify(person)[0] == "Confidential"
        assert classify(org)[0] == "Internal"


# ── Label-free numeric identifiers ──────────────────────────
class TestUnlabelledNumericIdentifiers:
    @pytest.mark.parametrize("text, expected", [
        ("9876543210", "9876543210"),
        ("Call me on 9876543210.", "9876543210"),
        ("Call me tomorrow on 9876543210.", "9876543210"),
        ("My contact is +91 9876543210.", "+91 9876543210"),
        ("Number: 9876543210", "9876543210"),
        ("Reach me at +91-98765-43210.", "+91-98765-43210"),
        ("My number is 09876543210.", "09876543210"),
        ("+919876543210", "+919876543210"),
        ("98765-43210", "98765-43210"),
    ])
    def test_mobile_without_keywords(self, text, expected):
        assert expected in find(text, "PHONE_IN")
        # A "+91" country-code number is a phone digits run, never an Aadhaar candidate
        assert "AADHAAR_FORMAT" not in types(text)
        assert "AADHAAR" not in types(text)

    def test_mobile_offsets_exact(self):
        text = "Call me tomorrow on 9876543210."
        det = next(d for d in spans(text) if d.entity_type == "PHONE_IN")
        assert text[det.start:det.end] == det.matched_value == "9876543210"

    @pytest.mark.parametrize("text", [
        "1234567890",        # does not start 6-9
        "5876543210",        # invalid Indian mobile prefix
        "98765432",          # too short
        "98765432101",       # too long
        "ID 98765432101",
        "ABC9876543210",     # embedded in an alphanumeric identifier
        "Date 12/05/2003",
        "Order 4500 was paid in 2023.",
    ])
    def test_invalid_mobile_structures_rejected(self, text):
        assert "PHONE_IN" not in types(text)

    @pytest.mark.parametrize("text, expected", [
        ("123456789012", "123456789012"),
        ("1234 5678 9012", "1234 5678 9012"),
        ("1234-5678-9012", "1234-5678-9012"),
        ("ID: 1234 5678 9012", "1234 5678 9012"),
        ("My ID is 1234 5678 9012.", "1234 5678 9012"),
        ("The document contains 123456789012.", "123456789012"),
    ])
    def test_aadhaar_candidates_without_keywords(self, text, expected):
        assert expected in find(text, "AADHAAR_FORMAT")

    def test_valid_checksum_stays_verified_aadhaar(self):
        text = "2345 6789 0124"
        assert find(text, "AADHAAR") == ["2345 6789 0124"]
        assert find(text, "AADHAAR_FORMAT") == []

    def test_unverified_checksum_is_candidate_not_verified(self):
        text = "The document contains 123456789012."
        det = next(d for d in spans(text) if d.entity_type.startswith("AADHAAR"))
        assert det.entity_type == "AADHAAR_FORMAT"
        assert det.confidence < 0.9
        assert classify(det)[0] == "Confidential"

    @pytest.mark.parametrize("text", [
        "1234567890123",                       # 13 digits
        "9123456789012",                       # 13 digits
        "ABC123456789012",                     # embedded in identifier
        "Order number 1234 5678 9012 was shipped.",
        "Invoice 1234-5678-9012.",
    ])
    def test_aadhaar_negative_cases(self, text):
        assert "AADHAAR" not in types(text)
        assert "AADHAAR_FORMAT" not in types(text)

    def test_label_on_previous_line_does_not_rescue_reference_number(self):
        text = "Aadhaar: 2345 6789 0124\nOrder number 1234 5678 9012 was shipped."
        aadhaar = [d for d in spans(text) if d.entity_type.startswith("AADHAAR")]
        assert [d.matched_value for d in aadhaar] == ["2345 6789 0124"]

    def test_repeated_numbers_keep_their_own_offsets(self):
        text = "Repeated 9876543210 and 9876543210."
        dets = [d for d in spans(text) if d.entity_type == "PHONE_IN"]
        assert len(dets) == 2
        assert len({(d.start, d.end) for d in dets}) == 2
        assert all(text[d.start:d.end] == d.matched_value for d in dets)

    def test_candidate_contributes_to_risk(self):
        text = "The document contains 123456789012."
        enriched = []
        for det in spans(text):
            privacy_class, reason = classify(det)
            enriched.append({
                **det.to_dict(),
                "privacy_class": privacy_class,
                "classification_reason": reason,
            })
        result = calculate_risk(enriched)
        assert result.score > 0
        assert result.class_counts.get("Confidential") == 1

    def test_candidate_is_sanitized(self):
        text = "The document contains 1234 5678 9012 tomorrow."
        detections = [d.to_dict() for d in spans(text)]
        cleaned = sanitize(text, detections, mode="redact")
        assert "1234 5678 9012" not in cleaned
        assert "[AADHAAR_REDACTED]" in cleaned


# ── Structured identifiers ──────────────────────────────────
class TestIdentifiers:
    @pytest.mark.parametrize("value", [
        "9876543210", "+91 98765 43210", "+91-98765-43210", "09876543210",
    ])
    def test_indian_mobiles(self, value):
        assert "PHONE_IN" in types(f"Call me on {value} today.")

    @pytest.mark.parametrize("value", ["(020) 2456 7890", "020-24567890", "+1 (415) 555-0132"])
    def test_non_mobile_phones(self, value):
        assert "PHONE_GENERIC" in types(f"Desk: {value}.")

    def test_toll_free_not_flagged(self):
        assert "PHONE_GENERIC" not in types("Toll free: 1800-123-4567")

    def test_valid_aadhaar_without_context(self):
        assert find("Reference 2345 6789 0124 on file.", "AADHAAR") == ["2345 6789 0124"]

    def test_invalid_aadhaar_without_context(self):
        assert "AADHAAR" not in types("Order number 1234 5678 9012 was shipped.")

    def test_invalid_aadhaar_with_context(self):
        assert "AADHAAR_FORMAT" in types("Aadhaar: 1234 5678 9012")

    def test_ungrouped_aadhaar(self):
        assert find("Aadhaar: 234567890124", "AADHAAR") == ["234567890124"]

    def test_pan(self):
        assert find("PAN Card: ABCDE1234F", "PAN") == ["ABCDE1234F"]

    def test_lowercase_pan_rejected(self):
        assert "PAN" not in types("not a pan: abcde1234f")

    def test_placeholder_pan_rejected(self):
        assert "PAN" not in types("The PAN format is AAAAA9999A.")

    def test_gstin_suppresses_embedded_pan(self):
        found_types = types("GSTIN: 27AAPFU0939F1ZV")
        assert "GSTIN" in found_types
        assert "PAN" not in found_types

    def test_passport(self):
        assert find("Passport No: M1234567", "PASSPORT") == ["M1234567"]

    def test_ifsc(self):
        assert find("IFSC Code: HDFC0001234", "IFSC") == ["HDFC0001234"]

    def test_invalid_ifsc_rejected(self):
        assert "IFSC" not in types("Code HDFC1001234 is not an IFSC.")

    def test_voter_and_licence(self):
        text = "Voter ID: ABC1234567\nDriving Licence: MH12 20150012345"
        found = types(text)
        assert "VOTER_ID" in found and "DRIVERS_LICENSE" in found

    def test_bank_account_context(self):
        assert find("Account Number: 1234567890123", "BANK_ACCOUNT") == ["1234567890123"]

    def test_bank_account_placeholder_rejected(self):
        assert "BANK_ACCOUNT" not in types("Sample account number 0000 0000 0000 is printed.")

    def test_credit_card_luhn(self):
        assert find("Card Number: 4111 1111 1111 1111", "CREDIT_CARD") == ["4111 1111 1111 1111"]
        assert find("Corporate card: 3782 822463 10005", "CREDIT_CARD") == ["3782 822463 10005"]

    def test_invalid_card_rejected(self):
        assert "CREDIT_CARD" not in types("Card Number: 4111 1111 1111 1112")

    def test_upi_and_username(self):
        text = "Username: ajit_b95\nUPI ID: ajit.birajdar@okhdfcbank"
        found = types(text)
        assert "USERNAME" in found and "UPI_ID" in found

    def test_ip_and_version(self):
        text = "Client IP: 203.0.113.77\nBuild version 1.2.3.4 deployed."
        assert find(text, "IP_ADDRESS") == ["203.0.113.77"]

    def test_pincode(self):
        assert find("PIN Code: 500034", "PIN_CODE") == ["500034"]

    def test_pin_code_invalid(self):
        assert "PIN_CODE" not in types("PIN Code: 012345")


# ── Dates, addresses, organisations, people ─────────────────
class TestContextualEntities:
    @pytest.mark.parametrize("value", ["15/08/1995", "15-08-1995", "2003-05-12", "12 May 2003"])
    def test_dob_formats(self, value):
        assert find(f"Date of Birth: {value}", "DATE_OF_BIRTH") == [value]

    def test_invalid_dob_rejected(self):
        assert "DATE_OF_BIRTH" not in types("Date of Birth: 31/02/1995")

    def test_multiline_address(self):
        text = (
            "Shipping Address:\n"
            "Flat 7, Green Park Society\n"
            "Andheri West, Mumbai\n"
            "Maharashtra 400053\n"
        )
        expected = "Flat 7, Green Park Society\nAndheri West, Mumbai\nMaharashtra 400053"
        assert find(text, "ADDRESS") == [expected]

    def test_address_does_not_swallow_next_field(self):
        text = "Address: 101, Lake View Residency, Pune 411045\nDate of Birth: 03/11/1988"
        assert find(text, "ADDRESS") == ["101, Lake View Residency, Pune 411045"]
        assert find(text, "DATE_OF_BIRTH") == ["03/11/1988"]

    def test_known_and_suffixed_orgs(self):
        found = find("Infosys Limited and Adani Enterprises filed the report.", "ORGANIZATION")
        assert "Infosys Limited" in found
        assert "Adani Enterprises" in found

    def test_medical_label_is_not_organisation(self):
        found = types("Blood Group: O+")
        assert "BLOOD_GROUP" in found
        assert "ORGANIZATION" not in found

    def test_labelled_and_gazetteer_names(self):
        assert "Ajit Birajdar" in find("Name: Ajit Birajdar", "PERSON_NAME")
        assert "Ananya Deshpande" in find("Dr. Ananya Deshpande reviewed the case.", "PERSON_NAME")
        assert "Rajeshwari Krishnamurthy" in find("Regards,\nRajeshwari Krishnamurthy", "PERSON_NAME")

    def test_international_names(self):
        found = find("John Smith met Maria Gonzalez and Zhang Wei.", "PERSON_NAME")
        assert {"John Smith", "Maria Gonzalez", "Zhang Wei"} <= set(found)

    def test_names_in_address_not_emitted(self):
        text = "Address: 101, Lake View Residency, Baner Road, Pune 411045"
        assert "PERSON_NAME" not in types(text)

    def test_capitalised_non_names_rejected(self):
        assert "PERSON_NAME" not in types("My name is not important. The Patient Report is confidential.")

    def test_location_requires_context(self):
        assert find("She is a resident of Nagpur.", "LOCATION") == ["Nagpur"]
        assert "LOCATION" not in types("Nagpur is a large city in India.")


# ── Medical and financial context ───────────────────────────
class TestMedicalFinancial:
    def test_clinical_note(self):
        text = (
            "Patient Name: Meera Joshi\n"
            "Diagnosis: Type 2 Diabetes Mellitus\n"
            "Prescription: Metformin 500 mg twice daily\n"
            "Blood Group: O+\n"
        )
        found = types(text)
        assert "MEDICAL_CONDITION" in found
        assert "MEDICATION" in found
        assert "BLOOD_GROUP" in found

    def test_financial_formats(self):
        text = "Annual CTC: INR 12,50,000\nClaim Amount: Rs. 2,50,000"
        assert find(text, "FINANCIAL_VALUE") == ["INR 12,50,000", "Rs. 2,50,000"]

    def test_general_mention_of_disease_not_flagged(self):
        assert "MEDICAL_CONDITION" not in types("Cancer research funding increased this year.")


# ── Offsets, preprocessing, sanitisation ────────────────────
class TestOffsetIntegrity:
    def test_offsets_address_original_text(self):
        raw = (
            "Name:\u00a0Ajit Birajdar\r\n"
            "Email: ajit.birajdar@example.com\r\n"
            "\r\n\r\n"
            "Aadhaar: 2345 6789 0124"
        )
        detections = spans(raw)
        assert detections
        for det in detections:
            assert raw[det.start:det.end] == det.matched_value
        assert any(d.entity_type == "EMAIL" for d in detections)

    def test_preprocess_offset_map(self):
        raw = "a\r\nb\x00c\u00a0d\n\n\n\ne"
        clean, offsets = preprocess_with_offsets(raw)
        assert len(clean) == len(offsets)
        assert offsets == sorted(offsets)
        assert "\r" not in clean and "\x00" not in clean
        assert "\n\n\n" not in clean
        for i, original_index in enumerate(offsets):
            if clean[i] not in (" ", "\n"):
                assert clean[i] == raw[original_index]

    def test_preprocess_contract_unchanged(self):
        assert "\r" not in preprocess("x\r\ny")
        assert "\x00" not in preprocess("x\x00y")
        assert "\n\n\n" not in preprocess("a\n\n\n\nb")

    def test_sanitize_uses_mapped_offsets(self):
        raw = "Name:\u00a0Ajit Birajdar\r\nAadhaar: 2345 6789 0124"
        detections = [d.to_dict() for d in spans(raw)]
        cleaned = sanitize(raw, detections, mode="redact")
        assert "Ajit Birajdar" not in cleaned
        assert "2345 6789 0124" not in cleaned
        assert "[PERSON_REDACTED]" in cleaned
        assert "[AADHAAR_REDACTED]" in cleaned

    def test_new_entity_placeholders(self):
        text = "Account Number: 1234567890123"
        detections = [d.to_dict() for d in spans(text)]
        cleaned = sanitize(text, detections, mode="redact")
        assert "1234567890123" not in cleaned
        assert "[ACCOUNT_REDACTED]" in cleaned

    def test_preview_never_leaks_full_values(self):
        assert "1234567890123" not in protect_preview("1234567890123", "BANK_ACCOUNT")
        assert "2345 6789 0124" not in protect_preview("2345 6789 0124", "AADHAAR")
        assert protect_preview("diabetes", "MEDICAL_CONDITION") == "***"

    def test_long_document_not_truncated(self):
        filler = "The quarterly report contains general information. " * 2400
        text = filler + "\nSigned by Barack Obama."
        assert len(text) > 110_000
        assert "Barack Obama" in find(text, "PERSON_NAME")


# ── Risk scoring and classification ─────────────────────────
class TestRiskScoring:
    def test_duplicates_do_not_inflate(self):
        single = [{"entity_type": "PAN", "privacy_class": "Restricted",
                   "matched_value": "ABCDE1234F", "confidence": 1.0}]
        duplicate = single * 5
        assert calculate_risk(duplicate).score == calculate_risk(single).score

    def test_confidence_lowers_contribution(self):
        high = [{"entity_type": "PAN", "privacy_class": "Restricted",
                 "matched_value": "ABCDE1234F", "confidence": 1.0}]
        low = [{"entity_type": "PAN", "privacy_class": "Restricted",
                "matched_value": "ABCDE1234F", "confidence": 0.2}]
        assert calculate_risk(low).score < calculate_risk(high).score

    def test_score_bounds_and_levels(self):
        items = [{"entity_type": "PASSWORD", "privacy_class": "Restricted",
                  "matched_value": f"secret-{i}", "confidence": 1.0} for i in range(200)]
        result = calculate_risk(items)
        assert 0 <= result.score <= 100
        # Per-type diminishing returns are documented: many values of ONE type
        # add less than the same count spread across several types.
        assert result.level == _level(result.score)
        assert result.score > calculate_risk(items[:1]).score

        mixed = [
            {"entity_type": t, "privacy_class": "Restricted",
             "matched_value": f"{t}-value", "confidence": 1.0}
            for t in ("AADHAAR", "PAN", "PASSPORT", "GSTIN", "BANK_ACCOUNT",
                      "CREDIT_CARD", "API_KEY", "PASSWORD")
        ]
        assert calculate_risk(mixed).level == "High Risk"
        assert _level(10) == "Low Risk"
        assert _level(45) == "Medium Risk"
        assert _level(75) == "High Risk"
        assert calculate_risk([]).score == 0.0

    def test_distinct_values_still_add(self):
        one = [{"entity_type": "EMAIL", "privacy_class": "Confidential",
                "matched_value": "a@b.com", "confidence": 1.0}]
        two = one + [{"entity_type": "EMAIL", "privacy_class": "Confidential",
                      "matched_value": "c@d.com", "confidence": 1.0}]
        assert calculate_risk(two).score > calculate_risk(one).score

    def test_new_types_classified(self):
        for entity_type, expected in [
            ("PASSPORT", "Restricted"),
            ("BANK_ACCOUNT", "Restricted"),
            ("GSTIN", "Restricted"),
            ("ADDRESS", "Confidential"),
            ("MEDICAL_CONDITION", "Confidential"),
            ("UPI_ID", "Confidential"),
            ("USERNAME", "Confidential"),
        ]:
            det = Detection(entity_type, "x", 0, 1, "regex")
            assert classify(det)[0] == expected


# ── End-to-end API pipeline ─────────────────────────────────
class TestAPIPipeline:
    def test_upload_analyse_sanitize_download(self):
        db = get_db()
        user_id = db.users.insert_one({
            "email": f"nlp_test_{ObjectId()}@example.com",
            "password_hash": "x",
            "role": "analyst",
        }).inserted_id
        token = create_access_token(data={"sub": str(user_id)})
        headers = {"Authorization": f"Bearer {token}"}

        content = (
            "KYC Form\n"
            "Name: Ravi Deshmukh\n"
            "Email: ravi.deshmukh@example.com\n"
            "Mobile: 9876543210\n"
            "Aadhaar: 2345 6789 0124\n"
            "PAN: ABCDE1234F\n"
            "Salary: INR 12,50,000\n"
        ).encode("utf-8")

        doc_id = analysis_id = None
        try:
            upload = client.post(
                "/api/documents/upload",
                headers=headers,
                files={"file": ("nlp_pipeline_case.txt", content, "text/plain")},
            )
            assert upload.status_code == 201, upload.text
            doc_id = upload.json()["id"]

            analyzed = client.post(f"/api/analysis/analyze/{doc_id}", headers=headers)
            assert analyzed.status_code == 200, analyzed.text
            body = analyzed.json()
            analysis_id = body["id"]

            found_types = {d["entity_type"] for d in body["detections"]}
            assert {"PERSON_NAME", "EMAIL", "PHONE_IN", "AADHAAR", "PAN",
                    "FINANCIAL_VALUE"} <= found_types
            assert "ravi.deshmukh@example.com" not in analyzed.text

            # Stored spans must address the stored raw text exactly.
            stored = db.analyses.find_one({"_id": ObjectId(analysis_id)})
            raw = stored["extracted_text"]
            for det in stored["detections"]:
                assert raw[det["start"]:det["end"]] == det["matched_value"]

            sanitized = client.post(f"/api/analysis/{analysis_id}/sanitize", headers=headers)
            assert sanitized.status_code == 200, sanitized.text
            clean = sanitized.json()["sanitized_text"]
            for secret in ("ravi.deshmukh@example.com", "9876543210",
                           "2345 6789 0124", "ABCDE1234F"):
                assert secret not in clean
            assert sanitized.json()["remaining_detections"] == 0

            download = client.get(
                f"/api/analysis/{analysis_id}/sanitized-download", headers=headers
            )
            assert download.status_code == 200
            assert b"ravi.deshmukh@example.com" not in download.content
            assert b"ABCDE1234F" not in download.content

            refreshed = client.get(f"/api/analysis/{analysis_id}", headers=headers)
            assert refreshed.status_code == 200
            assert len(refreshed.json()["detections"]) == len(stored["detections"])
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
                db.audit_logs.delete_many({"document_id": doc_id})
                if analysis_id:
                    db.audit_logs.delete_many({"analysis_id": analysis_id})
            db.users.delete_one({"_id": user_id})

    def test_unlabelled_phone_and_aadhaar_candidate_round_trip(self):
        db = get_db()
        user_id = db.users.insert_one({
            "email": f"nlp_unlabelled_{ObjectId()}@example.com",
            "password_hash": "x",
            "role": "analyst",
        }).inserted_id
        token = create_access_token(data={"sub": str(user_id)})
        headers = {"Authorization": f"Bearer {token}"}

        content = (
            "Quick note\n"
            "We met yesterday. You can reach me on 98765-43210 anytime.\n"
            "Keep 1234 5678 9012 on record.\n"
            "Write to meera.k@example.org when free.\n"
        ).encode("utf-8")

        doc_id = analysis_id = None
        try:
            upload = client.post(
                "/api/documents/upload",
                headers=headers,
                files={"file": ("unlabelled_note.txt", content, "text/plain")},
            )
            assert upload.status_code == 201, upload.text
            doc_id = upload.json()["id"]

            analyzed = client.post(f"/api/analysis/analyze/{doc_id}", headers=headers)
            assert analyzed.status_code == 200, analyzed.text
            body = analyzed.json()
            analysis_id = body["id"]

            by_type = {d["entity_type"]: d for d in body["detections"]}
            assert {"PHONE_IN", "AADHAAR_FORMAT", "EMAIL"} <= set(by_type)
            candidate = by_type["AADHAAR_FORMAT"]
            # API responses expose only protected previews, never raw identifiers.
            assert candidate["matched_value"].endswith("9012")
            assert "1234" not in candidate["matched_value"]
            assert candidate["privacy_class"] == "Confidential"
            assert by_type["PHONE_IN"]["privacy_class"] == "Confidential"
            assert candidate["category"] == "Government Identification"
            assert by_type["PHONE_IN"]["category"] == "Contact Information"
            assert set(body["category_summary"]) <= {
                "Personal Identification", "Contact Information", "Financial Information",
                "Medical Information", "Government Identification", "Employment Information",
                "Business Confidential", "Credentials", "Location Information", "General",
            }
            assert sum(body["category_summary"].values()) == body["total_detections"]

            stored = db.analyses.find_one({"_id": ObjectId(analysis_id)})
            raw = stored["extracted_text"]
            for det in stored["detections"]:
                assert raw[det["start"]:det["end"]] == det["matched_value"]

            # Preview stays length-preserving and non-revealing for the frontend.
            preview = body["extracted_text_preview"]
            assert len(preview) == min(500, len(raw))
            for secret in ("98765-43210", "1234 5678 9012", "meera.k@example.org"):
                assert secret not in preview

            sanitized = client.post(f"/api/analysis/{analysis_id}/sanitize", headers=headers)
            assert sanitized.status_code == 200, sanitized.text
            clean = sanitized.json()["sanitized_text"]
            for secret in ("98765-43210", "1234 5678 9012", "meera.k@example.org"):
                assert secret not in clean
            assert sanitized.json()["remaining_detections"] == 0

            download = client.get(
                f"/api/analysis/{analysis_id}/sanitized-download", headers=headers
            )
            assert download.status_code == 200
            assert b"98765-43210" not in download.content
            assert b"1234 5678 9012" not in download.content
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
                db.audit_logs.delete_many({"document_id": doc_id})
                if analysis_id:
                    db.audit_logs.delete_many({"analysis_id": analysis_id})
            db.users.delete_one({"_id": user_id})
