# ============================================================
# tests/test_detection.py — Unit tests for the detection engine
# ============================================================
import pytest
from app.services.detection_engine import run_regex_detection, detect, Detection
from app.services.classification import classify
from app.services.risk_scoring import calculate_risk
from app.services.sanitization import sanitize, protect_preview
from app.services.preprocessing import preprocess


# ── Fixtures ─────────────────────────────────────────────────
SAMPLE_TEXT = """
Name: Rahul Sharma
Email: rahul.sharma@example.com
Phone: +91 9876543210
Aadhaar: 1234 5678 9012
PAN: ABCDE1234F
IP Address: 192.168.1.100
DOB: 15/08/1995
API Key: api_key = sk-abcdef1234567890abcdef1234567890
Password: password = MySecret@123
"""


class TestEmailDetection:
    def test_detects_email(self):
        hits = run_regex_detection("Contact: user@example.com for details.")
        emails = [h for h in hits if h.entity_type == "EMAIL"]
        assert len(emails) == 1
        assert emails[0].matched_value == "user@example.com"

    def test_no_false_positive_on_plain_text(self):
        hits = run_regex_detection("This has no email address here.")
        emails = [h for h in hits if h.entity_type == "EMAIL"]
        assert len(emails) == 0

    def test_multiple_emails(self):
        hits = run_regex_detection("Send to a@b.com and c@d.org")
        emails = [h for h in hits if h.entity_type == "EMAIL"]
        assert len(emails) == 2


class TestPhoneDetection:
    def test_indian_mobile(self):
        hits = run_regex_detection("Call me on 9876543210")
        phones = [h for h in hits if "PHONE" in h.entity_type]
        assert len(phones) >= 1

    def test_with_country_code(self):
        hits = run_regex_detection("WhatsApp: +91-9876543210")
        phones = [h for h in hits if "PHONE" in h.entity_type]
        assert len(phones) >= 1


_AADHAAR_TYPES = ("AADHAAR", "AADHAAR_FORMAT")


class TestAadhaarDetection:
    def test_aadhaar_pattern(self):
        hits = run_regex_detection("Aadhaar: 1234 5678 9012")
        aadhaar = [h for h in hits if h.entity_type in _AADHAAR_TYPES]
        assert len(aadhaar) >= 1

    def test_aadhaar_without_spaces(self):
        hits = run_regex_detection("ID: 123456789012")
        aadhaar = [h for h in hits if h.entity_type in _AADHAAR_TYPES]
        assert len(aadhaar) >= 1

    def test_unverified_checksum_is_candidate(self):
        hits = run_regex_detection("Aadhaar: 1234 5678 9012")
        candidate = [h for h in hits if h.entity_type == "AADHAAR_FORMAT"]
        assert len(candidate) == 1
        assert not [h for h in hits if h.entity_type == "AADHAAR"]


class TestPANDetection:
    def test_pan_pattern(self):
        hits = run_regex_detection("PAN Card: ABCDE1234F")
        pan = [h for h in hits if h.entity_type == "PAN"]
        assert len(pan) == 1
        assert pan[0].matched_value == "ABCDE1234F"

    def test_lowercase_pan_not_detected(self):
        hits = run_regex_detection("not a pan: abcde1234f")
        pan = [h for h in hits if h.entity_type == "PAN"]
        assert len(pan) == 0


class TestIPDetection:
    def test_valid_ip(self):
        hits = run_regex_detection("Server at 192.168.1.100")
        ips = [h for h in hits if h.entity_type == "IP_ADDRESS"]
        assert len(ips) == 1

    def test_invalid_ip_not_detected(self):
        hits = run_regex_detection("Version 999.999.999.999")
        ips = [h for h in hits if h.entity_type == "IP_ADDRESS"]
        assert len(ips) == 0


class TestClassification:
    def test_email_is_confidential(self):
        hits = run_regex_detection("test@example.com")
        assert hits
        cls, _ = classify(hits[0])
        assert cls == "Confidential"

    def test_pan_is_restricted(self):
        hits = run_regex_detection("PAN: ABCDE1234F")
        pan_hits = [h for h in hits if h.entity_type == "PAN"]
        assert pan_hits
        cls, _ = classify(pan_hits[0])
        assert cls == "Restricted"

    def test_api_key_is_restricted(self):
        hits = run_regex_detection("api_key = sk-abc123def456ghi789jkl012")
        api_hits = [h for h in hits if h.entity_type == "API_KEY"]
        assert api_hits
        cls, _ = classify(api_hits[0])
        assert cls == "Restricted"


class TestRiskScoring:
    def test_empty_gives_zero(self):
        result = calculate_risk([])
        assert result.score == 0.0
        assert result.level == "Low Risk"

    def test_restricted_entity_raises_score(self):
        items = [{"entity_type": "PASSWORD", "privacy_class": "Restricted", "risk_points": 5.0}]
        result = calculate_risk(items)
        assert result.score > 0

    def test_score_never_exceeds_100(self):
        items = [{"entity_type": "PASSWORD", "privacy_class": "Restricted", "risk_points": 5.0}] * 100
        result = calculate_risk(items)
        assert result.score <= 100.0

    def test_score_increases_with_more_detections(self):
        few  = [{"entity_type": "EMAIL", "privacy_class": "Confidential", "risk_points": 3.0}] * 2
        many = [{"entity_type": "EMAIL", "privacy_class": "Confidential", "risk_points": 3.0}] * 10
        assert calculate_risk(many).score >= calculate_risk(few).score

    def test_risk_levels(self):
        from app.services.risk_scoring import _level
        assert _level(10)  == "Low Risk"
        assert _level(45)  == "Medium Risk"
        assert _level(75)  == "High Risk"
        assert _level(100) == "High Risk"


class TestSanitization:
    def test_email_redacted(self):
        text = "Email: user@example.com here"
        dets = [{"entity_type": "EMAIL", "matched_value": "user@example.com",
                 "start": text.index("user"), "end": text.index("user") + len("user@example.com")}]
        result = sanitize(text, dets, mode="redact")
        assert "[EMAIL_REDACTED]" in result
        assert "user@example.com" not in result

    def test_email_masked(self):
        text = "Email: user@example.com"
        dets = [{"entity_type": "EMAIL", "matched_value": "user@example.com",
                 "start": 7, "end": 7 + len("user@example.com")}]
        result = sanitize(text, dets, mode="mask")
        assert "u***@example.com" in result

    def test_no_detections_returns_original(self):
        text = "No sensitive info here."
        assert sanitize(text, []) == text

    def test_overlapping_handled(self):
        text = "Secret: api_key=abc123def456ghi789jkl012"
        dets = run_regex_detection(text)
        result = sanitize(text, [d.__dict__ for d in dets], mode="redact")
        assert result is not None   # must not crash

    def test_protect_preview_masks_email(self):
        masked = protect_preview("admin@corp.com", "EMAIL")
        assert "admin@corp.com" not in masked or masked.startswith("a***")

    def test_protect_preview_masks_phone(self):
        masked = protect_preview("9876543210", "PHONE_IN")
        assert "9876543210" not in masked


class TestPreprocessing:
    def test_normalizes_crlf(self):
        text = "line1\r\nline2\r\nline3"
        result = preprocess(text)
        assert "\r" not in result
        assert "line1" in result

    def test_removes_control_chars(self):
        text = "hello\x00world"
        result = preprocess(text)
        assert "\x00" not in result

    def test_collapses_blank_lines(self):
        text = "a\n\n\n\n\nb"
        result = preprocess(text)
        assert "\n\n\n" not in result


class TestFullPipeline:
    def test_sample_document_detection(self):
        detections = detect(SAMPLE_TEXT)
        entity_types = {d.entity_type for d in detections}
        assert "EMAIL"    in entity_types
        assert "PHONE_IN" in entity_types or "PHONE_GENERIC" in entity_types
        assert "PAN"      in entity_types

    def test_sanitization_removes_all_configured(self):
        raw   = "Email test@corp.com phone 9876543210"
        hits  = detect(raw)
        clean = sanitize(raw, [d.__dict__ for d in hits], mode="redact")
        assert "test@corp.com" not in clean
