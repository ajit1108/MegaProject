# ============================================================
# app/services/sanitization.py
# Text masking and redaction engine
# ============================================================
import re
from typing import Any


REDACT_PLACEHOLDERS: dict[str, str] = {
    "EMAIL":          "[EMAIL_REDACTED]",
    "PHONE_IN":       "[PHONE_REDACTED]",
    "PHONE_GENERIC":  "[PHONE_REDACTED]",
    "AADHAAR":        "[AADHAAR_REDACTED]",
    "PAN":            "[PAN_REDACTED]",
    "CREDIT_CARD":    "[CARD_REDACTED]",
    "IP_ADDRESS":     "[IP_REDACTED]",
    "DATE_OF_BIRTH":  "[DOB_REDACTED]",
    "API_KEY":        "[API_KEY_REDACTED]",
    "PASSWORD":       "[PASSWORD_REDACTED]",
    "PERSON_NAME":    "[PERSON_REDACTED]",
    "ORGANIZATION":   "[ORG_REDACTED]",
    "GEO_POLITICAL":  "[LOCATION_REDACTED]",
    "LOCATION":       "[LOCATION_REDACTED]",
    "FACILITY":       "[FACILITY_REDACTED]",
    "FINANCIAL_VALUE":"[FINANCIAL_REDACTED]",
    "DATE":           "[DATE_REDACTED]",
}

DEFAULT_PLACEHOLDER = "[REDACTED]"


def _mask_value(value: str, entity_type: str) -> str:
    """Produce a masked version of a sensitive value."""
    if entity_type == "EMAIL":
        parts = value.split("@")
        local = parts[0]
        domain = parts[1] if len(parts) > 1 else "example.com"
        masked_local = local[0] + "***" if len(local) > 1 else "***"
        return f"{masked_local}@{domain}"
    if entity_type in ("PHONE_IN", "PHONE_GENERIC"):
        digits = re.sub(r"\D", "", value)
        return "X" * max(0, len(digits) - 4) + digits[-4:] if len(digits) >= 4 else "XXXX"
    if entity_type in ("AADHAAR",):
        digits = re.sub(r"\D", "", value)
        return "XXXX-XXXX-" + digits[-4:] if len(digits) >= 4 else "XXXX-XXXX-XXXX"
    if entity_type == "PAN":
        return value[:2] + "***" + value[-2:] if len(value) >= 4 else "***"
    if entity_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        return "*" * max(0, len(digits) - 4) + digits[-4:]
    # Default: show first char and last char, mask middle
    if len(value) <= 3:
        return "***"
    return value[0] + "*" * (len(value) - 2) + value[-1]


def sanitize(text: str, detections: list[dict[str, Any]], mode: str = "redact") -> str:
    """
    Replace sensitive spans in text using verified offset positions.

    Strategy:
    1. Filter out overlapping/duplicate detection spans (preferring longer spans).
    2. Process replacements from right to left (highest end offset first)
       so that earlier offsets remain valid after each replacement.

    Args:
        text: original extracted text
        detections: list of dicts with keys: start, end, entity_type, matched_value
        mode: "redact" -> placeholder | "mask" -> partial masking
    """
    if not detections:
        return text

    # Sort by start ASC, confidence DESC (prefer specific high-confidence match), span length DESC
    sorted_by_span = sorted(
        detections,
        key=lambda d: (d.get("start", 0), -d.get("confidence", 0.5), -(d.get("end", 0) - d.get("start", 0)))
    )
    non_overlapping = []
    last_end = -1
    for det in sorted_by_span:
        s = det.get("start", 0)
        e = det.get("end", 0)
        if s >= last_end and e > s:
            non_overlapping.append(det)
            last_end = e

    # Sort non-overlapping by end offset descending (right-to-left replacement)
    sorted_detections = sorted(non_overlapping, key=lambda d: d["end"], reverse=True)

    result = text
    for det in sorted_detections:
        start = det.get("start", 0)
        end   = det.get("end", 0)
        etype = det.get("entity_type", "UNKNOWN")

        if start < 0 or end <= start or end > len(result):
            continue   # skip invalid spans

        if mode == "mask":
            replacement = _mask_value(det.get("matched_value", ""), etype)
        else:
            replacement = REDACT_PLACEHOLDERS.get(etype, DEFAULT_PLACEHOLDER)

        result = result[:start] + replacement + result[end:]

    return result


def protect_preview(value: str, entity_type: str) -> str:
    """Return a masked preview safe to display in the UI (never the raw value)."""
    return _mask_value(value, entity_type)
