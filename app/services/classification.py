# ============================================================
# app/services/classification.py
# Privacy classification of detected entities
# ============================================================
from app.services.detection_engine import Detection

# ── Classification rules ──────────────────────────────────────
# Maps entity_type → (privacy_class, reason)
# Classes: "Public" | "Internal" | "Confidential" | "Restricted"
CLASSIFICATION_RULES: dict[str, tuple[str, str]] = {
    # Restricted — highest protection
    "AADHAAR":          ("Restricted",    "Aadhaar-pattern number — government identifier requiring maximum protection."),
    "PAN":              ("Restricted",    "PAN-pattern number — government tax identifier requiring maximum protection."),
    "CREDIT_CARD":      ("Restricted",    "Payment card number candidate — financial data requiring maximum protection."),
    "API_KEY":          ("Restricted",    "API key or token — credential that could enable unauthorized system access."),
    "PASSWORD":         ("Restricted",    "Password-like string — credential requiring maximum protection."),

    # Confidential — significant risk if disclosed
    "EMAIL":            ("Confidential",  "Email address — personal contact information."),
    "PHONE_IN":         ("Confidential",  "Indian mobile number — personal contact information."),
    "PHONE_GENERIC":    ("Confidential",  "Phone number — personal contact information."),
    "IP_ADDRESS":       ("Confidential",  "IP address — may identify a device or network location."),
    "DATE_OF_BIRTH":    ("Confidential",  "Date of birth — personal identifier that can enable identity fraud."),
    "PERSON_NAME":      ("Confidential",  "Detected person name — personally identifiable information."),
    "FINANCIAL_VALUE":  ("Confidential",  "Financial value — may expose financial information."),

    # Internal — moderate sensitivity
    "ORGANIZATION":     ("Internal",      "Organisation name — internal business information."),
    "GEO_POLITICAL":    ("Internal",      "Geographic entity — may indicate location of persons or assets."),
    "LOCATION":         ("Internal",      "Location entity — internal geographic reference."),
    "FACILITY":         ("Internal",      "Facility name — internal reference."),

    # Public — lowest sensitivity
    "DATE":             ("Public",        "General date reference — typically low sensitivity."),
}

DEFAULT_CLASSIFICATION = ("Internal", "Entity matched a detection pattern; context-specific classification applied.")


def classify(detection: Detection) -> tuple[str, str]:
    """
    Return (privacy_class, reason) for a detection.
    Falls back to DEFAULT_CLASSIFICATION for unknown entity types.
    """
    return CLASSIFICATION_RULES.get(detection.entity_type, DEFAULT_CLASSIFICATION)


# Risk points per privacy class (used by risk_scoring.py)
CLASS_RISK_POINTS: dict[str, float] = {
    "Restricted":   5.0,
    "Confidential": 3.0,
    "Internal":     1.0,
    "Public":       0.0,
}


def class_risk_points(privacy_class: str) -> float:
    return CLASS_RISK_POINTS.get(privacy_class, 1.0)
