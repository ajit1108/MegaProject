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
    "AADHAAR_FORMAT":   ("Confidential",  "12-digit Aadhaar-format candidate — checksum could not be verified."),
    "PAN":              ("Restricted",    "PAN-pattern number — government tax identifier requiring maximum protection."),
    "PASSPORT":         ("Restricted",    "Passport number — government travel identifier requiring maximum protection."),
    "GSTIN":            ("Restricted",    "GSTIN — business tax registration identifier."),
    "CREDIT_CARD":      ("Restricted",    "Payment card number — financial data requiring maximum protection."),
    "BANK_ACCOUNT":     ("Restricted",    "Bank account number — financial data requiring maximum protection."),
    "API_KEY":          ("Restricted",    "API key or token — credential that could enable unauthorized system access."),
    "PASSWORD":         ("Restricted",    "Password-like string — credential requiring maximum protection."),

    # Confidential — significant risk if disclosed
    "EMAIL":            ("Confidential",  "Email address — personal contact information."),
    "PHONE_IN":         ("Confidential",  "Indian mobile number — personal contact information."),
    "PHONE_GENERIC":    ("Confidential",  "Phone number — personal contact information."),
    "IP_ADDRESS":       ("Confidential",  "IP address — may identify a device or network location."),
    "DATE_OF_BIRTH":    ("Confidential",  "Date of birth — personal identifier that can enable identity fraud."),
    "PERSON_NAME":      ("Confidential",  "Detected person name — personally identifiable information."),
    "ADDRESS":          ("Confidential",  "Physical address — personally identifiable location information."),
    "PIN_CODE":         ("Confidential",  "Postal PIN code linked to a person or account."),
    "IFSC":             ("Confidential",  "IFSC bank branch code — financial identifier."),
    "UPI_ID":           ("Confidential",  "UPI payment handle — financial identifier."),
    "VOTER_ID":         ("Confidential",  "Voter ID (EPIC) number — government identifier."),
    "DRIVERS_LICENSE":  ("Confidential",  "Driving licence number — government identifier."),
    "USERNAME":         ("Confidential",  "Account username or login identifier."),
    "CUSTOMER_ID":      ("Confidential",  "Customer identifier — links records to a specific individual."),
    "FINANCIAL_VALUE":  ("Confidential",  "Financial value — may expose financial information."),
    "MEDICAL_CONDITION":("Confidential",  "Medical condition — health information."),
    "MEDICAL_TREATMENT":("Confidential",  "Medical treatment — health information."),
    "MEDICATION":       ("Confidential",  "Medication — health information."),
    "BLOOD_GROUP":      ("Confidential",  "Blood group — health information."),

    # Internal — moderate sensitivity
    "EMPLOYEE_ID":      ("Internal",      "Employee identifier — internal employment record."),
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


# ── Data categories ───────────────────────────────────────────
# Independent of the four-level privacy class: the category says *what kind*
# of data was found, the privacy class says *how sensitive* it is.
CATEGORY_PII = "Personal Identification"
CATEGORY_CONTACT = "Contact Information"
CATEGORY_FINANCIAL = "Financial Information"
CATEGORY_MEDICAL = "Medical Information"
CATEGORY_GOVERNMENT_ID = "Government Identification"
CATEGORY_EMPLOYMENT = "Employment Information"
CATEGORY_BUSINESS = "Business Confidential"
CATEGORY_CREDENTIALS = "Credentials"
CATEGORY_LOCATION = "Location Information"
CATEGORY_GENERAL = "General"

DATA_CATEGORIES: tuple[str, ...] = (
    CATEGORY_PII,
    CATEGORY_CONTACT,
    CATEGORY_FINANCIAL,
    CATEGORY_MEDICAL,
    CATEGORY_GOVERNMENT_ID,
    CATEGORY_EMPLOYMENT,
    CATEGORY_BUSINESS,
    CATEGORY_CREDENTIALS,
    CATEGORY_LOCATION,
    CATEGORY_GENERAL,
)

CATEGORY_RULES: dict[str, str] = {
    "PERSON_NAME": CATEGORY_PII,
    "DATE_OF_BIRTH": CATEGORY_PII,
    "CUSTOMER_ID": CATEGORY_PII,

    "EMAIL": CATEGORY_CONTACT,
    "PHONE_IN": CATEGORY_CONTACT,
    "PHONE_GENERIC": CATEGORY_CONTACT,
    "ADDRESS": CATEGORY_CONTACT,
    "PIN_CODE": CATEGORY_CONTACT,

    "CREDIT_CARD": CATEGORY_FINANCIAL,
    "BANK_ACCOUNT": CATEGORY_FINANCIAL,
    "IFSC": CATEGORY_FINANCIAL,
    "UPI_ID": CATEGORY_FINANCIAL,
    "FINANCIAL_VALUE": CATEGORY_FINANCIAL,

    "MEDICAL_CONDITION": CATEGORY_MEDICAL,
    "MEDICAL_TREATMENT": CATEGORY_MEDICAL,
    "MEDICATION": CATEGORY_MEDICAL,
    "BLOOD_GROUP": CATEGORY_MEDICAL,

    "AADHAAR": CATEGORY_GOVERNMENT_ID,
    "AADHAAR_FORMAT": CATEGORY_GOVERNMENT_ID,
    "PAN": CATEGORY_GOVERNMENT_ID,
    "PASSPORT": CATEGORY_GOVERNMENT_ID,
    "VOTER_ID": CATEGORY_GOVERNMENT_ID,
    "DRIVERS_LICENSE": CATEGORY_GOVERNMENT_ID,
    "GSTIN": CATEGORY_GOVERNMENT_ID,

    "EMPLOYEE_ID": CATEGORY_EMPLOYMENT,

    "ORGANIZATION": CATEGORY_BUSINESS,

    "API_KEY": CATEGORY_CREDENTIALS,
    "PASSWORD": CATEGORY_CREDENTIALS,
    "USERNAME": CATEGORY_CREDENTIALS,

    "LOCATION": CATEGORY_LOCATION,
    "GEO_POLITICAL": CATEGORY_LOCATION,
    "FACILITY": CATEGORY_LOCATION,

    "DATE": CATEGORY_GENERAL,
    "IP_ADDRESS": CATEGORY_GENERAL,
}


def data_category(detection: Detection) -> str:
    """Return the data category for a detection (defaults to General)."""
    return CATEGORY_RULES.get(detection.entity_type, CATEGORY_GENERAL)


def category_summary(detections: list[dict]) -> dict[str, int]:
    """Count detections per category; every category is present when used."""
    counts: dict[str, int] = {}
    for det in detections:
        cat = det.get("category") or CATEGORY_GENERAL
        counts[cat] = counts.get(cat, 0) + 1
    return counts


# Risk points per privacy class (used by risk_scoring.py)
CLASS_RISK_POINTS: dict[str, float] = {
    "Restricted":   5.0,
    "Confidential": 3.0,
    "Internal":     1.0,
    "Public":       0.0,
}


def class_risk_points(privacy_class: str) -> float:
    return CLASS_RISK_POINTS.get(privacy_class, 1.0)
