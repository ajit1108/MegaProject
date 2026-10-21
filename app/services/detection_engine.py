# ============================================================
# app/services/detection_engine.py
# Regex + spaCy NLP sensitive-data detection
# ============================================================
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Detection result dataclass ────────────────────────────────
@dataclass
class Detection:
    entity_type: str
    matched_value: str          # raw matched text (to be masked before sending to client)
    start: int
    end: int
    detection_method: str       # "regex" | "nlp" | "both"
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "entity_type": self.entity_type,
            "matched_value": self.matched_value,
            "start": self.start,
            "end": self.end,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
        }


# ── Regex patterns (configurable) ────────────────────────────
REGEX_PATTERNS: list[dict] = [
    {
        "name": "EMAIL",
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "confidence": 0.97,
    },
    {
        "name": "PHONE_IN",   # Indian 10-digit mobile / with country code
        "pattern": r"(?:\+91[\s\-]?)?(?:0)?[6-9]\d{9}",
        "confidence": 0.85,
    },
    {
        "name": "PHONE_GENERIC",
        "pattern": r"\b(?:\+\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{4}\b",
        "confidence": 0.70,
    },
    {
        "name": "AADHAAR",    # 12-digit number, optionally space/dash separated
        "pattern": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        "confidence": 0.75,
        "note": "Pattern match only — does not verify Aadhaar validity.",
    },
    {
        "name": "PAN",        # Indian PAN: ABCDE1234F
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "confidence": 0.85,
        "note": "Pattern match only.",
    },
    {
        "name": "IP_ADDRESS",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "confidence": 0.92,
    },
    {
        "name": "CREDIT_CARD",
        "pattern": r"\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        "confidence": 0.80,
    },
    {
        "name": "DATE_OF_BIRTH",
        "pattern": r"\b(?:0?[1-9]|[12]\d|3[01])[\s/\-](?:0?[1-9]|1[0-2])[\s/\-](?:19|20)\d{2}\b",
        "confidence": 0.70,
    },
    {
        "name": "API_KEY",
        "pattern": r"(?i)(?:api[_\-]?key|token|secret)[_\-\s]*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
        "confidence": 0.85,
    },
    {
        "name": "PASSWORD",
        "pattern": r"(?i)(?:password|passwd|pwd)[_\-\s]*[:=]\s*['\"]?(\S{6,})['\"]?",
        "confidence": 0.80,
    },
]


def run_regex_detection(text: str) -> list[Detection]:
    """Run all configured regex patterns against the text."""
    results: list[Detection] = []
    for cfg in REGEX_PATTERNS:
        for m in re.finditer(cfg["pattern"], text):
            results.append(Detection(
                entity_type=cfg["name"],
                matched_value=m.group(0),
                start=m.start(),
                end=m.end(),
                detection_method="regex",
                confidence=cfg["confidence"],
            ))
    return results


# ── NLP detection ─────────────────────────────────────────────
_nlp = None
_nlp_available = False


def _load_nlp():
    global _nlp, _nlp_available
    if _nlp is not None:
        return
    try:
        import spacy
        _nlp = spacy.load("en_core_web_sm")
        _nlp_available = True
        logger.info("spaCy model en_core_web_sm loaded.")
    except OSError:
        logger.warning(
            "spaCy model 'en_core_web_sm' not found. "
            "Run: python -m spacy download en_core_web_sm\n"
            "NLP detection will be skipped."
        )
        _nlp_available = False
    except ImportError:
        logger.warning("spaCy not installed. NLP detection disabled.")
        _nlp_available = False


# Map spaCy entity labels to our entity types
SPACY_ENTITY_MAP: dict[str, str] = {
    "PERSON":  "PERSON_NAME",
    "ORG":     "ORGANIZATION",
    "GPE":     "GEO_POLITICAL",
    "LOC":     "LOCATION",
    "FAC":     "FACILITY",
    "MONEY":   "FINANCIAL_VALUE",
    "DATE":    "DATE",
}


def run_nlp_detection(text: str) -> list[Detection]:
    """Run spaCy NER on the text. Returns empty list if spaCy is unavailable."""
    _load_nlp()
    if not _nlp_available or _nlp is None:
        return []

    # Process in chunks to avoid memory issues with very long documents
    MAX_CHARS = 100_000
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS]

    doc = _nlp(text)
    results = []
    for ent in doc.ents:
        mapped = SPACY_ENTITY_MAP.get(ent.label_)
        if mapped:
            results.append(Detection(
                entity_type=mapped,
                matched_value=ent.text,
                start=ent.start_char,
                end=ent.end_char,
                detection_method="nlp",
                confidence=0.75,
            ))
    return results


# ── Merge & deduplicate ───────────────────────────────────────
def merge_detections(regex_hits: list[Detection], nlp_hits: list[Detection]) -> list[Detection]:
    """
    Combine regex and NLP detections.
    - Mark overlapping hits from both methods as "both".
    - Remove exact duplicates.
    - Sort by start position.
    """
    all_hits = list(regex_hits)

    for nlp in nlp_hits:
        # Check if this NLP entity overlaps with any regex hit
        overlapping = [
            r for r in regex_hits
            if r.start < nlp.end and nlp.start < r.end
        ]
        if overlapping:
            for r in overlapping:
                r.detection_method = "both"
        else:
            all_hits.append(nlp)

    # Remove fully duplicate spans (same start, end, type)
    seen: set[tuple] = set()
    unique = []
    for d in sorted(all_hits, key=lambda x: x.start):
        key = (d.start, d.end, d.entity_type)
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique


# ── Public API ────────────────────────────────────────────────
def detect(text: str) -> list[Detection]:
    """Full detection pipeline: regex + NLP, merged."""
    regex_hits = run_regex_detection(text)
    nlp_hits   = run_nlp_detection(text)
    return merge_detections(regex_hits, nlp_hits)


def nlp_is_available() -> bool:
    _load_nlp()
    return _nlp_available
