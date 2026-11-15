# ============================================================
# tests/legacy_engine.py
# Frozen copy of the ORIGINAL detection engine (pre-improvement).
# Kept ONLY so the evaluation harness can measure the real
# before/after difference on identical gold data. The application
# never imports this module.
# ============================================================
import re
from dataclasses import dataclass


@dataclass
class Detection:
    entity_type: str
    matched_value: str
    start: int
    end: int
    detection_method: str
    confidence: float = 1.0


REGEX_PATTERNS: list[dict] = [
    {
        "name": "EMAIL",
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "confidence": 0.97,
    },
    {
        "name": "PHONE_IN",
        "pattern": r"(?:\+91[\s\-]?)?(?:0)?[6-9]\d{9}",
        "confidence": 0.85,
    },
    {
        "name": "PHONE_GENERIC",
        "pattern": r"\b(?:\+\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{4}\b",
        "confidence": 0.70,
    },
    {
        "name": "AADHAAR",
        "pattern": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        "confidence": 0.75,
    },
    {
        "name": "PAN",
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "confidence": 0.85,
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
    results: list[Detection] = []
    for cfg in REGEX_PATTERNS:
        for match in re.finditer(cfg["pattern"], text):
            results.append(Detection(
                entity_type=cfg["name"],
                matched_value=match.group(0),
                start=match.start(),
                end=match.end(),
                detection_method="regex",
                confidence=cfg["confidence"],
            ))
    return results


_nlp = None
_nlp_available = False


def _load_nlp() -> None:
    global _nlp, _nlp_available
    if _nlp is not None:
        return
    try:
        import spacy
        _nlp = spacy.load("en_core_web_sm")
        _nlp_available = True
    except (OSError, ImportError):
        _nlp_available = False


SPACY_ENTITY_MAP: dict[str, str] = {
    "PERSON": "PERSON_NAME",
    "ORG": "ORGANIZATION",
    "GPE": "GEO_POLITICAL",
    "LOC": "LOCATION",
    "FAC": "FACILITY",
    "MONEY": "FINANCIAL_VALUE",
    "DATE": "DATE",
}


def run_nlp_detection(text: str) -> list[Detection]:
    _load_nlp()
    if not _nlp_available or _nlp is None:
        return []
    max_chars = 100_000
    if len(text) > max_chars:
        text = text[:max_chars]
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


def merge_detections(regex_hits: list[Detection], nlp_hits: list[Detection]) -> list[Detection]:
    all_hits = list(regex_hits)
    for nlp in nlp_hits:
        overlapping = [r for r in regex_hits if r.start < nlp.end and nlp.start < r.end]
        if overlapping:
            for hit in overlapping:
                hit.detection_method = "both"
        else:
            all_hits.append(nlp)

    seen: set[tuple] = set()
    unique = []
    for det in sorted(all_hits, key=lambda x: x.start):
        key = (det.start, det.end, det.entity_type)
        if key not in seen:
            seen.add(key)
            unique.append(det)
    return unique


def detect(text: str) -> list[Detection]:
    return merge_detections(run_regex_detection(text), run_nlp_detection(text))
