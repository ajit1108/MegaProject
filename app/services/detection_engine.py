# ============================================================
# app/services/detection_engine.py
# Hybrid sensitive-data detection engine:
#   1. rule layer  — validated regexes + context-gated extractors
#                    (app/services/sensitive_rules.py)
#   2. NER layer   — spaCy en_core_web_sm (+ EntityRuler gazetteer)
#   3. resolution  — type-priority overlap suppression + dedupe
#
# Offsets returned by detect() always address the ORIGINAL input string,
# because normalisation is mapped back character by character.
# ============================================================
import logging
from dataclasses import dataclass

from app.services import sensitive_rules as rules
from app.services.preprocessing import preprocess_with_offsets

logger = logging.getLogger(__name__)


# ── Detection result dataclass ────────────────────────────────
@dataclass
class Detection:
    entity_type: str
    matched_value: str          # raw matched text (masked before sending to client)
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


# ── Overlap resolution ───────────────────────────────────────
# Lower number wins when two detections overlap.
ENTITY_PRIORITY: dict[str, int] = {
    "CREDIT_CARD": 10,
    "EMPLOYEE_ID": 12,
    "CUSTOMER_ID": 13,
    "AADHAAR": 15,
    "AADHAAR_FORMAT": 16,
    "ADDRESS": 22,
    "PASSPORT": 24,
    "GSTIN": 26,
    "PAN": 30,
    "IFSC": 34,
    "BANK_ACCOUNT": 38,
    "VOTER_ID": 44,
    "DRIVERS_LICENSE": 46,
    "UPI_ID": 50,
    "EMAIL": 55,
    "PHONE_IN": 60,
    "PHONE_GENERIC": 60,
    "IP_ADDRESS": 62,
    "DATE_OF_BIRTH": 65,
    "PIN_CODE": 66,
    "USERNAME": 68,
    "FINANCIAL_VALUE": 70,
    "MEDICAL_CONDITION": 72,
    "MEDICAL_TREATMENT": 72,
    "MEDICATION": 72,
    "BLOOD_GROUP": 72,
    "PERSON_NAME": 80,
    "ORGANIZATION": 85,
    "GEO_POLITICAL": 90,
    "LOCATION": 90,
    "FACILITY": 90,
}

_ENTITY_FAMILY: dict[str, str] = {
    "PHONE_IN": "PHONE",
    "PHONE_GENERIC": "PHONE",
    "AADHAAR_FORMAT": "AADHAAR",
    "GEO_POLITICAL": "LOCATION",
    "FACILITY": "LOCATION",
}


def _family(entity_type: str) -> str:
    return _ENTITY_FAMILY.get(entity_type, entity_type)


def _priority(entity_type: str) -> int:
    return ENTITY_PRIORITY.get(entity_type, 78)


def resolve_detections(detections: list[Detection]) -> list[Detection]:
    """
    Greedy non-overlapping selection ordered by entity priority, then by
    span length (longer wins), then by confidence. When a dropped detection
    came from a different method but the same entity family, the surviving
    detection is marked "both" so the UI can show the hybrid agreement.
    """
    ranked = sorted(
        detections,
        key=lambda d: (_priority(d.entity_type), -(d.end - d.start), -d.confidence),
    )
    accepted: list[Detection] = []
    for det in ranked:
        conflict = next(
            (a for a in accepted if det.start < a.end and a.start < det.end),
            None,
        )
        if conflict is None:
            accepted.append(det)
            continue
        if (
            det.detection_method != conflict.detection_method
            and _family(det.entity_type) == _family(conflict.entity_type)
        ):
            conflict.detection_method = "both"
    return sorted(accepted, key=lambda d: (d.start, d.end))


def _map_span(start: int, end: int, offsets: list[int], raw_length: int) -> tuple[int, int] | None:
    if start < 0 or end <= start or end > len(offsets):
        return None
    mapped_start = offsets[start]
    mapped_end = offsets[end - 1] + 1
    if mapped_start < 0 or mapped_end <= mapped_start or mapped_end > raw_length:
        return None
    return mapped_start, mapped_end


# ── Rule layer ───────────────────────────────────────────────
def run_regex_detection(text: str) -> list[Detection]:
    """Run the validated rule layer against the given text."""
    detections = [
        Detection(
            entity_type=hit.entity_type,
            matched_value=hit.value,
            start=hit.start,
            end=hit.end,
            detection_method="regex",
            confidence=hit.confidence,
        )
        for hit in rules.extract_all(text)
    ]
    return resolve_detections(detections)


# ── NER layer ────────────────────────────────────────────────
_nlp = None
_nlp_available = False
_NLP_CHUNK = 40_000
_NLP_OVERLAP = 200


def _load_nlp() -> None:
    global _nlp, _nlp_available
    if _nlp is not None or _nlp_available:
        return
    try:
        import spacy

        nlp = spacy.load("en_core_web_sm")
        patterns = [{"label": "ORG", "pattern": name} for name in rules.KNOWN_ORGS]
        existing = nlp.pipe_names
        if "entity_ruler" not in existing:
            ruler = nlp.add_pipe(
                "entity_ruler",
                before="ner",
                config={"overwrite_ents": False},
            )
            ruler.add_patterns(patterns)
        _nlp = nlp
        _nlp_available = True
        logger.info("spaCy model en_core_web_sm loaded with organisation gazetteer.")
    except OSError:
        logger.warning(
            "spaCy model 'en_core_web_sm' not found. "
            "Run: python -m spacy download en_core_web_sm — NER layer skipped."
        )
        _nlp_available = False
    except ImportError:
        logger.warning("spaCy not installed — NER layer skipped.")
        _nlp_available = False


def _iter_chunks(text: str):
    start = 0
    length = len(text)
    while start < length:
        end = min(length, start + _NLP_CHUNK)
        if end < length:
            newline = text.rfind("\n", start, end)
            if newline > start + _NLP_CHUNK // 2:
                end = newline + 1
        yield start, text[start:end]
        if end >= length:
            break
        start = max(end - _NLP_OVERLAP, start + 1)


def _ner_detections(text: str) -> list[Detection]:
    results: list[Detection] = []
    seen: set[tuple[int, int, str]] = set()

    for base, chunk in _iter_chunks(text):
        doc = _nlp(chunk)
        for ent in doc.ents:
            start = base + ent.start_char
            end = base + ent.end_char
            label = ent.label_
            value = ent.text.strip()
            if not value:
                continue

            if ent.label_ in ("GPE", "LOC"):
                if not rules.location_allowed(text, start, end):
                    continue
                entity_type = "LOCATION"
                confidence = 0.6
            elif ent.label_ == "PERSON":
                if "\n" in ent.text:
                    value = ent.text.split("\n", 1)[0].strip()
                value = value.strip().lstrip(".,;: ").rstrip(".,;:")
                if not value:
                    continue
                start = text.find(value, start, end)
                if start == -1 or not rules.looks_like_person_name(value):
                    continue
                end = start + len(value)
                entity_type = "PERSON_NAME"
                confidence = 0.72
            elif ent.label_ == "ORG":
                if "\n" in ent.text:
                    value = ent.text.split("\n", 1)[0].strip()
                value = value.rstrip(":").strip()
                if not value:
                    continue
                start = text.find(value, start, end)
                if start == -1 or not rules.is_org_like(value):
                    continue
                end = start + len(value)
                entity_type = "ORGANIZATION"
                confidence = 0.7
            elif ent.label_ == "FAC":
                entity_type = "FACILITY"
                confidence = 0.55
            else:
                # DATE / MONEY / CARDINAL are too noisy to treat as
                # sensitive on their own; context rules cover DOB and money.
                continue

            key = (start, end, entity_type)
            if key in seen:
                continue
            seen.add(key)
            results.append(
                Detection(
                    entity_type=entity_type,
                    matched_value=value,
                    start=start,
                    end=end,
                    detection_method="nlp",
                    confidence=confidence,
                )
            )
    return results


def run_nlp_detection(text: str) -> list[Detection]:
    """Run spaCy NER on the given text. Returns [] when spaCy is unavailable."""
    _load_nlp()
    if not _nlp_available or _nlp is None:
        return []
    return _ner_detections(text)


def nlp_is_available() -> bool:
    _load_nlp()
    return _nlp_available


# ── Merge (backward-compatible helper) ──────────────────────
def merge_detections(regex_hits: list[Detection], nlp_hits: list[Detection]) -> list[Detection]:
    """Combine regex and NLP hits, marking overlaps as 'both'."""
    all_hits = list(regex_hits)
    for nlp_hit in nlp_hits:
        overlapping = [r for r in regex_hits if r.start < nlp_hit.end and nlp_hit.start < r.end]
        if overlapping:
            for regex_hit in overlapping:
                regex_hit.detection_method = "both"
        else:
            all_hits.append(nlp_hit)

    seen: set[tuple[int, int, str]] = set()
    unique: list[Detection] = []
    for det in sorted(all_hits, key=lambda d: (d.start, d.end)):
        key = (det.start, det.end, det.entity_type)
        if key not in seen:
            seen.add(key)
            unique.append(det)
    return unique


# ── Public API ────────────────────────────────────────────────
def detect(text: str) -> list[Detection]:
    """
    Full hybrid pipeline. Returned offsets address `text` exactly, so the
    frontend highlighting and format-preserving sanitisation stay aligned.
    """
    if not text:
        return []

    clean, offsets = preprocess_with_offsets(text)

    rule_hits = run_regex_detection(clean)
    nlp_hits = run_nlp_detection(clean)

    mapped: list[Detection] = []
    for det in [*rule_hits, *nlp_hits]:
        span = _map_span(det.start, det.end, offsets, len(text))
        if span is None:
            continue
        det.start, det.end = span
        det.matched_value = text[det.start:det.end]
        mapped.append(det)

    return resolve_detections(mapped)
