# ============================================================
# app/services/risk_scoring.py
# Documented, deterministic privacy risk scoring (0–100)
#
# Contribution of a unique entity value:
#     class_points × confidence_weight × repetition_weight
# where confidence_weight = 0.5 + 0.5 × confidence and each further
# occurrence of the SAME value adds nothing (duplicates never inflate).
# ============================================================
from dataclasses import dataclass
from typing import Any

from app.services.classification import CLASS_RISK_POINTS

# ── Configurable thresholds ───────────────────────────────────
RISK_THRESHOLDS = {
    "low":    (0,  29),
    "medium": (30, 59),
    "high":   (60, 100),
}

# Normalization cap: raw score at/above this maps to 100
SCORE_CAP = 50.0

# Penalty for repeated *distinct* values of the same type (diminishing returns)
REPETITION_FACTOR = 0.5


@dataclass
class RiskResult:
    score: float              # 0–100
    level: str                # "Low Risk" | "Medium Risk" | "High Risk"
    total_detections: int
    class_counts: dict[str, int]
    class_contributions: dict[str, float]
    top_factors: list[str]
    explanation: str


def _confidence_weight(det: dict[str, Any]) -> float:
    try:
        confidence = float(det.get("confidence", 1.0))
    except (TypeError, ValueError):
        confidence = 1.0
    confidence = min(1.0, max(0.0, confidence))
    return 0.5 + 0.5 * confidence


def _dedupe_key(det: dict[str, Any], index: int) -> tuple[str, str]:
    entity_type = det["entity_type"]
    value = det.get("matched_value") or det.get("value")
    if value:
        return entity_type, "".join(str(value).lower().split())
    # No value available (e.g. unit tests with synthetic dicts): treat each
    # entry as distinct, otherwise the caller's data would silently collapse.
    return entity_type, f"__entry_{index}"


def calculate_risk(detections_with_class: list[dict[str, Any]]) -> RiskResult:
    """
    Algorithm:
    1. Collapse duplicate detections of the same type and value.
    2. For each unique detection: class_points × confidence_weight.
    3. Apply diminishing returns per entity type (distinct values only).
    4. Sum contributions → raw_score.
    5. Normalize: score = min(raw_score / SCORE_CAP, 1.0) × 100.
    """
    if not detections_with_class:
        return RiskResult(
            score=0.0, level="Low Risk", total_detections=0,
            class_counts={}, class_contributions={},
            top_factors=[], explanation="No sensitive entities detected."
        )

    type_counts: dict[str, int] = {}
    class_counts: dict[str, int] = {}
    class_contributions: dict[str, float] = {}
    type_contributions: dict[str, float] = {}
    seen: set[tuple[str, str]] = set()
    raw_score = 0.0
    unique_count = 0

    for index, det in enumerate(detections_with_class):
        key = _dedupe_key(det, index)
        if key in seen:
            continue
        seen.add(key)
        unique_count += 1

        entity_type = det["entity_type"]
        privacy_class = det.get("privacy_class", "Internal")
        points = CLASS_RISK_POINTS.get(privacy_class, 1.0)

        repetition = type_counts.get(entity_type, 0)
        effective = points * _confidence_weight(det) * (REPETITION_FACTOR ** repetition)
        type_counts[entity_type] = repetition + 1

        raw_score += effective
        class_counts[privacy_class] = class_counts.get(privacy_class, 0) + 1
        class_contributions[privacy_class] = class_contributions.get(privacy_class, 0.0) + effective
        type_contributions[entity_type] = type_contributions.get(entity_type, 0.0) + effective

    score = round(min(raw_score / SCORE_CAP, 1.0) * 100.0, 1)
    level = _level(score)

    top_factors = sorted(type_contributions, key=type_contributions.get, reverse=True)[:3]

    duplicates = len(detections_with_class) - unique_count
    duplicate_note = f" ({duplicates} duplicate detection(s) ignored)" if duplicates else ""
    explanation = (
        f"Score {score}/100 ({level}). "
        f"{unique_count} unique sensitive value(s) across "
        f"{len(class_counts)} classification level(s){duplicate_note}. "
        f"Top contributors: {', '.join(top_factors) if top_factors else 'none'}."
    )

    return RiskResult(
        score=score, level=level,
        total_detections=len(detections_with_class),
        class_counts=class_counts,
        class_contributions={k: round(v, 2) for k, v in class_contributions.items()},
        top_factors=top_factors,
        explanation=explanation,
    )


def _level(score: float) -> str:
    if score <= RISK_THRESHOLDS["low"][1]:
        return "Low Risk"
    if score <= RISK_THRESHOLDS["medium"][1]:
        return "Medium Risk"
    return "High Risk"
