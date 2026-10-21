# ============================================================
# app/services/risk_scoring.py
# Documented, deterministic privacy risk scoring (0–100)
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

# Normalization cap: raw score above this maps to 100
SCORE_CAP = 50.0

# Penalty for repeated detections of the same type (diminishing returns)
REPETITION_FACTOR = 0.5   # each subsequent same-type hit contributes 50 % of first


@dataclass
class RiskResult:
    score: float              # 0–100
    level: str                # "Low Risk" | "Medium Risk" | "High Risk"
    total_detections: int
    class_counts: dict[str, int]
    class_contributions: dict[str, float]
    top_factors: list[str]
    explanation: str


def calculate_risk(detections_with_class: list[dict[str, Any]]) -> RiskResult:
    """
    Algorithm:
    1. For each detection, look up its privacy class risk points.
    2. Apply diminishing returns for repeated entity types.
    3. Sum all contributions → raw_score.
    4. Normalize: score = min(raw_score / SCORE_CAP, 1.0) × 100.
    5. Round to 1 decimal place and cap at 100.

    Args:
        detections_with_class: list of dicts, each containing
            "entity_type", "privacy_class", "risk_points" (pre-calculated)
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
    raw_score = 0.0

    for det in detections_with_class:
        etype  = det["entity_type"]
        pclass = det.get("privacy_class", "Internal")
        points = CLASS_RISK_POINTS.get(pclass, 1.0)

        # Diminishing returns for repeated types
        count = type_counts.get(etype, 0)
        effective = points * (REPETITION_FACTOR ** count)
        type_counts[etype] = count + 1

        raw_score += effective
        class_counts[pclass]        = class_counts.get(pclass, 0) + 1
        class_contributions[pclass] = class_contributions.get(pclass, 0.0) + effective

    # Normalize to 0–100
    score = min(raw_score / SCORE_CAP, 1.0) * 100.0
    score = round(score, 1)

    level = _level(score)

    # Top factors (up to 3 most significant entity types by contribution)
    type_contributions: dict[str, float] = {}
    for det in detections_with_class:
        et = det["entity_type"]
        pc = det.get("privacy_class", "Internal")
        type_contributions[et] = type_contributions.get(et, 0) + CLASS_RISK_POINTS.get(pc, 1.0)

    top_factors = sorted(type_contributions, key=type_contributions.get, reverse=True)[:3]

    explanation = (
        f"Score {score}/100 ({level}). "
        f"{len(detections_with_class)} sensitive entity/entities detected across "
        f"{len(class_counts)} classification level(s). "
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
