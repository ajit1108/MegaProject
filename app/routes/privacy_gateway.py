# ============================================================
# app/routes/privacy_gateway.py
# Local privacy gateway — inspect text before external sharing
# ============================================================
from fastapi import APIRouter, Depends, HTTPException
from app.security.authentication import get_current_user
from app.services.preprocessing import preprocess
from app.services.detection_engine import detect
from app.services.classification import classify, class_risk_points
from app.services.risk_scoring import calculate_risk
from app.services.sanitization import sanitize, protect_preview
from app.models.schemas import GatewayInspectRequest, GatewayInspectResponse

router = APIRouter(prefix="/api/privacy-gateway", tags=["Privacy Gateway"])


@router.post("/inspect", response_model=GatewayInspectResponse)
async def inspect(
    payload: GatewayInspectRequest,
    current_user: dict = Depends(get_current_user),
):
    text = payload.text

    # 1. Preprocess
    clean = preprocess(text)

    # 2. Detect
    raw_detections = detect(clean)

    # 3. Classify
    enriched = []
    for det in raw_detections:
        privacy_class, reason = classify(det)
        enriched.append({
            "entity_type":            det.entity_type,
            "matched_value":          det.matched_value,
            "protected_preview":      protect_preview(det.matched_value, det.entity_type),
            "start":                  det.start,
            "end":                    det.end,
            "detection_method":       det.detection_method,
            "confidence":             det.confidence,
            "privacy_class":          privacy_class,
            "classification_reason":  reason,
            "risk_points":            class_risk_points(privacy_class),
        })

    # 4. Risk score
    risk = calculate_risk(enriched)

    # 5. Sanitize
    sanitized_text = sanitize(text, enriched, mode="redact")

    # 6. Apply gateway policy: permit forwarding only if Low Risk
    permit_forward = risk.score <= 29 and payload.allow_forward

    warnings = []
    if risk.score > 29:
        warnings.append(
            f"Risk score {risk.score} ({risk.level}) — forwarding NOT recommended. "
            "Review the sanitized version before any external transmission."
        )
    if not payload.allow_forward and risk.score <= 29:
        warnings.append("allow_forward is false. Set allow_forward=true to permit forwarding.")

    # Client-safe detections (masked values only)
    safe_detections = [
        {
            "entity_type":           d["entity_type"],
            "matched_value":         d["protected_preview"],
            "start":                 d["start"],
            "end":                   d["end"],
            "privacy_class":         d["privacy_class"],
            "classification_reason": d["classification_reason"],
            "risk_points":           d["risk_points"],
            "detection_method":      d["detection_method"],
            "confidence":            d["confidence"],
        }
        for d in enriched
    ]

    return GatewayInspectResponse(
        risk_score=risk.score,
        risk_level=risk.level,
        total_detections=len(enriched),
        detections=safe_detections,
        sanitized_text=sanitized_text,
        permit_forward=permit_forward,
        warnings=warnings,
    )
