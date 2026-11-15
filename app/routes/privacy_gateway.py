# ============================================================
# app/routes/privacy_gateway.py
# Local privacy gateway — inspect text before external sharing,
# apply a sanitization/blocking policy, and optionally inspect a
# response from an external AI for leaked identifiers.
# ============================================================
import uuid
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from app.security.authentication import get_current_user
from app.database import get_db
from app.services.detection_engine import detect
from app.services.classification import classify, class_risk_points, data_category
from app.services.risk_scoring import calculate_risk
from app.services.pseudonymization import build_pseudonyms
from app.services.sanitization import sanitize, protect_preview
from app.models.schemas import GatewayInspectRequest, GatewayInspectResponse

router = APIRouter(prefix="/api/privacy-gateway", tags=["Privacy Gateway"])

_MODES = ("redact", "mask", "pseudonymize")


@router.post("/inspect", response_model=GatewayInspectResponse)
async def inspect(
    payload: GatewayInspectRequest,
    current_user: dict = Depends(get_current_user),
):
    text = payload.text
    mode = payload.mode if payload.mode in _MODES else "redact"
    gateway_id = uuid.uuid4().hex

    # 1. Detect
    raw_detections = detect(text)

    # 2. Classify + categorise
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
            "category":               data_category(det),
            "risk_points":            class_risk_points(privacy_class),
        })

    # 3. Risk score
    risk = calculate_risk(enriched)
    class_summary = dict(Counter(d["privacy_class"] for d in enriched))
    category_summary = dict(Counter(d["category"] for d in enriched))

    # 4. Apply the requested sanitization mode
    replacements = None
    if mode == "pseudonymize":
        replacements, _, _ = build_pseudonyms(gateway_id, enriched)
    sanitized_text = sanitize(text, enriched, mode=mode, replacements=replacements)

    # 5. Policy decision
    blocked = bool(payload.block_high_risk and risk.level == "High Risk")
    permit_forward = (not blocked) and payload.allow_forward and risk.level == "Low Risk"
    decision = "blocked" if blocked else ("allowed" if permit_forward else "sanitized_only")

    warnings: list[str] = []
    if blocked:
        warnings.append(
            f"Blocked by policy: risk score {risk.score} ({risk.level}). "
            "High-risk content must not be forwarded."
        )
    elif risk.level == "High Risk":
        warnings.append(
            f"Risk score {risk.score} ({risk.level}) — forwarding NOT recommended. "
            "Review the sanitized version before any external transmission."
        )
    if payload.allow_forward and not permit_forward and not blocked:
        warnings.append(
            "Forwarding was requested but is only permitted for Low Risk content."
        )
    if not payload.allow_forward and not blocked:
        warnings.append("allow_forward is false. Only the sanitized text is available.")
    if mode == "pseudonymize":
        warnings.append(
            "Pseudonym tokens are local to this inspection and cannot be restored."
        )

    # 6. Optional inspection of a response received from an external AI
    response_inspection = None
    if payload.inspect_response:
        response_dets = detect(payload.inspect_response)
        input_values = {(d["entity_type"], d["matched_value"]) for d in enriched}
        leaked = [
            d for d in response_dets
            if (d.entity_type, d.matched_value) in input_values
        ]
        safe_response = sanitize(
            payload.inspect_response,
            [d.__dict__ for d in response_dets],
            mode="redact",
        )
        response_safe = len(response_dets) == 0
        response_inspection = {
            "safe": response_safe,
            "detections": len(response_dets),
            "entity_types": sorted({d.entity_type for d in response_dets}),
            "leaked_from_input": len(leaked),
            "sanitized_response": safe_response,
        }
        if not response_safe:
            warnings.append(
                f"External response contains {len(response_dets)} sensitive "
                "pattern(s); a sanitized copy is returned instead."
            )

    # 7. Audit — never store the submitted text or raw values
    db = get_db()
    db.audit_logs.insert_one({
        "user_id": current_user["_id"],
        "action": "gateway_inspect",
        "gateway_id": gateway_id,
        "risk_score": risk.score,
        "risk_level": risk.level,
        "total_detections": len(enriched),
        "mode": mode,
        "blocked": blocked,
        "permit_forward": permit_forward,
        "response_checked": bool(payload.inspect_response),
        "status": "success",
        "timestamp": datetime.now(timezone.utc),
    })

    # Client-safe detections (masked values only)
    safe_detections = [
        {
            "entity_type":           d["entity_type"],
            "matched_value":         d["protected_preview"],
            "start":                 d["start"],
            "end":                   d["end"],
            "privacy_class":         d["privacy_class"],
            "classification_reason": d["classification_reason"],
            "category":              d["category"],
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
        blocked=blocked,
        decision=decision,
        mode=mode,
        class_summary=class_summary,
        category_summary=category_summary,
        response_inspection=response_inspection,
        gateway_id=gateway_id,
    )
