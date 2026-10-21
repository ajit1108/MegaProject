# ============================================================
# app/routes/analysis.py — Analysis, sanitization, download
# ============================================================
import io
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from bson import ObjectId
from app.database import get_db
from app.security.authentication import get_current_user
from app.services.document_service import analyse_document
from app.services.sanitization import sanitize
from app.services.detection_engine import detect
from app.services.preprocessing import preprocess

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])


def _safe_detection(det: dict) -> dict:
    """Strip raw matched_value; expose only the protected preview."""
    return {
        "entity_type":            det.get("entity_type"),
        "matched_value":          det.get("protected_preview", "***"),
        "start":                  det.get("start"),
        "end":                    det.get("end"),
        "privacy_class":          det.get("privacy_class"),
        "classification_reason":  det.get("classification_reason"),
        "risk_points":            det.get("risk_points"),
        "detection_method":       det.get("detection_method"),
        "confidence":             det.get("confidence"),
    }


def _analysis_to_out(a: dict, include_text: bool = False) -> dict:
    detections = [_safe_detection(d) for d in a.get("detections", [])]
    out = {
        "id":                    str(a["_id"]),
        "document_id":           str(a.get("document_id", "")),
        "document_name":         a.get("document_name", ""),
        "total_detections":      a.get("total_detections", 0),
        "detections":            detections,
        "risk_score":            a.get("risk_score", 0),
        "risk_level":            a.get("risk_level", "Low Risk"),
        "class_summary":         a.get("class_summary", {}),
        "risk_explanation":      a.get("risk_explanation", ""),
        "sanitization_status":   a.get("sanitization_status", "not_sanitized"),
        "used_ocr":              a.get("used_ocr", False),
        "extraction_warnings":   a.get("extraction_warnings", []),
        "created_at":            a.get("created_at"),
    }
    if include_text:
        out["extracted_text_preview"] = (a.get("extracted_text") or "")[:500]
    return out


@router.post("/analyze/{document_id}")
async def analyze(
    document_id: str,
    current_user: dict = Depends(get_current_user),
):
    db  = get_db()
    uid = current_user["_id"]
    try:
        doc_oid = ObjectId(document_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document ID.")

    doc = db.documents.find_one({"_id": doc_oid, "user_id": uid})
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    # Read file bytes
    fp = doc.get("file_path", "")
    try:
        with open(fp, "rb") as f:
            content = f.read()
    except OSError:
        raise HTTPException(status_code=500, detail="Could not read uploaded file.")

    result = analyse_document(
        document_id=document_id,
        content=content,
        filename=doc.get("original_filename", "file"),
        user_id=str(uid),
    )

    if "error" in result:
        raise HTTPException(status_code=422, detail=result["error"])

    return _analysis_to_out(result, include_text=True)


@router.get("/history")
async def history(
    current_user: dict = Depends(get_current_user),
    risk_level: str = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, le=100),
):
    db  = get_db()
    uid = current_user["_id"]
    query: dict = {"user_id": uid}
    if risk_level:
        query["risk_level"] = risk_level

    analyses = db.analyses.find(
        query,
        {"extracted_text": 0, "detections": 0}    # lightweight list
    ).sort("created_at", -1).skip(skip).limit(limit)

    return [
        {
            "id":                  str(a["_id"]),
            "document_name":       a.get("document_name", ""),
            "total_detections":    a.get("total_detections", 0),
            "risk_score":          a.get("risk_score", 0),
            "risk_level":          a.get("risk_level", "Low Risk"),
            "sanitization_status": a.get("sanitization_status", "not_sanitized"),
            "created_at":          a.get("created_at"),
        }
        for a in analyses
    ]


@router.get("/{analysis_id}")
async def get_analysis(
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
):
    db  = get_db()
    uid = current_user["_id"]
    try:
        oid = ObjectId(analysis_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid analysis ID.")

    a = db.analyses.find_one({"_id": oid, "user_id": uid})
    if not a:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return _analysis_to_out(a, include_text=True)


@router.post("/{analysis_id}/sanitize")
async def sanitize_analysis(
    analysis_id: str,
    mode: str = "redact",
    current_user: dict = Depends(get_current_user),
):
    db  = get_db()
    uid = current_user["_id"]
    try:
        oid = ObjectId(analysis_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid analysis ID.")

    a = db.analyses.find_one({"_id": oid, "user_id": uid})
    if not a:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    raw_text   = a.get("extracted_text", "")
    detections = a.get("detections", [])

    if mode not in ("redact", "mask"):
        mode = "redact"

    sanitized = sanitize(raw_text, detections, mode=mode)

    # Verify: re-run detection on sanitized output
    clean_again = preprocess(sanitized)
    remaining   = detect(clean_again)
    warnings    = []
    if remaining:
        warnings.append(
            f"Re-scan found {len(remaining)} potentially sensitive pattern(s) "
            "still detectable in the sanitized output. Review before sharing."
        )

    # Store sanitized text
    db.analyses.update_one(
        {"_id": oid},
        {"$set": {
            "sanitized_text":      sanitized,
            "sanitization_status": "sanitized",
            "sanitization_mode":   mode,
            "remaining_detections": len(remaining),
            "sanitization_warnings": warnings,
        }}
    )

    db.audit_logs.insert_one({
        "user_id":     uid,
        "action":      "sanitize",
        "analysis_id": str(oid),
        "mode":        mode,
        "status":      "success",
        "timestamp":   datetime.now(timezone.utc),
    })

    return {
        "analysis_id":         analysis_id,
        "sanitized_text":      sanitized,
        "mode":                mode,
        "remaining_detections": len(remaining),
        "warnings":            warnings,
        "original_text_preview": raw_text[:300] + ("..." if len(raw_text) > 300 else ""),
    }


@router.get("/{analysis_id}/sanitized-download")
async def download_sanitized(
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
):
    db  = get_db()
    uid = current_user["_id"]
    try:
        oid = ObjectId(analysis_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid analysis ID.")

    a = db.analyses.find_one({"_id": oid, "user_id": uid})
    if not a:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    sanitized = a.get("sanitized_text")
    if not sanitized:
        raise HTTPException(
            status_code=400,
            detail="This analysis has not been sanitized yet. Run sanitization first."
        )

    filename = a.get("document_name", "document").rsplit(".", 1)[0] + "_sanitized.txt"
    content  = sanitized.encode("utf-8")

    db.audit_logs.insert_one({
        "user_id":     uid,
        "action":      "download_sanitized",
        "analysis_id": str(oid),
        "status":      "success",
        "timestamp":   datetime.now(timezone.utc),
    })

    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
):
    db  = get_db()
    uid = current_user["_id"]
    try:
        oid = ObjectId(analysis_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid analysis ID.")

    a = db.analyses.find_one({"_id": oid, "user_id": uid})
    if not a:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    db.analyses.delete_one({"_id": oid})
    return {"message": "Analysis record deleted."}
