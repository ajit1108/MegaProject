# ============================================================
# app/routes/analysis.py — Analysis, sanitization, download
# ============================================================
import io
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from bson import ObjectId
from app.config import get_settings
from app.database import get_db
from app.security.authentication import get_current_user
from app.services.document_service import analyse_document
from app.services.sanitization import sanitize, sanitize_file
from app.services.pseudonymization import (
    build_pseudonyms,
    load_mapping,
    restore_text,
    store_mapping,
)
from app.services.detection_engine import detect
from app.models.schemas import RestoreRequest
from app.utils.file_validation import safe_filename

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])


def _safe_detection(det: dict) -> dict:
    """Strip raw matched_value; expose only the protected preview."""
    return {
        "entity_type":            det.get("entity_type"),
        "matched_value":          det.get("protected_preview", "***"),
        "start":                  det.get("start"),
        "end":                    det.get("end"),
        "page":                   det.get("page", 1),
        "privacy_class":          det.get("privacy_class"),
        "classification_reason":  det.get("classification_reason"),
        "category":               det.get("category", "General"),
        "risk_points":            det.get("risk_points"),
        "detection_method":       det.get("detection_method"),
        "confidence":             det.get("confidence"),
    }


def _masked_text_preview(raw: str, detections: list[dict], limit: int = 500) -> str:
    """Masked first `limit` characters, preserving length and offsets.

    Each character inside a detected span is replaced by '*', so the
    frontend can keep using start/end to highlight without revealing PII.
    """
    if not raw:
        return ""
    window = list(raw[:limit])
    for det in detections:
        start, end = det.get("start"), det.get("end")
        if not isinstance(start, int) or not isinstance(end, int):
            continue
        if start >= limit or end <= start:
            continue
        for i in range(max(0, start), min(end, limit)):
            if window[i] not in " \t\r\n":
                window[i] = "*"
    return "".join(window)


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
        "category_summary":      a.get("category_summary", {}),
        "page_count":            a.get("page_count", 1),
        "risk_explanation":      a.get("risk_explanation", ""),
        "sanitization_status":   a.get("sanitization_status", "not_sanitized"),
        "sanitization_mode":     a.get("sanitization_mode"),
        "pseudonymized":         a.get("sanitization_mode") == "pseudonymize",
        "sanitized_filename":    a.get("sanitized_filename"),
        "sanitized_file_type":   a.get("sanitized_file_type"),
        "used_ocr":              a.get("used_ocr", False),
        "extraction_warnings":   a.get("extraction_warnings", []),
        "created_at":            a.get("created_at"),
    }
    if include_text:
        raw_text = a.get("extracted_text") or ""
        out["extracted_text_preview"] = _masked_text_preview(
            raw_text, a.get("detections", [])
        )
        # Owner-only view: show the stored sanitized output so a reload does not
        # lose the result. The original file is never modified.
        out["sanitized_text"] = a.get("sanitized_text", "")
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

    if mode not in ("redact", "mask", "remove", "pseudonymize"):
        mode = "redact"

    # Pseudonymization: deterministic tokens + encrypted restoration mapping.
    span_replacements = None
    value_replacements = None
    pseudo_entries: list[dict] = []
    if mode == "pseudonymize":
        span_replacements, value_replacements, pseudo_entries = build_pseudonyms(
            analysis_id, detections
        )
        store_mapping(db, uid, analysis_id, pseudo_entries)

    # 1. Generate text sanitization
    sanitized_text = sanitize(raw_text, detections, mode=mode, replacements=span_replacements)

    # 2. Generate format-preserving file sanitization
    doc_id = a.get("document_id")
    doc = db.documents.find_one({"_id": doc_id, "user_id": uid}) if doc_id else None

    sanitized_file_path = None
    sanitized_filename = None
    sanitized_mime_type = "text/plain; charset=utf-8"
    sanitized_file_type = "txt"

    settings = get_settings()
    upload_dir = settings.upload_dir
    os.makedirs(upload_dir, exist_ok=True)

    if doc and doc.get("file_path") and os.path.isfile(doc["file_path"]):
        try:
            with open(doc["file_path"], "rb") as f:
                orig_bytes = f.read()
            orig_fname = doc.get("original_filename") or a.get("document_name", "document.txt")
            sanitized_bytes, sanitized_filename, sanitized_mime_type = sanitize_file(
                original_bytes=orig_bytes,
                filename=orig_fname,
                detections=detections,
                mode=mode,
                replacements=span_replacements,
                value_replacements=value_replacements,
            )
            sanitized_file_type = (sanitized_filename.rsplit(".", 1)[-1]).lower()
            internal_sanitized_name = safe_filename(f"sanitized_{sanitized_filename}")
            sanitized_file_path = os.path.join(upload_dir, internal_sanitized_name)
            with open(sanitized_file_path, "wb") as sf:
                sf.write(sanitized_bytes)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error("Format-preserving sanitization error: %s", exc, exc_info=True)
            sanitized_file_path = None

    # Fallback to saving text file if binary generation was not applicable
    if not sanitized_file_path:
        sanitized_filename = a.get("document_name", "document").rsplit(".", 1)[0] + "_sanitized.txt"
        sanitized_mime_type = "text/plain; charset=utf-8"
        sanitized_file_type = "txt"
        internal_sanitized_name = safe_filename(f"sanitized_{sanitized_filename}")
        sanitized_file_path = os.path.join(upload_dir, internal_sanitized_name)
        with open(sanitized_file_path, "wb") as sf:
            sf.write(sanitized_text.encode("utf-8"))

    # Verify: re-run detection on sanitized text output
    remaining   = detect(sanitized_text)
    warnings    = []
    if remaining:
        warnings.append(
            f"Re-scan found {len(remaining)} potentially sensitive pattern(s) "
            "still detectable in the sanitized text. Review before sharing."
        )
    if mode == "pseudonymize" and sanitized_file_type in ("png", "jpg", "jpeg"):
        warnings.append(
            "Images are protected with visual redaction; pseudonym tokens are "
            "available only in the extracted text output."
        )

    # Store sanitized metadata
    db.analyses.update_one(
        {"_id": oid},
        {"$set": {
            "sanitized_text":        sanitized_text,
            "sanitized_filename":    sanitized_filename,
            "sanitized_file_path":   sanitized_file_path,
            "sanitized_mime_type":   sanitized_mime_type,
            "sanitized_file_type":   sanitized_file_type,
            "sanitization_status":   "sanitized",
            "sanitization_mode":     mode,
            "remaining_detections":  len(remaining),
            "sanitization_warnings": warnings,
            "sanitized_at":          datetime.now(timezone.utc),
        }}
    )

    db.sanitized_documents.update_one(
        {"analysis_id": oid, "user_id": uid},
        {"$set": {
            "analysis_id":          oid,
            "document_id":          doc_id,
            "user_id":              uid,
            "sanitized_filename":   sanitized_filename,
            "sanitized_file_path":  sanitized_file_path,
            "sanitized_mime_type":  sanitized_mime_type,
            "mode":                 mode,
            "remaining_detections": len(remaining),
            "pseudonymized":        mode == "pseudonymize",
            "created_at":           datetime.now(timezone.utc),
        }},
        upsert=True,
    )

    db.audit_logs.insert_one({
        "user_id":     uid,
        "action":      "sanitize",
        "analysis_id": str(oid),
        "filename":    sanitized_filename,
        "mode":        mode,
        "status":      "success",
        "timestamp":   datetime.now(timezone.utc),
    })

    return {
        "analysis_id":           analysis_id,
        "sanitized_text":        sanitized_text,
        "sanitized_filename":    sanitized_filename,
        "sanitized_file_type":   sanitized_file_type,
        "mode":                  mode,
        "remaining_detections":  len(remaining),
        "warnings":              warnings,
        "pseudonymized":         mode == "pseudonymize",
        "pseudonym_count":       len(pseudo_entries),
        "download_url":          f"/api/analysis/{analysis_id}/sanitized-download",
        "preview_url":           f"/api/analysis/{analysis_id}/sanitized-preview",
        "original_text_preview": raw_text[:300] + ("..." if len(raw_text) > 300 else ""),
    }


@router.post("/{analysis_id}/restore")
async def restore_analysis(
    analysis_id: str,
    payload: RestoreRequest | None = None,
    current_user: dict = Depends(get_current_user),
):
    """Restore pseudonym tokens to their original values (owner only)."""
    db  = get_db()
    uid = current_user["_id"]
    try:
        oid = ObjectId(analysis_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid analysis ID.")

    a = db.analyses.find_one({"_id": oid, "user_id": uid})
    if not a:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    entries = load_mapping(db, uid, analysis_id)
    if not entries:
        raise HTTPException(
            status_code=400,
            detail="No pseudonym mapping exists for this analysis. "
                   "Sanitize with mode=pseudonymize first.",
        )

    source = payload.text if payload and payload.text is not None else a.get("sanitized_text", "")
    if not source:
        raise HTTPException(status_code=400, detail="No sanitized text available to restore.")

    restored, replaced = restore_text(source, entries)

    db.audit_logs.insert_one({
        "user_id":         uid,
        "action":          "restore",
        "analysis_id":     str(oid),
        "tokens_restored": replaced,
        "status":          "success",
        "timestamp":       datetime.now(timezone.utc),
    })

    return {
        "analysis_id":     analysis_id,
        "restored_text":   restored,
        "tokens_restored": replaced,
        "mapping_entries": len(entries),
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

    if a.get("sanitization_status") != "sanitized":
        raise HTTPException(
            status_code=400,
            detail="This analysis has not been sanitized yet. Run sanitization first."
        )

    sanitized_fp = a.get("sanitized_file_path")
    sanitized_filename = a.get("sanitized_filename") or (a.get("document_name", "document").rsplit(".", 1)[0] + "_sanitized.txt")
    media_type = a.get("sanitized_mime_type") or "text/plain; charset=utf-8"

    if sanitized_fp and os.path.isfile(sanitized_fp):
        with open(sanitized_fp, "rb") as f:
            content = f.read()
    else:
        sanitized = a.get("sanitized_text", "")
        content = sanitized.encode("utf-8")
        media_type = "text/plain; charset=utf-8"

    db.audit_logs.insert_one({
        "user_id":     uid,
        "action":      "download_sanitized",
        "analysis_id": str(oid),
        "filename":    sanitized_filename,
        "status":      "success",
        "timestamp":   datetime.now(timezone.utc),
    })

    return StreamingResponse(
        io.BytesIO(content),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{sanitized_filename}"'},
    )


@router.get("/{analysis_id}/sanitized-preview")
async def preview_sanitized(
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

    if a.get("sanitization_status") != "sanitized":
        raise HTTPException(
            status_code=400,
            detail="This analysis has not been sanitized yet. Run sanitization first."
        )

    sanitized_fp = a.get("sanitized_file_path")
    sanitized_filename = a.get("sanitized_filename") or (a.get("document_name", "document").rsplit(".", 1)[0] + "_sanitized.txt")
    media_type = a.get("sanitized_mime_type") or "text/plain; charset=utf-8"

    if sanitized_fp and os.path.isfile(sanitized_fp):
        with open(sanitized_fp, "rb") as f:
            content = f.read()
    else:
        sanitized = a.get("sanitized_text", "")
        content = sanitized.encode("utf-8")
        media_type = "text/plain; charset=utf-8"

    return StreamingResponse(
        io.BytesIO(content),
        media_type=media_type,
        headers={"Content-Disposition": f'inline; filename="{sanitized_filename}"'},
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

    sanitized = db.sanitized_documents.find_one({"analysis_id": oid, "user_id": uid})
    for path in (a.get("sanitized_file_path"), (sanitized or {}).get("sanitized_file_path")):
        if path and os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass

    db.analyses.delete_one({"_id": oid})
    db.sanitized_documents.delete_many({"analysis_id": oid})
    db.pseudonym_maps.delete_many({"analysis_id": oid, "user_id": uid})
    db.rag_chunks.delete_many({"analysis_id": oid, "user_id": uid})
    return {"message": "Analysis record deleted."}
