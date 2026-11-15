# ============================================================
# app/services/document_service.py
# Orchestrates: extraction → preprocessing → detection →
#               classification → risk scoring → storage
# ============================================================
import hashlib
import logging
from datetime import datetime, timezone
from bson import ObjectId
from app.database import get_db
from app.services.text_extraction import extract_text, page_for_offset
from app.services.detection_engine import detect
from app.services.classification import (
    classify,
    class_risk_points,
    data_category,
    category_summary,
)
from app.services.risk_scoring import calculate_risk
from app.services.sanitization import protect_preview

logger = logging.getLogger(__name__)


def analyse_document(document_id: str, content: bytes, filename: str, user_id: str) -> dict:
    """
    Full analysis pipeline.
    Returns the analysis document dict.
    """
    db = get_db()
    doc_oid  = ObjectId(document_id)
    user_oid = ObjectId(user_id)

    # Mark as processing
    db.documents.update_one(
        {"_id": doc_oid},
        {"$set": {"processing_status": "processing"}}
    )

    try:
        # 1. Extract text
        extraction = extract_text(content, filename)
        if not extraction.success:
            db.documents.update_one(
                {"_id": doc_oid},
                {"$set": {"processing_status": "failed"}}
            )
            return {"error": extraction.error or "Extraction failed"}

        raw_text = extraction.text

        # 2. Detect — the engine normalises internally and keeps all
        #    offsets anchored to raw_text, so stored spans stay valid.
        detections = detect(raw_text)

        # 4. Classify + calculate risk contributions
        enriched: list[dict] = []
        for det in detections:
            privacy_class, reason = classify(det)
            risk_pts = class_risk_points(privacy_class)
            enriched.append({
                "entity_type":          det.entity_type,
                "matched_value":        det.matched_value,    # raw — stored server-side
                "protected_preview":    protect_preview(det.matched_value, det.entity_type),
                "start":               det.start,
                "end":                 det.end,
                "page":                page_for_offset(extraction.page_spans, det.start),
                "detection_method":    det.detection_method,
                "confidence":          det.confidence,
                "privacy_class":       privacy_class,
                "classification_reason": reason,
                "category":            data_category(det),
                "risk_points":         risk_pts,
            })

        # 5. Risk score
        risk = calculate_risk(enriched)

        # 6. Class summary
        class_summary = risk.class_counts

        # 7. Text hash (for optional dedup, never store full text)
        text_hash = hashlib.sha256(raw_text.encode()).hexdigest()

        # 8. Build analysis doc
        analysis_doc = {
            "user_id":             user_oid,
            "document_id":         doc_oid,
            "document_name":       filename,
            "text_hash":           text_hash,
            "extracted_text":      raw_text,        # stored for sanitization
            "total_detections":    len(enriched),
            "detections":          enriched,
            "risk_score":          risk.score,
            "risk_level":          risk.level,
            "class_summary":       class_summary,
            "category_summary":    category_summary(enriched),
            "risk_explanation":    risk.explanation,
            "sanitization_status": "not_sanitized",
            "sanitized_text":      None,
            "used_ocr":            extraction.used_ocr,
            "page_count":          extraction.page_count,
            "page_spans":          [list(span) for span in extraction.page_spans],
            "extraction_warnings": extraction.warnings,
            "created_at":          datetime.now(timezone.utc),
        }

        result = db.analyses.insert_one(analysis_doc)
        analysis_doc["_id"] = result.inserted_id

        # Update document status
        db.documents.update_one(
            {"_id": doc_oid},
            {"$set": {"processing_status": "completed"}}
        )

        # Audit
        db.audit_logs.insert_one({
            "user_id":  user_oid,
            "action":   "analyse_document",
            "document_id": str(doc_oid),
            "status":   "success",
            "timestamp": datetime.now(timezone.utc),
        })

        # Build the privacy-aware RAG index (failure must not break analysis)
        try:
            from app.services.rag import index_analysis
            index_analysis(db, user_oid, analysis_doc)
        except Exception as exc:
            logger.warning("RAG indexing failed for analysis %s: %s",
                           analysis_doc["_id"], type(exc).__name__)
            db.analyses.update_one(
                {"_id": analysis_doc["_id"], "user_id": user_oid},
                {"$set": {"indexing_status": "failed", "indexed_chunks": 0}},
            )

        return analysis_doc

    except Exception as exc:
        logger.error("Analysis failed for doc %s: %s", document_id, exc, exc_info=True)
        db.documents.update_one(
            {"_id": doc_oid},
            {"$set": {"processing_status": "failed"}}
        )
        return {"error": str(exc)}
