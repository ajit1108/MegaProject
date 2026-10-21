# ============================================================
# app/routes/reports.py — Reports and CSV export
# ============================================================
import io
import csv
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from app.database import get_db
from app.security.authentication import get_current_user

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/summary")
async def report_summary(current_user: dict = Depends(get_current_user)):
    db  = get_db()
    uid = current_user["_id"]

    total_analyses  = db.analyses.count_documents({"user_id": uid})
    pipeline_totals = [
        {"$match": {"user_id": uid}},
        {"$group": {"_id": None, "total_detections": {"$sum": "$total_detections"}}},
    ]
    agg = list(db.analyses.aggregate(pipeline_totals))
    total_detections = agg[0]["total_detections"] if agg else 0

    # Risk distribution
    risk_dist = {}
    for rl in ("High Risk", "Medium Risk", "Low Risk"):
        risk_dist[rl] = db.analyses.count_documents({"user_id": uid, "risk_level": rl})

    # Classification distribution
    class_pipeline = [
        {"$match": {"user_id": uid}},
        {"$unwind": "$detections"},
        {"$group": {"_id": "$detections.privacy_class", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    class_dist = {r["_id"]: r["count"] for r in db.analyses.aggregate(class_pipeline)}

    # Top entity types
    entity_pipeline = [
        {"$match": {"user_id": uid}},
        {"$unwind": "$detections"},
        {"$group": {"_id": "$detections.entity_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_entities = [{"entity_type": r["_id"], "count": r["count"]}
                    for r in db.analyses.aggregate(entity_pipeline)]

    return {
        "total_analyses":    total_analyses,
        "total_detections":  total_detections,
        "risk_distribution": risk_dist,
        "class_distribution": class_dist,
        "top_entity_types":  top_entities,
    }


@router.get("/export")
async def export_csv(current_user: dict = Depends(get_current_user)):
    """Export analysis history as CSV (masked values only, no raw sensitive data)."""
    db  = get_db()
    uid = current_user["_id"]

    analyses = db.analyses.find(
        {"user_id": uid},
        {"extracted_text": 0}   # exclude full text
    ).sort("created_at", -1)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Analysis ID", "Document Name", "Date", "Total Detections",
        "Risk Score", "Risk Level", "Sanitization Status",
        "Restricted Count", "Confidential Count", "Internal Count", "Public Count"
    ])

    for a in analyses:
        cs = a.get("class_summary", {})
        writer.writerow([
            str(a["_id"]),
            a.get("document_name", ""),
            a.get("created_at", "").isoformat() if hasattr(a.get("created_at", ""), "isoformat") else str(a.get("created_at", "")),
            a.get("total_detections", 0),
            a.get("risk_score", 0),
            a.get("risk_level", ""),
            a.get("sanitization_status", ""),
            cs.get("Restricted", 0),
            cs.get("Confidential", 0),
            cs.get("Internal", 0),
            cs.get("Public", 0),
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=analysis_report.csv"},
    )
