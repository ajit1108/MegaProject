# ============================================================
# app/routes/dashboard.py — Dashboard statistics
# ============================================================
from fastapi import APIRouter, Depends
from app.database import get_db
from app.security.authentication import get_current_user
from app.models.schemas import DashboardStats, AnalysisHistoryItem
from bson import ObjectId
from datetime import datetime

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_stats(current_user: dict = Depends(get_current_user)):
    db = get_db()
    uid = current_user["_id"]

    total_documents = db.documents.count_documents({"user_id": uid})
    total_analyses  = db.analyses.count_documents({"user_id": uid})

    pipeline_detections = [
        {"$match": {"user_id": uid}},
        {"$group": {"_id": None, "total": {"$sum": "$total_detections"}}},
    ]
    agg = list(db.analyses.aggregate(pipeline_detections))
    total_detections = agg[0]["total"] if agg else 0

    high_risk   = db.analyses.count_documents({"user_id": uid, "risk_level": "High Risk"})
    medium_risk = db.analyses.count_documents({"user_id": uid, "risk_level": "Medium Risk"})
    low_risk    = db.analyses.count_documents({"user_id": uid, "risk_level": "Low Risk"})

    # Recent 5 analyses
    recent_cursor = db.analyses.find(
        {"user_id": uid},
        {"document_name": 1, "total_detections": 1, "risk_score": 1,
         "risk_level": 1, "sanitization_status": 1, "created_at": 1}
    ).sort("created_at", -1).limit(5)

    recent = []
    for r in recent_cursor:
        recent.append(AnalysisHistoryItem(
            id=str(r["_id"]),
            document_name=r.get("document_name", "Unknown"),
            total_detections=r.get("total_detections", 0),
            risk_score=r.get("risk_score", 0),
            risk_level=r.get("risk_level", "Low Risk"),
            sanitization_status=r.get("sanitization_status", "not_sanitized"),
            created_at=r.get("created_at", datetime.utcnow()),
        ))

    # Classification distribution
    class_pipeline = [
        {"$match": {"user_id": uid}},
        {"$unwind": "$detections"},
        {"$group": {"_id": "$detections.privacy_class", "count": {"$sum": 1}}},
    ]
    class_dist = {r["_id"]: r["count"] for r in db.analyses.aggregate(class_pipeline)}

    risk_dist = {"High Risk": high_risk, "Medium Risk": medium_risk, "Low Risk": low_risk}

    return DashboardStats(
        total_documents=total_documents,
        total_analyses=total_analyses,
        total_detections=total_detections,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        recent_analyses=recent,
        class_distribution=class_dist,
        risk_distribution=risk_dist,
    )
