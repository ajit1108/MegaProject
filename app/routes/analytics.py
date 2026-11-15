# ============================================================
# app/routes/analytics.py
# Analytics derived entirely from MongoDB — no hardcoded figures.
# User endpoints expose only the caller's own rows; admin
# endpoints require the admin role.
# ============================================================
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query

from app.database import get_db
from app.security.authentication import get_current_user, require_admin

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])


def _distribution(db, user_id=None, field: str = "privacy_class") -> dict[str, int]:
    match = {"user_id": user_id} if user_id is not None else {}
    pipeline = [
        {"$match": match},
        {"$unwind": "$detections"},
        {"$group": {"_id": f"$detections.{field}", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return {
        (row["_id"] or "Unknown"): row["count"]
        for row in db.analyses.aggregate(pipeline)
    }


def _top_entities(db, user_id=None, limit: int = 10) -> list[dict]:
    match = {"user_id": user_id} if user_id is not None else {}
    pipeline = [
        {"$match": match},
        {"$unwind": "$detections"},
        {"$group": {"_id": "$detections.entity_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    return [{"entity_type": row["_id"], "count": row["count"]}
            for row in db.analyses.aggregate(pipeline)]


def _risk_distribution(db, user_id=None) -> dict[str, int]:
    match = {"user_id": user_id} if user_id is not None else {}
    return {
        (row["_id"] or "Unknown"): row["count"]
        for row in db.analyses.aggregate([
            {"$match": match},
            {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}},
        ])
    }


def _audit_feed(db, query: dict, skip: int, limit: int) -> list[dict]:
    rows = db.audit_logs.find(
        query,
        {"_id": 0, "email": 0},   # never expose account identifiers in feeds
    ).sort("timestamp", -1).skip(skip).limit(limit)
    feed = []
    for row in rows:
        row["user_id"] = str(row["user_id"]) if row.get("user_id") else None
        feed.append(row)
    return feed


@router.get("/summary")
async def user_summary(current_user: dict = Depends(get_current_user)):
    db = get_db()
    uid = current_user["_id"]

    pipeline_totals = [
        {"$match": {"user_id": uid}},
        {"$group": {
            "_id": None,
            "analyses": {"$sum": 1},
            "detections": {"$sum": "$total_detections"},
            "avg_risk": {"$avg": "$risk_score"},
        }},
    ]
    totals = next(iter(db.analyses.aggregate(pipeline_totals)), {}) or {}

    sanitized_modes = {
        (row["_id"] or "unknown"): row["count"]
        for row in db.sanitized_documents.aggregate([
            {"$match": {"user_id": uid}},
            {"$group": {"_id": "$mode", "count": {"$sum": 1}}},
        ])
    }

    audit_actions = {
        row["_id"]: row["count"]
        for row in db.audit_logs.aggregate([
            {"$match": {"user_id": uid}},
            {"$group": {"_id": "$action", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ])
    }

    return {
        "documents":            db.documents.count_documents({"user_id": uid}),
        "analyses":             totals.get("analyses", 0),
        "total_detections":     totals.get("detections", 0),
        "average_risk_score":   round(totals.get("avg_risk", 0) or 0, 1),
        "sanitized_documents":  db.sanitized_documents.count_documents({"user_id": uid}),
        "sanitization_modes":   sanitized_modes,
        "gateway_inspections":  db.audit_logs.count_documents(
            {"user_id": uid, "action": "gateway_inspect"}
        ),
        "gateway_blocked":      db.audit_logs.count_documents(
            {"user_id": uid, "action": "gateway_inspect", "blocked": True}
        ),
        "rag_conversations":    db.rag_conversations.count_documents({"user_id": uid}),
        "rag_queries":          db.audit_logs.count_documents(
            {"user_id": uid, "action": "rag_query"}
        ),
        "risk_distribution":    _risk_distribution(db, uid),
        "class_distribution":   _distribution(db, uid, "privacy_class"),
        "category_distribution": _distribution(db, uid, "category"),
        "method_distribution":  _distribution(db, uid, "detection_method"),
        "top_entity_types":     _top_entities(db, uid),
        "audit_action_counts":  audit_actions,
        "recent_activity":      _audit_feed(db, {"user_id": uid}, 0, 20),
    }


@router.get("/audit")
async def user_audit(
    action: str | None = Query(default=None, max_length=64),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    query = {"user_id": current_user["_id"]}
    if action:
        query["action"] = action
    return {
        "skip": skip,
        "limit": limit,
        "events": _audit_feed(get_db(), query, skip, limit),
    }


@admin_router.get("/analytics")
async def admin_summary(current_user: dict = Depends(require_admin)):
    db = get_db()

    totals = next(iter(db.analyses.aggregate([
        {"$group": {
            "_id": None,
            "analyses": {"$sum": 1},
            "detections": {"$sum": "$total_detections"},
            "avg_risk": {"$avg": "$risk_score"},
        }},
    ])), {}) or {}

    return {
        "users":                db.users.count_documents({}),
        "documents":            db.documents.count_documents({}),
        "analyses":             totals.get("analyses", 0),
        "total_detections":     totals.get("detections", 0),
        "average_risk_score":   round(totals.get("avg_risk", 0) or 0, 1),
        "sanitized_documents":  db.sanitized_documents.count_documents({}),
        "gateway_inspections":  db.audit_logs.count_documents({"action": "gateway_inspect"}),
        "gateway_blocked":      db.audit_logs.count_documents(
            {"action": "gateway_inspect", "blocked": True}
        ),
        "rag_queries":          db.audit_logs.count_documents({"action": "rag_query"}),
        "risk_distribution":    _risk_distribution(db),
        "class_distribution":   _distribution(db, None, "privacy_class"),
        "category_distribution": _distribution(db, None, "category"),
        "method_distribution":  _distribution(db, None, "detection_method"),
        "top_entity_types":     _top_entities(db, None),
        "audit_action_counts": {
            row["_id"]: row["count"]
            for row in db.audit_logs.aggregate([
                {"$group": {"_id": "$action", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ])
        },
    }


@admin_router.get("/audit")
async def admin_audit(
    action: str | None = Query(default=None, max_length=64),
    user_id: str | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: dict = Depends(require_admin),
):
    query: dict = {}
    if action:
        query["action"] = action
    if user_id:
        try:
            query["user_id"] = ObjectId(user_id)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid user ID.")
    return {
        "skip": skip,
        "limit": limit,
        "events": _audit_feed(get_db(), query, skip, limit),
    }


@admin_router.get("/users")
async def admin_users(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
    current_user: dict = Depends(require_admin),
):
    db = get_db()
    rows = db.users.find({}, {"password_hash": 0}).sort("created_at", -1).skip(skip).limit(limit)
    return [
        {
            "id": str(row["_id"]),
            "name": row.get("name"),
            "email": row.get("email"),
            "role": row.get("role", "user"),
            "created_at": row.get("created_at"),
        }
        for row in rows
    ]
