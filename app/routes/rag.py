# ============================================================
# app/routes/rag.py — Privacy-aware document Q&A
# ============================================================
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from app.database import get_db
from app.models.schemas import RagQueryRequest
from app.security.authentication import get_current_user
from app.services import rag

router = APIRouter(prefix="/api/rag", tags=["Privacy-aware RAG"])


def _analysis_for_user(db, uid, analysis_id: str) -> dict:
    try:
        oid = ObjectId(analysis_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid analysis ID.")
    analysis = db.analyses.find_one({"_id": oid, "user_id": uid})
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


@router.post("/index/{analysis_id}")
async def index_document(analysis_id: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    uid = current_user["_id"]
    analysis = _analysis_for_user(db, uid, analysis_id)

    count = rag.index_analysis(db, uid, analysis)
    db.audit_logs.insert_one({
        "user_id": uid,
        "action": "rag_index",
        "analysis_id": analysis_id,
        "document_id": str(analysis.get("document_id", "")),
        "chunks": count,
        "status": "success",
        "timestamp": datetime.now(timezone.utc),
    })
    return {"analysis_id": analysis_id, "indexed_chunks": count}


@router.post("/query")
async def query_documents(
    payload: RagQueryRequest,
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    try:
        return rag.run_query(
            db,
            current_user["_id"],
            payload.question,
            document_ids=payload.document_ids,
            conversation_id=payload.conversation_id,
            top_k=payload.top_k,
            debug=payload.debug,
        )
    except rag.ConversationNotFound:
        raise HTTPException(status_code=404, detail="Conversation not found.")


@router.get("/conversations")
async def list_conversations(current_user: dict = Depends(get_current_user)):
    db = get_db()
    rows = db.rag_conversations.find(
        {"user_id": current_user["_id"]},
        {"title": 1, "created_at": 1, "updated_at": 1, "messages": 1},
    ).sort("updated_at", -1).limit(50)
    return [
        {
            "id": str(row["_id"]),
            "title": row.get("title", "Conversation"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "message_count": len(row.get("messages", [])),
        }
        for row in rows
    ]


@router.get("/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: str,
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    try:
        oid = ObjectId(conversation_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid conversation ID.")

    convo = db.rag_conversations.find_one(
        {"_id": oid, "user_id": current_user["_id"]}
    )
    if not convo:
        raise HTTPException(status_code=404, detail="Conversation not found.")

    return {
        "id": str(convo["_id"]),
        "title": convo.get("title", "Conversation"),
        "created_at": convo.get("created_at"),
        "updated_at": convo.get("updated_at"),
        "messages": convo.get("messages", []),
    }


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(
    conversation_id: str,
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    try:
        oid = ObjectId(conversation_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid conversation ID.")

    result = db.rag_conversations.delete_one(
        {"_id": oid, "user_id": current_user["_id"]}
    )
    if not result.deleted_count:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return {"message": "Conversation deleted."}


@router.get("/documents")
async def indexed_documents(current_user: dict = Depends(get_current_user)):
    """Live indexed documents for the signed-in user. Counts come from MongoDB."""
    db = get_db()
    uid = current_user["_id"]
    live = set(db.documents.distinct("_id", {"user_id": uid}))
    rows = db.rag_chunks.aggregate([
        {"$match": {"user_id": uid, "document_id": {"$in": list(live)}}},
        {"$group": {
            "_id": "$document_id",
            "document_name": {"$first": "$document_name"},
            "analysis_id": {"$first": "$analysis_id"},
            "chunks": {"$sum": 1},
            "embedded": {"$sum": {"$cond": [{"$isArray": "$embedding"}, 1, 0]}},
        }},
        {"$sort": {"document_name": 1}},
    ])
    return [
        {
            "document_id": str(row["_id"]),
            "analysis_id": str(row.get("analysis_id", "")),
            "document_name": row.get("document_name") or "document",
            "chunks": row.get("chunks", 0),
            "embedded_chunks": row.get("embedded", 0),
        }
        for row in rows
    ]


@router.get("/stats")
async def rag_stats(current_user: dict = Depends(get_current_user)):
    db = get_db()
    uid = current_user["_id"]
    live = set(db.documents.distinct("_id", {"user_id": uid}))
    scope = {"user_id": uid, "document_id": {"$in": list(live)}}
    chunks = db.rag_chunks.count_documents(scope)
    analyses = len(db.rag_chunks.distinct("analysis_id", scope))
    embedded = db.rag_chunks.count_documents({**scope, "embedding_status": "ok"})
    conversations = db.rag_conversations.count_documents({"user_id": uid})
    failed = db.analyses.count_documents({"user_id": uid, "indexing_status": "failed"})
    return {
        "indexed_analyses": analyses,
        "indexed_documents": analyses,
        "indexed_chunks": chunks,
        "embedded_chunks": embedded,
        "indexing_failures": failed,
        "conversations": conversations,
    }
