# ============================================================
# app/routes/documents.py — Document upload & management
# ============================================================
import os
import shutil
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from bson import ObjectId
from app.database import get_db
from app.security.authentication import get_current_user
from app.utils.file_validation import validate_upload, safe_filename
from app.config import get_settings
from app.models.schemas import DocumentOut

router = APIRouter(prefix="/api/documents", tags=["Documents"])


def _doc_to_out(doc: dict) -> dict:
    return {
        "id":                str(doc["_id"]),
        "original_filename": doc.get("original_filename", ""),
        "file_type":         doc.get("file_type", ""),
        "file_size":         doc.get("file_size", 0),
        "upload_timestamp":  doc.get("upload_timestamp"),
        "processing_status": doc.get("processing_status", "pending"),
    }


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    settings = get_settings()
    content = await validate_upload(file)   # raises HTTPException on failure

    ext          = (file.filename or "").rsplit(".", 1)[-1].lower()
    internal_name = safe_filename(file.filename or "upload")
    upload_dir    = settings.upload_dir
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, internal_name)

    with open(file_path, "wb") as f:
        f.write(content)

    db = get_db()
    doc = {
        "user_id":           current_user["_id"],
        "original_filename": file.filename,
        "internal_filename": internal_name,
        "file_path":         file_path,
        "file_type":         ext,
        "file_size":         len(content),
        "upload_timestamp":  datetime.now(timezone.utc),
        "processing_status": "pending",
    }
    result = db.documents.insert_one(doc)
    doc["_id"] = result.inserted_id

    db.audit_logs.insert_one({
        "user_id":   current_user["_id"],
        "action":    "upload_document",
        "document_id": str(result.inserted_id),
        "status":    "success",
        "timestamp": datetime.now(timezone.utc),
    })

    return {
        "id":               str(result.inserted_id),
        "original_filename": file.filename,
        "file_type":        ext,
        "file_size":        len(content),
        "message":          "File uploaded successfully. You can now analyse it.",
    }


@router.get("", response_model=list)
async def list_documents(current_user: dict = Depends(get_current_user)):
    db  = get_db()
    uid = current_user["_id"]
    docs = db.documents.find(
        {"user_id": uid},
        {"file_path": 0, "internal_filename": 0}   # exclude internal paths
    ).sort("upload_timestamp", -1)
    return [_doc_to_out(d) for d in docs]


@router.get("/{document_id}")
async def get_document(
    document_id: str,
    current_user: dict = Depends(get_current_user),
):
    db  = get_db()
    uid = current_user["_id"]
    try:
        oid = ObjectId(document_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document ID.")

    doc = db.documents.find_one(
        {"_id": oid, "user_id": uid},
        {"file_path": 0, "internal_filename": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")
    return _doc_to_out(doc)


@router.delete("/{document_id}", status_code=status.HTTP_200_OK)
async def delete_document(
    document_id: str,
    current_user: dict = Depends(get_current_user),
):
    db  = get_db()
    uid = current_user["_id"]
    try:
        oid = ObjectId(document_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document ID.")

    doc = db.documents.find_one({"_id": oid, "user_id": uid})
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    # Delete file from disk
    fp = doc.get("file_path", "")
    if fp and os.path.isfile(fp):
        try:
            os.remove(fp)
        except OSError:
            pass

    # Delete from DB (cascade to analyses)
    db.documents.delete_one({"_id": oid})
    db.analyses.delete_many({"document_id": oid})
    db.sanitized_documents.delete_many({"document_id": oid})

    db.audit_logs.insert_one({
        "user_id":   uid,
        "action":    "delete_document",
        "document_id": str(oid),
        "status":    "success",
        "timestamp": datetime.now(timezone.utc),
    })

    return {"message": "Document and associated analyses deleted."}
