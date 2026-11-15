# ============================================================
# app/database.py — MongoDB Connection via PyMongo
# ============================================================
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.database import Database
from app.config import get_settings
import logging

logger = logging.getLogger(__name__)

_client: MongoClient | None = None
_db: Database | None = None


def connect_db() -> None:
    """Initialize the MongoDB connection and create indexes."""
    global _client, _db
    settings = get_settings()
    try:
        _client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
        _client.admin.command("ping")   # verify connection
        _db = _client[settings.mongodb_database]
        _create_indexes()
        logger.info("MongoDB connected: %s / %s", settings.mongodb_uri, settings.mongodb_database)
    except Exception as exc:
        logger.error("MongoDB connection failed: %s", exc)
        raise


def close_db() -> None:
    """Close the MongoDB client."""
    global _client
    if _client:
        _client.close()
        logger.info("MongoDB connection closed.")


def get_db() -> Database:
    """Return the active database instance."""
    if _db is None:
        raise RuntimeError("Database not initialised. Call connect_db() first.")
    return _db


def _create_indexes() -> None:
    """Create indexes for performance and uniqueness constraints."""
    db = _db
    # users
    db.users.create_index([("email", ASCENDING)], unique=True)
    # documents
    db.documents.create_index([("user_id", ASCENDING)])
    db.documents.create_index([("upload_timestamp", DESCENDING)])
    # analyses
    db.analyses.create_index([("user_id", ASCENDING)])
    db.analyses.create_index([("document_id", ASCENDING)])
    db.analyses.create_index([("created_at", DESCENDING)])
    # audit_logs
    db.audit_logs.create_index([("user_id", ASCENDING)])
    db.audit_logs.create_index([("timestamp", DESCENDING)])
    # sanitized_documents (one current output per analysis)
    db.sanitized_documents.create_index(
        [("analysis_id", ASCENDING), ("user_id", ASCENDING)], unique=True
    )
    db.sanitized_documents.create_index([("document_id", ASCENDING)])
    # pseudonym_maps (encrypted restoration payloads)
    db.pseudonym_maps.create_index(
        [("analysis_id", ASCENDING), ("user_id", ASCENDING)], unique=True
    )
    # login throttling — rolling window documents expire automatically
    db.login_attempts.create_index([("last_at", ASCENDING)], expireAfterSeconds=900)
    # revoked JWTs — removed once the token would have expired anyway
    db.token_denylist.create_index([("jti", ASCENDING)], unique=True)
    db.token_denylist.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    # RAG chunk index and conversations
    db.rag_chunks.create_index([("user_id", ASCENDING), ("document_id", ASCENDING)])
    db.rag_chunks.create_index(
        [("analysis_id", ASCENDING), ("chunk_index", ASCENDING)], unique=True
    )
    db.rag_conversations.create_index([("user_id", ASCENDING), ("updated_at", DESCENDING)])
    logger.info("MongoDB indexes created.")
