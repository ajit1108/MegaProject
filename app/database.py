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
    logger.info("MongoDB indexes created.")
