# ============================================================
# app/services/login_throttle.py
# Short rolling-window lockout for repeated failed logins.
# The key is a SHA-256 of email + client IP, so raw identifiers
# are not persisted by the throttle table.
# ============================================================
import hashlib
from datetime import datetime, timedelta, timezone

from app.database import get_db

MAX_ATTEMPTS = 5
WINDOW = timedelta(minutes=15)


def attempt_key(email: str, ip: str) -> str:
    return hashlib.sha256(f"{(email or '').lower()}|{ip or ''}".encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def lock_seconds(key: str) -> int:
    """Return remaining lockout seconds, or 0 when not locked."""
    record = get_db().login_attempts.find_one({"_id": key})
    if not record:
        return 0
    last_at = _aware(record.get("last_at"))
    if not last_at or _now() - last_at > WINDOW:
        return 0
    if int(record.get("count", 0)) < MAX_ATTEMPTS:
        return 0
    remaining = WINDOW - (_now() - last_at)
    return max(1, int(remaining.total_seconds()))


def record_failure(key: str) -> None:
    db = get_db()
    now = _now()
    record = db.login_attempts.find_one({"_id": key})
    last_at = _aware(record.get("last_at")) if record else None
    if not record or not last_at or now - last_at > WINDOW:
        db.login_attempts.replace_one(
            {"_id": key}, {"count": 1, "first_at": now, "last_at": now}, upsert=True
        )
    else:
        db.login_attempts.update_one(
            {"_id": key}, {"$inc": {"count": 1}, "$set": {"last_at": now}}
        )


def clear(key: str) -> None:
    get_db().login_attempts.delete_one({"_id": key})
