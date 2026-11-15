# ============================================================
# app/security/authentication.py
# JWT creation, verification, and password hashing
# ============================================================
from datetime import datetime, timedelta, timezone
from typing import Optional
import uuid
from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.config import get_settings
from app.database import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        pwd_bytes = plain.encode("utf-8")[:72]
        return bcrypt.checkpw(pwd_bytes, hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.setdefault("iat", now)
    to_encode.setdefault("jti", uuid.uuid4().hex)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        raise CREDENTIALS_EXCEPTION


def is_token_revoked(payload: dict) -> bool:
    """A token is revoked when its jti is present in the denylist."""
    jti = payload.get("jti")
    if not jti:
        return False
    try:
        return get_db().token_denylist.find_one({"jti": jti}) is not None
    except Exception:
        # DB unavailable: signature and expiry are still enforced upstream.
        return False


def revoke_token(payload: dict, user_id=None) -> None:
    """Add a token's jti to the denylist until its natural expiry."""
    jti = payload.get("jti")
    if not jti:
        return
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
    else:
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=get_settings().access_token_expire_minutes
        )
    get_db().token_denylist.update_one(
        {"jti": jti},
        {"$setOnInsert": {
            "jti": jti,
            "user_id": user_id,
            "expires_at": expires_at,
            "revoked_at": datetime.now(timezone.utc),
        }},
        upsert=True,
    )


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """FastAPI dependency — returns the current authenticated user document."""
    payload = decode_token(token)
    if is_token_revoked(payload):
        raise CREDENTIALS_EXCEPTION
    user_id: str = payload.get("sub")
    if not user_id:
        raise CREDENTIALS_EXCEPTION

    try:
        from bson import ObjectId
        db = get_db()
        user = db.users.find_one({"_id": ObjectId(user_id)})
    except Exception:
        raise CREDENTIALS_EXCEPTION

    if not user:
        raise CREDENTIALS_EXCEPTION
    return user


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")
    return current_user
