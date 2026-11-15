# ============================================================
# app/routes/auth.py — Authentication endpoints
# ============================================================
from fastapi import APIRouter, HTTPException, status, Depends, Request
from datetime import datetime, timezone
from bson import ObjectId
from app.database import get_db
from app.models.schemas import RegisterRequest, LoginRequest, TokenResponse, UserOut
from app.security.authentication import (
    hash_password, verify_password, create_access_token, get_current_user,
    decode_token, revoke_token, oauth2_scheme,
)
from app.services import login_throttle

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _serialize_user(user: dict) -> dict:
    return {
        "id":         str(user["_id"]),
        "name":       user["name"],
        "email":      user["email"],
        "role":       user.get("role", "user"),
        "created_at": user["created_at"],
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest):
    db = get_db()

    # Duplicate email check
    if db.users.find_one({"email": payload.email.lower()}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email address already exists."
        )

    user_doc = {
        "name":          payload.name.strip(),
        "email":         payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "role":          "user",
        "created_at":    datetime.now(timezone.utc),
    }
    result = db.users.insert_one(user_doc)

    # Audit log
    db.audit_logs.insert_one({
        "user_id":   result.inserted_id,
        "action":    "register",
        "status":    "success",
        "timestamp": datetime.now(timezone.utc),
    })

    return {"message": "Account created successfully. Please log in."}


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, request: Request):
    db = get_db()
    client_ip = request.client.host if request.client else "unknown"
    throttle_key = login_throttle.attempt_key(payload.email, client_ip)

    locked = login_throttle.lock_seconds(throttle_key)
    if locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {locked} seconds.",
            headers={"Retry-After": str(locked)},
        )

    user = db.users.find_one({"email": payload.email.lower()})

    if not user or not verify_password(payload.password, user["password_hash"]):
        login_throttle.record_failure(throttle_key)
        # Log failed attempt
        db.audit_logs.insert_one({
            "user_id":   None,
            "action":    "login_failed",
            "email":     payload.email.lower(),
            "status":    "failure",
            "timestamp": datetime.now(timezone.utc),
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password."
        )

    login_throttle.clear(throttle_key)
    token = create_access_token({"sub": str(user["_id"])})

    # Audit log
    db.audit_logs.insert_one({
        "user_id":   user["_id"],
        "action":    "login",
        "status":    "success",
        "timestamp": datetime.now(timezone.utc),
    })

    return TokenResponse(
        access_token=token,
        user_id=str(user["_id"]),
        name=user["name"],
        role=user.get("role", "user"),
    )


@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(get_current_user),
):
    payload = decode_token(token)
    revoke_token(payload, user_id=current_user["_id"])
    get_db().audit_logs.insert_one({
        "user_id":   current_user["_id"],
        "action":    "logout",
        "status":    "success",
        "timestamp": datetime.now(timezone.utc),
    })
    return {"message": "Signed out successfully."}


@router.get("/me", response_model=UserOut)
async def me(current_user: dict = Depends(get_current_user)):
    return UserOut(**{
        "id":         str(current_user["_id"]),
        "name":       current_user["name"],
        "email":      current_user["email"],
        "role":       current_user.get("role", "user"),
        "created_at": current_user["created_at"],
    })
