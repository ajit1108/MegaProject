# ============================================================
# app/routes/auth.py — Authentication endpoints
# ============================================================
from fastapi import APIRouter, HTTPException, status, Depends
from datetime import datetime, timezone
from bson import ObjectId
from app.database import get_db
from app.models.schemas import RegisterRequest, LoginRequest, TokenResponse, UserOut
from app.security.authentication import (
    hash_password, verify_password, create_access_token, get_current_user
)

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
async def login(payload: LoginRequest):
    db = get_db()
    user = db.users.find_one({"email": payload.email.lower()})

    if not user or not verify_password(payload.password, user["password_hash"]):
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


@router.get("/me", response_model=UserOut)
async def me(current_user: dict = Depends(get_current_user)):
    return UserOut(**{
        "id":         str(current_user["_id"]),
        "name":       current_user["name"],
        "email":      current_user["email"],
        "role":       current_user.get("role", "user"),
        "created_at": current_user["created_at"],
    })
