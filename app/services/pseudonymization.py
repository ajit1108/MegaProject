# ============================================================
# app/services/pseudonymization.py
# Consistent pseudonymization with an encrypted, restorable mapping.
#
# Tokens are deterministic per (analysis, entity, value), so the same value
# is replaced by the same token throughout a document. The original values
# are only ever stored Fernet-encrypted and are never returned by the API.
# ============================================================
from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone

from bson import ObjectId
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

_FERNET_CONTEXT = "sdd-pseudonym-v1"


def _fernet() -> Fernet:
    settings = get_settings()
    seed = (settings.pseudonym_key or settings.secret_key or "").encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(_FERNET_CONTEXT.encode() + seed).digest())
    return Fernet(key)


def _token(analysis_id: str, entity_type: str, value: str) -> str:
    seed = (get_settings().secret_key or "").encode("utf-8")
    digest = hmac.new(
        seed,
        f"{analysis_id}|{entity_type}|{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:8].upper()
    label = entity_type.replace("_FORMAT", "")[:12]
    return f"[{label}_{digest}]"


def build_pseudonyms(
    analysis_id: str, detections: list[dict]
) -> tuple[dict[tuple[int, int], str], dict[tuple[str, str], str], list[dict]]:
    """
    Return (span_replacements, value_replacements, encrypted_entries).

    span_replacements  keyed by (start, end) for text sanitization.
    value_replacements keyed by (entity_type, matched_value) for file formats
                       that locate text by value rather than offset.
    encrypted_entries  one entry per distinct token, safe to persist.
    """
    span_map: dict[tuple[int, int], str] = {}
    value_map: dict[tuple[str, str], str] = {}
    entries: dict[str, dict] = {}
    cipher = _fernet()

    for det in detections:
        value = (det.get("matched_value") or "").strip()
        entity_type = det.get("entity_type") or "UNKNOWN"
        if not value:
            continue

        key = (entity_type, value)
        token = value_map.get(key)
        if token is None:
            token = _token(analysis_id, entity_type, value)
            # Extremely unlikely HMAC collision; disambiguate deterministically.
            if token in entries and entries[token]["entity_type"] != entity_type:
                token = f"{token[:-1]}_{len(entries):X}]"
            value_map[key] = token
            entries[token] = {
                "token": token,
                "entity_type": entity_type,
                "ciphertext": cipher.encrypt(value.encode("utf-8")).decode("ascii"),
            }

        start, end = det.get("start"), det.get("end")
        if isinstance(start, int) and isinstance(end, int) and end > start:
            span_map[(start, end)] = token

    return span_map, value_map, list(entries.values())


def restore_text(sanitized_text: str, entries: list[dict]) -> tuple[str, int]:
    """Replace pseudonym tokens with their decrypted originals."""
    if not sanitized_text or not entries:
        return sanitized_text, 0

    cipher = _fernet()
    restored = sanitized_text
    replaced = 0
    for entry in sorted(entries, key=lambda e: len(e.get("token", "")), reverse=True):
        token = entry.get("token")
        if not token or token not in restored:
            continue
        try:
            value = cipher.decrypt(entry["ciphertext"].encode("ascii")).decode("utf-8")
        except (InvalidToken, KeyError, ValueError):
            continue
        replaced += restored.count(token)
        restored = restored.replace(token, value)
    return restored, replaced


def store_mapping(db, user_id, analysis_id: str, entries: list[dict]) -> None:
    db.pseudonym_maps.replace_one(
        {"analysis_id": ObjectId(analysis_id), "user_id": user_id},
        {
            "analysis_id": ObjectId(analysis_id),
            "user_id": user_id,
            "entries": entries,
            "created_at": datetime.now(timezone.utc),
        },
        upsert=True,
    )


def load_mapping(db, user_id, analysis_id: str) -> list[dict]:
    record = db.pseudonym_maps.find_one(
        {"analysis_id": ObjectId(analysis_id), "user_id": user_id}
    )
    return (record or {}).get("entries", [])
