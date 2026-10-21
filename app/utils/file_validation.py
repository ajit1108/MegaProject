# ============================================================
# app/utils/file_validation.py — Upload file validation
# ============================================================
import os
from fastapi import UploadFile, HTTPException, status
from app.config import get_settings

MIME_TO_EXT: dict[str, list[str]] = {
    "application/pdf": ["pdf"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
    "text/plain": ["txt"],
    "image/png": ["png"],
    "image/jpeg": ["jpg", "jpeg"],
}


async def validate_upload(file: UploadFile) -> bytes:
    """
    Validates the upload and returns raw bytes.
    Raises HTTPException on validation failure.
    """
    settings = get_settings()

    # --- Extension check ---
    filename = file.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in settings.allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type '.{ext}' is not supported. Allowed: {', '.join(settings.allowed_extensions)}",
        )

    # --- Read content ---
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # --- Size check ---
    if len(content) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"File exceeds the {settings.max_upload_size_mb} MB size limit.",
        )

    # --- MIME / magic-byte check ---
    detected_mime = _detect_mime(content, filename)
    allowed_mimes = settings.allowed_mime_types
    if detected_mime not in allowed_mimes:
        raise HTTPException(
            status_code=400,
            detail=f"File content type '{detected_mime}' does not match a supported format.",
        )

    # --- Image integrity check ---
    if ext in ("png", "jpg", "jpeg") or detected_mime.startswith("image/"):
        try:
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(content))
            img.verify()
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Uploaded image is corrupted or invalid.",
            )

    return content


def _detect_mime(content: bytes, filename: str) -> str:
    """Best-effort MIME detection from magic bytes / header."""
    if content[:4] == b"%PDF":
        return "application/pdf"
    if content[:2] == b"PK" and filename.lower().endswith(".docx"):
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    # Fallback to Pillow
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(content))
        if img.format == "PNG":
            return "image/png"
        if img.format in ("JPEG", "JPG"):
            return "image/jpeg"
    except Exception:
        pass
    # Fallback: assume text
    try:
        content.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def safe_filename(original: str) -> str:
    """Return a sanitised filename safe for disk storage."""
    import re, uuid
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else "bin"
    return f"{uuid.uuid4().hex}.{ext}"
