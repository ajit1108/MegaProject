# ============================================================
# app/services/sanitization.py
# Format-Preserving Sanitization Engine
# Generates sanitized outputs in the exact same format as the uploaded document:
# - PDF  -> Sanitized PDF (PyMuPDF apply_redactions removes glyphs & underlying text)
# - DOCX -> Sanitized DOCX (python-docx replaces paragraphs, tables, headers)
# - Images (PNG/JPG/JPEG) -> Sanitized Image (Pixel-level bounding box redaction/masking)
# - TXT  -> Sanitized TXT
# ============================================================
import io
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

REDACT_PLACEHOLDERS: dict[str, str] = {
    "EMAIL":          "[EMAIL_REDACTED]",
    "PHONE_IN":       "[PHONE_REDACTED]",
    "PHONE_GENERIC":  "[PHONE_REDACTED]",
    "AADHAAR":        "[AADHAAR_REDACTED]",
    "PAN":            "[PAN_REDACTED]",
    "CREDIT_CARD":    "[CARD_REDACTED]",
    "IP_ADDRESS":     "[IP_REDACTED]",
    "DATE_OF_BIRTH":  "[DOB_REDACTED]",
    "API_KEY":        "[API_KEY_REDACTED]",
    "PASSWORD":       "[PASSWORD_REDACTED]",
    "PERSON_NAME":    "[PERSON_REDACTED]",
    "ORGANIZATION":   "[ORG_REDACTED]",
    "GEO_POLITICAL":  "[LOCATION_REDACTED]",
    "LOCATION":       "[LOCATION_REDACTED]",
    "FACILITY":       "[FACILITY_REDACTED]",
    "FINANCIAL_VALUE":"[FINANCIAL_REDACTED]",
    "DATE":           "[DATE_REDACTED]",
}

DEFAULT_PLACEHOLDER = "[REDACTED]"

MIME_TYPES = {
    "pdf":  "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "txt":  "text/plain; charset=utf-8",
    "png":  "image/png",
    "jpg":  "image/jpeg",
    "jpeg": "image/jpeg",
}


def _mask_value(value: str, entity_type: str) -> str:
    """Produce a masked preview/replacement of a sensitive value."""
    if not value:
        return "***"
    if entity_type == "EMAIL":
        parts = value.split("@")
        local = parts[0]
        domain = parts[1] if len(parts) > 1 else "example.com"
        masked_local = local[0] + "***" if len(local) > 1 else "***"
        return f"{masked_local}@{domain}"
    if entity_type in ("PHONE_IN", "PHONE_GENERIC"):
        digits = re.sub(r"\D", "", value)
        return "X" * max(0, len(digits) - 4) + digits[-4:] if len(digits) >= 4 else "XXXX"
    if entity_type in ("AADHAAR",):
        digits = re.sub(r"\D", "", value)
        return "XXXX-XXXX-" + digits[-4:] if len(digits) >= 4 else "XXXX-XXXX-XXXX"
    if entity_type == "PAN":
        return value[:2] + "***" + value[-2:] if len(value) >= 4 else "***"
    if entity_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        return "*" * max(0, len(digits) - 4) + digits[-4:]
    if len(value) <= 3:
        return "***"
    return value[0] + "*" * (len(value) - 2) + value[-1]


def protect_preview(value: str, entity_type: str) -> str:
    """Return a masked preview safe to display in the UI (never the raw value)."""
    return _mask_value(value, entity_type)


def sanitize(text: str, detections: list[dict[str, Any]], mode: str = "redact") -> str:
    """
    Replace sensitive spans in string text using verified offset positions.
    Processes right-to-left to keep earlier offsets valid.
    """
    if not text or not detections:
        return text

    sorted_by_span = sorted(
        detections,
        key=lambda d: (d.get("start", 0), -d.get("confidence", 0.5), -(d.get("end", 0) - d.get("start", 0)))
    )
    non_overlapping = []
    last_end = -1
    for det in sorted_by_span:
        s = det.get("start", 0)
        e = det.get("end", 0)
        if s >= last_end and e > s:
            non_overlapping.append(det)
            last_end = e

    sorted_detections = sorted(non_overlapping, key=lambda d: d["end"], reverse=True)

    result = text
    for det in sorted_detections:
        start = det.get("start", 0)
        end   = det.get("end", 0)
        etype = det.get("entity_type", "UNKNOWN")

        if start < 0 or end <= start or end > len(result):
            continue

        if mode == "mask":
            replacement = _mask_value(det.get("matched_value", ""), etype)
        else:
            replacement = REDACT_PLACEHOLDERS.get(etype, DEFAULT_PLACEHOLDER)

        result = result[:start] + replacement + result[end:]

    return result


# ── Format-Preserving File Generators ──────────────────────────────

def sanitize_file(
    original_bytes: bytes,
    filename: str,
    detections: list[dict[str, Any]],
    mode: str = "redact",
) -> tuple[bytes, str, str]:
    """
    Sanitize an uploaded file and generate output in the exact same format.

    Returns:
        (sanitized_bytes, sanitized_filename, content_type)
    """
    stem, ext_with_dot = os.path.splitext(filename)
    ext = ext_with_dot.lstrip(".").lower()
    sanitized_filename = f"{stem}_sanitized{ext_with_dot}"

    if ext == "pdf":
        return sanitize_pdf(original_bytes, sanitized_filename, detections, mode)
    elif ext == "docx":
        return sanitize_docx(original_bytes, sanitized_filename, detections, mode)
    elif ext in ("png", "jpg", "jpeg"):
        return sanitize_image(original_bytes, sanitized_filename, ext, detections, mode)
    elif ext == "txt":
        return sanitize_txt(original_bytes, sanitized_filename, detections, mode)
    else:
        # Fallback to plain text if format is unexpected
        sanitized_txt = sanitize(original_bytes.decode("utf-8", errors="replace"), detections, mode)
        return (
            sanitized_txt.encode("utf-8"),
            f"{stem}_sanitized.txt",
            "text/plain; charset=utf-8",
        )


def sanitize_pdf(
    original_bytes: bytes,
    sanitized_filename: str,
    detections: list[dict[str, Any]],
    mode: str = "redact",
) -> tuple[bytes, str, str]:
    """
    Sanitize PDF using PyMuPDF.
    Uses add_redact_annot and apply_redactions(images=fitz.PDF_REDACT_IMAGE_PIXELS)
    to permanently remove underlying text, character codes, and modify pixels.
    """
    try:
        import pymupdf as fitz
    except ImportError:
        import fitz

    doc = fitz.open(stream=original_bytes, filetype="pdf")

    # Collect search values
    values_to_redact: list[tuple[str, str, str]] = []
    for det in detections:
        val = (det.get("matched_value") or "").strip()
        etype = det.get("entity_type", "UNKNOWN")
        if val:
            values_to_redact.append((val, etype, det.get("privacy_class", "")))

    for page in doc:
        for val, etype, _ in values_to_redact:
            rects = page.search_for(val)
            # If multi-token or phone format, also search individual substantial components
            if not rects and " " in val:
                for sub in val.split():
                    if len(sub) >= 4:
                        rects.extend(page.search_for(sub))

            for r in rects:
                if mode == "mask":
                    masked = _mask_value(val, etype)
                    page.add_redact_annot(
                        r,
                        text=masked,
                        fill=(0.93, 0.93, 0.93),
                        text_color=(0, 0, 0),
                        fontsize=8,
                    )
                else:
                    page.add_redact_annot(r, fill=(0, 0, 0))

        # Permanently erase glyphs & redraw underlying page stream
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_PIXELS)

    sanitized_bytes = doc.tobytes(garbage=3, deflate=True)
    doc.close()

    return sanitized_bytes, sanitized_filename, MIME_TYPES["pdf"]


def sanitize_docx(
    original_bytes: bytes,
    sanitized_filename: str,
    detections: list[dict[str, Any]],
    mode: str = "redact",
) -> tuple[bytes, str, str]:
    """
    Sanitize DOCX file using python-docx.
    Replaces sensitive text in paragraphs, tables, headers, and footers.
    """
    from docx import Document

    doc = Document(io.BytesIO(original_bytes))

    replacements: list[tuple[str, str]] = []
    for det in detections:
        val = (det.get("matched_value") or "").strip()
        etype = det.get("entity_type", "UNKNOWN")
        if not val:
            continue
        rep = _mask_value(val, etype) if mode == "mask" else REDACT_PLACEHOLDERS.get(etype, DEFAULT_PLACEHOLDER)
        replacements.append((val, rep))

    # Sort replacements by length descending to prevent substring collisions
    replacements.sort(key=lambda x: len(x[0]), reverse=True)

    def _replace_in_text(text: str) -> str:
        for val, rep in replacements:
            if val in text:
                text = text.replace(val, rep)
        return text

    def _clean_paragraph(p):
        if not p.text:
            return
        new_text = _replace_in_text(p.text)
        if new_text != p.text:
            p.text = new_text

    # 1. Main body paragraphs
    for p in doc.paragraphs:
        _clean_paragraph(p)

    # 2. Tables
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    _clean_paragraph(p)

    # 3. Headers and Footers
    for section in doc.sections:
        if section.header:
            for p in section.header.paragraphs:
                _clean_paragraph(p)
        if section.footer:
            for p in section.footer.paragraphs:
                _clean_paragraph(p)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue(), sanitized_filename, MIME_TYPES["docx"]


def sanitize_image(
    original_bytes: bytes,
    sanitized_filename: str,
    ext: str,
    detections: list[dict[str, Any]],
    mode: str = "redact",
) -> tuple[bytes, str, str]:
    """
    Sanitize an image (PNG, JPG, JPEG) by modifying actual image pixels.
    Locates sensitive terms via OCR word bounding boxes and draws solid redaction boxes
    or blur filters over the target pixel regions.
    """
    from PIL import Image, ImageDraw, ImageFilter, ImageOps
    import pytesseract
    from app.services.text_extraction import _configure_tesseract

    _configure_tesseract()

    img = Image.open(io.BytesIO(original_bytes))
    # Correct orientation based on EXIF tag
    transposed = ImageOps.exif_transpose(img)
    if transposed is not None:
        img = transposed

    # Save original format mode
    save_format = "PNG" if ext == "png" else "JPEG"
    if save_format == "JPEG" and img.mode in ("RGBA", "P"):
        img = img.convert("RGB")
    elif img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    # Run OCR to get word-level bounding boxes
    try:
        data = pytesseract.image_to_data(img, lang="eng", output_type=pytesseract.Output.DICT)
    except Exception as exc:
        logger.warning("Failed to obtain OCR bounding boxes for image sanitization: %s", exc)
        data = {"text": [], "left": [], "top": [], "width": [], "height": []}

    num_boxes = len(data.get("text", []))
    words: list[dict] = []
    for i in range(num_boxes):
        w_text = (data["text"][i] or "").strip()
        if w_text:
            clean = re.sub(r"[^a-zA-Z0-9]", "", w_text.lower())
            words.append({
                "raw": w_text,
                "clean": clean,
                "box": (
                    data["left"][i],
                    data["top"][i],
                    data["left"][i] + data["width"][i],
                    data["top"][i] + data["height"][i],
                )
            })

    # Find boxes to redact
    boxes_to_redact: list[tuple[int, int, int, int]] = []
    for det in detections:
        val = (det.get("matched_value") or "").strip()
        if not val:
            continue
        val_clean = re.sub(r"[^a-zA-Z0-9]", "", val.lower())
        tokens = [re.sub(r"[^a-zA-Z0-9]", "", t.lower()) for t in re.split(r"[\s,]+", val) if t]
        tokens = [t for t in tokens if t]

        # 1. Single word / partial word matching
        for w in words:
            if not w["clean"]:
                continue
            # Exact clean match
            if w["clean"] == val_clean or (len(w["clean"]) >= 4 and w["clean"] in val_clean):
                boxes_to_redact.append(w["box"])
            elif any(t == w["clean"] or (len(t) >= 4 and t in w["clean"]) for t in tokens):
                boxes_to_redact.append(w["box"])

        # 2. Multi-word sequence match
        if len(tokens) > 1:
            k = len(tokens)
            for i in range(len(words) - k + 1):
                sub = [words[i + j]["clean"] for j in range(k)]
                if sub == tokens:
                    for j in range(k):
                        boxes_to_redact.append(words[i + j]["box"])

    # Draw redaction on pixels
    draw = ImageDraw.Draw(img)
    pad = 3
    for (x1, y1, x2, y2) in boxes_to_redact:
        rx1 = max(0, x1 - pad)
        ry1 = max(0, y1 - pad)
        rx2 = min(img.width, x2 + pad)
        ry2 = min(img.height, y2 + pad)

        if mode == "mask":
            # Apply heavy blur to the region
            region = img.crop((rx1, ry1, rx2, ry2))
            region = region.filter(ImageFilter.GaussianBlur(radius=10))
            img.paste(region, (rx1, ry1))
            draw.rectangle([rx1, ry1, rx2, ry2], outline=(100, 100, 100), width=1)
        else:
            # Solid black rectangle
            draw.rectangle([rx1, ry1, rx2, ry2], fill=(0, 0, 0))
            # If box has sufficient dimensions, overlay REDACTED label
            bw = rx2 - rx1
            bh = ry2 - ry1
            if bw >= 50 and bh >= 12:
                try:
                    draw.text((rx1 + 3, ry1 + max(0, (bh - 10) // 2)), "[REDACTED]", fill=(255, 255, 255))
                except Exception:
                    pass

    buf = io.BytesIO()
    if save_format == "JPEG":
        img.save(buf, format="JPEG", quality=95)
    else:
        img.save(buf, format="PNG")

    content_type = MIME_TYPES.get(ext, "image/png")
    return buf.getvalue(), sanitized_filename, content_type


def sanitize_txt(
    original_bytes: bytes,
    sanitized_filename: str,
    detections: list[dict[str, Any]],
    mode: str = "redact",
) -> tuple[bytes, str, str]:
    """Sanitize TXT document."""
    text = ""
    for enc in ("utf-8", "utf-16", "latin-1", "ascii"):
        try:
            text = original_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue

    sanitized_text = sanitize(text, detections, mode)
    return sanitized_text.encode("utf-8"), sanitized_filename, MIME_TYPES["txt"]

