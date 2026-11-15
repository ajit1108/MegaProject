# ============================================================
# app/services/text_extraction.py
# Extracts text from PDF, DOCX, TXT, and images (OCR)
# ============================================================
import io
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    text: str
    file_type: str
    used_ocr: bool
    warnings: list[str]
    success: bool
    error: Optional[str] = None
    page_count: int = 1
    # (start, end, page_number) spans into `text`, sorted by start.
    # DOCX and TXT have no reliable page breaks, so they report a single span.
    page_spans: list[tuple[int, int, int]] = field(default_factory=list)


def page_for_offset(page_spans: list[tuple[int, int, int]], offset: int) -> int:
    """Map a character offset to its 1-based source page (default 1)."""
    for start, end, page in page_spans:
        if start <= offset < end:
            return page
    if page_spans and offset >= page_spans[-1][1]:
        return page_spans[-1][2]
    return 1


def _single_page(text: str) -> tuple[int, list[tuple[int, int, int]]]:
    return 1, ([(0, len(text), 1)] if text else [])


def extract_text(content: bytes, filename: str) -> ExtractionResult:
    """
    Dispatch to the appropriate extractor based on file extension.
    Returns ExtractionResult with extracted text and metadata.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    warnings: list[str] = []

    if ext == "pdf":
        return _extract_pdf(content, warnings)
    elif ext == "docx":
        return _extract_docx(content, warnings)
    elif ext == "txt":
        return _extract_txt(content, warnings)
    elif ext in ("png", "jpg", "jpeg"):
        return _extract_image_ocr(content, ext, warnings)
    else:
        return ExtractionResult(
            text="", file_type=ext, used_ocr=False, warnings=[],
            success=False, error=f"Unsupported file type: {ext}"
        )


def _configure_tesseract():
    """Ensure pytesseract points to the effective tesseract binary."""
    try:
        import pytesseract
        from app.config import get_settings
        settings = get_settings()
        cmd = settings.effective_tesseract_cmd
        if cmd and os.path.isfile(cmd):
            pytesseract.pytesseract.tesseract_cmd = cmd
        return pytesseract
    except Exception as exc:
        logger.warning("Could not configure pytesseract: %s", exc)
        return None


# ── PDF ───────────────────────────────────────────────────────
def _extract_pdf(content: bytes, warnings: list[str]) -> ExtractionResult:
    try:
        try:
            import pymupdf as fitz
        except ImportError:
            import fitz
    except ImportError:
        return ExtractionResult(
            text="", file_type="pdf", used_ocr=False, warnings=[],
            success=False, error="PyMuPDF (fitz) is not installed."
        )

    try:
        doc = fitz.open(stream=content, filetype="pdf")
        pages_text: list[str] = []
        used_ocr = False

        for page_idx, page in enumerate(doc):
            p_text = page.get_text("text").strip()
            # If the page contains very little or no selectable text, attempt OCR
            if len(p_text) < 20:
                try:
                    mat = fitz.Matrix(2, 2)  # 2x zoom for clarity
                    pix = page.get_pixmap(matrix=mat)
                    img_bytes = pix.tobytes("png")
                    ocr_text = _ocr_image_bytes(img_bytes)
                    if ocr_text and ocr_text.strip():
                        p_text = ocr_text.strip()
                        used_ocr = True
                except Exception as ocr_err:
                    logger.warning("OCR failed for PDF page %d: %s", page_idx + 1, ocr_err)
            pages_text.append(p_text)

        doc.close()
        # Join only non-empty pages, recording the offset range of each page so
        # detections can be mapped back to the page they came from.
        chunks: list[str] = []
        page_spans: list[tuple[int, int, int]] = []
        cursor = 0
        for page_idx, p_text in enumerate(pages_text, start=1):
            if not p_text:
                continue
            if chunks:
                chunks.append("\n\n")
                cursor += 2
            start = cursor
            chunks.append(p_text)
            cursor += len(p_text)
            page_spans.append((start, cursor, page_idx))
        full_text = "".join(chunks)

        if used_ocr:
            warnings.append("OCR was performed on scanned or low-text PDF pages.")

        if not full_text:
            warnings.append("PDF contains no readable text or scanned content.")

        return ExtractionResult(
            text=full_text,
            file_type="pdf",
            used_ocr=used_ocr,
            warnings=warnings,
            success=True,
            page_count=len(pages_text) or 1,
            page_spans=page_spans,
        )

    except Exception as exc:
        logger.warning("PDF extraction error: %s", exc)
        return ExtractionResult(
            text="", file_type="pdf", used_ocr=False, warnings=[],
            success=False, error=f"PDF extraction failed: {exc}"
        )


# ── DOCX ──────────────────────────────────────────────────────
def _extract_docx(content: bytes, warnings: list[str]) -> ExtractionResult:
    try:
        from docx import Document
        doc = Document(io.BytesIO(content))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        # Also extract text from tables
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text.strip():
                        paragraphs.append(cell.text.strip())
        text = "\n".join(paragraphs).strip()
        if not text:
            warnings.append("DOCX contains no extractable text.")
        page_count, page_spans = _single_page(text)
        return ExtractionResult(
            text=text, file_type="docx", used_ocr=False,
            warnings=warnings, success=True,
            page_count=page_count, page_spans=page_spans,
        )
    except ImportError:
        return ExtractionResult(
            text="", file_type="docx", used_ocr=False, warnings=[],
            success=False, error="python-docx is not installed."
        )
    except Exception as exc:
        logger.warning("DOCX extraction error: %s", exc)
        return ExtractionResult(
            text="", file_type="docx", used_ocr=False, warnings=[],
            success=False, error=f"DOCX extraction failed: {exc}"
        )


# ── TXT ───────────────────────────────────────────────────────
def _extract_txt(content: bytes, warnings: list[str]) -> ExtractionResult:
    for encoding in ("utf-8", "utf-16", "latin-1", "ascii"):
        try:
            text = content.decode(encoding).strip()
            page_count, page_spans = _single_page(text)
            return ExtractionResult(
                text=text, file_type="txt", used_ocr=False,
                warnings=warnings, success=True,
                page_count=page_count, page_spans=page_spans,
            )
        except UnicodeDecodeError:
            continue
    return ExtractionResult(
        text="", file_type="txt", used_ocr=False, warnings=[],
        success=False, error="Could not decode text file. Unknown encoding."
    )


# ── Image OCR ─────────────────────────────────────────────────
def _extract_image_ocr(content: bytes, ext: str, warnings: list[str]) -> ExtractionResult:
    try:
        from PIL import Image, ImageOps
        image = Image.open(io.BytesIO(content))
        # Handle EXIF orientation (rotated images from phone/camera)
        image = ImageOps.exif_transpose(image)
        if image is None:
            image = Image.open(io.BytesIO(content))
    except Exception as exc:
        return ExtractionResult(
            text="", file_type=ext, used_ocr=False, warnings=[],
            success=False, error=f"Invalid or corrupted image: {exc}"
        )

    text = _ocr_pil_image(image)
    if not text:
        warnings.append("No readable text found in the image. Please ensure the image is clear and well-lit.")

    page_count, page_spans = _single_page(text)
    return ExtractionResult(
        text=text, file_type=ext, used_ocr=True,
        warnings=warnings, success=True,
        page_count=page_count, page_spans=page_spans,
    )


def _ocr_pil_image(image) -> str:
    """Run Tesseract OCR on a PIL Image object."""
    try:
        pytesseract = _configure_tesseract()
        if pytesseract is None:
            return ""

        # Preprocessing: convert to grayscale or RGB if needed
        proc_img = image
        if proc_img.mode not in ("RGB", "L"):
            proc_img = proc_img.convert("RGB")

        text = pytesseract.image_to_string(proc_img, lang="eng")
        return text.strip()
    except Exception as exc:
        logger.warning("OCR failed: %s", exc)
        return ""


def _ocr_image_bytes(img_bytes: bytes) -> str:
    """Run Tesseract OCR on raw image bytes."""
    try:
        from PIL import Image, ImageOps
        image = Image.open(io.BytesIO(img_bytes))
        image = ImageOps.exif_transpose(image) or image
        return _ocr_pil_image(image)
    except Exception as exc:
        logger.warning("Failed to open image for OCR: %s", exc)
        return ""
