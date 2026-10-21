# ============================================================
# app/services/text_extraction.py
# Extracts text from PDF, DOCX, TXT, and images (OCR)
# ============================================================
import io
import logging
from dataclasses import dataclass
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
        return _extract_image_ocr(content, warnings)
    else:
        return ExtractionResult(
            text="", file_type=ext, used_ocr=False, warnings=[],
            success=False, error=f"Unsupported file type: {ext}"
        )


# ── PDF ───────────────────────────────────────────────────────
def _extract_pdf(content: bytes, warnings: list[str]) -> ExtractionResult:
    try:
        try:
            import pymupdf as fitz
        except ImportError:
            import fitz
        doc = fitz.open(stream=content, filetype="pdf")
        pages_text = []
        for page in doc:
            pages_text.append(page.get_text("text"))
        doc.close()

        full_text = "\n".join(pages_text).strip()

        # If very little text was extracted, attempt OCR
        if len(full_text) < 50:
            warnings.append(
                "PDF appears to contain little selectable text. "
                "Attempting OCR on page images."
            )
            return _pdf_ocr_fallback(content, warnings)

        return ExtractionResult(
            text=full_text, file_type="pdf", used_ocr=False,
            warnings=warnings, success=True
        )

    except ImportError:
        return ExtractionResult(
            text="", file_type="pdf", used_ocr=False, warnings=[],
            success=False, error="PyMuPDF (fitz) is not installed."
        )
    except Exception as exc:
        logger.warning("PDF extraction error: %s", exc)
        return ExtractionResult(
            text="", file_type="pdf", used_ocr=False, warnings=[],
            success=False, error=f"PDF extraction failed: {exc}"
        )


def _pdf_ocr_fallback(content: bytes, warnings: list[str]) -> ExtractionResult:
    """Render PDF pages as images and run Tesseract OCR."""
    try:
        import fitz
        doc = fitz.open(stream=content, filetype="pdf")
        texts = []
        for page in doc:
            mat = fitz.Matrix(2, 2)   # 2× zoom for better OCR quality
            pix = page.get_pixmap(matrix=mat)
            img_bytes = pix.tobytes("png")
            page_text = _ocr_image_bytes(img_bytes)
            texts.append(page_text)
        doc.close()
        return ExtractionResult(
            text="\n".join(texts).strip(), file_type="pdf",
            used_ocr=True, warnings=warnings, success=True
        )
    except Exception as exc:
        return ExtractionResult(
            text="", file_type="pdf", used_ocr=True, warnings=warnings,
            success=False, error=f"PDF OCR fallback failed: {exc}"
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
        text = "\n".join(paragraphs)
        return ExtractionResult(
            text=text, file_type="docx", used_ocr=False,
            warnings=warnings, success=True
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
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            text = content.decode(encoding)
            return ExtractionResult(
                text=text, file_type="txt", used_ocr=False,
                warnings=warnings, success=True
            )
        except UnicodeDecodeError:
            continue
    return ExtractionResult(
        text="", file_type="txt", used_ocr=False, warnings=[],
        success=False, error="Could not decode text file. Unknown encoding."
    )


# ── Image OCR ─────────────────────────────────────────────────
def _extract_image_ocr(content: bytes, warnings: list[str]) -> ExtractionResult:
    text = _ocr_image_bytes(content)
    if not text:
        warnings.append("OCR produced no output. Check that Tesseract is installed and the image is clear.")
    return ExtractionResult(
        text=text, file_type="image", used_ocr=True,
        warnings=warnings, success=bool(text)
    )


def _ocr_image_bytes(img_bytes: bytes) -> str:
    """Run Tesseract OCR on raw image bytes via pytesseract."""
    try:
        import pytesseract
        from PIL import Image
        from app.config import get_settings
        settings = get_settings()
        if settings.tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = settings.tesseract_cmd
        image = Image.open(io.BytesIO(img_bytes))
        return pytesseract.image_to_string(image, lang="eng")
    except ImportError:
        logger.warning("pytesseract or Pillow not installed.")
        return ""
    except Exception as exc:
        logger.warning("OCR failed: %s", exc)
        return ""
