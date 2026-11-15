# ============================================================
# app/services/preprocessing.py
# Text normalisation with an offset map back to the original text.
#
# Detection runs on the normalised view, but every returned span is
# mapped back, so highlighting and sanitisation always operate on the
# exact characters of the original document.
# ============================================================
import re
import unicodedata

_NON_PRINTABLE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def preprocess_with_offsets(text: str) -> tuple[str, list[int]]:
    """
    Normalise text and return (clean_text, offsets) where
    offsets[i] is the index of clean_text[i] in the original string.

    Steps:
    1. Unicode NFC normalisation (skipped when it would change length,
       because that would break a 1:1 character mapping)
    2. CR+LF / bare CR -> LF
    3. Remove non-printable control characters
    4. Other unicode whitespace -> regular space
    5. Collapse runs of 3+ newlines to 2 (keeps paragraphs readable)
    """
    if not text:
        return "", []

    normalised = unicodedata.normalize("NFC", text)
    if len(normalised) != len(text):
        normalised = text

    chars: list[str] = []
    mapping: list[int] = []
    i = 0
    length = len(normalised)

    while i < length:
        ch = normalised[i]
        if ch == "\r":
            if i + 1 < length and normalised[i + 1] == "\n":
                chars.append("\n")
                mapping.append(i + 1)
                i += 2
            else:
                chars.append("\n")
                mapping.append(i)
                i += 1
            continue
        if ch in ("\n", "\t"):
            chars.append(ch)
            mapping.append(i)
            i += 1
            continue
        if _NON_PRINTABLE_RE.match(ch):
            i += 1
            continue
        if ch.isspace() and ch != " ":
            chars.append(" ")
            mapping.append(i)
            i += 1
            continue
        chars.append(ch)
        mapping.append(i)
        i += 1

    clean: list[str] = []
    clean_map: list[int] = []
    newline_run = 0
    for ch, original_index in zip(chars, mapping):
        if ch == "\n":
            newline_run += 1
            if newline_run > 2:
                continue
        else:
            newline_run = 0
        clean.append(ch)
        clean_map.append(original_index)

    return "".join(clean), clean_map


def preprocess(text: str) -> str:
    """Backward-compatible normaliser (no offset map)."""
    return preprocess_with_offsets(text)[0]
