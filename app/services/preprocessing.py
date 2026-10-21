# ============================================================
# app/services/preprocessing.py
# Text preprocessing before sensitive-data detection
# ============================================================
import re
import unicodedata


def preprocess(text: str) -> str:
    """
    Light preprocessing that preserves character offsets as much
    as possible so that detection start/end positions remain valid
    against the original text.

    Steps:
    1. Unicode NFC normalisation
    2. Replace CR+LF and bare CR with LF
    3. Remove non-printable control characters (keep tab, LF)
    4. Collapse runs of 3+ blank lines to 2 blank lines
    """
    # 1. Unicode normalisation
    text = unicodedata.normalize("NFC", text)

    # 2. Normalise line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # 3. Strip non-printable control characters (keep \t and \n)
    text = re.sub(r"[^\S\n\t]", " ", text)          # replace other whitespace chars
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # 4. Collapse excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text
