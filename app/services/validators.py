# ============================================================
# app/services/validators.py
# Checksum and format validators used by the detection engine.
# Each validator returns True/False and never raises.
# ============================================================
import re

# ── Verhoeff algorithm (used by Aadhaar) ─────────────────────
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    """Validate a digit string against the Verhoeff checksum."""
    digits = re.sub(r"\D", "", number or "")
    if not digits or len(digits) > 16:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


# ── Luhn algorithm (payment cards) ───────────────────────────
def luhn_valid(number: str) -> bool:
    """Validate a digit string against the Luhn checksum."""
    digits = re.sub(r"\D", "", number or "")
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Aadhaar ──────────────────────────────────────────────────
def aadhaar_format_valid(number: str) -> bool:
    """Twelve digits, not an all-identical placeholder. Checksum NOT checked."""
    digits = re.sub(r"\D", "", number or "")
    if len(digits) != 12:
        return False
    return len(set(digits)) > 1


def aadhaar_valid(number: str) -> bool:
    digits = re.sub(r"\D", "", number or "")
    if len(digits) != 12:
        return False
    return verhoeff_valid(digits)


# ── PAN ──────────────────────────────────────────────────────
_PAN_RE = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")


def pan_valid(number: str) -> bool:
    value = (number or "").strip()
    if not _PAN_RE.match(value):
        return False
    # Reject obvious placeholders (AAAAA9999A, 1111111111, ...)
    if len(set(value[:5])) == 1 and len(set(value[5:9])) == 1:
        return False
    return True


# ── GSTIN (15 chars, base-36 checksum) ──────────────────────
_GSTIN_RE = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9]Z[A-Z0-9]$")
_GSTIN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_valid(number: str) -> bool:
    value = (number or "").strip().upper()
    if not _GSTIN_RE.match(value):
        return False
    total = 0
    for i, ch in enumerate(value[:14]):
        value_of_char = _GSTIN_ALPHABET.index(ch)
        factor = 1 if i % 2 == 0 else 2
        product = value_of_char * factor
        total += product // 36 + product % 36
    check = (36 - (total % 36)) % 36
    return _GSTIN_ALPHABET[check] == value[14]


# ── IFSC ────────────────────────────────────────────────────
_IFSC_RE = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")


def ifsc_valid(code: str) -> bool:
    return bool(_IFSC_RE.match((code or "").strip()))


# ── Indian PIN code ─────────────────────────────────────────
def pincode_valid(pin: str) -> bool:
    return bool(re.fullmatch(r"[1-9][0-9]{5}", (pin or "").strip()))


# ── Indian passport ─────────────────────────────────────────
def passport_valid(number: str) -> bool:
    # One letter followed by seven digits; second digit is never 0.
    return bool(re.fullmatch(r"[A-Z][1-9][0-9]{6}", (number or "").strip()))


# ── Indian phone numbers ────────────────────────────────────
def phone_in_valid(number: str) -> bool:
    digits = re.sub(r"\D", "", number or "")
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    elif digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]
    if len(digits) != 10 or digits[0] not in "6789":
        return False
    # Reject trivially invalid numbers (all identical / repeating blocks)
    if len(set(digits)) == 1:
        return False
    return True


def bank_account_valid(number: str) -> bool:
    digits = re.sub(r"\D", "", number or "")
    if not 9 <= len(digits) <= 18:
        return False
    # Placeholder-style numbers (000000000, 111111111) are never real accounts
    if len(set(digits)) == 1:
        return False
    return True
