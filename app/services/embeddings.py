# ============================================================
# app/services/embeddings.py
# Local embeddings shared by document chunks and questions.
#
# There is no separate query model: embed_text() is used for both,
# so cosine similarity is comparable.
#
# Default backend is a deterministic feature-hash embedding
# (word unigrams, word bigrams, and character trigrams, signed
# hashing into a fixed dimension, then L2-normalised). Identical
# text always produces the identical vector. This backend has no
# torch dependency and runs on the project's Python 3.14 environment.
#
# If sentence-transformers is installed AND Settings.rag_embedding_backend
# is "sentence-transformers", that model is used instead. A failed
# load falls back to feature hashing and records the model name
# actually used, so documents and queries never mix dimensions.
# ============================================================
from __future__ import annotations

import hashlib
import logging
import math
import re

logger = logging.getLogger(__name__)

FEATURE_HASH_MODEL = "feature-hash-v1"
FEATURE_HASH_DIM = 256

_TOKEN_RE = re.compile(r"[0-9]+|[^\W\d_]+", re.UNICODE)

# English plus high-frequency Hindi / Marathi / Hinglish function words.
# Content words (names, numbers, project terms) are intentionally kept.
_STOPWORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had",
    "her", "was", "one", "our", "out", "has", "have", "from", "this", "that",
    "with", "what", "when", "where", "which", "who", "how", "why", "does", "did",
    "about", "into", "than", "then", "them", "they", "there", "their", "its",
    "his", "she", "him", "will", "would", "could", "should", "been",
    "being", "were", "also", "such", "more", "most", "some", "only", "very",
    "is", "in", "on", "at", "of", "to", "be", "by", "or", "as", "it", "an",
    "do", "so", "we", "he", "me", "my", "no", "up", "if", "a",
    "का", "की", "के", "है", "हैं", "में", "को", "से", "ने", "पर", "भी", "यह", "वह",
    "और", "या", "एक", "लिए", "क्या", "कौन", "कब", "कहाँ", "कहां", "कैसे", "क्यों",
    "मेरा", "मेरी", "मेरे", "हूं", "हूँ", "था", "थे", "थी",
    "आहे", "आहेत", "माझा", "माझी", "माझे", "माझं", "मी", "तो", "ती", "च्या",
    "आणि", "काय", "नाही", "होते", "होता",
    "hai", "hain", "mera", "meri", "mere", "ka", "ki", "ke", "mein", "main",
    "aur", "yah", "yeh", "kya", "kaun", "aahe", "ahe", "maza", "majha", "majhi",
    "majhe", "ani", "nahi",
}

# Paraphrase expansions used only as weak retrieval/answer signals.
# They never invent facts: a sentence is accepted only when the
# question's specific terms are actually present (see rag.extractive_answer).
_EXPANSIONS = {
    "project": ("developed", "built", "created", "designed", "building"),
    "projects": ("developed", "built", "created", "designed", "building"),
    "course": ("studying", "studies", "study", "degree", "programme", "program", "major"),
    "subject": ("studying", "studies", "study", "degree"),
    "degree": ("studying", "course", "programme", "program"),
    "mobile": ("phone", "contact", "number", "मोबाइल", "मोबाईल"),
    "phone": ("mobile", "contact", "number", "फोन"),
    "email": ("mail", "ईमेल"),
    "budget": ("rupees", "crore", "cost", "amount"),
    "launch": ("scheduled", "schedule", "release"),
    "region": ("located", "deployment", "office"),
    "manager": ("managed", "leads", "lead"),
}

_st_model = None
_st_failed = False
_active_backend = FEATURE_HASH_MODEL
_active_dim = FEATURE_HASH_DIM


def tokenize(text: str) -> list[str]:
    tokens = []
    for raw in _TOKEN_RE.findall((text or "").lower()):
        if len(raw) <= 1 or raw in _STOPWORDS:
            continue
        tokens.append(raw)
    return tokens


def expand_terms(terms: list[str] | set[str]) -> dict[str, float]:
    """Map query terms to weights. Original terms weigh 1, expansions 0.45."""
    weights: dict[str, float] = {}
    for term in terms:
        weights[term] = 1.0
        for extra in _EXPANSIONS.get(term, ()):
            weights.setdefault(extra, 0.45)
    return weights


def embedding_backend() -> tuple[str, int]:
    _ensure_backend()
    return _active_backend, _active_dim


def _ensure_backend() -> None:
    global _st_model, _st_failed, _active_backend, _active_dim
    if _active_backend != FEATURE_HASH_MODEL or _st_model is not None or _st_failed:
        return
    try:
        from app.config import get_settings
        backend = (get_settings().rag_embedding_backend or "feature-hash").strip().lower()
    except Exception:
        backend = "feature-hash"
    if backend not in {"sentence-transformers", "sentence_transformers", "st"}:
        return
    try:
        from sentence_transformers import SentenceTransformer
        from app.config import get_settings
        model_name = get_settings().rag_embedding_model or "paraphrase-multilingual-MiniLM-L12-v2"
        _st_model = SentenceTransformer(model_name)
        dim = int(_st_model.get_sentence_embedding_dimension())
        _active_backend = model_name
        _active_dim = dim
        logger.info("RAG embeddings: sentence-transformers model %s (%s-d).", model_name, dim)
    except Exception as exc:
        _st_failed = True
        _active_backend = FEATURE_HASH_MODEL
        _active_dim = FEATURE_HASH_DIM
        logger.warning(
            "sentence-transformers unavailable (%s). Using %s (%s-d).",
            exc.__class__.__name__, FEATURE_HASH_MODEL, FEATURE_HASH_DIM,
        )


def _hash_index(key: str, dim: int) -> tuple[int, float]:
    digest = hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest()
    number = int.from_bytes(digest, "little")
    index = number % dim
    sign = 1.0 if (number >> 8) & 1 else -1.0
    return index, sign


def _feature_hash(text: str) -> list[float]:
    tokens = tokenize(text)
    if not tokens:
        tokens = [t for t in _TOKEN_RE.findall((text or "").lower()) if t]
    if not tokens:
        raise ValueError("Cannot embed empty text.")

    vec = [0.0] * FEATURE_HASH_DIM
    for token in tokens:
        idx, sign = _hash_index("w:" + token, FEATURE_HASH_DIM)
        vec[idx] += sign
        compact = token
        if len(compact) >= 3:
            for i in range(len(compact) - 2):
                cidx, csign = _hash_index("c:" + compact[i:i + 3], FEATURE_HASH_DIM)
                vec[cidx] += 0.25 * csign
    for left, right in zip(tokens, tokens[1:]):
        idx, sign = _hash_index("b:" + left + "_" + right, FEATURE_HASH_DIM)
        vec[idx] += 0.8 * sign

    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        raise ValueError("Embedding norm is zero.")
    return [round(v / norm, 6) for v in vec]


def embed_text(text: str) -> list[float]:
    """Embed non-empty text. Raises ValueError on empty input."""
    cleaned = (text or "").strip()
    if not cleaned:
        raise ValueError("Cannot embed empty text.")
    _ensure_backend()
    if _st_model is not None:
        vector = _st_model.encode(cleaned, normalize_embeddings=True)
        return [round(float(x), 6) for x in vector.tolist()]
    return _feature_hash(cleaned)


def cosine(left: list[float] | None, right: list[float] | None) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    # Vectors are stored L2-normalised. Clamp numeric noise.
    if dot > 1.0:
        return 1.0
    if dot < -1.0:
        return -1.0
    return float(dot)
