"""
Embedding service backed by sentence-transformers.

Loads the model once at startup and exposes a thin encode() wrapper.
"""

import logging

from sentence_transformers import SentenceTransformer

import config

logger = logging.getLogger(__name__)

_model: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        logger.info("Loading embedding model: %s", config.EMBEDDING_MODEL_NAME)
        _model = SentenceTransformer(config.EMBEDDING_MODEL_NAME)
        logger.info("Embedding model loaded (dim=%d)", config.VECTOR_DIMENSION)
    return _model


def encode(text: str) -> list[float]:
    """Return a dense vector for *text* (length = VECTOR_DIMENSION)."""
    model = _get_model()
    vec = model.encode(text, normalize_embeddings=True)
    return vec.tolist()
