"""
SENTINEL AI — Embedding Generator
Uses sentence-transformers for real semantic embeddings.
Falls back to zero vector (not random) when model is unavailable,
so deduplication degrades gracefully without polluting with noise.
"""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
    _ST_AVAILABLE = True
except ImportError:
    SentenceTransformer = None
    _ST_AVAILABLE = False


_EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 output dimension
_ZERO_VECTOR = [0.0] * _EMBEDDING_DIM  # deterministic zero — NOT random


class EmbeddingGenerator:
    """
    Generates semantic embeddings for deduplication and similarity search.

    REAL path:  sentence-transformers installed → all-MiniLM-L6-v2 model
    FALLBACK:   model missing → returns zero vector (all-zero, deterministic).
                This causes cosine similarity to be 0 for all pairs,
                effectively disabling semantic dedup without incorrect data.
    """

    def __init__(self):
        self.model = None
        self.mode = "disabled"

        if not _ST_AVAILABLE:
            logger.warning(
                "[EMBEDDING] sentence-transformers not installed. "
                "Semantic deduplication disabled. "
                "Run: pip install sentence-transformers"
            )
            return

        try:
            self.model = SentenceTransformer("all-MiniLM-L6-v2")
            self.mode = "real"
            logger.info("[EMBEDDING] Real model loaded: all-MiniLM-L6-v2 (dim=384)")
        except Exception as exc:
            logger.error(
                "[EMBEDDING] Failed to load SentenceTransformer model: %s. "
                "Semantic deduplication disabled. "
                "Run: python -c \"from sentence_transformers import SentenceTransformer; "
                "SentenceTransformer('all-MiniLM-L6-v2')\" to pre-download.",
                exc,
            )

    def generate(self, text: str) -> list[float]:
        """
        Generate a semantic embedding for text.
        Returns real 384-dim vector if model loaded, otherwise zero vector.
        Never returns random data.
        """
        if self.model is not None:
            try:
                return self.model.encode(text).tolist()
            except Exception as exc:
                logger.error("[EMBEDDING] encode() failed: %s", exc)
                return _ZERO_VECTOR
        return _ZERO_VECTOR

    @property
    def is_real(self) -> bool:
        return self.model is not None


embedding_generator = EmbeddingGenerator()
