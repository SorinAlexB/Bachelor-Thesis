"""
Local embedding model wrapper.

Uses sentence-transformers/all-MiniLM-L6-v2 (22MB, ~5ms/query on CPU).
Runs alongside the MLX model without competing for GPU/ANE memory.
Implements the LangChain Embeddings interface.
"""

from __future__ import annotations

from typing import Any, Optional


class LocalEmbedder:
    """
    Thin wrapper around SentenceTransformer for local embedding.

    Lazy-loads the model on first call to avoid startup cost when RAG is
    not needed (e.g., direct-mode runs).

    Usage:
        embedder = LocalEmbedder()
        vec = embedder.embed_query("T1059 PowerShell execution")
        vecs = embedder.embed_documents(["doc1", "doc2"])
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model: Any = None

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer
        self._model = SentenceTransformer(self.model_name)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Batch encode a list of documents. Returns list of 384-dim float vectors."""
        self._ensure_loaded()
        embeddings = self._model.encode(
            texts,
            batch_size=64,
            show_progress_bar=len(texts) > 100,
            normalize_embeddings=True,
        )
        return embeddings.tolist()

    def embed_query(self, text: str) -> list[float]:
        """Encode a single query string."""
        self._ensure_loaded()
        return self._model.encode(
            [text], normalize_embeddings=True
        )[0].tolist()

    # LangChain Embeddings interface compatibility
    def __call__(self, texts: list[str]) -> list[list[float]]:
        return self.embed_documents(texts)


# Module-level singleton
_embedder_instance: Optional[LocalEmbedder] = None


def get_embedder(model_name: str = "all-MiniLM-L6-v2") -> LocalEmbedder:
    global _embedder_instance
    if _embedder_instance is None:
        _embedder_instance = LocalEmbedder(model_name)
    return _embedder_instance
