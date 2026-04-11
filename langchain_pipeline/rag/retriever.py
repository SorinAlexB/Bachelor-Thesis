"""
LangChain-compatible security document retriever.

Hybrid strategy:
  1. Dense retrieval from ChromaDB (cosine similarity, top-20)
  2. Optional cross-encoder re-ranking (ms-marco-MiniLM-L-6-v2, top-8)
  3. Format as LangChain Documents with full metadata

Also exposed as a LangChain @tool for use inside the ReAct agent.
"""

from __future__ import annotations

from typing import Optional

from langchain_core.documents import Document
from langchain_core.tools import tool

from rag.chroma_store import SecurityChromaStore, get_store
from rag.embedder import LocalEmbedder, get_embedder


class SecurityRetriever:
    """
    Retrieves relevant security documents for a given query.

    Usage:
        retriever = SecurityRetriever()
        docs = retriever.get_relevant_documents("credential dumping linux T1003")
    """

    def __init__(
        self,
        store: Optional[SecurityChromaStore] = None,
        embedder: Optional[LocalEmbedder] = None,
        top_k: int = 8,
        use_reranker: bool = True,
    ):
        self._store = store
        self._embedder = embedder
        self.top_k = top_k
        self.use_reranker = use_reranker
        self._reranker: object = None

    def _get_store(self) -> SecurityChromaStore:
        if self._store is None:
            self._store = get_store()
        return self._store

    def _get_embedder(self) -> LocalEmbedder:
        if self._embedder is None:
            self._embedder = get_embedder()
        return self._embedder

    def _get_reranker(self):
        if self._reranker is None and self.use_reranker:
            try:
                from sentence_transformers import CrossEncoder
                self._reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
            except Exception:
                self.use_reranker = False
        return self._reranker

    def get_relevant_documents(
        self,
        query: str,
        platform: Optional[str] = None,
        n_results: Optional[int] = None,
    ) -> list[Document]:
        """Return top-k LangChain Documents for the query."""
        k = n_results or self.top_k
        # Fetch more for re-ranking
        fetch_k = k * 3 if self.use_reranker else k

        raw = self._get_store().search(
            query,
            embedder=self._get_embedder(),
            n_results=fetch_k,
            platform=platform,
        )

        if not raw:
            return []

        # Cross-encoder re-ranking
        reranker = self._get_reranker()
        if reranker and len(raw) > k:
            pairs = [(query, r["content"]) for r in raw]
            scores = reranker.predict(pairs)
            ranked = sorted(zip(scores, raw), key=lambda x: x[0], reverse=True)
            raw = [r for _, r in ranked[:k]]

        return [
            Document(
                page_content=r["content"],
                metadata={**r["metadata"], "score": r["score"]},
            )
            for r in raw[:k]
        ]

    def format_context(self, query: str, platform: Optional[str] = None) -> str:
        """Return a formatted string of retrieved docs for LLM prompt injection."""
        docs = self.get_relevant_documents(query, platform=platform)
        if not docs:
            return "No relevant documents found in the security corpus."

        parts = [f"Retrieved {len(docs)} relevant security documents:\n"]
        for i, doc in enumerate(docs, 1):
            meta = doc.metadata
            source = meta.get("source", "unknown")
            tech = meta.get("technique_id", "")
            cve = meta.get("cve_id", "")
            ref = f"[{source}" + (f" {tech}" if tech else "") + (f" {cve}" if cve else "") + "]"
            parts.append(f"\n--- Document {i} {ref} ---\n{doc.page_content[:600]}")

        return "\n".join(parts)


# Module-level singleton
_retriever_instance: Optional[SecurityRetriever] = None


def get_retriever() -> SecurityRetriever:
    global _retriever_instance
    if _retriever_instance is None:
        from config import RAG_TOP_K, RAG_RERANK
        _retriever_instance = SecurityRetriever(top_k=RAG_TOP_K, use_reranker=RAG_RERANK)
    return _retriever_instance


# ─── LangChain Tool wrapper ───────────────────────────────────────────────────

@tool
def search_corpus(query: str, platform: str = "", top_k: int = 5) -> str:
    """
    Search the 25k security document corpus for MITRE techniques, CVEs, exploits,
    and defensive playbooks. Returns relevant excerpts with source citations.

    Args:
        query:    Natural language search query, e.g. "credential dumping Linux"
        platform: Filter by OS: "linux", "macos", "windows", or "" for all
        top_k:    Number of results to return (1-10)
    """
    retriever = get_retriever()
    plat = platform.lower() if platform else None
    return retriever.format_context(query, platform=plat)
