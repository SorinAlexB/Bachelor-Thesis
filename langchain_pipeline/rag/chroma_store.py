"""
ChromaDB-backed vector store for the 25k security document corpus.

Collections (all within one ChromaDB instance):
  - "mitre_techniques":  MITRE ATT&CK techniques and sub-techniques (~1,500 docs)
  - "cve_advisories":    NVD CVE descriptions, filtered CVSS >= 7.0 (~10,000 docs)
  - "exploitdb":         ExploitDB entries (~10,000 docs)
  - "blue_team":         Defensive playbooks, SIGMA rules, detection docs (~3,500 docs)

Document metadata schema:
  {
    "source":        "mitre|nvd|exploitdb|blue_team",
    "technique_id":  "T1059.003",    # MITRE technique, if applicable
    "cve_id":        "CVE-2024-...", # CVE ID, if applicable
    "platform":      "windows|linux|macos|cross",
    "severity":      "critical|high|medium|low",
    "tactic":        "execution|persistence|...",
    "tags":          "rce,privilege_escalation",  # comma-separated (ChromaDB metadata must be str)
  }
"""

from __future__ import annotations

import hashlib
import textwrap
from typing import Any, Optional

from rag.embedder import LocalEmbedder, get_embedder

CHUNK_SIZE    = 1000   # characters
CHUNK_OVERLAP = 100
BATCH_SIZE    = 500    # upsert batch size


def _chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks."""
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + size
        chunks.append(text[start:end])
        start += size - overlap
    return chunks


def _doc_id(content: str, metadata: dict) -> str:
    """Deterministic ID from full content + key metadata fields."""
    key = content + str(metadata.get("source", "")) + str(metadata.get("technique_id", "")) + str(metadata.get("cve_id", ""))
    return hashlib.sha256(key.encode()).hexdigest()[:32]


class SecurityChromaStore:
    """
    Manages the ChromaDB security corpus.

    Usage:
        store = SecurityChromaStore("data/chroma", "security_corpus")
        store.add_documents(docs, embedder)
        results = store.search("credential dumping linux", platform="linux")
    """

    def __init__(self, persist_dir: str, collection_name: str):
        import chromadb
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._embedder: Optional[LocalEmbedder] = None

    def _get_embedder(self) -> LocalEmbedder:
        if self._embedder is None:
            self._embedder = get_embedder()
        return self._embedder

    def add_documents(
        self,
        docs: list[dict],
        embedder: Optional[LocalEmbedder] = None,
    ) -> int:
        """
        Add documents to the store.

        Each doc is {"content": str, "metadata": dict}.
        Long documents are automatically chunked.
        Returns number of chunks upserted.
        """
        if embedder is None:
            embedder = self._get_embedder()

        all_ids: list[str] = []
        all_texts: list[str] = []
        all_metas: list[dict] = []

        for doc in docs:
            content = doc.get("content", "")
            meta = doc.get("metadata", {})
            # Ensure all metadata values are strings/ints/floats (ChromaDB requirement)
            safe_meta = {
                k: str(v) if not isinstance(v, (str, int, float, bool)) else v
                for k, v in meta.items()
            }
            for chunk in _chunk_text(content):
                cid = _doc_id(chunk, safe_meta)
                all_ids.append(cid)
                all_texts.append(chunk)
                all_metas.append(safe_meta)

        # Deduplicate across the full set before batching
        seen: set[str] = set()
        dedup_ids, dedup_texts, dedup_metas = [], [], []
        for cid, text, meta in zip(all_ids, all_texts, all_metas):
            if cid not in seen:
                seen.add(cid)
                dedup_ids.append(cid)
                dedup_texts.append(text)
                dedup_metas.append(meta)
        all_ids, all_texts, all_metas = dedup_ids, dedup_texts, dedup_metas

        total = 0
        for i in range(0, len(all_texts), BATCH_SIZE):
            batch_texts = all_texts[i : i + BATCH_SIZE]
            batch_ids   = all_ids[i : i + BATCH_SIZE]
            batch_metas = all_metas[i : i + BATCH_SIZE]
            embeddings  = embedder.embed_documents(batch_texts)
            self.collection.upsert(
                ids=batch_ids,
                documents=batch_texts,
                embeddings=embeddings,
                metadatas=batch_metas,
            )
            total += len(batch_texts)

        return total

    def search(
        self,
        query: str,
        embedder: Optional[LocalEmbedder] = None,
        n_results: int = 8,
        platform: Optional[str] = None,
        source: Optional[str] = None,
        score_threshold: float = 0.35,
    ) -> list[dict]:
        """
        Dense similarity search with optional metadata filtering.

        Returns list of {"content": str, "metadata": dict, "score": float}.
        Score is cosine similarity (0.0 - 1.0, higher = more similar).
        """
        if embedder is None:
            embedder = self._get_embedder()

        where: Optional[dict] = None
        filters = {}
        if platform:
            filters["platform"] = platform
        if source:
            filters["source"] = source
        if len(filters) == 1:
            where = filters
        elif len(filters) > 1:
            where = {"$and": [{k: v} for k, v in filters.items()]}

        query_vec = embedder.embed_query(query)
        kwargs: dict[str, Any] = {
            "query_embeddings": [query_vec],
            "n_results": min(n_results * 2, self.collection.count() or 1),
            "include": ["documents", "metadatas", "distances"],
        }
        if where:
            kwargs["where"] = where

        raw = self.collection.query(**kwargs)

        results: list[dict] = []
        for doc, meta, dist in zip(
            raw["documents"][0],
            raw["metadatas"][0],
            raw["distances"][0],
        ):
            score = 1.0 - dist  # cosine distance to similarity
            if score >= score_threshold:
                results.append({"content": doc, "metadata": meta, "score": score})

        # Sort by score descending, return top n
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:n_results]

    def count(self) -> int:
        return self.collection.count()

    def stats(self) -> dict:
        """Return collection statistics broken down by source and platform."""
        total = self.collection.count()
        if total == 0:
            return {"total": 0}
        # Sample up to 1000 docs to get distribution
        sample = self.collection.get(limit=min(1000, total), include=["metadatas"])
        by_source: dict[str, int] = {}
        by_platform: dict[str, int] = {}
        for meta in sample["metadatas"]:
            src = meta.get("source", "unknown")
            plt = meta.get("platform", "unknown")
            by_source[src] = by_source.get(src, 0) + 1
            by_platform[plt] = by_platform.get(plt, 0) + 1
        return {"total": total, "by_source": by_source, "by_platform": by_platform}


# Module-level singleton
_store_instance: Optional[SecurityChromaStore] = None


def get_store() -> SecurityChromaStore:
    global _store_instance
    if _store_instance is None:
        from config import CHROMA_PERSIST_DIR, CHROMA_COLLECTION
        import os
        os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
        _store_instance = SecurityChromaStore(CHROMA_PERSIST_DIR, CHROMA_COLLECTION)
    return _store_instance
