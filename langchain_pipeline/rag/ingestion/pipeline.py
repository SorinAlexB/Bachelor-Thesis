"""
Full RAG ingestion pipeline.

Runs all ingestors in sequence and prints a summary.

Usage:
    python -m rag.ingestion.pipeline
    # or
    from rag.ingestion.pipeline import build_rag_database
    build_rag_database()
"""

from __future__ import annotations

import time

from rag.chroma_store import get_store
from rag.embedder import get_embedder
from rag.ingestion.mitre_ingestor import MITREIngestor
from rag.ingestion.nvd_ingestor import NVDIngestor
from rag.ingestion.exploit_db_ingestor import ExploitDBIngestor


def build_rag_database(
    skip_mitre: bool = False,
    skip_nvd: bool = False,
    skip_exploitdb: bool = False,
) -> dict[str, int]:
    """
    Build the full 25k-document security RAG corpus.

    Returns a summary dict: {source: n_chunks_ingested}.
    """
    store    = get_store()
    embedder = get_embedder()

    print("\n" + "=" * 60)
    print("Building Security RAG Database")
    print("=" * 60)

    initial_count = store.count()
    print(f"Existing documents in store: {initial_count}")

    summary: dict[str, int] = {}
    t_start = time.time()

    # 1. MITRE ATT&CK Enterprise
    if not skip_mitre:
        print("\n[1/3] MITRE ATT&CK Enterprise techniques")
        n = MITREIngestor().run(store, embedder)
        summary["mitre"] = n

    # 2. NVD CVE advisories
    if not skip_nvd:
        print("\n[2/3] NVD CVE advisories (2020-2024, CVSS >= 7.0)")
        n = NVDIngestor().run(store, embedder)
        summary["nvd"] = n

    # 3. ExploitDB
    if not skip_exploitdb:
        print("\n[3/3] ExploitDB entries (most recent 10k)")
        n = ExploitDBIngestor().run(store, embedder)
        summary["exploitdb"] = n

    total_time = time.time() - t_start
    final_count = store.count()
    new_chunks = final_count - initial_count

    print("\n" + "=" * 60)
    print("RAG Database Build Complete")
    print(f"  Time elapsed:    {total_time / 60:.1f} minutes")
    print(f"  New chunks added: {new_chunks}")
    print(f"  Total in store:   {final_count}")
    stats = store.stats()
    print(f"  By source:       {stats.get('by_source', {})}")
    print(f"  By platform:     {stats.get('by_platform', {})}")
    print("=" * 60 + "\n")

    return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build security RAG database")
    parser.add_argument("--skip-mitre",    action="store_true")
    parser.add_argument("--skip-nvd",      action="store_true")
    parser.add_argument("--skip-exploitdb", action="store_true")
    args = parser.parse_args()

    build_rag_database(
        skip_mitre=args.skip_mitre,
        skip_nvd=args.skip_nvd,
        skip_exploitdb=args.skip_exploitdb,
    )
