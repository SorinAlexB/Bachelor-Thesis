"""
MITRE ATT&CK Enterprise ingestor.

Downloads the STIX 2.1 bundle from the mitre/cti GitHub repository and
ingests all techniques, sub-techniques, and mitigations into ChromaDB.

Produces ~1,500 documents covering all Enterprise ATT&CK techniques.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Optional

import requests
from tqdm import tqdm

from rag.chroma_store import SecurityChromaStore
from rag.embedder import LocalEmbedder

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _normalize_platform(platforms: list[str]) -> str:
    """Map MITRE platform list to a single cross|linux|macos|windows string."""
    pl = {p.lower() for p in platforms}
    if len(pl) > 2:
        return "cross"
    if "linux" in pl and "macos" in pl and "windows" not in pl:
        return "linux"
    if "windows" in pl and "linux" not in pl and "macos" not in pl:
        return "windows"
    if "macos" in pl and "windows" not in pl and "linux" not in pl:
        return "macos"
    return "cross"


def _stix_to_documents(stix_bundle: dict) -> list[dict]:
    """Parse a STIX 2.1 bundle and return a list of document dicts."""
    docs: list[dict] = []

    # Build a map of external_id -> object
    objects = stix_bundle.get("objects", [])

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type not in ("attack-pattern", "course-of-action"):
            continue

        # Technique ID
        tech_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break

        name = obj.get("name", "")
        description = obj.get("description", "")
        platforms = obj.get("x_mitre_platforms", [])
        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        # Detection info
        detection = obj.get("x_mitre_detection", "")

        # Build rich content
        content_parts = [
            f"Technique: {name}",
            f"ID: {tech_id}",
            f"Tactics: {', '.join(tactics)}",
            f"Platforms: {', '.join(platforms)}",
            "",
            description,
        ]
        if detection:
            content_parts += ["", "Detection:", detection]

        content = "\n".join(p for p in content_parts if p is not None)

        docs.append({
            "content": content,
            "metadata": {
                "source": "mitre",
                "technique_id": tech_id,
                "platform": _normalize_platform(platforms),
                "tactic": tactics[0] if tactics else "",
                "tactic_order": str(TACTIC_ORDER.index(tactics[0]) if tactics and tactics[0] in TACTIC_ORDER else 99),
                "severity": "high",
                "tags": ",".join(tactics),
                "name": name,
            },
        })

    return docs


class MITREIngestor:
    """
    Downloads and ingests MITRE ATT&CK Enterprise data into ChromaDB.

    Usage:
        ingestor = MITREIngestor()
        n = ingestor.run(store, embedder)
        print(f"Ingested {n} MITRE technique documents")
    """

    def __init__(self, stix_url: str = STIX_URL, cache_dir: str = "data"):
        self.stix_url = stix_url
        self.cache_path = Path(cache_dir) / "enterprise-attack.json"

    def _download(self) -> dict:
        """Download STIX bundle, use cache if available."""
        if self.cache_path.exists():
            print(f"Using cached STIX bundle: {self.cache_path}")
            with open(self.cache_path) as f:
                return json.load(f)

        print(f"Downloading MITRE ATT&CK STIX bundle from {self.stix_url}...")
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        response = requests.get(self.stix_url, timeout=120)
        response.raise_for_status()
        bundle = response.json()
        with open(self.cache_path, "w") as f:
            json.dump(bundle, f)
        print(f"Saved to {self.cache_path}")
        return bundle

    def fetch_documents(self) -> list[dict]:
        """Download and parse MITRE data into document dicts."""
        bundle = self._download()
        docs = _stix_to_documents(bundle)
        print(f"Parsed {len(docs)} MITRE technique documents")
        return docs

    def run(
        self,
        store: SecurityChromaStore,
        embedder: Optional[LocalEmbedder] = None,
    ) -> int:
        """Ingest all MITRE techniques into the store. Returns chunk count."""
        docs = self.fetch_documents()
        print(f"Ingesting {len(docs)} MITRE documents into ChromaDB...")
        n = store.add_documents(docs, embedder)
        print(f"Done — {n} chunks upserted")
        return n
