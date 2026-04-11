"""
MITRE ATT&CK graph builder.

Loads the MITRE STIX bundle (from the RAG cache or download) and builds
a MITREGraph instance. Uses the C++ extension if available, else networkx.

The graph is used by MITRECampaignPlanner (planner.py) for A* campaign planning.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# Try C++ extension first; fall back to networkx
try:
    from security_cpp import MITREGraph as _CppGraph, PathResult  # noqa: F401
    _HAS_CPP = True
except ImportError:
    _HAS_CPP = False
    import networkx as nx


STIX_CACHE_PATH = "data/enterprise-attack.json"
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
    pl = {p.lower() for p in platforms}
    if not pl:
        return "cross"
    if len(pl) > 2:
        return "cross"
    if "linux" in pl and "macos" not in pl and "windows" not in pl:
        return "linux"
    if "windows" in pl and "linux" not in pl and "macos" not in pl:
        return "windows"
    if "macos" in pl and "windows" not in pl and "linux" not in pl:
        return "macos"
    return "cross"


def _load_stix() -> dict:
    """Load STIX bundle from cache or download."""
    cache = Path(STIX_CACHE_PATH)
    if cache.exists():
        with open(cache) as f:
            return json.load(f)
    import requests
    print(f"Downloading MITRE STIX from {STIX_URL}...")
    resp = requests.get(STIX_URL, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    cache.parent.mkdir(parents=True, exist_ok=True)
    with open(cache, "w") as f:
        json.dump(data, f)
    return data


def _parse_techniques(stix_bundle: dict) -> list[dict]:
    """Parse STIX bundle into a list of technique dicts."""
    techniques = []
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        tech_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break
        if not tech_id:
            continue

        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        platforms = obj.get("x_mitre_platforms", [])

        # Stealth score heuristic: defense-evasion tagged → higher stealth
        stealth = 0.5
        if "defense-evasion" in tactics:
            stealth = 0.8
        elif "impact" in tactics or "exfiltration" in tactics:
            stealth = 0.3

        techniques.append({
            "id": tech_id,
            "name": obj.get("name", ""),
            "tactic": tactics[0] if tactics else "",
            "tactics": tactics,
            "platforms": [p.lower().replace(" ", "-") for p in platforms],
            "platform_norm": _normalize_platform(platforms),
            "stealth": stealth,
        })
    return techniques


# ─── Python fallback graph (networkx) ────────────────────────────────────────

class _NetworkxMITREGraph:
    """Pure Python MITRE graph using networkx. Used when C++ extension is unavailable."""

    def __init__(self):
        self.G = nx.DiGraph()
        self._technique_meta: dict[str, dict] = {}

    def add_technique(self, tech: dict) -> None:
        tid = tech["id"]
        self._technique_meta[tid] = tech
        self.G.add_node(tid, **tech)

    def build_default_edges(self) -> None:
        by_tactic: dict[str, list[str]] = {}
        for tid, meta in self._technique_meta.items():
            t = meta.get("tactic", "")
            if t:
                by_tactic.setdefault(t, []).append(tid)

        for i in range(len(TACTIC_ORDER) - 1):
            src_tactic = TACTIC_ORDER[i]
            dst_tactic = TACTIC_ORDER[i + 1]
            for src in by_tactic.get(src_tactic, []):
                for dst in by_tactic.get(dst_tactic, []):
                    stealth = self._technique_meta[dst].get("stealth", 0.5)
                    w = 1.0 + (1.0 - stealth) * 0.4
                    self.G.add_edge(src, dst, weight=w)

    def astar(self, start: str, goal_tactic: str, platform: Optional[str] = None) -> list[str]:
        """Return A* path from start technique to any technique in goal_tactic."""
        goal_nodes = [
            n for n, d in self.G.nodes(data=True)
            if d.get("tactic") == goal_tactic
        ]
        if not goal_nodes:
            return []

        def tactic_idx(t: str) -> int:
            try:
                return TACTIC_ORDER.index(t)
            except ValueError:
                return len(TACTIC_ORDER)

        start_idx = tactic_idx(self._technique_meta.get(start, {}).get("tactic", ""))

        best_path: list[str] = []
        best_cost = float("inf")

        for goal in goal_nodes:
            if platform:
                meta = self._technique_meta.get(goal, {})
                plist = meta.get("platforms", [])
                if platform not in plist and "cross" not in plist:
                    continue
            try:
                path = nx.astar_path(
                    self.G, start, goal,
                    heuristic=lambda u, v: abs(tactic_idx(self._technique_meta.get(u, {}).get("tactic", "")) -
                                               tactic_idx(self._technique_meta.get(v, {}).get("tactic", ""))),
                    weight="weight",
                )
                cost = sum(self.G[path[i]][path[i+1]]["weight"] for i in range(len(path)-1))
                if cost < best_cost:
                    best_cost = cost
                    best_path = path
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        return best_path


# ─── Public MITREGraphBuilder ─────────────────────────────────────────────────

class MITREGraphBuilder:
    """
    Builds and caches the MITRE ATT&CK graph.

    Automatically uses the C++ MITREGraph if available, else falls back to networkx.

    Usage:
        builder = MITREGraphBuilder()
        graph = builder.build()
        # graph is either security_cpp.MITREGraph or _NetworkxMITREGraph
    """

    def __init__(self, stix_path: str = STIX_CACHE_PATH):
        self.stix_path = stix_path
        self._graph = None
        self._technique_meta: dict[str, dict] = {}

    def build(self, force_rebuild: bool = False):
        """Build and return the graph (cached after first build)."""
        if self._graph is not None and not force_rebuild:
            return self._graph

        stix = _load_stix()
        techniques = _parse_techniques(stix)
        self._technique_meta = {t["id"]: t for t in techniques}

        if _HAS_CPP:
            g = _CppGraph()
            for t in techniques:
                g.add_technique(
                    t["id"], t["name"], t["tactic"],
                    t["platforms"], [],
                    t["stealth"],
                )
            g.build_default_edges()
            self._graph = g
        else:
            g = _NetworkxMITREGraph()
            for t in techniques:
                g.add_technique(t)
            g.build_default_edges()
            self._graph = g

        print(f"[MITREGraph] Built graph: {len(techniques)} techniques, backend={'cpp' if _HAS_CPP else 'networkx'}")
        return self._graph

    def technique_meta(self, tid: str) -> dict:
        return self._technique_meta.get(tid, {})

    def all_technique_ids(self) -> list[str]:
        return list(self._technique_meta.keys())

    def techniques_by_tactic(self, tactic: str) -> list[str]:
        return [t["id"] for t in self._technique_meta.values() if t.get("tactic") == tactic]


# Module-level singleton
_builder_instance: Optional[MITREGraphBuilder] = None


def get_mitre_graph() -> MITREGraphBuilder:
    global _builder_instance
    if _builder_instance is None:
        _builder_instance = MITREGraphBuilder()
    return _builder_instance
