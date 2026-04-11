"""
Multi-stage attack campaign planner.

Takes an initial technique and a goal tactic, then uses A* (C++ or networkx)
to plan the minimum-cost sequence of MITRE ATT&CK techniques to achieve the goal.

Applies stealth weighting, platform filtering, and MITRE kill-chain ordering.

Usage:
    planner = MITRECampaignPlanner()
    campaign = planner.plan("T1566.001", "exfiltration", platform="linux")
    for step in campaign.steps:
        print(step)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from mitre.graph import MITREGraphBuilder, get_mitre_graph, TACTIC_ORDER, _HAS_CPP


@dataclass
class TechniqueStep:
    technique_id: str
    name: str
    tactic: str
    platform: str
    stealth_score: float
    rationale: str = ""

    def __str__(self) -> str:
        return (
            f"  {self.technique_id:15s} | {self.name:45s} | "
            f"{self.tactic:20s} | stealth={self.stealth_score:.1f}"
        )


@dataclass
class Campaign:
    start_technique: str
    goal_tactic: str
    platform: str
    steps: list[TechniqueStep] = field(default_factory=list)
    total_cost: float = 0.0
    success: bool = False

    def __str__(self) -> str:
        lines = [
            f"Campaign: {self.start_technique} → {self.goal_tactic} [{self.platform}]",
            f"Steps: {len(self.steps)}, Cost: {self.total_cost:.2f}",
            "",
        ]
        for i, step in enumerate(self.steps, 1):
            lines.append(f"  Step {i}: {step}")
        return "\n".join(lines)

    def technique_ids(self) -> list[str]:
        return [s.technique_id for s in self.steps]

    def to_dict(self) -> dict:
        return {
            "start": self.start_technique,
            "goal": self.goal_tactic,
            "platform": self.platform,
            "total_cost": self.total_cost,
            "steps": [
                {
                    "id": s.technique_id,
                    "name": s.name,
                    "tactic": s.tactic,
                    "stealth": s.stealth_score,
                }
                for s in self.steps
            ],
        }


class MITRECampaignPlanner:
    """
    Plans multi-stage attack campaigns using A* over the MITRE ATT&CK graph.

    The planner:
    1. Loads the MITRE graph (from cache or STIX download)
    2. Runs A* from start_technique to goal_tactic
    3. Returns a Campaign object with enriched TechniqueStep metadata
    """

    def __init__(self, graph_builder: Optional[MITREGraphBuilder] = None):
        self._builder = graph_builder or get_mitre_graph()

    def plan(
        self,
        start_technique: str,
        goal_tactic: str,
        platform: str = "linux",
        max_steps: int = 10,
        stealth_weight: float = 0.4,
    ) -> Campaign:
        """
        Plan a campaign from start_technique to goal_tactic.

        Args:
            start_technique: MITRE technique ID (e.g. "T1566.001")
            goal_tactic:     Target tactic name (e.g. "exfiltration")
            platform:        Target OS: "linux", "macos", "windows"
            max_steps:       Maximum chain length
            stealth_weight:  0.0 = ignore stealth, 1.0 = maximize stealth

        Returns:
            Campaign object with ordered TechniqueStep list
        """
        graph = self._builder.build()

        # Run A*
        path: list[str] = []
        cost = 0.0

        if _HAS_CPP:
            result = graph.astar(
                start_technique,
                goal_tactic,
                platform_filter=platform,
                stealth_weight=stealth_weight,
            )
            if result.found:
                path = result.technique_ids
                cost = result.total_cost
        else:
            path = graph.astar(start_technique, goal_tactic, platform=platform)

        if not path:
            # Fallback: greedy kill-chain traversal
            path = self._greedy_plan(start_technique, goal_tactic, platform)

        # Cap at max_steps
        path = path[:max_steps]

        # Enrich steps with metadata
        steps: list[TechniqueStep] = []
        for tid in path:
            meta = self._builder.technique_meta(tid)
            step = TechniqueStep(
                technique_id=tid,
                name=meta.get("name", tid),
                tactic=meta.get("tactic", ""),
                platform=meta.get("platform_norm", "cross"),
                stealth_score=meta.get("stealth", 0.5),
                rationale=self._generate_rationale(tid, meta),
            )
            steps.append(step)

        return Campaign(
            start_technique=start_technique,
            goal_tactic=goal_tactic,
            platform=platform,
            steps=steps,
            total_cost=cost,
            success=len(steps) > 0,
        )

    def _greedy_plan(
        self,
        start: str,
        goal_tactic: str,
        platform: str,
    ) -> list[str]:
        """Greedy fallback: walk the kill chain stage by stage."""
        start_meta = self._builder.technique_meta(start)
        if not start_meta:
            return [start]

        start_tactic = start_meta.get("tactic", "")
        path = [start]

        try:
            start_idx = TACTIC_ORDER.index(start_tactic)
            goal_idx  = TACTIC_ORDER.index(goal_tactic)
        except ValueError:
            return path

        for idx in range(start_idx + 1, goal_idx + 1):
            tactic = TACTIC_ORDER[idx]
            candidates = self._builder.techniques_by_tactic(tactic)
            # Filter by platform
            if platform:
                platform_filtered = [
                    t for t in candidates
                    if platform in self._builder.technique_meta(t).get("platforms", [])
                    or "cross" == self._builder.technique_meta(t).get("platform_norm", "")
                ]
                if platform_filtered:
                    candidates = platform_filtered
            if candidates:
                # Pick highest stealth
                best = max(candidates, key=lambda t: self._builder.technique_meta(t).get("stealth", 0))
                path.append(best)

        return path

    def _generate_rationale(self, tid: str, meta: dict) -> str:
        """Generate a human-readable rationale for including this technique."""
        tactic = meta.get("tactic", "")
        name = meta.get("name", tid)
        stealth = meta.get("stealth", 0.5)
        stealth_desc = "high-stealth" if stealth > 0.6 else "moderate-stealth" if stealth > 0.4 else "noisy"
        return f"{name} ({tid}) — {tactic} phase, {stealth_desc} technique (stealth={stealth:.1f})"

    def list_tactics(self) -> list[str]:
        return list(TACTIC_ORDER)

    def techniques_for_tactic(self, tactic: str, platform: str = "") -> list[dict]:
        """Return technique metadata for a given tactic, optionally filtered by platform."""
        ids = self._builder.techniques_by_tactic(tactic)
        result = []
        for tid in ids:
            meta = self._builder.technique_meta(tid)
            if platform:
                plist = meta.get("platforms", [])
                if platform not in plist and "cross" not in meta.get("platform_norm", ""):
                    continue
            result.append({"id": tid, "name": meta.get("name", ""), "stealth": meta.get("stealth", 0.5)})
        return sorted(result, key=lambda x: x["stealth"], reverse=True)
