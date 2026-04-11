"""
ELO rating system for tracking the capability evolution of Red and Blue team AIs.

ELO provides a self-calibrating measure:
- Red team wins (evasion) → red ELO increases, blue ELO decreases
- Blue team wins (detection) → blue ELO increases, red ELO decreases
- Draw → small adjustments

This creates the "arms race" metric for the thesis.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class ELORating:
    name: str
    rating: float = 1200.0
    wins: int = 0
    losses: int = 0
    draws: int = 0
    history: list[dict] = field(default_factory=list)

    @property
    def games_played(self) -> int:
        return self.wins + self.losses + self.draws

    @property
    def win_rate(self) -> float:
        if self.games_played == 0:
            return 0.0
        return self.wins / self.games_played


def expected_score(rating_a: float, rating_b: float) -> float:
    """Expected score for player A against player B."""
    return 1.0 / (1.0 + math.pow(10, (rating_b - rating_a) / 400.0))


def update_elo(
    rating_a: ELORating,
    rating_b: ELORating,
    outcome: float,   # 1.0 = A wins, 0.0 = A loses, 0.5 = draw
    k: float = 32.0,
) -> tuple[float, float]:
    """
    Update ELO ratings after a match.

    Args:
        rating_a: Player A's ELORating object (mutated in place)
        rating_b: Player B's ELORating object (mutated in place)
        outcome:  1.0 = A wins, 0.0 = B wins, 0.5 = draw
        k:        K-factor (larger = faster rating change)

    Returns:
        (delta_a, delta_b) — rating changes
    """
    ea = expected_score(rating_a.rating, rating_b.rating)
    eb = 1.0 - ea

    delta_a = k * (outcome - ea)
    delta_b = k * ((1.0 - outcome) - eb)

    rating_a.rating += delta_a
    rating_b.rating += delta_b

    if outcome == 1.0:
        rating_a.wins += 1
        rating_b.losses += 1
    elif outcome == 0.0:
        rating_a.losses += 1
        rating_b.wins += 1
    else:
        rating_a.draws += 1
        rating_b.draws += 1

    ts = datetime.now(timezone.utc).isoformat()
    rating_a.history.append({"ts": ts, "rating": rating_a.rating, "delta": delta_a})
    rating_b.history.append({"ts": ts, "rating": rating_b.rating, "delta": delta_b})

    return delta_a, delta_b


class ELOTracker:
    """
    Tracks ELO ratings across co-evolution generations.

    Saves/loads ratings from a JSON file so progress persists across runs.
    """

    def __init__(self, save_path: str = "data/elo_ratings.json", k: float = 32.0):
        self.save_path = Path(save_path)
        self.k = k
        self.red_team  = ELORating(name="red_team")
        self.blue_team = ELORating(name="blue_team")
        self._load()

    def _load(self) -> None:
        if not self.save_path.exists():
            return
        with open(self.save_path) as f:
            data = json.load(f)
        for name, values in data.items():
            if name == "red_team":
                self.red_team.__dict__.update(values)
            elif name == "blue_team":
                self.blue_team.__dict__.update(values)

    def save(self) -> None:
        self.save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.save_path, "w") as f:
            json.dump({
                "red_team":  self.red_team.__dict__,
                "blue_team": self.blue_team.__dict__,
            }, f, indent=2)

    def record_round(self, red_score: float, blue_score: float) -> dict:
        """
        Record a round outcome and update ELO ratings.

        Args:
            red_score:  Red team score (0.0 - 1.0): fraction of techniques that evaded detection
            blue_score: Blue team score (0.0 - 1.0): fraction of techniques detected

        Returns:
            dict with old/new ratings and deltas
        """
        old_red  = self.red_team.rating
        old_blue = self.blue_team.rating

        # Outcome from red's perspective: red_score > blue_score → red wins
        if red_score > blue_score + 0.1:
            outcome = 1.0
        elif blue_score > red_score + 0.1:
            outcome = 0.0
        else:
            outcome = 0.5

        delta_red, delta_blue = update_elo(self.red_team, self.blue_team, outcome, k=self.k)
        self.save()

        return {
            "red_old":   old_red,
            "red_new":   self.red_team.rating,
            "red_delta": delta_red,
            "blue_old":  old_blue,
            "blue_new":  self.blue_team.rating,
            "blue_delta": delta_blue,
            "outcome":   "red_wins" if outcome == 1.0 else "blue_wins" if outcome == 0.0 else "draw",
        }

    def summary(self) -> str:
        return (
            f"ELO Ratings:\n"
            f"  Red Team:  {self.red_team.rating:.0f} "
            f"(W:{self.red_team.wins} L:{self.red_team.losses} D:{self.red_team.draws})\n"
            f"  Blue Team: {self.blue_team.rating:.0f} "
            f"(W:{self.blue_team.wins} L:{self.blue_team.losses} D:{self.blue_team.draws})"
        )

    def rating_history(self) -> dict:
        return {
            "red_team":  [h["rating"] for h in self.red_team.history],
            "blue_team": [h["rating"] for h in self.blue_team.history],
        }
