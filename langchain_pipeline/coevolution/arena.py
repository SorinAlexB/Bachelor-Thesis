"""
Adversarial Co-Evolution Arena — GAN-like Red vs Blue training loop.

Each "round":
  1. Red agent plans and executes a campaign on the target VM
  2. Blue agent analyzes IOC evidence and attempts detection
  3. Scores are calculated for both teams
  4. Training samples are generated for adapter retraining
  5. ELO ratings are updated

Each "generation" = N rounds + adapter retraining for both teams.

This implements the GAN analogy:
  - Red = Generator   (tries to "fool" blue team with stealthy exploits)
  - Blue = Discriminator (tries to detect / classify exploits as malicious)
  - Training loop drives both to improve against each other
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from coevolution.elo import ELOTracker
from coevolution.red_agent import RedTeamAgent, AttackResult
from coevolution.blue_agent import BlueTeamAgent, DetectionResult


@dataclass
class TargetProfile:
    platform: str          # "linux" | "macos" | "windows"
    vm_name: str           # "linux" | "macos" | "windows"
    techniques: list[str]  # MITRE technique IDs to test
    difficulty: str = "medium"  # "easy" | "medium" | "hard"

    @classmethod
    def easy_linux(cls) -> "TargetProfile":
        return cls(
            platform="linux", vm_name="linux",
            techniques=["T1082", "T1057", "T1049", "T1083"],
            difficulty="easy",
        )

    @classmethod
    def medium_linux(cls) -> "TargetProfile":
        return cls(
            platform="linux", vm_name="linux",
            techniques=["T1059.004", "T1078", "T1105", "T1003", "T1053"],
            difficulty="medium",
        )


@dataclass
class RoundResult:
    round_number: int
    target: TargetProfile
    attack_result: AttackResult
    detection_result: DetectionResult
    red_score: float
    blue_score: float
    evasion_score: float      # techniques confirmed but NOT detected by blue
    elo_update: dict = field(default_factory=dict)
    training_samples: list[dict] = field(default_factory=list)
    duration_s: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def summary(self) -> str:
        return (
            f"Round {self.round_number} [{self.target.difficulty}] on {self.target.vm_name}\n"
            f"  Red score:    {self.red_score:.2f} ({len(self.attack_result.techniques_confirmed)}/{len(self.attack_result.techniques_attempted)} confirmed)\n"
            f"  Blue score:   {self.blue_score:.2f} ({len(self.detection_result.techniques_detected)}/{len(self.attack_result.techniques_attempted)} detected)\n"
            f"  Evasion:      {self.evasion_score:.2f}\n"
            f"  Duration:     {self.duration_s:.1f}s\n"
            f"  ELO:          Red={self.elo_update.get('red_new', 0):.0f} Blue={self.elo_update.get('blue_new', 0):.0f}"
        )


@dataclass
class GenerationResult:
    generation_number: int
    rounds: list[RoundResult] = field(default_factory=list)
    avg_red_score: float = 0.0
    avg_blue_score: float = 0.0
    avg_evasion: float = 0.0
    red_elo: float = 1200.0
    blue_elo: float = 1200.0
    training_samples_added: int = 0

    def summary(self) -> str:
        return (
            f"Generation {self.generation_number} Summary\n"
            f"  Rounds:         {len(self.rounds)}\n"
            f"  Avg Red Score:  {self.avg_red_score:.2f}\n"
            f"  Avg Blue Score: {self.avg_blue_score:.2f}\n"
            f"  Avg Evasion:    {self.avg_evasion:.2f}\n"
            f"  Red ELO:        {self.red_elo:.0f}\n"
            f"  Blue ELO:       {self.blue_elo:.0f}\n"
            f"  New samples:    {self.training_samples_added}"
        )


class CoEvolutionArena:
    """
    Orchestrates adversarial co-evolution between Red and Blue team AIs.

    GAN-like training loop:
    - Red agent = generator (creates "exploits" the blue team can't detect)
    - Blue agent = discriminator (classifies technique artifacts as malicious/benign)
    - After N rounds, both adapters are retrained on new evidence
    """

    def __init__(
        self,
        red_agent: Optional[RedTeamAgent] = None,
        blue_agent: Optional[BlueTeamAgent] = None,
        elo_tracker: Optional[ELOTracker] = None,
        results_dir: str = "data/arena_results",
        retrain_after: int = 50,
    ):
        self.red_agent  = red_agent  or RedTeamAgent()
        self.blue_agent = blue_agent or BlueTeamAgent()
        self.elo_tracker = elo_tracker or ELOTracker()
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.retrain_after = retrain_after
        self._generation = 0
        self._total_samples = {"red_team": 0, "blue_team": 0}

    async def run_round(
        self,
        target: TargetProfile,
        round_number: int,
    ) -> RoundResult:
        """Execute one red-vs-blue round."""
        t0 = time.monotonic()

        # Phase 1: Red team attacks
        print(f"  [Round {round_number}] Red team attacking {target.vm_name}...")
        attack_result = await self.red_agent.attack(
            target.vm_name,
            target.techniques,
            target.platform,
        )

        # Phase 2: Blue team detects
        print(f"  [Round {round_number}] Blue team analyzing IOCs...")
        detection_result = self.blue_agent.detect_from_ioc_reports(
            attack_result.ioc_reports,
            attack_result.techniques_attempted,
            target.platform,
        )

        # Phase 3: Score
        red_score = attack_result.red_score

        # Evasion = confirmed but NOT detected
        confirmed_set = set(attack_result.techniques_confirmed)
        detected_set  = set(detection_result.techniques_detected)
        evaded = confirmed_set - detected_set
        evasion_score = len(evaded) / max(len(confirmed_set), 1)

        # Blue score = detection rate
        blue_score = detection_result.detection_rate

        # Phase 4: ELO update
        elo_update = self.elo_tracker.record_round(red_score, blue_score)

        # Phase 5: Generate training samples
        training_samples = self._generate_training_samples(
            attack_result, detection_result, target
        )

        duration = time.monotonic() - t0
        result = RoundResult(
            round_number=round_number,
            target=target,
            attack_result=attack_result,
            detection_result=detection_result,
            red_score=red_score,
            blue_score=blue_score,
            evasion_score=evasion_score,
            elo_update=elo_update,
            training_samples=training_samples,
            duration_s=duration,
        )

        # Save round result
        self._save_round(result)
        return result

    async def run_generation(
        self,
        target: Optional[TargetProfile] = None,
        n_rounds: int = 10,
    ) -> GenerationResult:
        """Run N rounds, then optionally retrain adapters."""
        self._generation += 1
        if target is None:
            target = TargetProfile.medium_linux()

        gen_result = GenerationResult(generation_number=self._generation)

        print(f"\n{'='*60}")
        print(f"Generation {self._generation} — {n_rounds} rounds")
        print(f"Target: {target.vm_name} ({target.platform}), difficulty={target.difficulty}")
        print(f"{'='*60}")

        for i in range(1, n_rounds + 1):
            round_result = await self.run_round(target, round_number=i)
            gen_result.rounds.append(round_result)
            print(f"\n{round_result.summary()}")

            # Append training samples
            for sample in round_result.training_samples:
                adapter = sample.pop("_adapter", "red_team")
                self._append_training_sample(adapter, sample)

        # Aggregate
        if gen_result.rounds:
            gen_result.avg_red_score  = sum(r.red_score  for r in gen_result.rounds) / n_rounds
            gen_result.avg_blue_score = sum(r.blue_score for r in gen_result.rounds) / n_rounds
            gen_result.avg_evasion    = sum(r.evasion_score for r in gen_result.rounds) / n_rounds
            gen_result.red_elo        = self.elo_tracker.red_team.rating
            gen_result.blue_elo       = self.elo_tracker.blue_team.rating
            gen_result.training_samples_added = sum(len(r.training_samples) for r in gen_result.rounds)

        # Conditional retraining
        total_samples = sum(self._total_samples.values())
        if total_samples >= self.retrain_after:
            print(f"\n[Arena] Triggering adapter retraining ({total_samples} new samples)...")
            self._retrain_adapters()
            self._total_samples = {"red_team": 0, "blue_team": 0}

        print(f"\n{gen_result.summary()}")
        print(f"\n{self.elo_tracker.summary()}")
        return gen_result

    def _generate_training_samples(
        self,
        attack: AttackResult,
        detection: DetectionResult,
        target: TargetProfile,
    ) -> list[dict]:
        """Create adapter training samples from round outcomes."""
        samples = []

        # Red team samples: confirmed techniques → positive examples
        for cmd_info in attack.commands_executed:
            tech_id = cmd_info.get("technique", "")
            confidence = cmd_info.get("ioc_confidence", 0.0)
            agent_response = cmd_info.get("agent_response", "")

            if confidence >= 0.5 and agent_response:
                sample = {
                    "_adapter": "red_team",
                    "messages": [
                        {"role": "user", "content": f"Execute MITRE technique {tech_id} on {target.platform}"},
                        {"role": "assistant", "content": agent_response},
                    ],
                    "quality": confidence,
                }
                samples.append(sample)

        # Blue team samples: detected techniques → positive detection examples
        for tech_id in detection.techniques_detected:
            # Find evidence from IOC reports
            evidence = next(
                (r for r in attack.ioc_reports if r.get("technique_id") == tech_id), {}
            )
            if evidence:
                sample = {
                    "_adapter": "blue_team",
                    "messages": [
                        {"role": "user", "content": f"Analyze this IOC evidence and identify the MITRE technique: {str(evidence)[:500]}"},
                        {"role": "assistant", "content": f"Detected technique: {tech_id}\nEvidence: {evidence.get('confidence', 0):.2f} confidence\nIOCs: {evidence.get('process_iocs', [])}"},
                    ],
                    "quality": detection.detection_rate,
                }
                samples.append(sample)

        return samples

    def _append_training_sample(self, adapter_name: str, sample: dict) -> None:
        """Append a training sample to the adapter's train.jsonl."""
        from llm.adapter_manager import get_adapter_manager
        manager = get_adapter_manager()
        manager.append_training_sample(adapter_name, sample)
        self._total_samples[adapter_name] = self._total_samples.get(adapter_name, 0) + 1

    def _retrain_adapters(self) -> None:
        """Retrain red_team and blue_team adapters with accumulated samples."""
        from llm.adapter_manager import get_adapter_manager
        manager = get_adapter_manager()
        for adapter_name in ("red_team", "blue_team"):
            count = manager.sample_count(adapter_name)
            if count >= 10:  # Minimum viable dataset
                print(f"[Arena] Retraining {adapter_name} adapter ({count} samples)...")
                proc = manager.train(adapter_name, iters=500, blocking=False)
                print(f"[Arena] Training process for {adapter_name} started (PID: {proc.pid})")

    def _save_round(self, result: RoundResult) -> None:
        """Save round result to JSONL file."""
        path = self.results_dir / f"gen_{self._generation:03d}_rounds.jsonl"
        record = {
            "round": result.round_number,
            "timestamp": result.timestamp,
            "platform": result.target.platform,
            "red_score": result.red_score,
            "blue_score": result.blue_score,
            "evasion": result.evasion_score,
            "duration_s": result.duration_s,
            "elo": result.elo_update,
        }
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
