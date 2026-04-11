"""
Self-improving feedback loop.

Cycle:
  1. Generate technique command (via LLM + RAG)
  2. Snapshot VM
  3. Execute command on VM via SSH
  4. Collect IOCs (verify execution)
  5. Analyze: success or failure?
  6. Append to adapter training data if confidence >= threshold
  7. After N samples, retrain adapter
  8. Restore VM to clean state

This implements "learning from execution" — the model improves with each
iteration because successful (confirmed) technique-command pairs are added
to the training data.

Metrics tracked: success rate over iterations (shows improvement curve).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class FeedbackSample:
    technique_id: str
    platform: str
    command: str
    execution_result: dict
    ioc_confidence: float
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_training_sample(self) -> dict:
        """Convert to mlx-lm chat format training sample."""
        return {
            "messages": [
                {
                    "role": "user",
                    "content": f"Generate a command to test MITRE technique {self.technique_id} on {self.platform}",
                },
                {
                    "role": "assistant",
                    "content": (
                        f"<think>\n"
                        f"Technique {self.technique_id} on {self.platform}. "
                        f"Command executed with IOC confidence {self.ioc_confidence:.2f}.\n"
                        f"</think>\n"
                        f"{self.command}"
                    ),
                },
            ],
            "quality": self.ioc_confidence,
        }


@dataclass
class FeedbackSummary:
    total_attempts: int = 0
    successful: int = 0
    failed: int = 0
    training_samples_added: int = 0
    adapter_retrains: int = 0
    success_rate_history: list[float] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.successful / self.total_attempts

    def summary(self) -> str:
        return (
            f"Feedback Loop Summary\n"
            f"  Attempts:     {self.total_attempts}\n"
            f"  Successful:   {self.successful}\n"
            f"  Failed:       {self.failed}\n"
            f"  Success rate: {self.success_rate:.1%}\n"
            f"  Training samples: {self.training_samples_added}\n"
            f"  Retrains:     {self.adapter_retrains}\n"
            f"  Duration:     {self.duration_s:.1f}s"
        )


class FeedbackLoop:
    """
    Self-improving feedback loop: execute → learn → improve.

    Usage:
        loop = FeedbackLoop()
        summary = loop.run(
            technique_ids=["T1082", "T1057", "T1059.004"],
            target_vms=["linux"],
            adapter_name="red_team",
            iterations=3,
        )
    """

    def __init__(
        self,
        adapter_name: str = "red_team",
        feedback_log: str = "data/feedback.jsonl",
        min_confidence: float = 0.5,
        retrain_threshold: int = 50,
    ):
        self.adapter_name    = adapter_name
        self.feedback_log    = Path(feedback_log)
        self.min_confidence  = min_confidence
        self.retrain_threshold = retrain_threshold
        self.feedback_log.parent.mkdir(parents=True, exist_ok=True)

    def _generate_command(self, technique_id: str, platform: str) -> str:
        """Generate a test command for the technique via RAG + oneliner library."""
        from tools.security_tools import generate_test_oneliner
        result = generate_test_oneliner.invoke({
            "technique_id": technique_id,
            "target_os": platform,
            "context": "No placeholders. Command must run as-is.",
        })
        # Extract just the command if there's RAG context above it
        lines = result.strip().splitlines()
        for line in reversed(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                return stripped
        return result.strip().splitlines()[0] if result.strip() else ""

    def _run_single(
        self,
        technique_id: str,
        vm_name: str,
        platform: str,
    ) -> FeedbackSample:
        """Run one feedback iteration for a single technique on one VM."""
        from tools.ssh_executor import get_ssh_pool
        from tools.ioc_collector import get_ioc_collector
        from tools.vm_tools import get_vm_manager
        from config import VMS

        ssh_pool     = get_ssh_pool()
        ioc_collector = get_ioc_collector()
        vm_mgr       = get_vm_manager()
        cfg          = VMS.get(vm_name, {})
        actual_name  = cfg.get("vm_name", vm_name)
        backend      = cfg.get("backend", "tart")

        # Generate command
        command = self._generate_command(technique_id, platform)
        if not command:
            return FeedbackSample(
                technique_id=technique_id, platform=platform,
                command="", execution_result={"error": "No command generated"},
                ioc_confidence=0.0, success=False,
            )

        # Snapshot
        try:
            vm_mgr.snapshot(actual_name, backend=backend)
        except Exception:
            pass

        # Execute
        try:
            exec_result = ssh_pool.execute(vm_name, command, timeout=60)
            result_dict = {
                "stdout": exec_result.stdout[:500],
                "stderr": exec_result.stderr[:200],
                "exit_code": exec_result.exit_code,
                "duration_s": exec_result.duration_s,
            }
        except Exception as exc:
            result_dict = {"error": str(exc)}
            exec_result = None

        # Collect IOCs
        try:
            ioc_report = ioc_collector.collect(ssh_pool, vm_name, technique_id, platform)
            confidence = ioc_report.confidence
        except Exception:
            confidence = 0.1 if exec_result and exec_result.success else 0.0

        # Restore
        try:
            snap = f"{actual_name}-clean"
            vm_mgr.restore(actual_name, snap, backend=backend)
        except Exception:
            pass

        success = confidence >= self.min_confidence
        return FeedbackSample(
            technique_id=technique_id,
            platform=platform,
            command=command,
            execution_result=result_dict,
            ioc_confidence=confidence,
            success=success,
        )

    def _log_sample(self, sample: FeedbackSample) -> None:
        """Append sample to the JSONL feedback log."""
        with open(self.feedback_log, "a") as f:
            f.write(json.dumps(sample.__dict__) + "\n")

    def run(
        self,
        technique_ids: list[str],
        target_vms: list[str],
        iterations: int = 1,
    ) -> FeedbackSummary:
        """
        Run the feedback loop over the given techniques and VMs.

        Args:
            technique_ids: MITRE technique IDs to test
            target_vms:    VM names to test on (e.g. ["linux", "macos"])
            iterations:    How many times to repeat the full technique list

        Returns:
            FeedbackSummary with improvement metrics
        """
        from llm.adapter_manager import get_adapter_manager
        manager = get_adapter_manager()

        summary = FeedbackSummary()
        t0 = time.monotonic()

        for iteration in range(1, iterations + 1):
            iter_successes = 0
            iter_total = 0

            print(f"\n[FeedbackLoop] Iteration {iteration}/{iterations}")

            for vm_name in target_vms:
                from config import VMS
                platform = VMS.get(vm_name, {}).get("platform", "linux")

                for tech_id in technique_ids:
                    print(f"  [{tech_id}] on {vm_name}...", end=" ", flush=True)
                    sample = self._run_single(tech_id, vm_name, platform)
                    self._log_sample(sample)

                    summary.total_attempts += 1
                    iter_total += 1

                    if sample.success:
                        summary.successful += 1
                        iter_successes += 1
                        print(f"OK (confidence={sample.ioc_confidence:.2f})")

                        # Add to training data
                        training_sample = sample.to_training_sample()
                        count = manager.append_training_sample(self.adapter_name, training_sample)
                        summary.training_samples_added += 1

                        # Retrain if threshold reached
                        if count % self.retrain_threshold == 0:
                            print(f"\n[FeedbackLoop] Triggering retrain ({count} samples)...")
                            manager.train(self.adapter_name, iters=500, blocking=False)
                            summary.adapter_retrains += 1
                    else:
                        summary.failed += 1
                        print(f"FAIL (confidence={sample.ioc_confidence:.2f})")

            # Track per-iteration success rate
            iter_rate = iter_successes / max(iter_total, 1)
            summary.success_rate_history.append(iter_rate)
            print(f"\n[Iteration {iteration}] Success rate: {iter_rate:.1%}")

        summary.duration_s = time.monotonic() - t0
        print(f"\n{summary.summary()}")

        # Show improvement trend
        if len(summary.success_rate_history) > 1:
            first = summary.success_rate_history[0]
            last  = summary.success_rate_history[-1]
            delta = last - first
            print(f"\nImprovement: {first:.1%} → {last:.1%} (Δ{delta:+.1%})")

        return summary

    def load_history(self) -> list[dict]:
        """Load all feedback samples from the log file."""
        if not self.feedback_log.exists():
            return []
        samples = []
        with open(self.feedback_log) as f:
            for line in f:
                line = line.strip()
                if line:
                    samples.append(json.loads(line))
        return samples

    def success_rate_over_time(self) -> list[float]:
        """Calculate rolling success rate from the log (for thesis graphs)."""
        samples = self.load_history()
        if not samples:
            return []
        window = 10
        rates: list[float] = []
        for i in range(len(samples)):
            window_samples = samples[max(0, i - window + 1):i + 1]
            rate = sum(1 for s in window_samples if s.get("success")) / len(window_samples)
            rates.append(rate)
        return rates
