"""
Evaluation metrics for the security AI system.

Metrics:
  - pass@k:           probability that at least one of k attempts succeeds
  - IOC detection rate: fraction of executed techniques detected by blue team
  - campaign success rate: fraction of full campaigns completed
  - cross-platform transfer: success rate on unseen platforms
  - statistical significance: paired t-test, Cohen's d, confidence intervals
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

import numpy as np
from scipy import stats


@dataclass
class PassAtKResult:
    technique_id: str
    platform: str
    k: int
    successes: int
    attempts: int
    pass_at_k: float

    def __str__(self) -> str:
        return f"pass@{self.k}({self.technique_id}/{self.platform}) = {self.pass_at_k:.3f}"


def compute_pass_at_k(n_samples: int, n_correct: int, k: int) -> float:
    """
    Compute the pass@k metric.

    pass@k = 1 - C(n-c, k) / C(n, k)
    where n = total samples, c = correct samples.

    This is the probability that at least one of k randomly chosen samples succeeds.
    """
    if n_correct == 0:
        return 0.0
    if n_correct >= n_samples:
        return 1.0
    # Use log-space to avoid overflow
    # C(n-c, k) / C(n, k) = product_{i=0}^{k-1} (n-c-i) / (n-i)
    if n_samples - n_correct < k:
        return 1.0
    result = 1.0
    for i in range(k):
        result *= (n_samples - n_correct - i) / (n_samples - i)
    return max(0.0, 1.0 - result)


@dataclass
class StatisticalTestResult:
    test_name: str
    p_value: float
    effect_size: float  # Cohen's d
    significant: bool   # p < 0.05
    confidence_interval: tuple[float, float]  # 95% CI for effect size

    def __str__(self) -> str:
        sig = "SIGNIFICANT" if self.significant else "not significant"
        return (
            f"{self.test_name}: p={self.p_value:.4f} ({sig}), "
            f"Cohen's d={self.effect_size:.3f}, "
            f"95% CI=[{self.confidence_interval[0]:.3f}, {self.confidence_interval[1]:.3f}]"
        )


def paired_t_test(
    baseline: list[float],
    experimental: list[float],
    test_name: str = "Comparison",
) -> StatisticalTestResult:
    """
    Paired t-test comparing baseline vs experimental results.

    Args:
        baseline:     Scores from the baseline system
        experimental: Scores from the experimental system (same samples)
        test_name:    Label for the comparison

    Returns:
        StatisticalTestResult with p-value, Cohen's d, and 95% CI
    """
    assert len(baseline) == len(experimental), "Lists must have equal length"

    baseline_arr     = np.array(baseline)
    experimental_arr = np.array(experimental)
    differences      = experimental_arr - baseline_arr

    t_stat, p_value = stats.ttest_rel(baseline_arr, experimental_arr)

    # Cohen's d for paired samples
    d_mean = np.mean(differences)
    d_std  = np.std(differences, ddof=1)
    cohens_d = d_mean / d_std if d_std > 0 else 0.0

    # 95% CI for Cohen's d (bootstrap approximation)
    n = len(differences)
    se = 1 / math.sqrt(n) * math.sqrt(1 + cohens_d**2 / 2)
    ci_low  = cohens_d - 1.96 * se
    ci_high = cohens_d + 1.96 * se

    return StatisticalTestResult(
        test_name=test_name,
        p_value=float(p_value),
        effect_size=float(cohens_d),
        significant=float(p_value) < 0.05,
        confidence_interval=(float(ci_low), float(ci_high)),
    )


def ioc_detection_rate(
    executed_techniques: list[str],
    detected_techniques: list[str],
) -> float:
    """
    Fraction of executed techniques detected by the blue team.

    Args:
        executed_techniques: All technique IDs that were executed
        detected_techniques: Technique IDs the blue team detected

    Returns:
        Detection rate in [0.0, 1.0]
    """
    if not executed_techniques:
        return 0.0
    detected_set = set(detected_techniques)
    return sum(1 for t in executed_techniques if t in detected_set) / len(executed_techniques)


def campaign_success_metrics(campaigns: list[dict]) -> dict:
    """
    Aggregate metrics across multiple campaign results.

    Each campaign dict: {steps_planned, steps_completed, techniques: []}

    Returns:
        {
          avg_steps_completed,
          full_campaign_success_rate,
          partial_success_rate (>= 50% steps),
          technique_coverage: {tactic: rate}
        }
    """
    if not campaigns:
        return {}

    full_successes = 0
    partial_successes = 0
    step_fractions: list[float] = []

    for camp in campaigns:
        planned   = camp.get("steps_planned", 1)
        completed = camp.get("steps_completed", 0)
        frac = completed / planned if planned > 0 else 0.0
        step_fractions.append(frac)
        if frac >= 1.0:
            full_successes += 1
        if frac >= 0.5:
            partial_successes += 1

    return {
        "avg_steps_completed_rate": float(np.mean(step_fractions)),
        "full_campaign_success_rate": full_successes / len(campaigns),
        "partial_success_rate": partial_successes / len(campaigns),
        "std_completion_rate": float(np.std(step_fractions)),
    }


def cross_platform_transfer_score(
    linux_results: list[float],
    windows_results: list[float],
    macos_results: list[float],
) -> dict:
    """
    Measure cross-platform transfer: how well knowledge from one OS transfers to others.

    Args:
        *_results: Success rates (0-1) per technique on each platform

    Returns:
        {platform_scores, transfer_score, consistency_score}
    """
    scores = {
        "linux":   float(np.mean(linux_results))   if linux_results   else 0.0,
        "windows": float(np.mean(windows_results)) if windows_results else 0.0,
        "macos":   float(np.mean(macos_results))   if macos_results   else 0.0,
    }
    all_scores = [s for s in scores.values() if s > 0]
    transfer_score = float(np.mean(all_scores)) if all_scores else 0.0
    consistency    = 1.0 - float(np.std(all_scores)) if len(all_scores) > 1 else 1.0

    return {
        "platform_scores": scores,
        "transfer_score": transfer_score,
        "consistency_score": max(0.0, consistency),
    }
