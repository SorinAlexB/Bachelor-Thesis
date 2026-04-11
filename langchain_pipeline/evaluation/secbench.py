"""
SecBench evaluation framework.

Evaluates the system against a security AI benchmark dataset.
Supports multiple evaluation modes:
  - MCQ:      multiple-choice questions (SecBench format)
  - technique: given a technique ID, generate and test a command
  - campaign:  plan a multi-step campaign, evaluate completeness

SecBench dataset format (JSONL):
{
  "id":         "SB-001",
  "category":   "attack_technique|cve|cwe|defensive|mitre",
  "question":   "What is the primary purpose of T1059.001?",
  "choices":    {"A": "...", "B": "...", "C": "...", "D": "..."},
  "answer":     "B",
  "difficulty": "easy|medium|hard",
  "platform":   "windows|linux|macos|cross"
}
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from evaluation.metrics import paired_t_test, StatisticalTestResult


@dataclass
class EvalResult:
    sample_id: str
    category: str
    difficulty: str
    correct: bool
    model_answer: str
    expected_answer: str
    thinking: str = ""
    latency_s: float = 0.0
    used_rag: bool = False
    adapter_name: Optional[str] = None


@dataclass
class EvalReport:
    total: int = 0
    correct: int = 0
    by_category: dict = field(default_factory=dict)
    by_difficulty: dict = field(default_factory=dict)
    results: list[EvalResult] = field(default_factory=list)
    duration_s: float = 0.0
    model_info: dict = field(default_factory=dict)

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total > 0 else 0.0

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "SECBENCH EVALUATION REPORT",
            "=" * 60,
            f"  Total samples: {self.total}",
            f"  Accuracy:      {self.accuracy:.1%} ({self.correct}/{self.total})",
            f"  Duration:      {self.duration_s:.1f}s",
            f"  Model:         {self.model_info.get('model', 'unknown')}",
            f"  Adapter:       {self.model_info.get('adapter', 'none')}",
            f"  RAG:           {self.model_info.get('use_rag', False)}",
            "",
            "By Category:",
        ]
        for cat, stats in sorted(self.by_category.items()):
            acc = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
            lines.append(f"  {cat:20s}: {acc:.1%} ({stats['correct']}/{stats['total']})")
        lines.append("")
        lines.append("By Difficulty:")
        for diff in ("easy", "medium", "hard"):
            stats = self.by_difficulty.get(diff, {})
            if stats.get("total"):
                acc = stats["correct"] / stats["total"]
                lines.append(f"  {diff:8s}: {acc:.1%} ({stats['correct']}/{stats['total']})")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "accuracy": self.accuracy,
            "total": self.total,
            "correct": self.correct,
            "by_category": self.by_category,
            "by_difficulty": self.by_difficulty,
            "model_info": self.model_info,
            "duration_s": self.duration_s,
        }


# Default benchmark questions (subset; full dataset loaded from file)
_DEFAULT_QUESTIONS = [
    {
        "id": "SB-001", "category": "attack_technique", "difficulty": "easy",
        "question": "Which MITRE ATT&CK technique involves adversaries using the Windows command shell (cmd.exe)?",
        "choices": {"A": "T1059.001 (PowerShell)", "B": "T1059.003 (Windows Command Shell)", "C": "T1059.004 (Unix Shell)", "D": "T1059.006 (Python)"},
        "answer": "B", "platform": "windows",
    },
    {
        "id": "SB-002", "category": "cve", "difficulty": "medium",
        "question": "Log4Shell (CVE-2021-44228) affects which component?",
        "choices": {"A": "OpenSSL", "B": "Apache Log4j 2", "C": "Spring Framework", "D": "Apache Tomcat"},
        "answer": "B", "platform": "cross",
    },
    {
        "id": "SB-003", "category": "defensive", "difficulty": "medium",
        "question": "Which Windows Event ID is associated with process creation?",
        "choices": {"A": "4624", "B": "4688", "C": "4776", "D": "7045"},
        "answer": "B", "platform": "windows",
    },
    {
        "id": "SB-004", "category": "attack_technique", "difficulty": "hard",
        "question": "Which MITRE technique uses the Windows API CreateRemoteThread to inject code into another process?",
        "choices": {"A": "T1055.001", "B": "T1055.002", "C": "T1055.003", "D": "T1055.004"},
        "answer": "A", "platform": "windows",
    },
    {
        "id": "SB-005", "category": "mitre", "difficulty": "easy",
        "question": "In the MITRE ATT&CK framework, which tactic involves techniques that try to access credentials?",
        "choices": {"A": "Discovery", "B": "Lateral Movement", "C": "Credential Access", "D": "Collection"},
        "answer": "C", "platform": "cross",
    },
    {
        "id": "SB-006", "category": "cwe", "difficulty": "medium",
        "question": "CWE-79 refers to which class of vulnerability?",
        "choices": {"A": "SQL Injection", "B": "Cross-Site Scripting (XSS)", "C": "Buffer Overflow", "D": "Path Traversal"},
        "answer": "B", "platform": "cross",
    },
    {
        "id": "SB-007", "category": "attack_technique", "difficulty": "easy",
        "question": "T1003 OS Credential Dumping on Linux most commonly targets which file?",
        "choices": {"A": "/etc/passwd", "B": "/etc/hosts", "C": "/etc/shadow", "D": "/etc/sudoers"},
        "answer": "C", "platform": "linux",
    },
    {
        "id": "SB-008", "category": "defensive", "difficulty": "hard",
        "question": "A SIGMA rule uses which condition to detect PowerShell with encoded commands?",
        "choices": {
            "A": "CommandLine contains 'powershell'",
            "B": "CommandLine contains '-EncodedCommand'",
            "C": "EventID equals 4103",
            "D": "ParentImage endswith 'explorer.exe'",
        },
        "answer": "B", "platform": "windows",
    },
    {
        "id": "SB-009", "category": "mitre", "difficulty": "medium",
        "question": "T1566.001 (Spearphishing Attachment) belongs to which MITRE tactic?",
        "choices": {"A": "Execution", "B": "Persistence", "C": "Initial Access", "D": "Resource Development"},
        "answer": "C", "platform": "cross",
    },
    {
        "id": "SB-010", "category": "attack_technique", "difficulty": "hard",
        "question": "Which technique uses the /etc/cron.d directory on Linux to achieve persistence?",
        "choices": {"A": "T1053.003", "B": "T1053.005", "C": "T1078", "D": "T1547.001"},
        "answer": "A", "platform": "linux",
    },
]


class SecBenchEvaluator:
    """
    Evaluates the security AI pipeline against SecBench questions.

    Supports four evaluation variants for ablation study:
    1. Baseline: base model, no RAG, no adapter
    2. RAG only: base model + RAG context
    3. Adapter only: specialized adapter, no RAG
    4. Full (CPT + RAG): adapter + RAG (best expected performance)
    """

    def __init__(self, dataset_path: Optional[str] = None):
        self.dataset_path = dataset_path
        self._questions: Optional[list[dict]] = None

    def _load_questions(self) -> list[dict]:
        if self._questions is not None:
            return self._questions
        if self.dataset_path and Path(self.dataset_path).exists():
            questions = []
            with open(self.dataset_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        questions.append(json.loads(line))
            self._questions = questions
        else:
            self._questions = _DEFAULT_QUESTIONS
        return self._questions

    def _build_prompt(
        self,
        question: dict,
        rag_context: str = "",
    ) -> str:
        choices_text = "\n".join(
            f"  {k}. {v}" for k, v in question.get("choices", {}).items()
        )
        prompt_parts = []
        if rag_context:
            prompt_parts.append(f"Context from security corpus:\n{rag_context}\n\n")
        prompt_parts.append(
            f"Question: {question['question']}\n\n"
            f"Choices:\n{choices_text}\n\n"
            f"Answer with the letter only (A, B, C, or D):"
        )
        return "".join(prompt_parts)

    def _extract_answer(self, response: str) -> str:
        """Extract the single letter answer from LLM response."""
        import re
        # Remove thinking block
        response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
        # Look for a standalone letter
        match = re.search(r"\b([ABCD])\b", response)
        if match:
            return match.group(1)
        # Take first character if it's a valid choice
        first = response.strip()[:1].upper()
        if first in "ABCD":
            return first
        return ""

    def evaluate(
        self,
        llm=None,
        adapter_name: Optional[str] = None,
        use_rag: bool = True,
        n_samples: Optional[int] = None,
        verbose: bool = True,
    ) -> EvalReport:
        """
        Run evaluation against the SecBench dataset.

        Args:
            llm:          MLXLM instance (created from config if None)
            adapter_name: LoRA adapter to use (None = base model)
            use_rag:      Whether to inject RAG context into prompts
            n_samples:    Limit evaluation to N samples (None = all)
            verbose:      Print per-question results

        Returns:
            EvalReport with accuracy breakdown
        """
        if llm is None:
            from config import MODEL_PATH, MAX_TOKENS, TEMPERATURE
            from llm.mlx_wrapper import MLXLM
            llm = MLXLM(
                model_path=MODEL_PATH,
                max_tokens=512,
                temperature=0.0,  # Greedy for evaluation
                adapter_name=adapter_name,
            )

        retriever = None
        if use_rag:
            from rag.retriever import get_retriever
            retriever = get_retriever()

        questions = self._load_questions()
        if n_samples:
            questions = questions[:n_samples]

        report = EvalReport(
            model_info={
                "model": getattr(llm, "model_path", "unknown"),
                "adapter": adapter_name,
                "use_rag": use_rag,
            }
        )
        t_start = time.time()

        for i, q in enumerate(questions):
            t0 = time.monotonic()

            # RAG context injection
            rag_context = ""
            if retriever:
                rag_context = retriever.format_context(
                    q["question"],
                    platform=q.get("platform") if q.get("platform") != "cross" else None,
                )

            prompt   = self._build_prompt(q, rag_context)
            response = llm.invoke(prompt)
            answer   = self._extract_answer(response)
            correct  = answer == q.get("answer", "")
            latency  = time.monotonic() - t0

            # Extract thinking
            from llm.mlx_wrapper import MLXLM as _MLXLM
            thinking, _ = _MLXLM.parse_thinking(response)

            result = EvalResult(
                sample_id=q.get("id", str(i)),
                category=q.get("category", "unknown"),
                difficulty=q.get("difficulty", "medium"),
                correct=correct,
                model_answer=answer,
                expected_answer=q.get("answer", ""),
                thinking=thinking[:200] if thinking else "",
                latency_s=latency,
                used_rag=use_rag,
                adapter_name=adapter_name,
            )
            report.results.append(result)
            report.total += 1
            if correct:
                report.correct += 1

            # Update breakdown dicts
            cat = result.category
            diff = result.difficulty
            report.by_category.setdefault(cat, {"correct": 0, "total": 0})
            report.by_category[cat]["total"] += 1
            if correct:
                report.by_category[cat]["correct"] += 1
            report.by_difficulty.setdefault(diff, {"correct": 0, "total": 0})
            report.by_difficulty[diff]["total"] += 1
            if correct:
                report.by_difficulty[diff]["correct"] += 1

            if verbose:
                status = "✓" if correct else "✗"
                print(f"  [{status}] {result.sample_id} ({result.category}/{result.difficulty}): "
                      f"got={answer} expected={result.expected_answer} ({latency:.1f}s)")

        report.duration_s = time.time() - t_start
        return report

    def ablation_study(self, n_samples: int = 10) -> dict[str, EvalReport]:
        """
        Run the 4-variant ablation study:
          1. Baseline (base model, no RAG, no adapter)
          2. RAG only
          3. Adapter only (red_team)
          4. Full (adapter + RAG)

        Returns dict mapping variant name to EvalReport.
        """
        results: dict[str, EvalReport] = {}
        from config import MODEL_PATH, MAX_TOKENS
        from llm.mlx_wrapper import MLXLM

        variants = [
            ("baseline",      None,       False),
            ("rag_only",      None,       True),
            ("adapter_only",  "red_team", False),
            ("full",          "red_team", True),
        ]

        for name, adapter, rag in variants:
            print(f"\n[Ablation] Running variant: {name}")
            llm = MLXLM(
                model_path=MODEL_PATH,
                max_tokens=512,
                temperature=0.0,
                adapter_name=adapter,
            )
            report = self.evaluate(
                llm=llm,
                adapter_name=adapter,
                use_rag=rag,
                n_samples=n_samples,
                verbose=False,
            )
            results[name] = report
            print(f"  Accuracy: {report.accuracy:.1%}")

        # Statistical comparison: baseline vs full
        if "baseline" in results and "full" in results:
            baseline_scores = [1.0 if r.correct else 0.0 for r in results["baseline"].results]
            full_scores     = [1.0 if r.correct else 0.0 for r in results["full"].results]
            if len(baseline_scores) == len(full_scores):
                stat = paired_t_test(baseline_scores, full_scores, "Baseline vs Full")
                print(f"\n[Statistics] {stat}")

        return results

    def save_report(self, report: EvalReport, path: str = "reports/eval_report.json") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"Report saved to {path}")
