"""
High-level pipeline orchestrator for thesis experiments.

This is the main entry point for running the complete system.

Modes:
  ingest              - Build the 25k-document RAG corpus (run once)
  train <adapter>     - Train a LoRA adapter (ctf|red_team|blue_team|explainer)
  feedback            - Run the self-improving feedback loop
  coevolve            - Run adversarial co-evolution (Red vs Blue)
  evaluate            - Run SecBench ablation study
  ablation            - Full 4-variant ablation study
  campaign <t> <g> <p> - Plan attack campaign (technique, goal_tactic, platform)
  build-cpp           - Build the C++ extensions

Usage:
  python pipeline_runner.py ingest
  python pipeline_runner.py train red_team
  python pipeline_runner.py feedback --techniques T1082,T1057 --vms linux --iters 3
  python pipeline_runner.py coevolve --rounds 5
  python pipeline_runner.py evaluate --n 10
  python pipeline_runner.py ablation --n 10
  python pipeline_runner.py campaign T1566.001 exfiltration linux
  python pipeline_runner.py build-cpp
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
from pathlib import Path


class PipelineRunner:
    """Wires all subsystems together and exposes high-level experiment methods."""

    def __init__(self):
        # All subsystems are lazy-initialized
        self._adapter_manager = None
        self._rag_store        = None
        self._embedder         = None
        self._retriever        = None
        self._planner          = None
        self._evaluator        = None
        self._feedback_loop    = None
        self._arena            = None

    # ─── Lazy accessors ───────────────────────────────────────────────────────

    def adapter_manager(self):
        if self._adapter_manager is None:
            from llm.adapter_manager import get_adapter_manager
            self._adapter_manager = get_adapter_manager()
        return self._adapter_manager

    def rag_store(self):
        if self._rag_store is None:
            from rag.chroma_store import get_store
            self._rag_store = get_store()
        return self._rag_store

    def retriever(self):
        if self._retriever is None:
            from rag.retriever import get_retriever
            self._retriever = get_retriever()
        return self._retriever

    def planner(self):
        if self._planner is None:
            from mitre.planner import MITRECampaignPlanner
            self._planner = MITRECampaignPlanner()
        return self._planner

    def evaluator(self):
        if self._evaluator is None:
            from evaluation.secbench import SecBenchEvaluator
            from config import SECBENCH_PATH
            self._evaluator = SecBenchEvaluator(SECBENCH_PATH)
        return self._evaluator

    def feedback_loop(self):
        if self._feedback_loop is None:
            from feedback.feedback_loop import FeedbackLoop
            from config import FEEDBACK_LOG, FEEDBACK_RETRAIN_THRESHOLD, FEEDBACK_MIN_CONFIDENCE
            self._feedback_loop = FeedbackLoop(
                feedback_log=FEEDBACK_LOG,
                min_confidence=FEEDBACK_MIN_CONFIDENCE,
                retrain_threshold=FEEDBACK_RETRAIN_THRESHOLD,
            )
        return self._feedback_loop

    def arena(self):
        if self._arena is None:
            from coevolution.arena import CoEvolutionArena
            from config import FEEDBACK_RETRAIN_THRESHOLD
            self._arena = CoEvolutionArena(retrain_after=FEEDBACK_RETRAIN_THRESHOLD)
        return self._arena

    # ─── Experiment methods ───────────────────────────────────────────────────

    def ingest(
        self,
        skip_mitre: bool = False,
        skip_nvd: bool = False,
        skip_exploitdb: bool = False,
    ) -> None:
        """Build the full RAG database."""
        from rag.ingestion.pipeline import build_rag_database
        build_rag_database(
            skip_mitre=skip_mitre,
            skip_nvd=skip_nvd,
            skip_exploitdb=skip_exploitdb,
        )

    def train_adapter(self, adapter_name: str, iters: int = 1000) -> None:
        """Train a LoRA adapter."""
        valid = ("ctf", "red_team", "blue_team", "explainer")
        if adapter_name not in valid:
            print(f"Unknown adapter '{adapter_name}'. Valid: {valid}")
            return
        mgr = self.adapter_manager()
        count = mgr.sample_count(adapter_name)
        print(f"Training {adapter_name} adapter ({count} samples, {iters} iterations)...")
        mgr.train(adapter_name, iters=iters, blocking=True)

    def run_feedback_loop(
        self,
        techniques: list[str] | None = None,
        vms: list[str] | None = None,
        iterations: int = 1,
    ) -> None:
        """Run the self-improving feedback loop."""
        if techniques is None:
            techniques = ["T1082", "T1057", "T1049", "T1059.004"]
        if vms is None:
            vms = ["linux"]

        loop = self.feedback_loop()
        summary = loop.run(
            technique_ids=techniques,
            target_vms=vms,
            iterations=iterations,
        )
        print("\n" + summary.summary())

        # Show improvement curve and generate chart
        history = loop.success_rate_over_time()
        if len(history) > 1:
            print(f"\nSuccess rate over time: {[f'{r:.1%}' for r in history[-10:]]}")
            from evaluation.report import plot_feedback_improvement
            plot_feedback_improvement(history)

    def run_coevolution(self, rounds: int = 5, platform: str = "linux") -> None:
        """Run adversarial co-evolution between Red and Blue teams."""
        from coevolution.arena import TargetProfile
        arena = self.arena()

        if platform == "linux":
            target = TargetProfile.medium_linux()
        else:
            target = TargetProfile(
                platform=platform, vm_name=platform,
                techniques=["T1082", "T1057", "T1059.004"],
                difficulty="medium",
            )

        asyncio.run(arena.run_generation(target=target, n_rounds=rounds))

    def run_evaluation(self, n_samples: int | None = None, adapter: str | None = None) -> None:
        """Run SecBench evaluation."""
        ev = self.evaluator()
        report = ev.evaluate(adapter_name=adapter, use_rag=True, n_samples=n_samples)
        from evaluation.report import print_eval_report, generate_html_report
        print_eval_report(report)
        from config import EVAL_REPORT_DIR
        ev.save_report(report, f"{EVAL_REPORT_DIR}/eval_{adapter or 'base'}.json")
        generate_html_report(report, f"{EVAL_REPORT_DIR}/eval_{adapter or 'base'}.html")

    def plan_campaign(
        self,
        start_technique: str,
        goal_tactic: str,
        platform: str = "linux",
    ) -> None:
        """Plan and display a multi-stage attack campaign."""
        planner = self.planner()
        campaign = planner.plan(start_technique, goal_tactic, platform=platform)
        print(f"\n{campaign}")

    def run_cross_platform(
        self,
        techniques: list[str] | None = None,
        platforms: list[str] | None = None,
    ) -> None:
        """Run cross-platform transfer test."""
        if techniques is None:
            techniques = ["T1082", "T1057", "T1059.004", "T1083", "T1049"]
        from feedback.cross_platform import CrossPlatformExecutor
        executor = CrossPlatformExecutor()
        results = executor.run_batch(techniques, platforms=platforms)

        # Generate heatmap
        from evaluation.report import plot_cross_platform_heatmap
        plot_cross_platform_heatmap(results)

    def run_ablation_study(self, n_samples: int = 10) -> None:
        """Run the 4-variant ablation study."""
        ev = self.evaluator()
        results = ev.ablation_study(n_samples=n_samples)
        print("\n" + "=" * 60)
        print("ABLATION STUDY RESULTS")
        print("=" * 60)

        from evaluation.report import print_ablation_table, plot_ablation_comparison
        print_ablation_table(results)
        plot_ablation_comparison(results)

        from config import EVAL_REPORT_DIR
        import json
        Path(EVAL_REPORT_DIR).mkdir(parents=True, exist_ok=True)
        with open(f"{EVAL_REPORT_DIR}/ablation_study.json", "w") as f:
            json.dump({k: v.to_dict() for k, v in results.items()}, f, indent=2)
        print(f"\nResults saved to {EVAL_REPORT_DIR}/ablation_study.json")

    def build_cpp_extensions(self) -> None:
        """Build the C++ pybind11 extensions."""
        cpp_dir = Path(__file__).parent.parent / "cpp_extensions"
        if not cpp_dir.exists():
            print("cpp_extensions/ directory not found")
            return
        print(f"Building C++ extensions in {cpp_dir}...")
        result = subprocess.run(
            [sys.executable, "setup.py", "build_ext", "--inplace"],
            cwd=cpp_dir,
            capture_output=False,
        )
        if result.returncode == 0:
            print("C++ extensions built successfully")
        else:
            print("Build failed — check output above")

    def rag_stats(self) -> None:
        """Print RAG corpus statistics."""
        store = self.rag_store()
        stats = store.stats()
        print(f"\nRAG Corpus Statistics:")
        print(f"  Total chunks: {stats.get('total', 0)}")
        by_source = stats.get("by_source", {})
        for source, count in sorted(by_source.items()):
            print(f"  {source:15s}: {count}")
        by_platform = stats.get("by_platform", {})
        print(f"\n  By platform:")
        for platform, count in sorted(by_platform.items()):
            print(f"  {platform:15s}: {count}")

    def rag_search(self, query: str, platform: str = "") -> None:
        """Quick RAG search for testing."""
        r = self.retriever()
        context = r.format_context(query, platform=platform or None)
        print(context)


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Security AI Pipeline Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ingest
    p = subparsers.add_parser("ingest", help="Build RAG corpus")
    p.add_argument("--skip-mitre",    action="store_true")
    p.add_argument("--skip-nvd",      action="store_true")
    p.add_argument("--skip-exploitdb", action="store_true")

    # train
    p = subparsers.add_parser("train", help="Train a LoRA adapter")
    p.add_argument("adapter", choices=["ctf", "red_team", "blue_team", "explainer"])
    p.add_argument("--iters", type=int, default=1000)

    # feedback
    p = subparsers.add_parser("feedback", help="Run self-improving feedback loop")
    p.add_argument("--techniques", type=str, default="T1082,T1057,T1059.004")
    p.add_argument("--vms", type=str, default="linux")
    p.add_argument("--iters", type=int, default=1, dest="iterations")

    # coevolve
    p = subparsers.add_parser("coevolve", help="Run adversarial co-evolution")
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--platform", type=str, default="linux")

    # evaluate
    p = subparsers.add_parser("evaluate", help="Run SecBench evaluation")
    p.add_argument("--n", type=int, default=None, dest="n_samples")
    p.add_argument("--adapter", type=str, default=None)

    # ablation
    p = subparsers.add_parser("ablation", help="Run ablation study")
    p.add_argument("--n", type=int, default=10, dest="n_samples")

    # campaign
    p = subparsers.add_parser("campaign", help="Plan attack campaign")
    p.add_argument("start_technique")
    p.add_argument("goal_tactic")
    p.add_argument("platform", nargs="?", default="linux")

    # build-cpp
    subparsers.add_parser("build-cpp", help="Build C++ extensions")

    # rag-stats
    subparsers.add_parser("rag-stats", help="Show RAG corpus statistics")

    # rag-search
    p = subparsers.add_parser("rag-search", help="Search RAG corpus")
    p.add_argument("query")
    p.add_argument("--platform", type=str, default="")

    # cross-platform
    p = subparsers.add_parser("cross-platform", help="Cross-platform transfer test")
    p.add_argument("--techniques", type=str, default="T1082,T1057,T1059.004,T1083,T1049")
    p.add_argument("--platforms", type=str, default="", help="Comma-separated: linux,macos,windows")

    args = parser.parse_args()
    runner = PipelineRunner()

    if args.command == "ingest":
        runner.ingest(
            skip_mitre=args.skip_mitre,
            skip_nvd=args.skip_nvd,
            skip_exploitdb=args.skip_exploitdb,
        )
    elif args.command == "train":
        runner.train_adapter(args.adapter, iters=args.iters)
    elif args.command == "feedback":
        runner.run_feedback_loop(
            techniques=args.techniques.split(","),
            vms=args.vms.split(","),
            iterations=args.iterations,
        )
    elif args.command == "coevolve":
        runner.run_coevolution(rounds=args.rounds, platform=args.platform)
    elif args.command == "evaluate":
        runner.run_evaluation(n_samples=args.n_samples, adapter=args.adapter)
    elif args.command == "ablation":
        runner.run_ablation_study(n_samples=args.n_samples)
    elif args.command == "campaign":
        runner.plan_campaign(args.start_technique, args.goal_tactic, args.platform)
    elif args.command == "build-cpp":
        runner.build_cpp_extensions()
    elif args.command == "rag-stats":
        runner.rag_stats()
    elif args.command == "rag-search":
        runner.rag_search(args.query, platform=args.platform)
    elif args.command == "cross-platform":
        platforms = args.platforms.split(",") if args.platforms else None
        runner.run_cross_platform(
            techniques=args.techniques.split(","),
            platforms=platforms,
        )


if __name__ == "__main__":
    main()
