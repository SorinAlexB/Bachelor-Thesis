"""
Evaluation report generator.

Generates human-readable reports from evaluation results in multiple formats:
  - Terminal (rich tables)
  - JSON (machine-readable)
  - HTML (for thesis appendix)
  - Markdown (for GitHub)

Also generates thesis-quality visualizations:
  - Accuracy by category/difficulty (bar chart → saved as PNG)
  - ELO rating over time (line chart)
  - Feedback loop success rate improvement curve
  - Cross-platform transfer heatmap
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─── Terminal (Rich) reports ──────────────────────────────────────────────────

def print_eval_report(report, title: str = "Evaluation Report") -> None:
    """Print an EvalReport to terminal using Rich tables."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        console = Console()

        # Summary panel
        console.print(Panel(
            f"Accuracy: [bold green]{report.accuracy:.1%}[/] "
            f"({report.correct}/{report.total} correct)\n"
            f"Duration: {report.duration_s:.1f}s\n"
            f"Model: {report.model_info.get('model', 'unknown')}\n"
            f"Adapter: {report.model_info.get('adapter', 'none')} | "
            f"RAG: {report.model_info.get('use_rag', False)}",
            title=f"[bold]{title}[/]",
            border_style="green",
        ))

        # By category table
        table = Table(title="Results by Category", show_header=True)
        table.add_column("Category",   style="cyan")
        table.add_column("Correct",    justify="right")
        table.add_column("Total",      justify="right")
        table.add_column("Accuracy",   justify="right", style="bold")
        for cat, stats in sorted(report.by_category.items()):
            acc = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
            color = "green" if acc >= 0.7 else "yellow" if acc >= 0.5 else "red"
            table.add_row(
                cat,
                str(stats["correct"]),
                str(stats["total"]),
                f"[{color}]{acc:.1%}[/{color}]",
            )
        console.print(table)

    except ImportError:
        print(report.summary())


def print_ablation_table(ablation_results: dict) -> None:
    """Print ablation study results as a comparison table."""
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()

        table = Table(title="Ablation Study Results", show_header=True)
        table.add_column("Variant",  style="cyan", width=20)
        table.add_column("Accuracy", justify="right", style="bold")
        table.add_column("Δ Baseline", justify="right")
        table.add_column("Correct/Total", justify="right")

        baseline_acc = ablation_results.get("baseline", type("X", (), {"accuracy": 0})()).accuracy

        for variant in ("baseline", "rag_only", "adapter_only", "full"):
            if variant not in ablation_results:
                continue
            rep = ablation_results[variant]
            delta = rep.accuracy - baseline_acc
            delta_str = f"[green]+{delta:.1%}[/green]" if delta > 0 else f"[red]{delta:.1%}[/red]"
            color = "green" if rep.accuracy >= 0.7 else "yellow" if rep.accuracy >= 0.5 else "red"
            table.add_row(
                variant,
                f"[{color}]{rep.accuracy:.1%}[/{color}]",
                delta_str if variant != "baseline" else "-",
                f"{rep.correct}/{rep.total}",
            )
        console.print(table)
    except ImportError:
        for variant, rep in ablation_results.items():
            print(f"  {variant:20s}: {rep.accuracy:.1%} ({rep.correct}/{rep.total})")


# ─── HTML report ──────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecBench Evaluation Report</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 960px; margin: 2em auto; color: #333; }}
  h1 {{ color: #2c3e50; }}
  .summary {{ background: #ecf0f1; padding: 1em; border-radius: 6px; margin-bottom: 2em; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2em; }}
  th {{ background: #2c3e50; color: white; padding: 0.5em 1em; text-align: left; }}
  td {{ border: 1px solid #ddd; padding: 0.5em 1em; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  .correct {{ color: green; font-weight: bold; }}
  .incorrect {{ color: red; }}
  .badge-easy {{ background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; }}
  .badge-medium {{ background: #f39c12; color: white; padding: 2px 8px; border-radius: 4px; }}
  .badge-hard {{ background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; }}
  footer {{ text-align: center; color: #999; margin-top: 3em; }}
</style>
</head>
<body>
<h1>Security AI — SecBench Evaluation Report</h1>
<div class="summary">
  <strong>Accuracy:</strong> {accuracy:.1%} ({correct}/{total})<br>
  <strong>Model:</strong> {model}<br>
  <strong>Adapter:</strong> {adapter}<br>
  <strong>RAG:</strong> {use_rag}<br>
  <strong>Duration:</strong> {duration:.1f}s<br>
  <strong>Date:</strong> {date}
</div>

<h2>Results by Category</h2>
<table>
  <tr><th>Category</th><th>Correct</th><th>Total</th><th>Accuracy</th></tr>
  {category_rows}
</table>

<h2>Results by Difficulty</h2>
<table>
  <tr><th>Difficulty</th><th>Correct</th><th>Total</th><th>Accuracy</th></tr>
  {difficulty_rows}
</table>

<h2>Per-Question Results</h2>
<table>
  <tr><th>ID</th><th>Category</th><th>Difficulty</th><th>Result</th><th>Got</th><th>Expected</th><th>Latency</th></tr>
  {question_rows}
</table>

<footer>Generated by Security AI Pipeline — Bachelor Thesis</footer>
</body>
</html>"""


def generate_html_report(report, output_path: str = "reports/eval_report.html") -> str:
    """Generate an HTML evaluation report for the thesis appendix."""
    def _cat_rows():
        rows = []
        for cat, stats in sorted(report.by_category.items()):
            acc = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
            rows.append(
                f"<tr><td>{cat}</td><td>{stats['correct']}</td>"
                f"<td>{stats['total']}</td><td>{acc:.1%}</td></tr>"
            )
        return "\n  ".join(rows)

    def _diff_rows():
        rows = []
        for diff in ("easy", "medium", "hard"):
            stats = report.by_difficulty.get(diff, {})
            if not stats.get("total"):
                continue
            acc = stats["correct"] / stats["total"]
            rows.append(
                f"<tr><td><span class='badge-{diff}'>{diff}</span></td>"
                f"<td>{stats['correct']}</td><td>{stats['total']}</td>"
                f"<td>{acc:.1%}</td></tr>"
            )
        return "\n  ".join(rows)

    def _q_rows():
        rows = []
        for r in report.results:
            status_class = "correct" if r.correct else "incorrect"
            status_icon  = "✓" if r.correct else "✗"
            diff_class   = r.difficulty
            rows.append(
                f"<tr><td>{r.sample_id}</td><td>{r.category}</td>"
                f"<td><span class='badge-{diff_class}'>{r.difficulty}</span></td>"
                f"<td class='{status_class}'>{status_icon}</td>"
                f"<td>{r.model_answer}</td><td>{r.expected_answer}</td>"
                f"<td>{r.latency_s:.1f}s</td></tr>"
            )
        return "\n  ".join(rows)

    html = _HTML_TEMPLATE.format(
        accuracy=report.accuracy,
        correct=report.correct,
        total=report.total,
        model=report.model_info.get("model", "unknown"),
        adapter=report.model_info.get("adapter", "none"),
        use_rag=report.model_info.get("use_rag", False),
        duration=report.duration_s,
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        category_rows=_cat_rows(),
        difficulty_rows=_diff_rows(),
        question_rows=_q_rows(),
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html, encoding="utf-8")
    print(f"HTML report saved to {output_path}")
    return html


# ─── Matplotlib charts (optional) ────────────────────────────────────────────

def plot_ablation_comparison(ablation_results: dict, output_path: str = "reports/ablation.png") -> None:
    """Bar chart comparing the 4 ablation variants. Saved as PNG."""
    try:
        import matplotlib.pyplot as plt
        import numpy as np

        variants = ["baseline", "rag_only", "adapter_only", "full"]
        labels   = ["Baseline", "RAG Only", "Adapter Only", "Full\n(CPT+RAG)"]
        accs     = []
        for v in variants:
            rep = ablation_results.get(v)
            accs.append(rep.accuracy if rep else 0.0)

        colors = ["#95a5a6", "#3498db", "#e67e22", "#2ecc71"]
        fig, ax = plt.subplots(figsize=(8, 5))
        bars = ax.bar(labels, accs, color=colors, edgecolor="black", linewidth=0.7)

        # Value labels on bars
        for bar, acc in zip(bars, accs):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{acc:.1%}", ha="center", va="bottom", fontweight="bold")

        ax.set_ylim(0, 1.15)
        ax.set_ylabel("Accuracy")
        ax.set_title("SecBench Ablation Study — Accuracy by System Variant")
        ax.axhline(y=accs[0], color="gray", linestyle="--", alpha=0.5, label="Baseline")
        ax.legend()
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"Ablation chart saved to {output_path}")
    except ImportError:
        print("matplotlib not installed — skipping chart generation")


def plot_elo_history(elo_tracker, output_path: str = "reports/elo_history.png") -> None:
    """Line chart of ELO rating evolution across co-evolution rounds."""
    try:
        import matplotlib.pyplot as plt

        history = elo_tracker.rating_history()
        red_hist  = history.get("red_team", [])
        blue_hist = history.get("blue_team", [])

        if not red_hist:
            print("No ELO history to plot")
            return

        rounds = list(range(1, len(red_hist) + 1))
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.plot(rounds, red_hist,  color="#e74c3c", linewidth=2, label="Red Team (Offensive)")
        ax.plot(rounds, blue_hist, color="#3498db", linewidth=2, label="Blue Team (Defensive)")
        ax.axhline(y=1200, color="gray", linestyle="--", alpha=0.5, label="Starting ELO")
        ax.fill_between(rounds, red_hist, blue_hist, alpha=0.1, color="purple")
        ax.set_xlabel("Round")
        ax.set_ylabel("ELO Rating")
        ax.set_title("Adversarial Co-Evolution — ELO Rating History\n(GAN-like Red vs Blue Arms Race)")
        ax.legend()
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"ELO history chart saved to {output_path}")
    except ImportError:
        print("matplotlib not installed — skipping chart generation")


def plot_feedback_improvement(success_rates: list[float], output_path: str = "reports/feedback_curve.png") -> None:
    """Line chart of success rate improvement over feedback loop iterations."""
    try:
        import matplotlib.pyplot as plt
        import numpy as np

        if not success_rates:
            return

        iters = list(range(1, len(success_rates) + 1))
        # Smooth with a rolling average
        window = min(5, len(success_rates))
        smoothed = np.convolve(success_rates, np.ones(window) / window, mode="valid")

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.plot(iters, success_rates, color="#95a5a6", alpha=0.5, linewidth=1, label="Raw success rate")
        ax.plot(
            range(window, len(success_rates) + 1),
            smoothed,
            color="#2ecc71", linewidth=2, label=f"Rolling avg (window={window})"
        )
        ax.set_ylim(0, 1.1)
        ax.set_xlabel("Iteration")
        ax.set_ylabel("Success Rate")
        ax.set_title("Self-Improving Feedback Loop — Success Rate Over Iterations")
        ax.legend()
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"Feedback improvement chart saved to {output_path}")
    except ImportError:
        print("matplotlib not installed — skipping chart generation")


def plot_cross_platform_heatmap(
    cross_platform_results: dict,
    output_path: str = "reports/cross_platform_heatmap.png"
) -> None:
    """Heatmap: techniques (rows) × platforms (cols), cell = IOC confidence."""
    try:
        import matplotlib.pyplot as plt
        import numpy as np

        techniques = list(cross_platform_results.keys())
        platforms  = ["linux", "macos", "windows"]

        matrix = np.zeros((len(techniques), len(platforms)))
        for i, tech_id in enumerate(techniques):
            report = cross_platform_results[tech_id]
            for j, plat in enumerate(platforms):
                result = report.results.get(plat)
                matrix[i, j] = result.ioc_confidence if result else 0.0

        fig, ax = plt.subplots(figsize=(8, max(4, len(techniques) * 0.5 + 2)))
        im = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
        plt.colorbar(im, ax=ax, label="IOC Confidence")

        ax.set_xticks(range(len(platforms)))
        ax.set_xticklabels([p.capitalize() for p in platforms])
        ax.set_yticks(range(len(techniques)))
        ax.set_yticklabels(techniques, fontsize=8)
        ax.set_title("Cross-Platform Transfer — IOC Confidence Heatmap")

        # Add text annotations
        for i in range(len(techniques)):
            for j in range(len(platforms)):
                val = matrix[i, j]
                ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                        color="black" if val > 0.3 else "white", fontsize=7)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"Cross-platform heatmap saved to {output_path}")
    except ImportError:
        print("matplotlib not installed — skipping chart generation")
