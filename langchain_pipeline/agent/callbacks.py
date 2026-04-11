"""
LangChain callbacks for visualizing the agent's reasoning process.

ThinkingVisualizer  -> displays <think> blocks separately from the final answer, with a box in terminal
StepTracer          -> traces each agent step (tool calls, results)
PipelineLogger      -> logs everything to a JSONL file for post-analysis
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL)


def _parse(raw: str) -> tuple[str, str]:
    m = _THINK_RE.search(raw)
    if not m:
        return "", raw.strip()
    return m.group(1).strip(), re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()


# ─── ThinkingVisualizer ───────────────────────────────────────────────────────

class ThinkingVisualizer(BaseCallbackHandler):
    """
    Afiseaza chain-of-thought separat de raspunsul final.
    Functioneaza cu modele Instruct care produc <think> blocks.
    Pentru Base models, afiseaza direct raspunsul.
    """

    def __init__(self, show_prompt: bool = False, max_thinking_chars: int = 2000):
        self.show_prompt = show_prompt
        self.max_thinking_chars = max_thinking_chars
        self._start_time: float = 0.0

    def on_llm_start(
        self,
        serialized: dict,
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        self._start_time = time.time()
        if self.show_prompt and prompts:
            if HAS_RICH:
                console.print(Rule("[dim]LLM Input[/dim]"))
                console.print(Panel(
                    prompts[0][:800] + ("..." if len(prompts[0]) > 800 else ""),
                    title="[dim]Prompt[/dim]",
                    border_style="dim",
                ))
            else:
                print(f"\n[PROMPT] {prompts[0][:400]}...\n")

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        elapsed = time.time() - self._start_time
        try:
            raw = response.generations[0][0].text
        except (IndexError, AttributeError):
            return

        thinking, answer = _parse(raw)

        if HAS_RICH:
            if thinking:
                # Truncheaza daca e prea lung
                display = thinking
                if len(display) > self.max_thinking_chars:
                    display = display[:self.max_thinking_chars] + f"\n… [{len(thinking)-self.max_thinking_chars} chars trunchiate]"

                console.print(Panel(
                    Text(display, style="dim italic"),
                    title=f"[yellow]💭 Chain of Thought[/yellow]",
                    border_style="yellow",
                    padding=(1, 2),
                ))

            console.print(Panel(
                Text(answer, style="white"),
                title=f"[green]📋 Final answer[/green]  [dim]{elapsed:.1f}s[/dim]",
                border_style="green",
                padding=(1, 2),
            ))
        else:
            # Fallback fara rich
            if thinking:
                sep = "─" * 60
                print(f"\n{sep}")
                print("💭 CHAIN OF THOUGHT:")
                print(thinking[:self.max_thinking_chars])
                print(sep)
            print(f"\n📋 ANSWER ({elapsed:.1f}s):\n{answer}\n")

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        msg = f"LLM Error: {error}"
        if HAS_RICH:
            console.print(f"[red]❌ {msg}[/red]")
        else:
            print(f"❌ {msg}")


# ─── StepTracer ───────────────────────────────────────────────────────────────

class StepTracer(BaseCallbackHandler):
    """
    Traseaza fiecare decizie a agentului:
      - Ce tool vrea sa apeleze
      - Ce argumente trimite
      - Ce rezultat primeste inapoi
    """

    def __init__(self):
        self._step = 0

    def on_tool_start(
        self,
        serialized: dict,
        input_str: str,
        **kwargs: Any,
    ) -> None:
        self._step += 1
        tool_name = serialized.get("name", "unknown_tool")
        if HAS_RICH:
            console.print(f"\n[cyan]🔧 Step {self._step} — Tool call: [bold]{tool_name}[/bold][/cyan]")
            try:
                parsed = json.loads(input_str)
                console.print_json(json.dumps(parsed))
            except (json.JSONDecodeError, TypeError):
                console.print(f"  [dim]{input_str[:300]}[/dim]")
        else:
            print(f"\n🔧 Step {self._step} — {tool_name}")
            print(f"   Input: {input_str[:300]}")

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        output_str = str(output)
        if HAS_RICH:
            preview = output_str[:500] + ("…" if len(output_str) > 500 else "")
            console.print(Panel(
                Text(preview, style="dim"),
                title="[dim]Tool result[/dim]",
                border_style="dim cyan",
                padding=(0, 1),
            ))
        else:
            print(f"   Result: {output_str[:300]}")

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        if HAS_RICH:
            console.print(f"[red]  ❌ Tool error: {error}[/red]")
        else:
            print(f"   ❌ Error: {error}")

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        if HAS_RICH and hasattr(action, "log") and action.log:
            thinking, _ = _parse(action.log)
            if thinking:
                console.print(Panel(
                    Text(thinking[:600], style="dim italic"),
                    title="[yellow]💭 Agent thought[/yellow]",
                    border_style="yellow dim",
                ))

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        if HAS_RICH:
            console.print(Rule("[green]✅ Agent finished[/green]"))
        else:
            print("\n✅ Agent finished\n")


# ─── PipelineLogger ───────────────────────────────────────────────────────────

class PipelineLogger(BaseCallbackHandler):
    """
    Salveaza fiecare run intr-un fisier JSONL pentru analiza ulterioara.
    Useful for thesis analysis — inspect agent decisions after the fact.

    Format: each line is a JSON object {timestamp, event, data}
    """

    def __init__(self, log_path: str = "logs/pipeline.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._run_id: str = ""

    def _write(self, event: str, data: dict) -> None:
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "run_id": self._run_id,
            "event": event,
            "data": data,
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs: Any) -> None:
        run_id = kwargs.get("run_id")
        if run_id:
            self._run_id = str(run_id)
        self._write("llm_start", {"prompt_len": len(prompts[0]) if prompts else 0})

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        try:
            raw = response.generations[0][0].text
            thinking, answer = _parse(raw)
            self._write("llm_end", {
                "has_thinking": bool(thinking),
                "thinking_len": len(thinking),
                "answer_len": len(answer),
                "answer_preview": answer[:200],
            })
        except (IndexError, AttributeError):
            pass

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        self._write("tool_start", {
            "tool": serialized.get("name"),
            "input": input_str[:500],
        })

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        self._write("tool_end", {"output": str(output)[:500]})

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        self._write("tool_error", {"error": str(error)})


# ─── Factory helper ──────────────────────────────────────────────────────────

def make_callbacks(
    show_thinking: bool = True,
    trace_steps: bool = True,
    log_to_file: bool = True,
    show_prompt: bool = False,
    log_path: str = "logs/pipeline.jsonl",
) -> list[BaseCallbackHandler]:
    """
    Returneaza o lista de callbacks configurata.
    Foloseste in config={"callbacks": make_callbacks()} la invoke.
    """
    cb: list[BaseCallbackHandler] = []
    if show_thinking:
        cb.append(ThinkingVisualizer(show_prompt=show_prompt))
    if trace_steps:
        cb.append(StepTracer())
    if log_to_file:
        cb.append(PipelineLogger(log_path=log_path))
    return cb
