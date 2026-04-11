"""
Main exploit-agent.

Combines:
  - MLXLM wrapper (Base or Instruct, with/without thinking)
  - LoRA adapter hot-swap via AdapterManager
  - Custom security tools + MCP server tools
  - RAG context injection into the system prompt
  - ThinkingVisualizer + StepTracer callbacks
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import AsyncIterator, Optional

from langchain_core.messages import HumanMessage, SystemMessage

from agent.callbacks import make_callbacks
from config import (
    ACTIVE_ADAPTER,
    ENABLE_THINKING,
    MAX_TOKENS,
    MODEL_PATH,
    MCP_SERVER_SCRIPT,
    REPETITION_PENALTY,
    SYSTEM_PROMPT,
    TEMPERATURE,
    TOP_P,
)
from llm.mlx_wrapper import MLXLM
from tools.security_tools import get_all_tools


def build_llm(adapter_name: Optional[str] = None) -> MLXLM:
    """Build an MLXLM instance, optionally with a LoRA adapter."""
    return MLXLM(
        model_path=MODEL_PATH,
        max_tokens=MAX_TOKENS,
        temperature=TEMPERATURE,
        top_p=TOP_P,
        repetition_penalty=REPETITION_PENALTY,
        enable_thinking=ENABLE_THINKING,
        adapter_name=adapter_name or ACTIVE_ADAPTER,
    )


async def _get_mcp_tools() -> tuple[list, object]:
    """Connect to the MCP server and return its exposed tools."""
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient

        mcp_config = {
            "exploit_corpus": {
                "command": "python",
                "args": [str(Path(__file__).parent.parent / MCP_SERVER_SCRIPT)],
                "transport": "stdio",
            },
        }

        client = MultiServerMCPClient(mcp_config)
        await client.__aenter__()
        tools = client.get_tools()
        return tools, client

    except ImportError:
        print("Warning: langchain-mcp-adapters not installed. MCP tools disabled.")
        return [], None
    except Exception as exc:
        print(f"Warning: MCP server error: {exc}. MCP tools disabled.")
        return [], None


def _rag_system_prompt(query: str, platform: Optional[str] = None) -> str:
    """
    Inject RAG-retrieved context into the system prompt.

    The retriever is called lazily so the base agent still works without
    a built RAG corpus (e.g. first run before `python pipeline_runner.py ingest`).
    """
    try:
        from rag.retriever import get_retriever
        retriever = get_retriever()
        context = retriever.format_context(query, platform=platform)
        if context and "No relevant documents" not in context:
            return SYSTEM_PROMPT + f"\n\nRelevant security knowledge:\n{context}"
    except Exception:
        pass
    return SYSTEM_PROMPT


class ExploitAgent:
    """
    Main ReAct agent with security tools, MCP integration, and RAG context.

    Usage:
        async with ExploitAgent() as agent:
            answer = await agent.run("T1059.004 on Linux — generate and execute")

    Adapter selection:
        ExploitAgent(adapter_name="red_team")   # offensive tasks
        ExploitAgent(adapter_name="blue_team")  # defensive tasks
        ExploitAgent(adapter_name="ctf")        # CTF solving
        ExploitAgent(adapter_name="explainer")  # chain-of-thought explanations
    """

    def __init__(
        self,
        use_mcp: bool = True,
        adapter_name: Optional[str] = None,
        inject_rag: bool = True,
    ):
        self.llm = build_llm(adapter_name=adapter_name)
        self.use_mcp = use_mcp
        self.inject_rag = inject_rag
        self.adapter_name = adapter_name
        self._mcp_client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        if self._mcp_client:
            await self._mcp_client.__aexit__(*args)

    async def _build_agent(self, query: str = ""):
        from langgraph.prebuilt import create_react_agent

        tools = get_all_tools()

        if self.use_mcp:
            mcp_tools, client = await _get_mcp_tools()
            self._mcp_client = client
            tools = tools + mcp_tools

        system = _rag_system_prompt(query) if self.inject_rag else SYSTEM_PROMPT

        agent = create_react_agent(
            model=self.llm,
            tools=tools,
            state_modifier=system,
        )
        return agent

    async def run(
        self,
        query: str,
        show_thinking: bool = True,
        trace_steps: bool = True,
        log_to_file: bool = True,
    ) -> str:
        """
        Run the agent on a query and return the final answer.
        Thinking and step tracing are displayed live in the terminal.
        """
        agent = await self._build_agent(query)
        callbacks = make_callbacks(
            show_thinking=show_thinking,
            trace_steps=trace_steps,
            log_to_file=log_to_file,
        )

        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=query)]},
            config={"callbacks": callbacks, "recursion_limit": 20},
        )

        final_msg = result["messages"][-1]
        return final_msg.content

    async def stream(
        self,
        query: str,
        show_thinking: bool = True,
    ) -> AsyncIterator[str]:
        """
        Stream the response step by step.
        Yields: each node update from the LangGraph graph.
        """
        agent = await self._build_agent(query)
        callbacks = make_callbacks(show_thinking=show_thinking, trace_steps=True)

        async for chunk in agent.astream(
            {"messages": [HumanMessage(content=query)]},
            stream_mode="updates",
            config={"callbacks": callbacks},
        ):
            for node_name, output in chunk.items():
                for msg in output.get("messages", []):
                    if hasattr(msg, "content") and msg.content:
                        yield f"[{node_name}] {msg.content}"


# ─── Direct LLM (no agent, no tools) ─────────────────────────────────────────

class DirectLLM:
    """
    Simple wrapper for direct LLM inference without the ReAct agent.
    Good for quick tests, benchmarks, and chain-of-thought analysis.

    Usage:
        runner = DirectLLM()
        thinking, answer = runner.run_with_thinking("Explain T1059.004")

        # With a specific adapter:
        runner = DirectLLM(adapter_name="explainer")
    """

    def __init__(self, adapter_name: Optional[str] = None):
        self.llm = build_llm(adapter_name=adapter_name)
        self.callbacks = make_callbacks(trace_steps=False)

    def run(self, prompt: str) -> str:
        """Invoke directly, displaying thinking if the model produces it."""
        return self.llm.invoke(prompt, config={"callbacks": self.callbacks})

    def run_with_thinking(self, prompt: str) -> tuple[str, str]:
        """Return (thinking, answer) separately."""
        raw = self.run(prompt)
        return MLXLM.parse_thinking(raw)

    def run_with_rag(self, query: str, platform: Optional[str] = None) -> str:
        """Inject RAG context then run. Returns the full response."""
        try:
            from rag.retriever import get_retriever
            retriever = get_retriever()
            context = retriever.format_context(query, platform=platform)
            prompt = f"{context}\n\nQuery: {query}"
        except Exception:
            prompt = query
        return self.run(prompt)
