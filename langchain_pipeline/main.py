"""
exploit-agent — entry point.

Run modes:
    python main.py direct      -> Direct LLM inference (no tools)
    python main.py agent       -> Full ReAct agent with MCP tools
    python main.py stream      -> Live streaming output
    python main.py rag         -> RAG-augmented direct inference
    python main.py campaign    -> Plan a multi-step attack campaign
    python main.py coevolve    -> Start adversarial co-evolution
    python main.py evaluate    -> Run SecBench evaluation
    python main.py adapter     -> Train/list LoRA adapters
"""

from __future__ import annotations

import asyncio
import sys


# ─── Mode: direct ─────────────────────────────────────────────────────────────

def run_direct():
    from agent.agent import DirectLLM

    runner = DirectLLM()
    request = "Give a one-liner command to test MITRE T1082 (System Information Discovery) on Linux"

    prompt = (
        "You are a cybersecurity assistant specialized in offensive security.\n"
        "Rules:\n"
        "- Respond with the ONE LINER command only.\n"
        "- No disclaimers, no markdown, no code blocks.\n\n"
        f"Task: {request}"
    )

    print(f"\n{'='*60}")
    print(f"Query: {request}")
    print(f"{'='*60}")

    thinking, answer = runner.run_with_thinking(prompt)

    if thinking:
        print(f"\n[Chain of Thought] ({len(thinking)} chars)")
    print(f"\nFinal command:\n{answer}")


# ─── Mode: rag ────────────────────────────────────────────────────────────────

def run_rag():
    from agent.agent import DirectLLM

    runner = DirectLLM()
    query = "How to perform credential dumping on Linux (T1003)?"

    print(f"\n{'='*60}")
    print(f"RAG-augmented query: {query}")
    print(f"{'='*60}")

    answer = runner.run_with_rag(query, platform="linux")
    thinking, clean = type(runner.llm).parse_thinking(answer)

    if thinking:
        print(f"\n[Chain of Thought] ({len(thinking)} chars):\n{thinking[:400]}...")
    print(f"\nAnswer:\n{clean}")


# ─── Mode: agent ──────────────────────────────────────────────────────────────

async def run_agent(adapter: str | None = None):
    """Full ReAct agent with MCP server and all security tools."""
    from agent.agent import ExploitAgent

    queries = [
        "What is MITRE technique T1082 and how do I test it on Linux?",
        "Search the corpus for Log4Shell exploitation techniques",
        "List all available lab VMs and their status",
    ]

    async with ExploitAgent(use_mcp=True, adapter_name=adapter) as agent:
        for q in queries:
            print(f"\n{'='*60}")
            print(f"Query: {q}")
            print(f"{'='*60}")

            answer = await agent.run(q, show_thinking=True, trace_steps=True)
            print(f"\nFinal answer:\n{answer}\n")
            await asyncio.sleep(0.5)


# ─── Mode: stream ─────────────────────────────────────────────────────────────

async def run_stream():
    """Live streaming output, each agent step shown immediately."""
    from agent.agent import ExploitAgent

    query = "Find exploits for T1059.004 and generate a test command for Linux"

    print(f"\nLIVE STREAM: {query}\n")

    async with ExploitAgent(use_mcp=False) as agent:
        async for update in agent.stream(query):
            print(update)


# ─── Mode: campaign ───────────────────────────────────────────────────────────

def run_campaign(start: str = "T1566.001", goal: str = "exfiltration", platform: str = "linux"):
    """Plan and display a multi-stage MITRE ATT&CK campaign."""
    from mitre.planner import MITRECampaignPlanner

    print(f"\n{'='*60}")
    print(f"Planning campaign: {start} → {goal} [{platform}]")
    print(f"{'='*60}")

    planner = MITRECampaignPlanner()
    campaign = planner.plan(start, goal, platform=platform, max_steps=8)
    print(f"\n{campaign}")


# ─── Mode: coevolve ───────────────────────────────────────────────────────────

async def run_coevolve(rounds: int = 3):
    """Run one generation of Red vs Blue adversarial co-evolution."""
    from coevolution.arena import CoEvolutionArena, TargetProfile

    arena = CoEvolutionArena()
    target = TargetProfile.easy_linux()
    await arena.run_generation(target=target, n_rounds=rounds)


# ─── Mode: evaluate ───────────────────────────────────────────────────────────

def run_evaluate(n: int = 10, adapter: str | None = None):
    """Run SecBench evaluation."""
    from evaluation.secbench import SecBenchEvaluator

    ev = SecBenchEvaluator()
    report = ev.evaluate(adapter_name=adapter, use_rag=True, n_samples=n)
    print("\n" + report.summary())


# ─── Mode: adapter ────────────────────────────────────────────────────────────

def run_adapter(action: str = "list", name: str | None = None):
    """Manage LoRA adapters: list, train."""
    from llm.adapter_manager import get_adapter_manager

    mgr = get_adapter_manager()

    if action == "list":
        trained = mgr.list_trained()
        print("\nAdapter Status:")
        from llm.adapter_manager import ADAPTER_NAMES
        for a in ADAPTER_NAMES:
            trained_str = "trained" if a in trained else "seed only"
            count = mgr.sample_count(a)
            print(f"  {a:12s} | {trained_str:12s} | {count} training samples")
    elif action == "train" and name:
        print(f"Training adapter: {name}")
        mgr.train(name, iters=1000, blocking=True)
    else:
        print("Usage: python main.py adapter [list|train] [adapter_name]")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]
    mode = args[0] if args else "direct"

    if mode == "direct":
        run_direct()

    elif mode == "rag":
        run_rag()

    elif mode == "agent":
        adapter = args[1] if len(args) > 1 else None
        asyncio.run(run_agent(adapter=adapter))

    elif mode == "stream":
        asyncio.run(run_stream())

    elif mode == "campaign":
        start   = args[1] if len(args) > 1 else "T1566.001"
        goal    = args[2] if len(args) > 2 else "exfiltration"
        platform = args[3] if len(args) > 3 else "linux"
        run_campaign(start, goal, platform)

    elif mode == "coevolve":
        rounds = int(args[1]) if len(args) > 1 else 3
        asyncio.run(run_coevolve(rounds=rounds))

    elif mode == "evaluate":
        n       = int(args[1]) if len(args) > 1 else 10
        adapter = args[2] if len(args) > 2 else None
        run_evaluate(n=n, adapter=adapter)

    elif mode == "adapter":
        action = args[1] if len(args) > 1 else "list"
        name   = args[2] if len(args) > 2 else None
        run_adapter(action, name)

    else:
        print(f"Unknown mode: {mode}")
        print(__doc__)
        sys.exit(1)
