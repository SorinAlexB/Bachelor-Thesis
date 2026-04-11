"""
MCP (Model Context Protocol) server for the exploit-agent pipeline.

Exposes security tools via stdio transport so external MCP clients
(including the LangChain MCP adapter in agent.py) can call them.

Tools exposed:
  - search_corpus       : semantic search over 25k security documents
  - mitre_lookup        : MITRE ATT&CK technique details
  - list_techniques     : filtered technique list by tactic/platform
  - execute_on_vm       : SSH command execution on a lab VM
  - vm_snapshot         : create a VM snapshot
  - restore_vm          : restore VM to clean snapshot
  - collect_iocs        : IOC collection after technique execution
  - list_vms            : VM status and configuration

Run standalone:
    python mcp/server.py

Or via langchain-mcp-adapters (as configured in agent.py):
    MultiServerMCPClient({"exploit_corpus": {"command": "python", "args": ["mcp/server.py"]}})
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Ensure the langchain_pipeline package is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    InitializationOptions,
    ServerCapabilities,
    TextContent,
    Tool,
)

server = Server("exploit-corpus")

# ─── Tool registry ────────────────────────────────────────────────────────────

TOOLS = [
    Tool(
        name="search_corpus",
        description="Search the 25k security document corpus (MITRE, CVEs, ExploitDB) using natural language.",
        inputSchema={
            "type": "object",
            "properties": {
                "query":    {"type": "string", "description": "Natural language search query"},
                "platform": {"type": "string", "description": "Filter by OS: linux, macos, windows, or empty for all", "default": ""},
                "top_k":    {"type": "integer", "description": "Number of results (1-10)", "default": 5},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="mitre_lookup",
        description="Look up a MITRE ATT&CK technique by ID (e.g. T1059.001). Returns description, platforms, tactics, detection.",
        inputSchema={
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "MITRE technique ID, e.g. T1059.001"},
            },
            "required": ["technique_id"],
        },
    ),
    Tool(
        name="list_techniques",
        description="List MITRE ATT&CK techniques filtered by tactic and/or platform.",
        inputSchema={
            "type": "object",
            "properties": {
                "tactic":   {"type": "string", "description": "Tactic name, e.g. 'execution', 'persistence'", "default": ""},
                "platform": {"type": "string", "description": "Platform: linux, macos, windows, or empty for all", "default": ""},
                "top_k":    {"type": "integer", "description": "Max results", "default": 10},
            },
            "required": [],
        },
    ),
    Tool(
        name="execute_on_vm",
        description="Execute a shell command on a lab VM via SSH. VM must be running. Always snapshot first.",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_name": {"type": "string", "description": "VM name: linux, macos, or windows"},
                "command": {"type": "string", "description": "Shell command to execute"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (max 300)", "default": 60},
            },
            "required": ["vm_name", "command"],
        },
    ),
    Tool(
        name="vm_snapshot",
        description="Create a snapshot of the VM before running exploits.",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_name": {"type": "string", "description": "VM name: linux, macos, or windows"},
            },
            "required": ["vm_name"],
        },
    ),
    Tool(
        name="restore_vm",
        description="Restore VM to the clean snapshot state after exploit testing.",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_name": {"type": "string", "description": "VM name: linux, macos, or windows"},
            },
            "required": ["vm_name"],
        },
    ),
    Tool(
        name="collect_iocs",
        description="Collect IOCs from a VM after executing a technique. Returns confidence score and evidence.",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_name":      {"type": "string", "description": "VM name: linux, macos, or windows"},
                "technique_id": {"type": "string", "description": "MITRE technique ID that was executed"},
            },
            "required": ["vm_name", "technique_id"],
        },
    ),
    Tool(
        name="list_vms",
        description="List all configured lab VMs with their current status and IP addresses.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Dispatch incoming tool calls to the underlying security tool implementations."""
    try:
        result = await _dispatch(name, arguments)
    except Exception as exc:
        result = f"Error in tool '{name}': {exc}"

    return [TextContent(type="text", text=str(result))]


async def _dispatch(name: str, args: dict) -> str:
    """Route tool calls to their implementations."""
    loop = asyncio.get_event_loop()

    if name == "search_corpus":
        from rag.retriever import get_retriever
        retriever = get_retriever()
        platform = args.get("platform") or None
        return await loop.run_in_executor(
            None,
            lambda: retriever.format_context(args["query"], platform=platform),
        )

    elif name == "mitre_lookup":
        from tools.security_tools import mitre_lookup
        return await loop.run_in_executor(
            None,
            lambda: mitre_lookup.invoke({"technique_id": args["technique_id"]}),
        )

    elif name == "list_techniques":
        from rag.chroma_store import get_store
        from rag.embedder import get_embedder
        store = get_store()
        embedder = get_embedder()
        query = f"{args.get('tactic', 'security')} technique"
        results = await loop.run_in_executor(
            None,
            lambda: store.search(
                query, embedder,
                n_results=args.get("top_k", 10),
                platform=args.get("platform") or None,
                source="mitre",
            ),
        )
        lines = []
        for r in results:
            m = r["metadata"]
            tech = m.get("technique_id", "")
            name_str = m.get("name", "")
            tactic = m.get("tactic", "")
            platform = m.get("platform", "")
            lines.append(f"  {tech:15s} {name_str:45s} | {tactic:20s} | {platform}")
        return "\n".join(lines) if lines else "No techniques found."

    elif name == "execute_on_vm":
        from tools.security_tools import execute_on_vm
        return await loop.run_in_executor(
            None,
            lambda: execute_on_vm.invoke({
                "vm_name": args["vm_name"],
                "command": args["command"],
                "timeout": args.get("timeout", 60),
            }),
        )

    elif name == "vm_snapshot":
        from tools.security_tools import vm_snapshot
        return await loop.run_in_executor(
            None,
            lambda: vm_snapshot.invoke({"vm_name": args["vm_name"]}),
        )

    elif name == "restore_vm":
        from tools.security_tools import restore_vm
        return await loop.run_in_executor(
            None,
            lambda: restore_vm.invoke({"vm_name": args["vm_name"]}),
        )

    elif name == "collect_iocs":
        from tools.security_tools import collect_iocs
        return await loop.run_in_executor(
            None,
            lambda: collect_iocs.invoke({
                "vm_name": args["vm_name"],
                "technique_id": args["technique_id"],
            }),
        )

    elif name == "list_vms":
        from tools.security_tools import list_vms
        return await loop.run_in_executor(
            None,
            lambda: list_vms.invoke({}),
        )

    else:
        return f"Unknown tool: {name}"


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="exploit-corpus",
                server_version="1.0.0",
                capabilities=ServerCapabilities(tools={}),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
