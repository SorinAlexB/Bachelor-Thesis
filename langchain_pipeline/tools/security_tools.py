"""
Security tools for the exploit-agent pipeline.

All tools are LangChain @tool decorated functions that the ReAct agent can call.
Each tool is backed by a real implementation (SSH, RAG, VM manager).

Tools:
  1. mitre_lookup          - MITRE ATT&CK technique details via RAG
  2. generate_test_oneliner - Platform-specific technique command (no placeholders)
  3. execute_on_vm          - SSH execution on a named VM
  4. vm_snapshot            - Create a VM snapshot before exploitation
  5. restore_vm             - Restore VM to clean snapshot
  6. collect_iocs           - Collect IOCs after technique execution
  7. search_corpus          - Semantic search over 25k security documents
  8. list_vms               - Show VM status and IPs
"""

from __future__ import annotations

import re
from typing import Optional

from langchain_core.tools import tool
from pydantic import BaseModel, Field


# ─── Lazy singletons (imported at first call, not at module import) ───────────

def _get_ssh_pool():
    from tools.ssh_executor import get_ssh_pool
    return get_ssh_pool()

def _get_vm_manager():
    from tools.vm_tools import get_vm_manager
    return get_vm_manager()

def _get_ioc_collector():
    from tools.ioc_collector import get_ioc_collector
    return get_ioc_collector()

def _get_retriever():
    from rag.retriever import get_retriever
    return get_retriever()


# ─── Tool 1: MITRE Lookup ────────────────────────────────────────────────────

@tool
def mitre_lookup(technique_id: str) -> str:
    """
    Look up a MITRE ATT&CK technique or sub-technique by ID (e.g. T1059.001).

    Returns: name, description, affected platforms, associated tactics,
    detection guidance, and mitigation strategies.
    """
    technique_id = technique_id.strip().upper()
    retriever = _get_retriever()

    # Try direct search with the technique ID first
    context = retriever.format_context(
        f"MITRE ATT&CK technique {technique_id}",
        platform=None,
    )

    # Also try a broader name search if ID search returned little
    if "No relevant documents" in context:
        context = retriever.format_context(technique_id)

    if "No relevant documents" in context:
        return (
            f"Technique {technique_id} not found in corpus. "
            "Check the ID format (e.g., T1059 or T1059.001) and ensure the "
            "RAG database has been built (run: python pipeline_runner.py ingest)."
        )

    return f"MITRE ATT&CK — {technique_id}\n\n{context}"


# ─── Tool 2: Generate Test One-Liner ─────────────────────────────────────────

class OneLinerInput(BaseModel):
    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID, e.g. T1059.001 or T1003",
    )
    target_os: str = Field(
        "linux",
        description="Target operating system: 'linux', 'macos', or 'windows'",
    )
    context: str = Field(
        "",
        description="Additional constraints or context for the command (optional)",
    )


# Known safe/educational test one-liners (no destructive operations)
_ONELINER_LIBRARY: dict[str, dict[str, str]] = {
    "T1059.001": {  # PowerShell
        "windows": 'powershell -NoProfile -Command "Get-Process | Select-Object -First 5"',
        "linux": "",
        "macos": "",
    },
    "T1059.003": {  # Windows Command Shell
        "windows": 'cmd /c "whoami && echo test_T1059_003"',
        "linux": "",
        "macos": "",
    },
    "T1059.004": {  # Unix Shell
        "linux": 'bash -c "id && uname -a && echo test_T1059_004"',
        "macos": 'bash -c "id && uname -a && echo test_T1059_004"',
        "windows": "",
    },
    "T1083": {  # File and Directory Discovery
        "linux": 'find /tmp -maxdepth 2 -ls 2>/dev/null | head -20',
        "macos": 'find /tmp -maxdepth 2 -ls 2>/dev/null | head -20',
        "windows": 'Get-ChildItem $env:TEMP -Recurse -Depth 2 | Select-Object -First 20 | Format-Table Name,Length',
    },
    "T1057": {  # Process Discovery
        "linux": 'ps aux --no-headers | head -20',
        "macos": 'ps aux | head -20',
        "windows": 'Get-Process | Select-Object Name,Id,CPU | Sort-Object CPU -Descending | Select-Object -First 20',
    },
    "T1049": {  # System Network Connections Discovery
        "linux": 'ss -tulpn 2>/dev/null | head -20',
        "macos": 'netstat -an | head -20',
        "windows": 'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,State | Select-Object -First 20',
    },
    "T1105": {  # Ingress Tool Transfer
        "linux": 'curl -s -o /tmp/test_t1105.txt https://example.com && ls -la /tmp/test_t1105.txt',
        "macos": 'curl -s -o /tmp/test_t1105.txt https://example.com && ls -la /tmp/test_t1105.txt',
        "windows": 'Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:TEMP\\test_t1105.html" -UseBasicParsing; Get-Item "$env:TEMP\\test_t1105.html"',
    },
    "T1078": {  # Valid Accounts
        "linux": 'cat /etc/passwd | grep -v nologin | grep -v false | head -10',
        "macos": 'dscl . -list /Users | grep -v "^_" | head -10',
        "windows": 'Get-LocalUser | Select-Object Name,Enabled,LastLogon | Format-Table',
    },
    "T1053.005": {  # Scheduled Task
        "linux": 'crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null | head -10',
        "macos": 'crontab -l 2>/dev/null; ls -la /Library/LaunchDaemons/ 2>/dev/null | head -10',
        "windows": 'Get-ScheduledTask | Select-Object TaskName,State | Select-Object -First 10',
    },
    "T1082": {  # System Information Discovery
        "linux": 'uname -a && cat /etc/os-release 2>/dev/null | head -5',
        "macos": 'uname -a && sw_vers',
        "windows": 'Get-ComputerInfo | Select-Object OsName,OsVersion,OsArchitecture,CsProcessors',
    },
}


def _validate_command(cmd: str) -> tuple[bool, str]:
    """Basic safety check: reject commands with unresolved placeholders."""
    placeholders = re.findall(r"<[A-Z_]+>|\$\{[A-Z_]+\}|\[YOUR[^\]]+\]", cmd)
    if placeholders:
        return False, f"Command contains unresolved placeholders: {placeholders}"
    if not cmd.strip():
        return False, "Empty command"
    return True, ""


@tool(args_schema=OneLinerInput)
def generate_test_oneliner(
    technique_id: str,
    target_os: str = "linux",
    context: str = "",
) -> str:
    """
    Generate a single executable command to test a MITRE ATT&CK technique on
    the target OS. The command is ready to run — no placeholders.

    For research/lab use only.
    """
    tech_id = technique_id.strip().upper()
    os_key = target_os.strip().lower()

    # Check the built-in library first
    if tech_id in _ONELINER_LIBRARY:
        cmd = _ONELINER_LIBRARY[tech_id].get(os_key, "")
        if cmd:
            valid, err = _validate_command(cmd)
            if valid:
                return cmd

    # Fall back to RAG-augmented generation hint
    retriever = _get_retriever()
    rag_context = retriever.format_context(
        f"{tech_id} command {target_os} example one-liner",
        platform=os_key if os_key in ("linux", "macos", "windows") else None,
    )

    return (
        f"# Technique: {tech_id} | Platform: {os_key}\n"
        f"# Context from corpus:\n{rag_context[:800]}\n\n"
        f"# Note: Use the LLM with the above context to generate the exact command.\n"
        f"# The agent will synthesize a validated one-liner from the RAG results."
    )


# ─── Tool 3: Execute on VM ────────────────────────────────────────────────────

class VMExecuteInput(BaseModel):
    vm_name: str  = Field(..., description="VM name: 'linux', 'macos', or 'windows'")
    command: str  = Field(..., description="Shell command to execute (no placeholders)")
    timeout: int  = Field(60,  description="Execution timeout in seconds (max 300)")


@tool(args_schema=VMExecuteInput)
def execute_on_vm(vm_name: str, command: str, timeout: int = 60) -> str:
    """
    Execute a command on the specified lab VM via SSH and return the output.
    The VM must be running. Always snapshot first.

    Returns stdout, stderr, exit code, and execution time.
    """
    valid, err = _validate_command(command)
    if not valid:
        return f"ERROR: {err}"

    timeout = min(timeout, 300)
    ssh_pool = _get_ssh_pool()

    try:
        result = ssh_pool.execute(vm_name, command, timeout=timeout)
        return (
            f"VM: {vm_name} | Exit: {result.exit_code} | Time: {result.duration_s:.1f}s\n"
            f"STDOUT:\n{result.stdout or '(empty)'}\n"
            f"STDERR:\n{result.stderr or '(empty)'}"
        )
    except Exception as exc:
        return f"SSH execution failed: {exc}"


# ─── Tool 4: VM Snapshot ──────────────────────────────────────────────────────

@tool
def vm_snapshot(vm_name: str) -> str:
    """
    Create a snapshot of the specified VM before running exploits.
    Snapshot name: '<vm_name>-clean'.

    Required: always call this before execute_on_vm for exploit testing.
    """
    from config import VMS
    cfg = VMS.get(vm_name, {})
    backend = cfg.get("backend", "tart")
    actual_name = cfg.get("vm_name", vm_name)

    try:
        mgr = _get_vm_manager()
        snap_name = mgr.snapshot(actual_name, backend=backend)
        return f"Snapshot created: {snap_name} (VM: {actual_name}, backend: {backend})"
    except Exception as exc:
        return f"Snapshot failed: {exc}"


# ─── Tool 5: Restore VM ───────────────────────────────────────────────────────

@tool
def restore_vm(vm_name: str) -> str:
    """
    Restore the specified VM to its clean snapshot state.
    Snapshot name assumed: '<vm_name>-clean'.

    Call this after exploit testing to reset the VM for the next test.
    """
    from config import VMS
    cfg = VMS.get(vm_name, {})
    backend = cfg.get("backend", "tart")
    actual_name = cfg.get("vm_name", vm_name)
    snap_name = f"{actual_name}-clean"

    try:
        mgr = _get_vm_manager()
        mgr.restore(actual_name, snap_name, backend=backend)
        return f"VM {actual_name} restored to snapshot '{snap_name}'"
    except Exception as exc:
        return f"Restore failed: {exc}"


# ─── Tool 6: Collect IOCs ─────────────────────────────────────────────────────

class IOCInput(BaseModel):
    vm_name:      str = Field(..., description="VM name: 'linux', 'macos', or 'windows'")
    technique_id: str = Field(..., description="MITRE technique ID that was executed")


@tool(args_schema=IOCInput)
def collect_iocs(vm_name: str, technique_id: str) -> str:
    """
    Collect indicators of compromise from the VM after executing a technique.
    Returns a confidence score and list of observed IOCs.

    Use this immediately after execute_on_vm to verify technique execution.
    """
    from config import VMS
    cfg = VMS.get(vm_name, {})
    platform = cfg.get("platform", "linux")

    ssh_pool = _get_ssh_pool()
    collector = _get_ioc_collector()

    try:
        report = collector.collect(ssh_pool, vm_name, technique_id, platform)
        return report.summary()
    except Exception as exc:
        return f"IOC collection failed: {exc}"


# ─── Tool 7: List VMs ─────────────────────────────────────────────────────────

@tool
def list_vms() -> str:
    """
    List all configured lab VMs with their current status and IP addresses.
    """
    from config import VMS
    mgr = _get_vm_manager()
    lines = ["VM Infrastructure Status:", ""]
    for name, cfg in VMS.items():
        backend = cfg.get("backend", "tart")
        actual = cfg.get("vm_name", name)
        status = mgr.status(actual, backend)
        host = cfg.get("host", "unknown")
        port = cfg.get("port", 22)
        lines.append(
            f"  {name:8s} | {actual:20s} | {status:10s} | {host}:{port} | {backend}"
        )
    return "\n".join(lines)


# ─── Export ───────────────────────────────────────────────────────────────────

def get_all_tools() -> list:
    """Return all security tools for registration with the ReAct agent."""
    from rag.retriever import search_corpus as _search_corpus
    return [
        mitre_lookup,
        generate_test_oneliner,
        execute_on_vm,
        vm_snapshot,
        restore_vm,
        collect_iocs,
        list_vms,
        _search_corpus,
    ]
