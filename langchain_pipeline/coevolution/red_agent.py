"""
Red Team adversarial agent.

Specializes the base ExploitAgent with the 'red_team' LoRA adapter and
additional offensive tools (campaign planner, IOC feedback).

The red agent's goal: execute MITRE techniques successfully while evading
detection by the blue team agent. Rewarded for high IOC confidence + low
blue team detection rate.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

from langchain_core.messages import HumanMessage


@dataclass
class AttackResult:
    target_vm: str
    platform: str
    techniques_attempted: list[str] = field(default_factory=list)
    techniques_confirmed: list[str] = field(default_factory=list)  # IOC confidence > 0.5
    ioc_reports: list[dict] = field(default_factory=list)
    commands_executed: list[dict] = field(default_factory=list)
    red_score: float = 0.0  # fraction of techniques confirmed
    evasion_score: float = 0.0  # will be set by arena after blue team detection

    def summary(self) -> str:
        return (
            f"Red Team Attack on {self.target_vm} ({self.platform})\n"
            f"  Attempted: {len(self.techniques_attempted)} techniques\n"
            f"  Confirmed: {len(self.techniques_confirmed)} techniques\n"
            f"  Red Score: {self.red_score:.2f}\n"
            f"  Evasion:   {self.evasion_score:.2f}"
        )


class RedTeamAgent:
    """
    Offensive adversarial agent using the red_team LoRA adapter.

    Combines:
    - MITRECampaignPlanner for multi-step attack planning
    - execute_on_vm, collect_iocs tools for real VM exploitation
    - IOC-based success scoring
    """

    def __init__(self, use_adapter: bool = True):
        self.use_adapter = use_adapter
        self._llm = None
        self._agent = None

    def _get_llm(self):
        if self._llm is None:
            from config import MODEL_PATH, MAX_TOKENS, TEMPERATURE, TOP_P, REPETITION_PENALTY, ENABLE_THINKING
            from llm.mlx_wrapper import MLXLM
            self._llm = MLXLM(
                model_path=MODEL_PATH,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                top_p=TOP_P,
                repetition_penalty=REPETITION_PENALTY,
                enable_thinking=ENABLE_THINKING,
                adapter_name="red_team" if self.use_adapter else None,
            )
        return self._llm

    async def _get_agent(self):
        if self._agent is None:
            from langgraph.prebuilt import create_react_agent
            from tools.security_tools import get_all_tools
            from config import SYSTEM_PROMPT
            self._agent = create_react_agent(
                model=self._get_llm(),
                tools=get_all_tools(),
                state_modifier=(
                    SYSTEM_PROMPT + "\n"
                    "You are the RED TEAM agent. Your goal is to execute MITRE ATT&CK techniques "
                    "on the target VM and confirm execution via IOCs. "
                    "Always: 1) snapshot VM, 2) execute technique, 3) collect IOCs, 4) restore VM."
                ),
            )
        return self._agent

    async def attack(
        self,
        target_vm: str,
        technique_ids: list[str],
        platform: str = "linux",
    ) -> AttackResult:
        """
        Execute a list of MITRE techniques on the target VM.
        Returns AttackResult with IOC evidence.
        """
        result = AttackResult(target_vm=target_vm, platform=platform)

        from tools.ssh_executor import get_ssh_pool
        from tools.ioc_collector import get_ioc_collector
        from tools.vm_tools import get_vm_manager
        from config import VMS

        ssh_pool = get_ssh_pool()
        ioc_collector = get_ioc_collector()
        vm_mgr = get_vm_manager()

        cfg = VMS.get(target_vm, {})
        actual_vm = cfg.get("vm_name", target_vm)
        backend = cfg.get("backend", "tart")

        # Snapshot before attack
        try:
            vm_mgr.snapshot(actual_vm, backend=backend)
        except Exception as e:
            print(f"[RedAgent] Snapshot failed: {e}")

        agent = await self._get_agent()

        for tech_id in technique_ids:
            result.techniques_attempted.append(tech_id)

            # Ask agent to generate and execute the technique
            query = (
                f"Execute MITRE technique {tech_id} on the {platform} VM named '{target_vm}'. "
                f"1. Look up the technique. 2. Generate the command. "
                f"3. Execute it on the VM. 4. Collect IOCs."
            )

            try:
                agent_result = await agent.ainvoke(
                    {"messages": [HumanMessage(content=query)]},
                    config={"recursion_limit": 10},
                )
                last_msg = agent_result["messages"][-1]
                command_used = str(last_msg.content)[:500]

                # Also collect IOCs directly for accurate scoring
                ioc_report = ioc_collector.collect(
                    ssh_pool, target_vm, tech_id, platform
                )

                result.ioc_reports.append(ioc_report.__dict__)
                result.commands_executed.append({
                    "technique": tech_id,
                    "agent_response": command_used,
                    "ioc_confidence": ioc_report.confidence,
                })

                if ioc_report.confidence >= 0.5:
                    result.techniques_confirmed.append(tech_id)

            except Exception as e:
                print(f"[RedAgent] Error on {tech_id}: {e}")

        # Restore VM after attack
        try:
            snap = f"{actual_vm}-clean"
            vm_mgr.restore(actual_vm, snap, backend=backend)
        except Exception as e:
            print(f"[RedAgent] Restore failed: {e}")

        # Calculate score
        if result.techniques_attempted:
            result.red_score = len(result.techniques_confirmed) / len(result.techniques_attempted)

        return result

    async def plan_and_attack(
        self,
        target_vm: str,
        start_technique: str,
        goal_tactic: str,
        platform: str = "linux",
        max_steps: int = 5,
    ) -> AttackResult:
        """Plan a campaign then execute it."""
        from mitre.planner import MITRECampaignPlanner
        planner = MITRECampaignPlanner()
        campaign = planner.plan(start_technique, goal_tactic, platform=platform, max_steps=max_steps)
        return await self.attack(target_vm, campaign.technique_ids(), platform)
