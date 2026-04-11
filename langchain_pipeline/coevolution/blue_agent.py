"""
Blue Team defensive agent.

Uses the 'blue_team' LoRA adapter and a set of detection tools to:
1. Analyze IOC reports from the red team
2. Determine which techniques were detected
3. Generate SIGMA-style detection rules for observed TTPs

Blue agent's goal: maximize detection rate while minimizing false positives.
Rewarded for identifying all red team techniques from the IOC evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionResult:
    techniques_detected: list[str] = field(default_factory=list)
    techniques_missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    sigma_rules: list[str] = field(default_factory=list)
    analysis: str = ""

    def summary(self) -> str:
        return (
            f"Blue Team Detection Result\n"
            f"  Detected:       {len(self.techniques_detected)} techniques\n"
            f"  Missed:         {len(self.techniques_missed)} techniques\n"
            f"  False positives:{len(self.false_positives)}\n"
            f"  Detection rate: {self.detection_rate:.2f}\n"
            f"  FP rate:        {self.false_positive_rate:.2f}"
        )


# Pattern-based IOC detection (fast path, no LLM call needed)
_DETECTION_PATTERNS: dict[str, list[str]] = {
    "T1059.001": ["powershell", "System.Management.Automation", "encodedcommand"],
    "T1059.003": ["cmd.exe", "command processor"],
    "T1059.004": ["bash", "/bin/sh", "id && ", "uname -a"],
    "T1003":     ["lsass", "/etc/shadow", "mimikatz", "credential", "sekurlsa"],
    "T1053":     ["crontab", "schtasks", "launchd", "scheduled task"],
    "T1078":     ["valid accounts", "su ", "runas", "net user"],
    "T1083":     ["file discovery", "find /", "dir /", "get-childitem"],
    "T1105":     ["wget", "curl", "invoke-webrequest", "certutil"],
    "T1082":     ["uname -a", "systeminfo", "get-computerinfo", "sw_vers"],
    "T1049":     ["netstat", "ss -", "get-nettcpconnection"],
}

# SIGMA rule templates
_SIGMA_TEMPLATE = """title: Detection of MITRE {technique_id} - {name}
status: experimental
description: Detects execution of {name} technique
logsource:
    product: {platform}
    category: process_creation
detection:
    selection:
        CommandLine|contains:
{patterns_yaml}
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: medium
tags:
    - attack.{tactic}
    - attack.{technique_id}
"""


def _generate_sigma(technique_id: str, platform: str, patterns: list[str]) -> str:
    """Generate a basic SIGMA detection rule for the technique."""
    from rag.retriever import get_retriever
    retriever = get_retriever()
    context = retriever.format_context(f"detect {technique_id} {platform}", platform=platform)
    meta_name = technique_id  # Would be enriched by MITRE lookup in real use

    patterns_yaml = "\n".join(f"            - '{p}'" for p in patterns[:5])
    return _SIGMA_TEMPLATE.format(
        technique_id=technique_id,
        name=meta_name,
        platform=platform,
        patterns_yaml=patterns_yaml,
        tactic="execution",
    )


class BlueTeamAgent:
    """
    Defensive agent that detects red team techniques from IOC reports.

    Two detection strategies:
    1. Fast: Pattern matching against known IOC signatures (no LLM)
    2. Deep: LLM-based analysis of raw execution logs (blue_team adapter)
    """

    def __init__(self, use_adapter: bool = True):
        self.use_adapter = use_adapter
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            from config import MODEL_PATH, MAX_TOKENS, TEMPERATURE
            from llm.mlx_wrapper import MLXLM
            self._llm = MLXLM(
                model_path=MODEL_PATH,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                adapter_name="blue_team" if self.use_adapter else None,
            )
        return self._llm

    def detect_from_ioc_reports(
        self,
        ioc_reports: list[dict],
        attempted_techniques: list[str],
        platform: str = "linux",
    ) -> DetectionResult:
        """
        Analyze IOC reports and determine which techniques were detected.

        Uses pattern matching first (fast), then optionally LLM for ambiguous cases.
        """
        result = DetectionResult()
        all_evidence = " ".join(
            str(r.get("raw_evidence", "")) + " ".join(r.get("file_iocs", []))
            + " ".join(r.get("process_iocs", []))
            for r in ioc_reports
        ).lower()

        for tech_id in attempted_techniques:
            patterns = _DETECTION_PATTERNS.get(tech_id, [])
            detected = False

            # Pattern-based detection
            for p in patterns:
                if p.lower() in all_evidence:
                    detected = True
                    break

            # Also check raw IOC confidence from the reports
            if not detected:
                for report in ioc_reports:
                    if report.get("technique_id") == tech_id:
                        if report.get("confidence", 0) >= 0.6:
                            detected = True
                            break

            if detected:
                result.techniques_detected.append(tech_id)
                # Generate SIGMA rule for detected technique
                sigma = _generate_sigma(tech_id, platform, patterns)
                result.sigma_rules.append(sigma)
            else:
                result.techniques_missed.append(tech_id)

        # Calculate metrics
        total = len(attempted_techniques)
        if total > 0:
            result.detection_rate = len(result.techniques_detected) / total

        return result

    def analyze_with_llm(
        self,
        execution_logs: str,
        platform: str = "linux",
    ) -> str:
        """
        Use the blue_team LLM adapter to analyze raw execution logs for TTPs.
        Returns a threat analysis report with detected technique IDs.
        """
        prompt = (
            f"You are a blue team analyst. Analyze the following execution logs "
            f"from a {platform} system and identify MITRE ATT&CK techniques present.\n\n"
            f"Logs:\n{execution_logs[:2000]}\n\n"
            f"List each detected technique with: technique ID, name, evidence, confidence (0-1)."
        )
        llm = self._get_llm()
        return llm.invoke(prompt)

    def generate_detections_report(
        self,
        detection_result: DetectionResult,
        platform: str = "linux",
    ) -> str:
        """Format a human-readable detection report for the thesis."""
        lines = [
            "=" * 60,
            "BLUE TEAM DETECTION REPORT",
            "=" * 60,
            detection_result.summary(),
            "",
            "Detected Techniques:",
        ]
        for tid in detection_result.techniques_detected:
            lines.append(f"  [DETECTED]  {tid}")
        for tid in detection_result.techniques_missed:
            lines.append(f"  [MISSED]    {tid}")

        if detection_result.sigma_rules:
            lines += ["", f"Generated {len(detection_result.sigma_rules)} SIGMA rules"]

        return "\n".join(lines)
