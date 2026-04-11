"""
IOC (Indicator of Compromise) collector.

After executing a MITRE technique command, this collector queries the VM
for evidence that the technique actually ran. Returns a confidence score 0.0-1.0.

IOC types per platform:
  Linux/macOS:
    - File artifacts: new files in /tmp, modified config files
    - Process artifacts: unexpected processes in ps output
    - Network artifacts: new connections in ss/netstat
    - Log artifacts: new entries in /var/log/auth.log, /var/log/syslog
  Windows:
    - File artifacts: Get-ChildItem $env:TEMP
    - Process artifacts: Get-Process (unexpected names)
    - Event log: Get-WinEvent -LogName Security -Newest 20
    - Registry: new keys under HKCU/HKLM run keys
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.ssh_executor import SSHPool

# Technique-specific IOC signatures
# Maps technique_id -> {platform -> [expected_ioc_patterns]}
TECHNIQUE_IOC_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "T1059.001": {  # PowerShell
        "windows": ["powershell", "System.Management.Automation"],
        "linux": [],
    },
    "T1059.003": {  # Windows Command Shell
        "windows": ["cmd.exe", "Command Processor"],
        "linux": [],
    },
    "T1059.004": {  # Unix Shell
        "linux": ["bash", "sh", "/bin/"],
        "macos": ["bash", "sh", "/bin/"],
    },
    "T1003": {  # OS Credential Dumping
        "linux": ["/etc/shadow", "passwd", "credential"],
        "windows": ["lsass", "mimikatz", "sekurlsa"],
        "macos": ["security find-generic-password", "keychain"],
    },
    "T1053": {  # Scheduled Task/Job
        "linux": ["crontab", "/etc/cron"],
        "windows": ["schtasks", "Task Scheduler"],
        "macos": ["launchd", "plist"],
    },
    "T1083": {  # File and Directory Discovery
        "linux": ["ls", "find", "locate"],
        "windows": ["dir", "Get-ChildItem"],
        "macos": ["ls", "find"],
    },
    "T1105": {  # Ingress Tool Transfer
        "linux": ["wget", "curl", "scp"],
        "windows": ["Invoke-WebRequest", "certutil", "bitsadmin"],
        "macos": ["curl", "wget"],
    },
    "T1078": {  # Valid Accounts
        "linux": ["su ", "sudo ", "login"],
        "windows": ["net user", "runas"],
        "macos": ["su ", "sudo "],
    },
}

# Commands to run after technique execution to collect evidence
IOC_COLLECTION_COMMANDS: dict[str, list[str]] = {
    "linux": [
        "ps aux --no-headers | tail -20",
        "ls -la /tmp/ 2>/dev/null | tail -20",
        "ss -tulpn 2>/dev/null | tail -20",
        "tail -20 /var/log/auth.log 2>/dev/null || tail -20 /var/log/secure 2>/dev/null || echo 'no auth log'",
        "last -20 2>/dev/null",
        "find /tmp -newer /tmp -maxdepth 2 -ls 2>/dev/null | head -20",
    ],
    "macos": [
        "ps aux | tail -20",
        "ls -la /tmp/ 2>/dev/null | tail -20",
        "netstat -an 2>/dev/null | tail -20",
        "log show --predicate 'eventMessage contains \"auth\"' --last 5m 2>/dev/null | tail -30",
        "last -20 2>/dev/null",
    ],
    "windows": [
        "Get-Process | Select-Object -Last 20 | Format-Table Name,Id -AutoSize",
        "Get-ChildItem $env:TEMP | Select-Object -Last 20",
        "netstat -an | Select-String 'ESTABLISHED' | Select-Object -Last 20",
        "Get-WinEvent -LogName Security -Newest 10 -ErrorAction SilentlyContinue | Format-List Message",
        "Get-Item 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue",
    ],
}


@dataclass
class IOCReport:
    technique_id: str
    vm_name: str
    platform: str
    file_iocs: list[str] = field(default_factory=list)
    process_iocs: list[str] = field(default_factory=list)
    network_iocs: list[str] = field(default_factory=list)
    log_iocs: list[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_evidence: dict = field(default_factory=dict)

    def summary(self) -> str:
        total_iocs = len(self.file_iocs) + len(self.process_iocs) + len(self.network_iocs) + len(self.log_iocs)
        return (
            f"IOC Report for {self.technique_id} on {self.vm_name} ({self.platform})\n"
            f"  Confidence: {self.confidence:.2f}\n"
            f"  File IOCs: {len(self.file_iocs)}\n"
            f"  Process IOCs: {len(self.process_iocs)}\n"
            f"  Network IOCs: {len(self.network_iocs)}\n"
            f"  Log IOCs: {len(self.log_iocs)}\n"
            f"  Total IOC hits: {total_iocs}"
        )


class IOCCollector:
    """
    Collects and analyzes IOCs from a VM after technique execution.

    Confidence scoring:
    - Each matched IOC pattern adds 0.2 to confidence (capped at 1.0)
    - Zero matches = confidence 0.0
    - Unknown technique ID = confidence 0.1 if command exited 0, else 0.0
    """

    def collect(
        self,
        ssh_pool: "SSHPool",
        vm_name: str,
        technique_id: str,
        platform: str,
    ) -> IOCReport:
        report = IOCReport(
            technique_id=technique_id,
            vm_name=vm_name,
            platform=platform,
        )

        # Run collection commands
        collection_cmds = IOC_COLLECTION_COMMANDS.get(platform, IOC_COLLECTION_COMMANDS["linux"])
        evidence: dict[str, str] = {}
        for cmd in collection_cmds:
            try:
                result = ssh_pool.execute(vm_name, cmd, timeout=30)
                evidence[cmd] = result.stdout + result.stderr
            except Exception as exc:
                evidence[cmd] = f"ERROR: {exc}"

        report.raw_evidence = evidence
        all_output = "\n".join(evidence.values()).lower()

        # Match against technique signatures
        sigs = TECHNIQUE_IOC_SIGNATURES.get(technique_id, {})
        patterns = sigs.get(platform, []) or sigs.get("linux", [])

        matched = 0
        for pattern in patterns:
            if pattern.lower() in all_output:
                matched += 1
                # Categorize the IOC
                if any(k in pattern.lower() for k in ["log", "auth", "event"]):
                    report.log_iocs.append(pattern)
                elif any(k in pattern.lower() for k in ["process", "ps", "exe", "pid"]):
                    report.process_iocs.append(pattern)
                elif any(k in pattern.lower() for k in ["net", "port", "connection", "socket"]):
                    report.network_iocs.append(pattern)
                else:
                    report.file_iocs.append(pattern)

        # Score confidence
        if patterns:
            report.confidence = min(1.0, matched * 0.2 + (0.1 if matched > 0 else 0.0))
        else:
            # Unknown technique — heuristic: any output in evidence means something ran
            non_empty = sum(1 for v in evidence.values() if v.strip() and "ERROR" not in v)
            report.confidence = 0.1 if non_empty >= len(collection_cmds) // 2 else 0.0

        return report


# Module-level singleton
_ioc_collector_instance: IOCCollector | None = None


def get_ioc_collector() -> IOCCollector:
    global _ioc_collector_instance
    if _ioc_collector_instance is None:
        _ioc_collector_instance = IOCCollector()
    return _ioc_collector_instance
