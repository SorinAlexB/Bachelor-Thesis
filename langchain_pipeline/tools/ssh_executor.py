"""
SSH execution pool for the three lab VMs.

SSHPool maintains one persistent paramiko.SSHClient per VM and auto-reconnects.
ExecutionResult is a dataclass capturing stdout, stderr, exit_code, and timing.
"""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import paramiko
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class ExecutionResult:
    vm_name: str
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_s: float
    platform: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def summary(self) -> str:
        status = "OK" if self.success else f"FAIL({self.exit_code})"
        return (
            f"[{self.vm_name}/{self.platform}] {status} in {self.duration_s:.1f}s\n"
            f"STDOUT: {self.stdout[:500]}\n"
            f"STDERR: {self.stderr[:200]}"
        )


class SSHPool:
    """
    Thread-safe SSH connection pool for Linux, macOS, and Windows VMs.

    Usage:
        pool = SSHPool(VMS)
        result = pool.execute("linux", "id")
        print(result.stdout)

    The pool is a singleton — import `ssh_pool` from this module.
    """

    def __init__(self, vm_configs: dict[str, dict]):
        self._configs = vm_configs
        self._connections: dict[str, paramiko.SSHClient] = {}
        self._lock = threading.Lock()

    def _connect(self, vm_name: str) -> paramiko.SSHClient:
        cfg = self._configs[vm_name]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=cfg["host"],
            port=cfg["port"],
            username=cfg["user"],
            password=cfg["password"],
            timeout=30,
            banner_timeout=60,
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def _get_connection(self, vm_name: str) -> paramiko.SSHClient:
        with self._lock:
            existing = self._connections.get(vm_name)
            if existing is not None:
                try:
                    existing.get_transport().send_ignore()
                    return existing
                except Exception:
                    # Connection dropped — reconnect
                    pass
            client = self._connect(vm_name)
            self._connections[vm_name] = client
            return client

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def execute(
        self,
        vm_name: str,
        command: str,
        timeout: int = 60,
    ) -> ExecutionResult:
        """Execute a shell command on the named VM and return the result."""
        cfg = self._configs[vm_name]
        platform = cfg.get("platform", "linux")

        # Windows needs PowerShell wrapping
        if platform == "windows":
            command = f'powershell -NonInteractive -Command "{command}"'

        client = self._get_connection(vm_name)
        t0 = time.monotonic()
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        duration = time.monotonic() - t0

        return ExecutionResult(
            vm_name=vm_name,
            command=command,
            stdout=stdout.read().decode("utf-8", errors="replace").strip(),
            stderr=stderr.read().decode("utf-8", errors="replace").strip(),
            exit_code=exit_code,
            duration_s=duration,
            platform=platform,
        )

    def execute_parallel(
        self,
        commands: list[tuple[str, str]],  # [(vm_name, command), ...]
        timeout: int = 60,
    ) -> list[ExecutionResult]:
        """Execute multiple commands in parallel across VMs using threads."""
        results: list[Optional[ExecutionResult]] = [None] * len(commands)

        def worker(idx: int, vm_name: str, cmd: str) -> None:
            try:
                results[idx] = self.execute(vm_name, cmd, timeout)
            except Exception as exc:
                results[idx] = ExecutionResult(
                    vm_name=vm_name,
                    command=cmd,
                    stdout="",
                    stderr=str(exc),
                    exit_code=-1,
                    duration_s=0.0,
                    platform=self._configs.get(vm_name, {}).get("platform", "unknown"),
                )

        threads = [
            threading.Thread(target=worker, args=(i, vm, cmd), daemon=True)
            for i, (vm, cmd) in enumerate(commands)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 10)

        return [r for r in results if r is not None]

    def resolve_vm_ip(self, vm_name: str) -> str:
        """
        Resolve the current IP of a Tart VM and update the config.
        No-op for UTM/Windows (always localhost:2222).
        """
        cfg = self._configs.get(vm_name, {})
        if cfg.get("backend") != "tart":
            return cfg.get("host", "localhost")

        try:
            result = subprocess.run(
                ["tart", "ip", cfg["vm_name"], "--wait", "60"],
                capture_output=True, text=True, timeout=70,
            )
            ip = result.stdout.strip()
            if ip:
                cfg["host"] = ip
                return ip
        except Exception:
            pass
        return cfg.get("host", "")

    def close_all(self) -> None:
        with self._lock:
            for client in self._connections.values():
                try:
                    client.close()
                except Exception:
                    pass
            self._connections.clear()


# Module-level lazy singleton — only initialized when actually used
_pool_instance: Optional[SSHPool] = None


def get_ssh_pool() -> SSHPool:
    """Return the module-level SSH pool singleton, creating it on first call."""
    global _pool_instance
    if _pool_instance is None:
        from config import VMS
        _pool_instance = SSHPool(VMS)
        # Resolve dynamic IPs for Tart VMs
        for vm_name in ("linux", "macos"):
            _pool_instance.resolve_vm_ip(vm_name)
    return _pool_instance
