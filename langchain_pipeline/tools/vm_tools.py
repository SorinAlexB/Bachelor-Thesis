"""
VM lifecycle management: snapshot, restore, start, stop, status.

Tart VMs (Linux, macOS): uses `tart` CLI.
UTM VMs  (Windows):      uses `utmctl` CLI.

Snapshot strategy:
  - Tart does not have native snapshots; `tart clone` is the equivalent.
  - Clone is created at setup time (the "-clean" suffix clone).
  - Restore = stop current + delete + re-clone from clean.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class VMInfo:
    name: str
    backend: str   # "tart" | "utm"
    status: str    # "running" | "stopped" | "not_found"
    ip: Optional[str] = None


class VMManager:
    """
    Controls VM lifecycle for the three sandbox VMs.

    Usage:
        mgr = VMManager()
        mgr.snapshot("linux-sandbox")
        # ... run exploits ...
        mgr.restore("linux-sandbox", "linux-sandbox-clean")
    """

    # ─── Tart helpers ─────────────────────────────────────────────────────────

    def _tart(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["tart", *args],
            capture_output=True, text=True, timeout=timeout,
        )

    def _utmctl(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["utmctl", *args],
            capture_output=True, text=True, timeout=timeout,
        )

    # ─── Status ───────────────────────────────────────────────────────────────

    def status(self, vm_name: str, backend: str = "tart") -> str:
        """Returns 'running', 'stopped', or 'not_found'."""
        try:
            if backend == "tart":
                result = self._tart("list")
                for line in result.stdout.splitlines():
                    if vm_name in line:
                        if "running" in line.lower():
                            return "running"
                        return "stopped"
                return "not_found"
            else:
                result = self._utmctl("status", vm_name)
                out = result.stdout.lower()
                if "started" in out or "running" in out:
                    return "running"
                if "stopped" in out:
                    return "stopped"
                return "not_found"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "not_found"

    def list_vms(self, backend: str = "tart") -> list[VMInfo]:
        """List all VMs for the given backend."""
        vms: list[VMInfo] = []
        try:
            if backend == "tart":
                result = self._tart("list")
                for line in result.stdout.splitlines()[1:]:  # skip header
                    parts = line.split()
                    if parts:
                        name = parts[0]
                        status = "running" if len(parts) > 1 and "running" in parts[1].lower() else "stopped"
                        vms.append(VMInfo(name=name, backend="tart", status=status))
        except Exception:
            pass
        return vms

    # ─── IP resolution ────────────────────────────────────────────────────────

    def get_ip(self, vm_name: str, backend: str = "tart") -> str:
        """Get the current IP of a running VM. Returns 'localhost' for UTM."""
        if backend == "utm":
            return "localhost"
        try:
            result = self._tart("ip", vm_name, "--wait", "60")
            return result.stdout.strip()
        except Exception:
            return ""

    # ─── Start / Stop ─────────────────────────────────────────────────────────

    def start(self, vm_name: str, backend: str = "tart", headless: bool = True) -> bool:
        """Start a stopped VM. Returns True on success."""
        try:
            if backend == "tart":
                args = ["run", vm_name]
                if headless:
                    args.append("--no-graphics")
                proc = subprocess.Popen(
                    ["tart", *args],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                # Give it a moment to spin up
                time.sleep(5)
                return proc.poll() is None  # None means still running (background)
            else:
                result = self._utmctl("start", vm_name)
                return result.returncode == 0
        except Exception:
            return False

    def stop(self, vm_name: str, backend: str = "tart") -> bool:
        """Stop a running VM. Returns True on success."""
        try:
            if backend == "tart":
                result = self._tart("stop", vm_name)
                return result.returncode == 0
            else:
                result = self._utmctl("stop", vm_name)
                return result.returncode == 0
        except Exception:
            return False

    # ─── Snapshot (clone) ─────────────────────────────────────────────────────

    def snapshot(self, vm_name: str, snap_name: Optional[str] = None, backend: str = "tart") -> str:
        """
        Create a snapshot clone of the VM.
        For Tart: `tart clone <vm_name> <snap_name>`
        Returns the snapshot name.
        """
        if snap_name is None:
            snap_name = f"{vm_name}-clean"

        try:
            if backend == "tart":
                # Stop VM first so the clone is clean
                self.stop(vm_name, backend)
                time.sleep(2)
                result = self._tart("clone", vm_name, snap_name, timeout=300)
                if result.returncode != 0:
                    raise RuntimeError(f"tart clone failed: {result.stderr}")
            else:
                # UTM: use utmctl snapshot
                result = self._utmctl("snapshot", "--name", snap_name, vm_name)
                if result.returncode != 0:
                    raise RuntimeError(f"utmctl snapshot failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Snapshot timed out for {vm_name}")

        return snap_name

    def restore(self, vm_name: str, snap_name: str, backend: str = "tart") -> None:
        """
        Restore VM to a snapshot.
        For Tart: stop current, delete it, re-clone from snap_name.
        """
        try:
            if backend == "tart":
                self.stop(vm_name, backend)
                time.sleep(2)
                # Delete the current running VM
                self._tart("delete", vm_name, timeout=60)
                time.sleep(1)
                # Re-clone from the clean snapshot
                result = self._tart("clone", snap_name, vm_name, timeout=300)
                if result.returncode != 0:
                    raise RuntimeError(f"Restore failed: {result.stderr}")
            else:
                self.stop(vm_name, backend)
                result = self._utmctl("revert", "--snapshot", snap_name, vm_name)
                if result.returncode != 0:
                    raise RuntimeError(f"UTM revert failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Restore timed out for {vm_name}")

    def list_snapshots(self) -> dict[str, list[str]]:
        """Return {vm_name: [snapshot_names]} for all backends."""
        snapshots: dict[str, list[str]] = {}
        try:
            result = self._tart("list")
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if parts:
                    name = parts[0]
                    if "-clean" in name:
                        base = name.replace("-clean", "")
                        snapshots.setdefault(base, []).append(name)
        except Exception:
            pass
        return snapshots


# Module-level singleton
_vm_manager_instance: Optional[VMManager] = None


def get_vm_manager() -> VMManager:
    global _vm_manager_instance
    if _vm_manager_instance is None:
        _vm_manager_instance = VMManager()
    return _vm_manager_instance
