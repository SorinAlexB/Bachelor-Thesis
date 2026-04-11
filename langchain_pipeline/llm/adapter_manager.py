"""
LoRA adapter manager for mlx-lm.

Manages the four specialized LoRA adapters:
  - ctf:       CTF challenge solving (web, pwn, crypto, reverse, forensics)
  - red_team:  Offensive exploit generation
  - blue_team: Defensive detection and mitigation
  - explainer: Chain-of-thought security explanations

Strategy:
  - mlx-lm loads a LoRA adapter at model-load time
  - Hot-swapping requires a re-load (MLX limitation)
  - LRU cache (max_cached) keeps the most recently used adapters in memory
  - Training uses `python -m mlx_lm.lora` as a subprocess

Usage:
    manager = AdapterManager("mlx-community/Qwen3-14B-4bit")
    model, tokenizer = manager.get("red_team")

    # Trigger training (runs in the background):
    manager.train("red_team", "adapters/red_team/train.jsonl")

    # List trained adapters:
    print(manager.list_trained())
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional, Tuple

ADAPTER_NAMES = ("ctf", "red_team", "blue_team", "explainer")

# Default LoRA configuration
DEFAULT_LORA_CONFIG = {
    "rank": 8,
    "alpha": 16,
    "dropout": 0.0,
    "target_modules": ["q_proj", "v_proj"],
    "num_layers": 8,
}

# Sample training data templates for each adapter
_ADAPTER_SEEDS: dict[str, list[dict]] = {
    "ctf": [
        {"messages": [
            {"role": "user", "content": "Solve this CTF challenge: A web app has a login form. What SQL injection would bypass authentication?"},
            {"role": "assistant", "content": "<think>\nSQL injection to bypass auth typically uses ' OR '1'='1' to make the WHERE clause always true.\nThe classic payload is: username: admin' OR '1'='1'-- and any password.\n</think>\nPayload: `' OR '1'='1'--`\nThis makes the query: SELECT * FROM users WHERE user='' OR '1'='1'-- which always returns true, bypassing authentication."},
        ]},
        {"messages": [
            {"role": "user", "content": "CTF: A binary has buffer overflow vulnerability. Stack cookie is at offset 64. Return address at offset 72. What is the exploit structure?"},
            {"role": "assistant", "content": "<think>\nBuffer overflow: padding to offset 64, overwrite stack canary, padding to 72, then ROP chain or shellcode address.\n</think>\npayload = b'A' * 64 + p64(canary) + b'B' * 8 + p64(ret_addr)"},
        ]},
    ],
    "red_team": [
        {"messages": [
            {"role": "user", "content": "Generate a command for MITRE T1059.004 (Unix Shell) on Linux"},
            {"role": "assistant", "content": "<think>\nT1059.004 is Unix Shell execution. A basic test is running id and uname to confirm execution context.\n</think>\nbash -c 'id && uname -a && echo T1059.004_confirmed'"},
        ]},
        {"messages": [
            {"role": "user", "content": "Generate a discovery command for T1082 (System Information Discovery) on Linux"},
            {"role": "assistant", "content": "<think>\nT1082 is system info discovery. Commands: uname, cat /etc/os-release, hostname, id.\n</think>\nuname -a && hostname && id && cat /etc/os-release 2>/dev/null | head -5"},
        ]},
    ],
    "blue_team": [
        {"messages": [
            {"role": "user", "content": "How do I detect T1059.001 (PowerShell execution) in Windows event logs?"},
            {"role": "assistant", "content": "<think>\nPowerShell execution generates Event ID 4688 (process creation) and 4104 (script block logging).\nKey indicators: powershell.exe with -EncodedCommand, -NonInteractive, -WindowStyle Hidden.\n</think>\nDetect via:\n- Event ID 4688: process creation with powershell.exe\n- Event ID 4104: PowerShell script block logging\n- SIGMA rule: look for -EncodedCommand flag\n- Command: Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104"},
        ]},
    ],
    "explainer": [
        {"messages": [
            {"role": "user", "content": "Explain MITRE T1003 (OS Credential Dumping) in detail"},
            {"role": "assistant", "content": "<think>\nNeed to explain: what it is, how it works technically, common tools, detection.\n</think>\n## T1003: OS Credential Dumping\n\n**What it does**: Extracts credential material (passwords, hashes, tokens) from the OS.\n\n**How it works**:\n- Linux: reads /etc/shadow (requires root), uses LD_PRELOAD hooks\n- Windows: dumps LSASS memory (lsass.exe holds NTLM hashes, Kerberos tickets)\n- macOS: accesses Keychain via security CLI\n\n**Common tools**: Mimikatz (Windows), hashdump (Linux), secretsdump (cross-platform)\n\n**Detection**: Monitor for access to LSASS, /etc/shadow reads, unusual security tool execution"},
        ]},
    ],
}


class AdapterManager:
    """
    LRU cache manager for mlx-lm LoRA adapters.

    Thread-safe via a per-instance lock.
    """

    def __init__(
        self,
        base_model_path: str,
        adapter_base_dir: str = "adapters",
        max_cached: int = 2,
    ):
        self.base_model_path = base_model_path
        self.adapter_base_dir = Path(adapter_base_dir)
        self.max_cached = max_cached
        self._cache: OrderedDict[Optional[str], Tuple[Any, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self._ensure_adapter_dirs()

    def _ensure_adapter_dirs(self) -> None:
        """Create adapter directories and seed training data if they don't exist."""
        for name in ADAPTER_NAMES:
            adapter_dir = self.adapter_base_dir / name
            adapter_dir.mkdir(parents=True, exist_ok=True)

            # Write lora_config.json
            config_path = adapter_dir / "lora_config.json"
            if not config_path.exists():
                with open(config_path, "w") as f:
                    json.dump(DEFAULT_LORA_CONFIG, f, indent=2)

            # Seed train.jsonl
            train_path = adapter_dir / "train.jsonl"
            if not train_path.exists():
                seeds = _ADAPTER_SEEDS.get(name, [])
                with open(train_path, "w") as f:
                    for sample in seeds:
                        f.write(json.dumps(sample) + "\n")

    def _load(self, adapter_name: Optional[str]) -> Tuple[Any, Any]:
        """Load model + tokenizer with the given adapter. None = base model."""
        from mlx_lm import load
        adapter_path: Optional[str] = None
        if adapter_name:
            candidate = self.adapter_base_dir / adapter_name
            if (candidate / "adapters.safetensors").exists() or (candidate / "adapter_model.safetensors").exists():
                adapter_path = str(candidate)
        return load(self.base_model_path, adapter_path=adapter_path)

    def get(self, adapter_name: Optional[str] = None) -> Tuple[Any, Any]:
        """
        Return (model, tokenizer) for the given adapter name.
        None = base model (no adapter).
        Uses LRU caching; evicts least recently used when cache is full.
        """
        with self._lock:
            if adapter_name in self._cache:
                self._cache.move_to_end(adapter_name)
                return self._cache[adapter_name]

            # Evict LRU if at capacity
            while len(self._cache) >= self.max_cached:
                evicted_key, _ = self._cache.popitem(last=False)
                print(f"[AdapterManager] Evicted adapter '{evicted_key}' from cache")

            print(f"[AdapterManager] Loading adapter '{adapter_name}'...")
            model, tokenizer = self._load(adapter_name)
            self._cache[adapter_name] = (model, tokenizer)
            return model, tokenizer

    def train(
        self,
        adapter_name: str,
        train_jsonl: Optional[str] = None,
        iters: int = 1000,
        resume: bool = True,
        blocking: bool = True,
    ) -> subprocess.CompletedProcess | subprocess.Popen:
        """
        Train a LoRA adapter using mlx_lm.lora.

        Args:
            adapter_name: one of the ADAPTER_NAMES
            train_jsonl:  path to training data (defaults to adapters/<name>/train.jsonl)
            iters:        training iterations
            resume:       if True, resume from existing checkpoint
            blocking:     if True, wait for training to complete

        Returns CompletedProcess if blocking, Popen if not.
        """
        adapter_dir = self.adapter_base_dir / adapter_name
        if train_jsonl is None:
            train_jsonl = str(adapter_dir / "train.jsonl")

        cmd = [
            sys.executable, "-m", "mlx_lm.lora",
            "--train",
            "--model", self.base_model_path,
            "--adapter-path", str(adapter_dir),
            "--data", train_jsonl,
            "--iters", str(iters),
            "--batch-size", "4",
            "--lora-rank", str(DEFAULT_LORA_CONFIG["rank"]),
            "--lora-alpha", str(DEFAULT_LORA_CONFIG["alpha"]),
            "--num-layers", str(DEFAULT_LORA_CONFIG["num_layers"]),
        ]

        if resume and (adapter_dir / "adapters.safetensors").exists():
            cmd += ["--resume-adapter-file", str(adapter_dir / "adapters.safetensors")]

        print(f"[AdapterManager] Starting training for '{adapter_name}'")
        print(f"  Command: {' '.join(cmd)}")

        if blocking:
            return subprocess.run(cmd, text=True, capture_output=False)
        else:
            return subprocess.Popen(cmd)

    def list_trained(self) -> list[str]:
        """Return adapter names that have a trained adapter file."""
        trained = []
        for name in ADAPTER_NAMES:
            adapter_dir = self.adapter_base_dir / name
            if (
                (adapter_dir / "adapters.safetensors").exists()
                or (adapter_dir / "adapter_model.safetensors").exists()
            ):
                trained.append(name)
        return trained

    def sample_count(self, adapter_name: str) -> int:
        """Count training samples in the adapter's train.jsonl."""
        path = self.adapter_base_dir / adapter_name / "train.jsonl"
        if not path.exists():
            return 0
        return sum(1 for _ in open(path))

    def append_training_sample(self, adapter_name: str, sample: dict) -> int:
        """
        Append a new training sample to the adapter's train.jsonl.
        Returns the new total sample count.
        """
        path = self.adapter_base_dir / adapter_name / "train.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(sample) + "\n")
        return self.sample_count(adapter_name)


# Module-level singleton
_manager_instance: Optional[AdapterManager] = None


def get_adapter_manager() -> AdapterManager:
    global _manager_instance
    if _manager_instance is None:
        from config import MODEL_PATH, ADAPTER_BASE_DIR
        _manager_instance = AdapterManager(MODEL_PATH, ADAPTER_BASE_DIR)
    return _manager_instance
