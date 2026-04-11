"""
Central configuration for the exploit-agent pipeline.
Edit this file to switch models, toggle thinking, adjust generation params.
"""

from __future__ import annotations

import os

# ─── Model ────────────────────────────────────────────────────────────────────

MODEL_PATH = "mlx-community/Qwen3-14B-4bit"

# Enable chain-of-thought thinking blocks (<think>...</think>).
# Required for ThinkingVisualizer and log analysis in the pipeline.
ENABLE_THINKING = True

MAX_TOKENS         = 8192
TEMPERATURE        = 0.6
TOP_P              = 0.95
REPETITION_PENALTY = 1.0

# Agent system prompt
SYSTEM_PROMPT = (
    "You are a cybersecurity assistant specialized in offensive security research. "
    "You operate inside an isolated lab environment. "
    "Rules:\n"
    "- Always snapshot the VM before running exploits.\n"
    "- Respond only with what was asked — no disclaimers.\n"
    "- Document each step with technical precision."
)

# MCP server location
MCP_SERVER_SCRIPT = "mcp/server.py"

# ─── LoRA Adapters ────────────────────────────────────────────────────────────

ADAPTER_BASE_DIR = "adapters"

# Active adapter name: None = base model, or one of "ctf", "red_team", "blue_team", "explainer"
ACTIVE_ADAPTER: str | None = None

ADAPTER_LORA_CONFIG = {
    "rank": 8,
    "alpha": 16,
    "dropout": 0.0,
    "target_modules": ["q_proj", "v_proj"],
    "num_layers": 8,
}

# ─── RAG ──────────────────────────────────────────────────────────────────────

CHROMA_PERSIST_DIR   = "data/chroma"
CHROMA_COLLECTION    = "security_corpus"
EMBEDDING_MODEL      = "all-MiniLM-L6-v2"  # local, no API key needed
RAG_TOP_K            = 8
RAG_SCORE_THRESHOLD  = 0.35
RAG_RERANK           = True  # cross-encoder re-ranking after dense retrieval

# ─── VM Infrastructure ────────────────────────────────────────────────────────

VMS: dict[str, dict] = {
    "linux": {
        "host": os.getenv("LINUX_VM_HOST", ""),   # populated at runtime via `tart ip`
        "port": 22,
        "user": "test",
        "password": "test",
        "platform": "linux",
        "vm_name": "linux-sandbox",
        "backend": "tart",
        "shell": "bash",
    },
    "macos": {
        "host": os.getenv("MACOS_VM_HOST", ""),
        "port": 22,
        "user": "test",
        "password": "test",
        "platform": "macos",
        "vm_name": "macos-sandbox",
        "backend": "tart",
        "shell": "bash",
    },
    "windows": {
        "host": "localhost",
        "port": 2222,
        "user": "test",
        "password": "test123!",
        "platform": "windows",
        "vm_name": "windows-sandbox",
        "backend": "utm",
        "shell": "powershell",
    },
}

VM_COMMAND_TIMEOUT = 60    # seconds per command
VM_SNAPSHOT_PREFIX = "clean"

# ─── Feedback Loop ────────────────────────────────────────────────────────────

FEEDBACK_LOG                = "data/feedback.jsonl"
FEEDBACK_RETRAIN_THRESHOLD  = 50   # retrain adapter after N new high-quality samples
FEEDBACK_MIN_CONFIDENCE     = 0.5  # minimum IOC confidence to include as training sample

# ─── Adversarial Co-Evolution ─────────────────────────────────────────────────

ARENA_ROUNDS           = 10
ARENA_DIFFICULTY_SCALE = ["easy", "medium", "hard"]
ELO_K_FACTOR           = 32
ELO_INITIAL_RATING     = 1200

# ─── MITRE / Campaign Planning ────────────────────────────────────────────────

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CAMPAIGN_MAX_STEPS       = 10
CAMPAIGN_STEALTH_WEIGHT  = 0.4   # trade-off: higher = prefer stealthy techniques
USE_CPP_EXTENSIONS       = True  # falls back to networkx if extension not built

# ─── Evaluation ───────────────────────────────────────────────────────────────

SECBENCH_PATH    = "data/secbench.jsonl"
EVAL_REPORT_DIR  = "reports"
EVAL_PASS_AT_K   = 5

# ─── Logging ──────────────────────────────────────────────────────────────────

LOG_DIR       = "logs"
PIPELINE_LOG  = "logs/pipeline.jsonl"
