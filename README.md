# Bachelor Thesis — Security AI Pipeline

An AI-powered offensive/defensive security research system built around a locally-running LLM (Qwen3-14B via mlx-lm on Apple Silicon). The architecture combines a modular LoRA adapter system, a hybrid RAG knowledge base, a GAN-like adversarial co-evolution loop, and real multi-platform VM testing.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r langchain_pipeline/requirements.txt

# 2. Build C++ extensions (MITRE A* graph + parallel pattern matching)
cd cpp_extensions && pip install -e . && cd ..

# 3. Build the RAG corpus (run once — ~2 hours, downloads MITRE/NVD/ExploitDB)
cd langchain_pipeline
python pipeline_runner.py ingest

# 4. Run the agent
python main.py agent
```

---

## Repository Structure

```
Bachelor-Thesis/
├── langchain_pipeline/     # Main Python application
├── cpp_extensions/         # C++ performance extensions (pybind11)
├── tart_infra/             # Linux + macOS VM setup scripts (Tart)
├── utm_infra/              # Windows VM setup scripts (UTM)
├── .env.example            # Template for VM IP environment variables
└── .gitignore
```

---

## `langchain_pipeline/`

The core application. All modules use lazy initialization — nothing loads until actually called.

### Root files

| File | Description |
|------|-------------|
| `config.py` | Single source of truth for all configuration: model path, VM credentials, RAG settings, adapter paths, ELO parameters, evaluation paths. Edit this file to change behaviour. |
| `main.py` | Entry point. Run modes: `direct`, `rag`, `agent`, `stream`, `campaign`, `coevolve`, `evaluate`, `adapter`. |
| `pipeline_runner.py` | CLI orchestrator for thesis experiments. Commands: `ingest`, `train`, `feedback`, `coevolve`, `evaluate`, `ablation`, `campaign`, `cross-platform`, `build-cpp`, `rag-stats`, `rag-search`. |
| `requirements.txt` | All Python dependencies. |
| `inference_qwen3.5-4b.py` | Standalone quick inference test for the 4B model. |
| `inference_qwen9b.py` | Standalone quick inference test for the 9B model. |

---

### `agent/`

The LangGraph ReAct agent that combines LLM + tools + RAG + MCP.

| File | Description |
|------|-------------|
| `agent.py` | `ExploitAgent` — full ReAct agent with MCP tools, RAG context injection, and LoRA adapter selection. `DirectLLM` — lightweight wrapper for direct inference without a tool loop. |
| `callbacks.py` | Three LangChain callback handlers: `ThinkingVisualizer` (renders `<think>` blocks in a terminal box), `StepTracer` (prints each tool call and result), `PipelineLogger` (writes every event to `logs/pipeline.jsonl`). |

---

### `llm/`

Model loading and adapter management.

| File | Description |
|------|-------------|
| `mlx_wrapper.py` | LangChain `LLM` subclass wrapping `mlx_lm`. Auto-detects Base vs Instruct models, applies chat templates, supports streaming, parses `<think>` blocks, and loads LoRA adapters at model-load time. |
| `adapter_manager.py` | LRU cache for the four LoRA adapters (`ctf`, `red_team`, `blue_team`, `explainer`). Triggers `mlx_lm.lora` retraining as a subprocess, appends new training samples to `adapters/<name>/train.jsonl`, and manages adapter directories with seed data. |

---

### `rag/`

25k-document security knowledge base backed by ChromaDB.

| File | Description |
|------|-------------|
| `embedder.py` | Wraps `sentence-transformers/all-MiniLM-L6-v2` (22 MB, runs on CPU alongside the MLX model). Implements the LangChain `Embeddings` interface. |
| `chroma_store.py` | ChromaDB persistent store. Handles document chunking (1000-char with overlap), batch upsert, and metadata-filtered similarity search. |
| `retriever.py` | Hybrid retriever: dense ChromaDB search (top-20) → cross-encoder re-ranking → top-8. Also exposed as a `@tool` called `search_corpus` for use inside the agent. |
| `ingestion/mitre_ingestor.py` | Downloads the MITRE ATT&CK Enterprise STIX bundle, parses ~1,500 technique documents, ingests into ChromaDB. |
| `ingestion/nvd_ingestor.py` | Downloads NVD annual JSON feeds (2020–2024), filters CVSS ≥ 7.0, ingests ~10,000 CVE advisories. |
| `ingestion/exploit_db_ingestor.py` | Downloads the ExploitDB CSV index, takes the 10,000 most recent entries, ingests into ChromaDB. |
| `ingestion/pipeline.py` | Runs all three ingestors in sequence. Entry point: `python pipeline_runner.py ingest`. |

---

### `tools/`

LangChain `@tool` decorated functions the agent calls during reasoning.

| File | Description |
|------|-------------|
| `security_tools.py` | All agent tools: `mitre_lookup` (RAG-backed technique details), `generate_test_oneliner` (platform-specific command, no placeholders), `execute_on_vm` (SSH execution), `vm_snapshot`, `restore_vm`, `collect_iocs`, `list_vms`. Exports `get_all_tools()`. |
| `ssh_executor.py` | `SSHPool` — thread-safe paramiko connection pool for the three lab VMs. Auto-reconnects on drop, supports parallel execution across VMs, resolves Tart VM IPs dynamically. `ExecutionResult` dataclass captures stdout/stderr/exit code/timing. |
| `vm_tools.py` | `VMManager` — controls VM lifecycle via `tart` CLI (Linux/macOS) and `utmctl` CLI (Windows). Snapshot = `tart clone`, Restore = stop + delete + re-clone. |
| `ioc_collector.py` | After a technique is executed, queries the VM for evidence (new files, processes, network connections, log entries). Matches against per-technique IOC signatures and returns a 0–1 confidence score. |

---

### `mcp/`

Model Context Protocol server — exposes all tools to external MCP clients.

| File | Description |
|------|-------------|
| `server.py` | Full MCP server using `stdio` transport (matches the client config in `agent.py`). Exposes `search_corpus`, `mitre_lookup`, `list_techniques`, `execute_on_vm`, `vm_snapshot`, `restore_vm`, `collect_iocs`, `list_vms`. Run standalone with `python mcp/server.py`. |

---

### `mitre/`

MITRE ATT&CK graph and multi-step campaign planning.

| File | Description |
|------|-------------|
| `graph.py` | `MITREGraphBuilder` — loads the STIX bundle, parses all techniques, builds a directed graph. Uses the C++ `MITREGraph` if the extension is built, otherwise falls back to networkx. |
| `planner.py` | `MITRECampaignPlanner` — runs A* from a start technique to a goal tactic, applies platform filtering and stealth weighting, returns a `Campaign` object with ordered `TechniqueStep` metadata. Greedy kill-chain fallback if no A* path is found. |

---

### `coevolution/`

GAN-like adversarial co-evolution between offensive and defensive AIs.

| File | Description |
|------|-------------|
| `arena.py` | `CoEvolutionArena` — orchestrates rounds of Red vs Blue. Each round: red attacks → blue detects → scores calculated → training samples generated → ELO updated. After N rounds, both adapters are retrained. Analogous to GAN: red = generator, blue = discriminator. |
| `red_agent.py` | `RedTeamAgent` — wraps `ExploitAgent` with the `red_team` adapter. Executes a list of MITRE techniques on a target VM, collects IOC evidence, and returns an `AttackResult` with a success score. |
| `blue_agent.py` | `BlueTeamAgent` — defensive agent using the `blue_team` adapter. Analyses IOC reports with pattern matching and LLM reasoning to detect which techniques were executed. Generates SIGMA detection rules for confirmed TTPs. |
| `elo.py` | `ELOTracker` — tracks ELO ratings for red and blue teams across generations. Produces the "arms race" thesis graph showing both agents improving over time. Persists to `data/elo_ratings.json`. |

---

### `feedback/`

Self-improving feedback loop and cross-platform transfer evaluation.

| File | Description |
|------|-------------|
| `feedback_loop.py` | `FeedbackLoop` — the core self-improvement cycle: generate command → snapshot VM → execute → collect IOCs → if confident, append to adapter training data → retrain when threshold reached → restore VM. Tracks success rate over iterations to demonstrate learning. |
| `cross_platform.py` | `CrossPlatformExecutor` — runs the same MITRE technique on all three VMs using platform-specific commands, compares IOC confidence across Linux/macOS/Windows. Produces a transfer score showing how well abstract technique knowledge generalises across operating systems. |

---

### `evaluation/`

Benchmarking, statistics, and report generation.

| File | Description |
|------|-------------|
| `secbench.py` | `SecBenchEvaluator` — evaluates the system on multiple-choice security questions. Supports a 4-variant ablation study: baseline (no RAG, no adapter), RAG only, adapter only, and full (adapter + RAG). Ships with 10 built-in questions; loads more from `data/secbench.jsonl` if present. |
| `metrics.py` | Statistical metrics: `pass@k`, paired t-test with Cohen's d and 95% confidence interval, `ioc_detection_rate`, `campaign_success_metrics`, `cross_platform_transfer_score`. |
| `report.py` | Report generation. Rich terminal tables, HTML reports with per-question breakdown, and matplotlib charts: ablation bar chart, ELO history line chart, feedback improvement curve, cross-platform confidence heatmap. |

---

### `adapters/`

LoRA adapter directories, created automatically on first run.

```
adapters/
├── ctf/            # CTF challenge solving (web, pwn, crypto, reverse, forensics)
├── red_team/       # Exploit generation and technique execution
├── blue_team/      # Threat detection and SIGMA rule generation
└── explainer/      # Chain-of-thought security explanations
```

Each directory contains `train.jsonl` (training data in Qwen instruct chat format) and `lora_config.json` (rank=8, alpha=16). New samples are appended automatically by the feedback loop and co-evolution arena. Retrain manually with `python pipeline_runner.py train <name>`.

---

## `cpp_extensions/`

C++ performance extensions compiled as a Python module (`security_cpp`) via pybind11. Falls back gracefully to pure Python if not built.

| File | Description |
|------|-------------|
| `src/mitre_graph.cpp` | `MITREGraph` — directed graph with A* and Dijkstra pathfinding over MITRE ATT&CK techniques. Edge weights encode kill-chain distance and per-technique stealth scores. O((V+E) log V). |
| `src/pattern_matcher.cpp` | `PatternMatcher` — Aho-Corasick automaton for multi-pattern IOC matching. `search_parallel()` distributes texts across `std::thread` workers (one per CPU core), GIL released during parallel work. |
| `src/bindings.cpp` | pybind11 module definition. Exposes `MITREGraph`, `PatternMatcher`, `Match`, `PathResult` to Python with full docstrings. |
| `include/mitre_graph.hpp` | Header: `Technique`, `Edge`, `PathResult` structs and `MITREGraph` class declaration. |
| `include/pattern_matcher.hpp` | Header: `AhoCorasick` automaton and `PatternMatcher` class declaration. |
| `setup.py` | pybind11 setuptools build script. Build: `cd cpp_extensions && pip install -e .` |
| `CMakeLists.txt` | Alternative CMake build. Installs the `.so` directly into `langchain_pipeline/` so it can be imported. |
| `tests/test_cpp.py` | Tests for both extensions: graph construction, A* pathfinding, platform filtering, Aho-Corasick matching, parallel search correctness. Run: `python tests/test_cpp.py`. |

---

## `tart_infra/`

Shell scripts for Linux (Ubuntu) and macOS sandbox VMs using [Tart](https://github.com/cirruslabs/tart). VMs connect via direct IP (resolved with `tart ip`).

| File | Description |
|------|-------------|
| `build_machines.sh` | Pulls base images and creates the `linux-sandbox` and `macos-sandbox` VMs. |
| `setup_ubuntu_vm.sh` | Provisions Ubuntu: installs packages, creates the `test` user, enables SSH, creates a clean snapshot. |
| `setup_macos_vm.sh` | Provisions macOS similarly. |
| `start_machines.sh` | Starts both Tart VMs in headless mode. |
| `stop_machines.sh` | Stops both Tart VMs. |

---

## `utm_infra/`

Shell scripts for the Windows 11 sandbox VM using [UTM](https://mac.getutm.app/). Windows connects via SSH port-forward on `localhost:2222`.

| File | Description |
|------|-------------|
| `build_machines.sh` | Creates the UTM Windows VM. |
| `setup_windows_vm.sh` | Installs OpenSSH, creates the `test` user, configures port-forward. |
| `start_machines.sh` | Starts the UTM VM. |
| `stop_machines.sh` | Stops the UTM VM. |

---

## Generated data directories (not committed)

```
langchain_pipeline/data/
├── chroma/                   # ChromaDB vector store (~15 GB after full ingest)
├── enterprise-attack.json    # MITRE STIX bundle cache
├── nvd-<year>.json           # NVD annual feed caches
├── exploitdb.csv             # ExploitDB CSV cache
├── feedback.jsonl            # Feedback loop execution log
├── elo_ratings.json          # ELO rating history
├── arena_results/            # Per-round co-evolution results (JSONL)
└── cross_platform/           # Cross-platform transfer test results

logs/
└── pipeline.jsonl            # Agent run logs (one JSON record per event)

reports/
├── eval_base.html            # Evaluation report (HTML)
├── ablation_study.json       # Ablation study results
├── ablation.png              # Ablation bar chart
├── elo_history.png           # ELO rating evolution chart
├── feedback_curve.png        # Success rate improvement chart
└── cross_platform_heatmap.png
```
