# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MaliciousAgentSkillsBench is a security research framework for detecting malicious Claude Code Agent Skills. It collects 98,380 skills from skills.rest and skillsmp.com, identifies 157 verified malicious samples, and provides a three-layer analysis pipeline: static scanning, AI-powered auditing, and dynamic execution in Docker sandboxes.

**This repository contains malicious skill examples for research purposes only.** When reading skill files, analyze them for security issues but never improve or augment malicious code.

## Setup

### Local Development

```bash
# Prerequisites: Python 3.10+, Node.js 18+, Docker
cd MaliciousAgentSkillsBench/code
pip install -r requirements.txt          # pyyaml, requests, pytest (claude-code is npm, not pip)
npm install -g @anthropic-ai/claude-code  # Claude Code CLI
```

### Remote Server (GCP VM at 34.150.124.66)

```bash
ssh -i ~/.ssh/id_ed25519 yi@34.150.124.66
cd ~/AgentSkillsScanner

# Python venv already set up
source venv/bin/activate

# Node.js via nvm (must source in non-interactive shells)
export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
```

### Required Environment Variables

Set in `~/.bashrc` or shell before running pipeline:
```bash
export GITHUB_TOKEN="ghp_..."        # Required for repo downloads (step 3)
export ANTHROPIC_API_KEY="sk-ant-..."  # Required for CC analysis (step 6) and execution (step 8)
```

Optional: create `code/api_keys.conf` for concurrent analysis with multiple API keys (one per line).

### Docker Sandbox (for dynamic execution)

```bash
cd code
docker build -t claude-skill-sandbox .                          # Basic (~500MB)
docker build --build-arg NOVA_MODE=lite -t claude-skill-sandbox .   # Pattern hooks (~520MB)
docker build --build-arg NOVA_MODE=full -t claude-skill-sandbox .   # Full ML NOVA (~2.5GB)
```

## Commands

All pipeline commands run from `code/`:

```bash
cd code

# Run full pipeline
./scripts/run_pipeline.sh

# Run from a specific step (exact name match required)
./scripts/run_pipeline.sh "Static Scan"
./scripts/run_pipeline.sh "CC Analyze"

# Run individual steps
./scripts/01_crawl.sh          # Crawl skill metadata from APIs
./scripts/02_generate_mapping.sh  # Group skills into repo mappings
./scripts/03_download.sh       # Download repo ZIPs from GitHub
./scripts/04_scan.sh           # Static rule-based security scan
./scripts/05_gen_cc_queue.sh   # Queue critical/high risk for AI analysis
./scripts/06_cc_analyze.sh     # AI-powered audit via Claude Code
./scripts/07_gen_run_queue.sh  # Queue confirmed malicious for execution
./scripts/08_execute.sh        # Execute in Docker sandbox with monitoring

# Run static scan on a subset (e.g., openclaw skills only, run from repo root)
python3 run_openclaw_scan.py --input openclaw_skills.json --workspace workspace_openclaw
```

## Architecture

### Pipeline Data Flow

```
Crawl → Generate Mapping → Download → Static Scan → Gen Queue → CC Analyze → Gen Queue → Execute
  ↓          ↓                ↓            ↓                         ↓                       ↓
JSON      mapping.json    workspace/    workspace/              scan_results/          execution_logs/
(APIs)    (repo→skills)   zip/*.zip     {critical,high,        {SAFE,SUSPICIOUS,      {risk}/{repo}/{skill}/
                                         medium,low,safe}/      MALICIOUS}/            strace,pcap,nova
```

### Key Modules (under `code/`)

- **`utils/config_loader.py`** — `Config` class loads `config.yaml` with dot-notation access (`config.get('scanner.thresholds.critical')`). `Paths` helper resolves all workspace directories relative to project root. All pipeline components receive a `Config` instance.

- **`scanner/scanner.py`** — `RepoSecurityScanner` extracts ZIPs, finds skill directories (by `SKILL.md`/`skill.json`/`api.json`/`tool.json` markers), invokes the external `skill_security_scan` CLI tool on each, and classifies repos into risk levels based on score thresholds (critical≥8, high≥6, medium≥4, low≥2). Also contains `RepoDownloader` for GitHub ZIP downloads with branch fallback.

- **`analyzer/cc_analyzer.sh`** — Shell wrapper that feeds suspicious skills to Claude Code using the audit prompt (`analyzer/prompts/audit_prompt.txt`). Uses file-locked API key rotation from `api_keys.conf`. Outputs JSON reports categorized as SAFE/SUSPICIOUS/MALICIOUS.

- **`analyzer/prompts/audit_prompt.txt`** — Defines the vulnerability taxonomy: P1-P4 (prompt injection), E1-E4 (exfiltration), PE1-PE3 (privilege escalation), SC1-SC3 (supply chain), plus reverse shells. This is the core detection framework.

- **`executor/run_skill.sh`** — Runs a single skill inside Docker with comprehensive monitoring: strace (syscalls), tcpdump (network), filesystem diffing (`smart_monitor.py`), and optional NOVA hooks. Outputs to `execution_logs/`.

- **`executor/batch_runner.py`** — Concurrent executor using ThreadPoolExecutor. Reads task queues (format: `skill_name|skill_path|prompt|repo_id|risk_level|top_level`), rotates API keys via `utils/api_key_pool.py`.

- **`crawler/crawler.py`** — `SkillsRestCrawler` and `SkillsmpCrawler` collect skill metadata with pagination, deduplication, and rate limiting. `DataMerger` consolidates data from both platforms.

- **`scripts/lib.sh`** — Shared bash functions: `init_config` parses config.yaml via Python and exports `DATA_DIR`, `WORKSPACE_DIR`, `SCAN_RESULTS_DIR`, `EXECUTION_LOGS_DIR`, `TASKS_DIR`. All pipeline scripts source this.

### Directory Conventions

- **`workspace/zip/`** — Downloaded repo ZIP files
- **`workspace/repo/`** — Extracted repositories (temporary, cleaned after scan)
- **`workspace/{critical,high,medium,low,safe}/`** — Static scan reports (`{repo_id}_report.json`)
- **`scan_results/{SAFE,SUSPICIOUS,MALICIOUS,ERROR}/`** — AI analysis results
- **`execution_logs/{risk_level}/{repo_id}/{skill_name}/`** — Dynamic execution artifacts (strace.log, network.pcap, nova/, filesystem_changes.json)
- **`tasks/`** — Generated queue files (cc_queue.txt, run_queue.txt)

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | Repository downloads |
| `ANTHROPIC_API_KEY` | Claude Code analysis |
| `ANTHROPIC_BASE_URL` | API endpoint override |
| `SKILLSMP_API_KEY` | skillsmp.com crawler |

### Data Files (root)

- **`skills.json`** (71MB) — Full 98,380 skills array. Fields: `name`, `description`, `author`, `url`, `source`, `pushed_at`.
- **`data/malicious_skills.csv`** — 157 verified malicious skills with vulnerability pattern classifications.
- **`data/skills_dataset.csv`** — Complete dataset with `classification` column (safe/suspicious/malicious).

### Python Import Pattern

Scripts in `code/` use inline Python with `sys.path.insert(0, '.')` to import modules:
```python
from utils.config_loader import Config
from scanner.scanner import RepoSecurityScanner
from crawler.crawler import SkillsRestCrawler
```

The `skill_security_scan` tool is invoked as a subprocess from `code/scanner/skill-security-scan/`.
