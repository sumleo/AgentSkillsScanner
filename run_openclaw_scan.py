#!/usr/bin/env python3
"""
Run Claude Code security analysis on openclaw skills.

Uses `claude -p` with the audit prompt to analyze each skill directory,
classifying them as SAFE / SUSPICIOUS / MALICIOUS.

Usage:
    python3 run_openclaw_scan.py [--input openclaw_skills.json] [--workspace workspace_openclaw]
                                 [--skip-download] [--workers 5] [--force]
"""

import argparse
import json
import logging
import os
import re
import subprocess
import shutil
import sys
import time
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

CODE_DIR = Path(__file__).parent / "code"
AUDIT_PROMPT = CODE_DIR / "analyzer" / "prompts" / "audit_prompt.txt"
SKILL_INDICATORS = ["SKILL.md", "skill.json", "api.json", "tool.json"]
OUTPUT_SUFFIX = "_audit.json"


# ---------------------------------------------------------------------------
# Step 1: Build repo mapping from openclaw_skills.json
# ---------------------------------------------------------------------------
def build_repo_mapping(skills: list[dict]) -> list[dict]:
    """Group skills by GitHub repo and produce a download mapping."""
    repo_groups: dict[str, list[dict]] = defaultdict(list)

    for skill in skills:
        url = skill.get("url", "")
        if "github.com" not in url:
            continue

        path = url.split("github.com/")[-1]
        parts = path.split("/")
        if len(parts) < 2:
            continue
        repo = f"{parts[0]}/{parts[1]}"

        branch = "main"
        if "/tree/" in path:
            branch = path.split("/tree/")[1].split("/")[0]

        repo_groups[repo].append({
            "name": skill.get("name", ""),
            "branch": branch,
        })

    mapping = []
    for idx, (repo, repo_skills) in enumerate(repo_groups.items()):
        branch = repo_skills[0]["branch"]
        mapping.append({
            "repo_id": f"openclaw_{idx}",
            "repo": repo,
            "download_url": f"https://github.com/{repo}/archive/{branch}.zip",
            "branch": branch,
            "total_skills": len(repo_skills),
        })

    return mapping


# ---------------------------------------------------------------------------
# Step 2: Download repos
# ---------------------------------------------------------------------------
def download_repo(entry: dict, zip_dir: Path, timeout: int = 300, retries: int = 3) -> tuple[bool, str]:
    repo_id = entry["repo_id"]
    zip_path = zip_dir / f"{repo_id}.zip"

    if zip_path.exists() and zip_path.stat().st_size > 0:
        return True, f"{repo_id}: already exists"

    token = os.environ.get("GITHUB_TOKEN", "")
    cmd = ["curl", "-L", "-o", str(zip_path), "-s", "--max-time", str(timeout)]
    if token:
        cmd += ["-H", f"Authorization: token {token}"]
    cmd.append(entry["download_url"])

    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
            if result.returncode == 0 and zip_path.exists() and zip_path.stat().st_size > 0:
                size_mb = zip_path.stat().st_size / 1024 / 1024
                return True, f"{repo_id}: downloaded ({size_mb:.1f} MB)"
            else:
                zip_path.unlink(missing_ok=True)
        except Exception as e:
            zip_path.unlink(missing_ok=True)
            if attempt == retries:
                return False, f"{repo_id}: {e}"

        if attempt < retries:
            delay = 2 ** attempt
            logger.warning(f"  {repo_id}: attempt {attempt}/{retries} failed, retrying in {delay}s...")
            time.sleep(delay)

    return False, f"{repo_id}: download failed after {retries} attempts"


def download_all(mapping: list[dict], zip_dir: Path, workers: int = 5):
    zip_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Downloading {len(mapping)} repos → {zip_dir} (workers={workers})")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(download_repo, entry, zip_dir): entry for entry in mapping}
        for future in as_completed(futures):
            ok, msg = future.result()
            status = "OK" if ok else "FAIL"
            logger.info(f"  [{status}] {msg}")


# ---------------------------------------------------------------------------
# Step 3: Extract
# ---------------------------------------------------------------------------
def extract_zip(zip_path: Path, repo_dir: Path) -> Path | None:
    repo_id = zip_path.stem
    target = repo_dir / repo_id

    if target.exists() and any(target.iterdir()):
        return target

    tmp = repo_dir / f"_tmp_{repo_id}"
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmp)

        items = list(tmp.iterdir())
        source = items[0] if len(items) == 1 else tmp
        shutil.move(str(source), str(target))
        shutil.rmtree(tmp, ignore_errors=True)
        return target
    except Exception as e:
        logger.error(f"Extract failed {zip_path.name}: {e}")
        shutil.rmtree(tmp, ignore_errors=True)
        return None


def find_skill_dirs(repo_path: Path) -> list[Path]:
    return [
        p for p in repo_path.rglob("*")
        if p.is_dir() and any((p / f).exists() for f in SKILL_INDICATORS)
    ]


# ---------------------------------------------------------------------------
# Step 4: Claude Code analysis
# ---------------------------------------------------------------------------
def _extract_json(raw: str) -> dict | None:
    """Extract audit JSON from Claude Code output (handles wrapper + markdown)."""
    try:
        # Claude --output-format json wraps in {"result": "..."}
        start = raw.find("{")
        if start == -1:
            return None
        wrapper = json.loads(raw[start:])
        inner = wrapper.get("result", raw[start:]) if isinstance(wrapper, dict) else raw[start:]
    except json.JSONDecodeError:
        inner = raw

    # Try markdown code block first
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", inner, re.DOTALL | re.IGNORECASE)
    if m:
        candidate = m.group(1)
    else:
        # Greedy brace match
        s = inner.find("{")
        e = inner.rfind("}")
        if s != -1 and e != -1:
            candidate = inner[s:e + 1]
        else:
            return None

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def analyze_skill(skill_dir: Path, repo_id: str, results_dir: Path,
                  prompt_text: str, timeout: int = 120, retries: int = 3) -> str:
    """Analyze a single skill with claude -p. Returns status string."""
    skill_name = skill_dir.name
    filename = f"{repo_id}_{skill_name}{OUTPUT_SUFFIX}"

    # Skip if already analyzed
    for category in ["SAFE", "SUSPICIOUS", "MALICIOUS", "ERROR"]:
        if (results_dir / category / filename).exists():
            return f"SKIP|{repo_id}|{skill_name}|EXISTS"

    cmd = [
        "claude", "-p",
        "--output-format", "json",
        "--append-system-prompt", prompt_text,
        f"Analyze Skill Directory: {skill_dir}",
    ]

    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                stdin=subprocess.DEVNULL,
            )

            if result.returncode != 0 or not result.stdout.strip():
                if attempt < retries:
                    delay = 2 ** attempt
                    logger.warning(f"  {repo_id}/{skill_name}: attempt {attempt}/{retries} failed (rc={result.returncode}), retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                # Save raw error
                err_path = results_dir / "ERROR" / f"{filename}.api_fail"
                err_path.write_text(result.stderr or result.stdout or "empty response")
                return f"ERROR|{repo_id}|{skill_name}|API_FAIL"

            report = _extract_json(result.stdout)
            if not report:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                err_path = results_dir / "ERROR" / f"{filename}.parse_err"
                err_path.write_text(result.stdout)
                return f"ERROR|{repo_id}|{skill_name}|INVALID_JSON"

            # Determine classification
            status = (
                report.get("audit_summary", {})
                .get("intent_alignment_status", "")
                .strip()
                .upper()
            )

            if status in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
                out_path = results_dir / status / filename
                out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
                return f"DONE|{repo_id}|{skill_name}|{status}"
            else:
                err_path = results_dir / "ERROR" / f"{filename}.status_missing"
                err_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
                return f"ERROR|{repo_id}|{skill_name}|STATUS_MISSING"

        except subprocess.TimeoutExpired:
            if attempt < retries:
                logger.warning(f"  {repo_id}/{skill_name}: timeout (attempt {attempt}/{retries}), retrying...")
                continue
            return f"ERROR|{repo_id}|{skill_name}|TIMEOUT"
        except Exception as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            return f"ERROR|{repo_id}|{skill_name}|{e}"

    return f"ERROR|{repo_id}|{skill_name}|EXHAUSTED_RETRIES"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Run Claude Code security analysis on openclaw skills")
    parser.add_argument("--input", default="openclaw_skills.json", help="Input skills JSON")
    parser.add_argument("--workspace", default="workspace_openclaw", help="Workspace directory")
    parser.add_argument("--skip-download", action="store_true", help="Skip download step")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent analysis workers")
    parser.add_argument("--timeout", type=int, default=120, help="Per-skill analysis timeout (seconds)")
    parser.add_argument("--retries", type=int, default=3, help="Retry attempts per skill")
    parser.add_argument("--force", action="store_true", help="Re-analyze even if result exists")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of skills to analyze (0=all)")
    args = parser.parse_args()

    input_path = Path(args.input)
    workspace = Path(args.workspace)
    zip_dir = workspace / "zip"
    repo_dir = workspace / "repo"
    results_dir = workspace / "results"

    # Verify audit prompt exists
    if not AUDIT_PROMPT.exists():
        logger.error(f"Audit prompt not found: {AUDIT_PROMPT}")
        sys.exit(1)
    prompt_text = AUDIT_PROMPT.read_text()

    # Verify claude CLI is available
    if shutil.which("claude") is None:
        logger.error("claude CLI not found in PATH")
        sys.exit(1)

    # Load skills
    logger.info(f"Loading skills from {input_path}")
    with open(input_path) as f:
        skills = json.load(f)
    logger.info(f"Loaded {len(skills)} openclaw skills")

    # Step 1: Build mapping
    mapping = build_repo_mapping(skills)
    logger.info(f"Mapped to {len(mapping)} unique repos:")
    for m in mapping:
        logger.info(f"  {m['repo']} ({m['total_skills']} skills)")

    workspace.mkdir(parents=True, exist_ok=True)
    with open(workspace / "repo_mapping.json", "w") as f:
        json.dump(mapping, f, indent=2)

    # Step 2: Download
    if not args.skip_download:
        download_all(mapping, zip_dir, workers=args.workers)
    else:
        logger.info("Skipping download (--skip-download)")

    # Step 3: Extract all repos and collect skill dirs
    logger.info("=" * 50)
    logger.info("Extracting repos and discovering skills...")
    logger.info("=" * 50)

    zip_files = sorted(zip_dir.glob("*.zip"))
    if not zip_files:
        logger.error(f"No ZIP files found in {zip_dir}")
        sys.exit(1)

    all_skills: list[tuple[Path, str]] = []  # (skill_dir, repo_id)
    for zf in zip_files:
        repo_id = zf.stem
        repo_path = extract_zip(zf, repo_dir)
        if not repo_path:
            continue
        for sd in find_skill_dirs(repo_path):
            all_skills.append((sd, repo_id))

    logger.info(f"Found {len(all_skills)} total skill directories")

    # Step 4: Analyze with Claude Code
    for category in ["SAFE", "SUSPICIOUS", "MALICIOUS", "ERROR"]:
        (results_dir / category).mkdir(parents=True, exist_ok=True)

    # If --force, clear existing results for these skills
    if args.force:
        logger.info("--force: will re-analyze all skills")
        for category in ["SAFE", "SUSPICIOUS", "MALICIOUS", "ERROR"]:
            for f in (results_dir / category).iterdir():
                f.unlink()

    # Apply limit
    tasks = all_skills
    if args.limit > 0:
        tasks = all_skills[:args.limit]
        logger.info(f"Limiting to first {args.limit} skills")

    total = len(tasks)
    logger.info("=" * 50)
    logger.info(f"Starting Claude Code analysis: {total} skills (workers={args.workers})")
    logger.info("=" * 50)

    summary = defaultdict(int)
    processed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                analyze_skill, sd, repo_id, results_dir,
                prompt_text, args.timeout, args.retries,
            ): (sd, repo_id)
            for sd, repo_id in tasks
        }

        for future in as_completed(futures):
            sd, repo_id = futures[future]
            processed += 1
            try:
                result_line = future.result()
            except Exception as e:
                result_line = f"ERROR|{repo_id}|{sd.name}|{e}"

            parts = result_line.split("|")
            status = parts[0] if parts else "ERROR"
            verdict = parts[3] if len(parts) > 3 else "UNKNOWN"

            if status == "DONE":
                summary[verdict] += 1
                level = {"SAFE": "INFO", "SUSPICIOUS": "WARNING", "MALICIOUS": "WARNING"}.get(verdict, "INFO")
                getattr(logger, level.lower())(
                    f"  [{processed}/{total}] {repo_id}/{sd.name} → [{verdict}]"
                )
            elif status == "SKIP":
                summary["SKIPPED"] += 1
                logger.info(f"  [{processed}/{total}] {repo_id}/{sd.name} → [SKIPPED]")
            else:
                summary["ERROR"] += 1
                logger.error(f"  [{processed}/{total}] {repo_id}/{sd.name} → [ERROR: {verdict}]")

    # Print summary
    logger.info("=" * 50)
    logger.info("Analysis Summary")
    logger.info("=" * 50)
    for label in ["SAFE", "SUSPICIOUS", "MALICIOUS", "ERROR", "SKIPPED"]:
        if summary[label]:
            logger.info(f"  {label}: {summary[label]}")
    logger.info(f"Results saved to: {results_dir}/")


if __name__ == "__main__":
    main()
