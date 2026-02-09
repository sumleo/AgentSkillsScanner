#!/usr/bin/env python3
"""
Run the static security scanner on openclaw skills only.

Usage:
    python3 run_openclaw_scan.py [--input openclaw_skills.json] [--workspace workspace_openclaw]
                                 [--skip-download] [--workers 5]
"""

import argparse
import json
import logging
import os
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

        # Extract owner/repo from URL like
        #   https://github.com/openclaw/skills/tree/main/skills/foo/bar
        path = url.split("github.com/")[-1]
        parts = path.split("/")
        if len(parts) < 2:
            continue
        repo = f"{parts[0]}/{parts[1]}"

        # Detect branch (between /tree/<branch>/)
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
# Step 3: Extract + scan
# ---------------------------------------------------------------------------
SKILL_INDICATORS = ["SKILL.md", "skill.json", "api.json", "tool.json"]

THRESHOLDS = {"critical": 8, "high": 6, "medium": 4, "low": 2}


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


def scan_skill_dir(skill_dir: Path, timeout: int = 60, retries: int = 2) -> dict | None:
    """Run skill_security_scan on a single skill directory."""
    import tempfile

    scan_tool_dir = CODE_DIR / "scanner" / "skill-security-scan"
    if not scan_tool_dir.exists():
        logger.error(f"Scan tool not found at {scan_tool_dir}")
        return None

    for attempt in range(1, retries + 1):
        fd, out_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        cmd = [
            sys.executable, "-m", "skill_security_scan.src.cli",
            "scan", str(skill_dir),
            "--format", "json",
            "--output", out_file,
            "--no-color",
        ]

        try:
            subprocess.run(
                cmd, cwd=str(scan_tool_dir),
                capture_output=True, text=True, timeout=timeout,
            )
            if Path(out_file).exists():
                with open(out_file) as f:
                    report = json.load(f)
                os.remove(out_file)
                return report
        except subprocess.TimeoutExpired:
            logger.warning(f"Scan timeout: {skill_dir.name} (attempt {attempt}/{retries})")
        except Exception as e:
            logger.warning(f"Scan error {skill_dir.name}: {e} (attempt {attempt}/{retries})")
        finally:
            Path(out_file).unlink(missing_ok=True)

        if attempt < retries:
            time.sleep(1)

    return None


def risk_label(score: float) -> str:
    if score >= THRESHOLDS["critical"]:
        return "CRITICAL"
    if score >= THRESHOLDS["high"]:
        return "HIGH"
    if score >= THRESHOLDS["medium"]:
        return "MEDIUM"
    if score >= THRESHOLDS["low"]:
        return "LOW"
    return "SAFE"


def _find_existing_report(repo_id: str, results_dir: Path) -> Path | None:
    """Check if a scan report already exists for this repo in any risk dir."""
    for risk in ["critical", "high", "medium", "low", "safe"]:
        report_path = results_dir / risk / f"{repo_id}_report.json"
        if report_path.exists():
            return report_path
    return None


def scan_repo(zip_path: Path, repo_dir: Path, results_dir: Path, timeout: int = 60):
    """Extract, find skills, scan, and write report."""
    repo_id = zip_path.stem

    # Skip if report already exists
    existing = _find_existing_report(repo_id, results_dir)
    if existing:
        risk = existing.parent.name.upper()
        logger.info(f"  [{repo_id}] Skipping — report already exists ({risk})")
        return "skipped_existing", risk, 0

    repo_path = extract_zip(zip_path, repo_dir)
    if not repo_path:
        return "failed", "UNKNOWN", 0

    skill_dirs = find_skill_dirs(repo_path)
    if not skill_dirs:
        logger.info(f"  [{repo_id}] No skill dirs found")
        return "skipped", "UNKNOWN", 0

    logger.info(f"  [{repo_id}] Found {len(skill_dirs)} skill dirs, scanning...")

    skill_reports = []
    for sd in skill_dirs:
        report = scan_skill_dir(sd, timeout=timeout)
        if report:
            skill_reports.append(report)

    if not skill_reports:
        return "scanned", "SAFE", len(skill_dirs)

    # Determine worst risk
    worst = "SAFE"
    priority = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "SAFE": 1}
    risk_counts = defaultdict(int)
    total_issues = 0

    for r in skill_reports:
        rl = risk_label(r.get("risk_score", 0))
        risk_counts[rl] += 1
        total_issues += len(r.get("findings", []))
        if priority.get(rl, 0) > priority.get(worst, 0):
            worst = rl

    # Save report
    from datetime import datetime

    report = {
        "repo_id": repo_id,
        "scan_timestamp": datetime.now().isoformat(),
        "risk_level": worst,
        "total_skills": len(skill_dirs),
        "scanned_skills": len(skill_reports),
        "total_issues": total_issues,
        "risk_counts": dict(risk_counts),
        "skills_reports": skill_reports,
    }

    out_dir = results_dir / worst.lower()
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / f"{repo_id}_report.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return "scanned", worst, len(skill_dirs)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Run static scan on openclaw skills only")
    parser.add_argument("--input", default="openclaw_skills.json", help="Input skills JSON")
    parser.add_argument("--workspace", default="workspace_openclaw", help="Workspace directory")
    parser.add_argument("--skip-download", action="store_true", help="Skip download step")
    parser.add_argument("--workers", type=int, default=5, help="Scanner workers")
    parser.add_argument("--timeout", type=int, default=60, help="Per-skill scan timeout")
    parser.add_argument("--retries", type=int, default=3, help="Download retry attempts")
    parser.add_argument("--force", action="store_true", help="Re-scan even if report exists")
    args = parser.parse_args()

    input_path = Path(args.input)
    workspace = Path(args.workspace)
    zip_dir = workspace / "zip"
    repo_dir = workspace / "repo"
    results_dir = workspace / "results"

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

    # Save mapping for reference
    workspace.mkdir(parents=True, exist_ok=True)
    with open(workspace / "repo_mapping.json", "w") as f:
        json.dump(mapping, f, indent=2)

    # Step 2: Download
    if not args.skip_download:
        download_all(mapping, zip_dir, workers=args.workers)
    else:
        logger.info("Skipping download (--skip-download)")

    # Step 3: Scan
    logger.info("=" * 50)
    logger.info(f"Starting static security scan (workers={args.workers})")
    logger.info("=" * 50)

    for risk in ["critical", "high", "medium", "low", "safe"]:
        (results_dir / risk).mkdir(parents=True, exist_ok=True)

    zip_files = sorted(zip_dir.glob("*.zip"))
    if not zip_files:
        logger.error(f"No ZIP files found in {zip_dir}")
        sys.exit(1)

    # If --force, remove existing reports so they get re-scanned
    if args.force:
        logger.info("--force: will re-scan all repos regardless of existing reports")

    summary = defaultdict(int)

    def _scan_one(zf: Path) -> tuple[str, str, int]:
        if args.force:
            # Remove existing report so scan_repo won't skip it
            existing = _find_existing_report(zf.stem, results_dir)
            if existing:
                existing.unlink()
        return scan_repo(zf, repo_dir, results_dir, timeout=args.timeout)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_scan_one, zf): zf for zf in zip_files}
        for future in as_completed(futures):
            zf = futures[future]
            try:
                status, risk, skill_count = future.result()
            except Exception as e:
                status, risk, skill_count = "error", "UNKNOWN", 0
                logger.error(f"  [{zf.stem}] exception: {e}")
            summary[risk] += 1
            logger.info(f"  [{zf.stem}] {status} → {risk} ({skill_count} skills)")

    # Print summary
    logger.info("=" * 50)
    logger.info("Scan Summary")
    logger.info("=" * 50)
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]:
        if summary[risk]:
            logger.info(f"  {risk}: {summary[risk]} repos")
    logger.info(f"Reports saved to: {results_dir}/")


if __name__ == "__main__":
    main()
