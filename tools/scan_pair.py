#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Scan a (parent, child) commit pair into one per-repo history database.

The rung-6 harness primitive (gitgalaxy#2982). For each commit: a detached
git worktree (the engine repo's scope_check.py shape), a REAL `galaxyscope
<worktree> --db-only` run with cwd at the repo's accumulating output dir, and
the worktree removed. The engine's own schema does the bookkeeping: file_data
rows are keyed (repo_name, commit_hash) with UNIQUE on repo_data, so a re-run
of an already-scanned commit is skipped here and would be an idempotent
per-commit rewrite even if it weren't.

Scans run with GITGALAXY_DISABLE_GIT_HISTORY=1 (tools/_engine.py SCAN_ENV):
the temporal ablation is the design, not an option -- see the epic's guard 1.

Usage:
    python tools/scan_pair.py --repo curl --sha <event-sha>          # parent^ + sha
    python tools/scan_pair.py --repo curl --commit <sha>             # one commit
    python tools/scan_pair.py --repo curl --sha <sha> --dry-run
"""
from __future__ import annotations

import argparse
import pathlib
import sqlite3
import subprocess
import sys

from _engine import DBS_DIR, GALAXYSCOPE_BIN, POOL_DIR, SCAN_ENV


def _run(cmd, cwd=None, env=None, check=True):
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, capture_output=True, text=True)


def resolve_repo(name_or_path: str) -> pathlib.Path:
    p = pathlib.Path(name_or_path)
    if p.exists():
        return p.resolve()
    pool = POOL_DIR / name_or_path
    if pool.exists():
        return pool.resolve()
    sys.exit(f"repo not found: {name_or_path} (looked in {POOL_DIR})")


def out_dir_for(repo: pathlib.Path) -> pathlib.Path:
    d = DBS_DIR / f"{repo.name}_out"
    d.mkdir(parents=True, exist_ok=True)
    return d


def history_db(out_dir: pathlib.Path) -> pathlib.Path | None:
    dbs = sorted(out_dir.rglob("*.db"))
    return dbs[0] if dbs else None


def already_scanned(out_dir: pathlib.Path, sha: str) -> bool:
    db = history_db(out_dir)
    if db is None:
        return False
    con = sqlite3.connect(db)
    try:
        n = con.execute(
            "SELECT COUNT(*) FROM repo_data WHERE commit_hash = ?", (sha,)
        ).fetchone()[0]
        return n > 0
    except sqlite3.OperationalError:
        return False
    finally:
        con.close()


def scan_commit(repo: pathlib.Path, sha: str, out_dir: pathlib.Path) -> str:
    """Worktree at `sha` (named exactly like the repo so repo_name is stable),
    scan into out_dir's accumulating DB, remove the worktree. Returns status."""
    if already_scanned(out_dir, sha):
        return "skip (already in DB)"
    scratch = out_dir / "worktrees"
    scratch.mkdir(exist_ok=True)
    wt = scratch / repo.name  # basename == repo name == engine's repo_name key
    if wt.exists():
        _run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)], check=False)
    _run(["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), sha])
    try:
        res = _run([GALAXYSCOPE_BIN, str(wt), "--db-only"], cwd=out_dir, env=SCAN_ENV)
        if res.returncode != 0:
            return f"SCAN FAILED: {res.stderr[-400:]}"
    finally:
        _run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)], check=False)
        _run(["git", "-C", str(repo), "worktree", "prune"], check=False)
    # Post-condition: the DB now carries this commit's rows.
    if not already_scanned(out_dir, sha):
        return "SCAN COMPLETED BUT COMMIT NOT IN DB — investigate repo_name/db accumulation"
    return "scanned"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, help="pool repo name or path")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sha", help="event commit; scans first-parent AND the commit")
    g.add_argument("--commit", help="scan exactly one commit")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repo = resolve_repo(args.repo)
    out_dir = out_dir_for(repo)

    if args.commit:
        shas = [_run(["git", "-C", str(repo), "rev-parse", args.commit]).stdout.strip()]
    else:
        child = _run(["git", "-C", str(repo), "rev-parse", args.sha]).stdout.strip()
        parent = _run(["git", "-C", str(repo), "rev-parse", f"{child}^"]).stdout.strip()
        shas = [parent, child]

    for sha in shas:
        if args.dry_run:
            state = "already in DB" if already_scanned(out_dir, sha) else "would scan"
            print(f"{sha[:12]}  {state}")
            continue
        print(f"{sha[:12]}  {scan_commit(repo, sha, out_dir)}", flush=True)
    db = history_db(out_dir)
    if db:
        print(f"db: {db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
