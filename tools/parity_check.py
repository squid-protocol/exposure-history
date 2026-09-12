#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Incremental-vs-full parity audit (gitgalaxy#2982 phase P).

For each event pair: full-scan the parent into a scratch DB, run the engine's
shipped `--incremental` mode for the child against that DB (the scratch DB
holds ONLY the parent, so StateRehydrator's latest-by-date baseline IS the
parent — the workaround that makes this audit runnable against unmodified
engine main while gitgalaxy#2983 adds explicit selection), then full-scan the
child independently and row-diff the two child snapshots across the full risk
vector and context columns.

Full-scan determinism is already proven (identical rows across independent
scans), so any divergence found here is attributable to the incremental path:
either rehydration fidelity or the surgical-parse/ripple boundary.

    python tools/parity_check.py --events events/curl.json --pairs 5
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sqlite3
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DBS_DIR, GALAXYSCOPE_BIN, SCAN_ENV  # noqa: E402
from exposure_delta import CONTEXT_COLS, RISK_COLS  # noqa: E402
from scan_pair import resolve_repo  # noqa: E402

COMPARE_COLS = ["file_path"] + RISK_COLS + CONTEXT_COLS


def _run(cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, env=SCAN_ENV, check=check,
                          capture_output=True, text=True)


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def scan_at(repo: pathlib.Path, sha: str, out_dir: pathlib.Path, extra=()) -> pathlib.Path:
    """Full or incremental scan of `sha` via a detached worktree; returns the DB."""
    wt = out_dir / "wt" / repo.name  # basename == repo name == repo_name key
    wt.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
                   capture_output=True)
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), sha],
                   check=True, capture_output=True)
    try:
        _run([GALAXYSCOPE_BIN, str(wt), "--db-only", *extra], cwd=out_dir)
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
                       capture_output=True)
    dbs = sorted(p for p in out_dir.rglob("*.db"))
    if not dbs:
        sys.exit(f"no DB produced in {out_dir}")
    return dbs[0]


def rows(db: pathlib.Path, sha: str) -> dict[str, tuple]:
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    out = {}
    for r in con.execute(
        f"SELECT {', '.join(COMPARE_COLS)} FROM file_data WHERE commit_hash = ?", (sha,)
    ):
        out[r["file_path"]] = tuple(r[c] for c in COMPARE_COLS[1:])
    con.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True)
    ap.add_argument("--pairs", type=int, default=5)
    ap.add_argument("--keep", action="store_true", help="keep scratch dirs")
    args = ap.parse_args()

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    fixes = [e for e in data["events"] if e["class"] == "security-fix"][: args.pairs]

    verdicts = []
    for e in fixes:
        child = _git(repo, "rev-parse", e["sha"])
        parent = _git(repo, "rev-parse", f"{child}^")
        scratch = DBS_DIR / "parity" / child[:12]
        inc_dir, full_dir = scratch / "inc", scratch / "full"
        for d in (inc_dir, full_dir):
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True)

        # Leg 1: full parent, then the SHIPPED incremental mode for the child.
        db_inc = scan_at(repo, parent, inc_dir)
        scan_at(repo, child, inc_dir, extra=("--incremental", str(db_inc)))
        # Leg 2: independent full scan of the child.
        db_full = scan_at(repo, child, full_dir)

        a, b = rows(db_inc, child), rows(db_full, child)
        only_inc = sorted(set(a) - set(b))
        only_full = sorted(set(b) - set(a))
        diff = sorted(p for p in set(a) & set(b) if a[p] != b[p])
        ok = not (only_inc or only_full or diff)
        verdicts.append(ok)
        print(f"{e['id']:28s} {child[:12]}  files inc={len(a)} full={len(b)}  "
              f"{'PARITY' if ok else 'DIVERGENT'}", flush=True)
        if not ok:
            for p in only_inc[:5]:
                print(f"   only-incremental: {p}")
            for p in only_full[:5]:
                print(f"   only-full: {p}")
            for p in diff[:5]:
                cols = [c for c, x, y in zip(COMPARE_COLS[1:], a[p], b[p]) if x != y]
                print(f"   differs: {p} -> {cols[:8]}")
        if not args.keep:
            shutil.rmtree(scratch)

    n_ok = sum(verdicts)
    print(f"\nparity: {n_ok}/{len(verdicts)} pairs identical")
    return 0 if n_ok == len(verdicts) else 1


if __name__ == "__main__":
    sys.exit(main())
