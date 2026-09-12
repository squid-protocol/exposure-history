#!/usr/bin/env python3
# ==============================================================================
# exposure-history
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Per-file exposure deltas between two scanned commits of one repo.

Joins file_data across the two commit_hash row-sets on file_path, with rename
remapping from `git diff --name-status -M parent..child` (guard 3 of
gitgalaxy#2982: an R-entry's old path is looked up for "before", its new path
for "after", and the record carries both). Every file is tagged with its diff
status -- touched (M/R), added, deleted, untouched -- because the hypotheses
read TOUCHED files and the controls need the rest.

Output: one JSON record on stdout (or --out), the validation.md harness shape:
commit SHA, parent, per-file exposure before/after/delta for the full risk
vector and the structural subset, plus file identity and diff status.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import subprocess
import sys

from _engine import RISK_VECTOR, STRUCTURAL_COLUMNS, TEMPORAL_COLUMNS

RISK_COLS = [f"risk_{c}" for c in RISK_VECTOR]
CONTEXT_COLS = ["total_loc", "coding_loc", "function_count", "class_count"]


def rows_for(con: sqlite3.Connection, sha: str) -> dict[str, sqlite3.Row]:
    cur = con.execute(
        f"SELECT file_path, {', '.join(RISK_COLS + CONTEXT_COLS)} "
        "FROM file_data WHERE commit_hash = ?",
        (sha,),
    )
    return {r["file_path"]: r for r in cur.fetchall()}


def diff_statuses(repo: pathlib.Path, parent: str, child: str) -> dict[str, dict]:
    """{child_path: {status, old_path}} from a rename-aware name-status diff."""
    out = subprocess.run(
        ["git", "-C", str(repo), "diff", "--name-status", "-M", f"{parent}..{child}"],
        capture_output=True, text=True, check=True,
    ).stdout
    result: dict[str, dict] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        code = parts[0]
        if code.startswith("R") and len(parts) == 3:
            result[parts[2]] = {"status": "touched", "old_path": parts[1], "renamed": True}
        elif code == "A":
            result[parts[1]] = {"status": "added", "old_path": None, "renamed": False}
        elif code == "D":
            result[parts[1]] = {"status": "deleted", "old_path": parts[1], "renamed": False}
        else:  # M, T, C...
            result[parts[1]] = {"status": "touched", "old_path": parts[1], "renamed": False}
    return result


def vec(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {c: row[f"risk_{c}"] for c in RISK_VECTOR} | {c: row[c] for c in CONTEXT_COLS}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, help="path to the git clone (for the rename diff)")
    ap.add_argument("--db", required=True, help="history DB produced by scan_pair.py")
    ap.add_argument("--parent", required=True)
    ap.add_argument("--child", required=True)
    ap.add_argument("--out", help="write JSON here instead of stdout")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo).resolve()
    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    before = rows_for(con, args.parent)
    after = rows_for(con, args.child)
    if not before or not after:
        sys.exit(f"missing rows: parent={len(before)} child={len(after)} — scan first")
    statuses = diff_statuses(repo, args.parent, args.child)

    # The DB stores paths as the scanner saw them (relative to the scan root,
    # forward slashes) — same convention as git's output, so keys align.
    files = []
    seen_before = set()
    for path, arow in after.items():
        st = statuses.get(path, {"status": "untouched", "old_path": path, "renamed": False})
        old = st["old_path"] if st["old_path"] is not None else None
        brow = before.get(old) if old else None
        if old:
            seen_before.add(old)
        b, a = vec(brow), vec(arow)
        delta = None
        if b and a:
            delta = {k: round(a[k] - b[k], 6) for k in b if a[k] is not None and b[k] is not None}
        files.append({
            "path": path, "old_path": old if st["renamed"] else None,
            "status": st["status"] if brow is not None or st["status"] == "added" else "added",
            "before": b, "after": a, "delta": delta,
            "structural_delta": (
                round(sum(delta[c] for c in STRUCTURAL_COLUMNS if c in delta), 6)
                if delta else None
            ),
            "temporal_delta": (
                round(sum(delta[c] for c in TEMPORAL_COLUMNS if c in delta), 6)
                if delta else None
            ),
        })
    for path, brow in before.items():
        if path not in seen_before and path not in after:
            files.append({
                "path": path, "old_path": None, "status": "deleted",
                "before": vec(brow), "after": None, "delta": None,
                "structural_delta": None, "temporal_delta": None,
            })

    record = {
        "repo": repo.name, "parent": args.parent, "child": args.child,
        "n_files_before": len(before), "n_files_after": len(after),
        "n_touched": sum(1 for f in files if f["status"] == "touched"),
        "files": files,
    }
    text = json.dumps(record, indent=1)
    if args.out:
        pathlib.Path(args.out).write_text(text)
        print(f"wrote {args.out} ({record['n_touched']} touched files)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
