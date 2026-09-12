#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Batch-scan event pairs from an events file. Resumable by construction:
scan_pair skips any (repo, commit) already in the history DB, so this can be
interrupted and re-launched at any time.

    python tools/run_batch.py --events events/curl.json \
        --classes security-fix,control --limit 50
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from scan_pair import out_dir_for, resolve_repo, scan_commit  # noqa: E402


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True)
    ap.add_argument("--classes", default="security-fix,control")
    ap.add_argument("--limit", type=int, default=0, help="events per class (0 = all)")
    args = ap.parse_args()

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    out_dir = out_dir_for(repo)
    wanted = args.classes.split(",")

    picked = []
    per_class: dict[str, int] = {}
    for e in data["events"]:
        if e["class"] not in wanted:
            continue
        if args.limit and per_class.get(e["class"], 0) >= args.limit:
            continue
        per_class[e["class"]] = per_class.get(e["class"], 0) + 1
        picked.append(e)

    print(f"{len(picked)} events -> up to {2 * len(picked)} scans", flush=True)
    t0 = time.time()
    done = 0
    for e in picked:
        child = e["sha"]
        try:
            parent = _git(repo, "rev-parse", f"{child}^")
        except subprocess.CalledProcessError:
            print(f"skip {e['id']}: {child[:12]} has no parent (root commit)", flush=True)
            continue
        for sha in (parent, child):
            status = scan_commit(repo, sha, out_dir)
            done += 1
            print(f"[{done}] {e['class']:13s} {e['id']:28s} {sha[:12]} {status} "
                  f"({(time.time() - t0) / 60:.1f}m)", flush=True)
    print(f"batch complete in {(time.time() - t0) / 60:.1f} minutes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
