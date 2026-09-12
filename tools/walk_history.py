#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Build a chronological repo dataset: scan history in time order into the
accumulating per-repo DB (gitgalaxy#2982 phase W).

Every walked revision lands as its own `(repo_name, commit_hash)` row-set —
non-destructive accumulation, joinable across time by file_path (and per
function via function_data → file_data). The walk manifest
(`walks/<repo>_walk.json`) records ref → sha → date so analysis tools read
the panel without re-deriving it.

Modes:
  --tags [PATTERN]    every tag matching PATTERN (default 'curl-*'), sorted by
                      commit time — the release-level panel (~270 scans for
                      curl; full scans, works against unmodified engine main)
  --every N           every Nth first-parent commit of the default branch
                      (chronological densification between releases)

Scans are full scans today: deterministic and parity-proven. The switch to
onboard+`--incremental` per step lands with gitgalaxy#2983 (explicit
rehydrator baseline); until then a dense walk is just linearly slower, never
wrong. Resumable by construction — rerunning skips scanned revisions.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import REPO_ROOT  # noqa: E402
from scan_pair import out_dir_for, resolve_repo, scan_commit  # noqa: E402

WALKS_DIR = REPO_ROOT / "walks"


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout


def tag_refs(repo, pattern):
    out = _git(repo, "for-each-ref", "--sort=creatordate",
               "--format=%(refname:short)\t%(creatordate:iso-strict)",
               f"refs/tags/{pattern}")
    refs = []
    for line in out.splitlines():
        ref, date = line.split("\t")
        sha = _git(repo, "rev-list", "-n", "1", ref).strip()
        refs.append({"ref": ref, "sha": sha, "date": date})
    return refs


def every_nth(repo, n):
    shas = _git(repo, "rev-list", "--first-parent", "--reverse", "HEAD").split()
    picked = shas[::n]
    if shas and picked[-1] != shas[-1]:
        picked.append(shas[-1])
    return [{"ref": f"first-parent/{i * n}", "sha": s,
             "date": _git(repo, "show", "-s", "--format=%cI", s).strip()}
            for i, s in enumerate(picked)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--tags", nargs="?", const="curl-*", metavar="PATTERN")
    g.add_argument("--every", type=int, metavar="N")
    ap.add_argument("--limit", type=int, default=0, help="cap revisions (0 = all)")
    args = ap.parse_args()

    repo = resolve_repo(args.repo)
    out_dir = out_dir_for(repo)
    WALKS_DIR.mkdir(exist_ok=True)

    refs = tag_refs(repo, args.tags) if args.tags else every_nth(repo, args.every)
    if args.limit:
        refs = refs[: args.limit]
    manifest_path = WALKS_DIR / f"{repo.name}_walk.json"
    print(f"{len(refs)} revisions, oldest {refs[0]['date'][:10]} newest {refs[-1]['date'][:10]}",
          flush=True)

    t0, done = time.time(), 0
    for r in refs:
        status = scan_commit(repo, r["sha"], out_dir)
        r["status"] = "ok" if status in ("scanned", "skip (already in DB)") else status
        done += 1
        print(f"[{done}/{len(refs)}] {r['ref']:24s} {r['sha'][:12]} {status} "
              f"({(time.time() - t0) / 60:.1f}m)", flush=True)
        # manifest updated every step so analysis can start mid-walk
        manifest_path.write_text(json.dumps(
            {"repo": repo.name, "mode": "tags" if args.tags else f"every-{args.every}",
             "revisions": refs}, indent=1) + "\n")
    print(f"walk complete: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
