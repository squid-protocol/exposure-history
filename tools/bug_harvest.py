#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Harvest the overnight bug-label sample (gitgalaxy#2982, comment 5651082895).

Implements the registered procedure verbatim: census three commit-message label
classes over curl's full history (merges excluded), exclude SHAs already in
events/curl.json + events/curl_wave1.json, then draw ALL regression commits +
seeded uniform samples of 500 `Fixes #` and 300 remaining `Bug:` commits
(seed 2982, drawn AFTER registration). Multi-label kept (list-valued `labels`,
the wave-1 schema); overlap counts reported in the output header.

    python tools/bug_harvest.py            # writes events/curl_bugs.json
"""
from __future__ import annotations

import json
import random
import re
import subprocess
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import EVENTS_DIR, POOL_DIR  # noqa: E402

SEED = 2982
N_FIXES = 500
N_BUG = 300

RE_FIXES = re.compile(r"Fixes #\d+")
RE_BUG = re.compile(r"^Bug: \S+", re.MULTILINE)
RE_REGR = re.compile(r"regression", re.IGNORECASE)


def main() -> int:
    repo = POOL_DIR / "curl"
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()

    # ---- census: one full-history walk, subject+body per commit -------------
    out = subprocess.run(
        ["git", "-C", str(repo), "log", "--no-merges", "--format=%H%x01%B%x02"],
        capture_output=True, text=True, check=True, errors="replace").stdout
    pools = {"bugfix-fixes": [], "bugfix-bug": [], "regression": []}
    labels_by_sha: dict[str, list[str]] = {}
    subj_by_sha: dict[str, str] = {}
    for chunk in out.split("\x02"):
        chunk = chunk.strip()
        if not chunk:
            continue
        sha, _, body = chunk.partition("\x01")
        sha = sha.strip()
        if len(sha) != 40:
            continue
        labs = []
        if RE_FIXES.search(body):
            labs.append("bugfix-fixes")
        if RE_BUG.search(body):
            labs.append("bugfix-bug")
        if RE_REGR.search(body):
            labs.append("regression")
        if not labs:
            continue
        labels_by_sha[sha] = labs
        subj_by_sha[sha] = body.split("\n", 1)[0][:120]
        for lab in labs:
            pools[lab].append(sha)

    # ---- exclusions: SHAs already scanned as events -------------------------
    excluded = set()
    for name in ("curl.json", "curl_wave1.json"):
        d = json.loads((EVENTS_DIR / name).read_text())
        excluded |= {e["sha"] for e in d["events"]}
    for lab in pools:
        pools[lab] = [s for s in pools[lab] if s not in excluded]

    census = {lab: len(v) for lab, v in pools.items()}
    overlap2 = sum(1 for labs in labels_by_sha.values() if len(labs) >= 2)

    # ---- the registered draw (seed fixed BEFORE any draw) -------------------
    rng = random.Random(SEED)
    chosen: dict[str, list[str]] = {}
    chosen_all = set(pools["regression"])          # ALL regression
    chosen["regression"] = sorted(pools["regression"])
    fixes_pool = sorted(set(pools["bugfix-fixes"]) - chosen_all)
    chosen["bugfix-fixes"] = sorted(rng.sample(fixes_pool, min(N_FIXES, len(fixes_pool))))
    chosen_all |= set(chosen["bugfix-fixes"])
    bug_pool = sorted(set(pools["bugfix-bug"]) - chosen_all)
    chosen["bugfix-bug"] = sorted(rng.sample(bug_pool, min(N_BUG, len(bug_pool))))
    chosen_all |= set(chosen["bugfix-bug"])

    # ---- emit: one event per unique SHA, primary class = draw bucket --------
    events = []
    for lab in ("regression", "bugfix-fixes", "bugfix-bug"):
        for sha in chosen[lab]:
            events.append({
                "id": f"{lab}-{sha[:12]}", "class": lab, "sha": sha,
                "labels": labels_by_sha[sha], "summary": subj_by_sha[sha],
            })

    payload = {
        "repo": "curl",
        "source": "tools/bug_harvest.py (commit-message labels; gitgalaxy#2982 comment 5651082895)",
        "pool_head": head, "seed": SEED,
        "census_after_exclusions": census,
        "n_excluded_already_scanned": len(excluded),
        "n_multi_label_in_census": overlap2,
        "counts": {lab: len(v) for lab, v in chosen.items()},
        "n_unique_events": len(events),
        "events": events,
    }
    out_path = EVENTS_DIR / "curl_bugs.json"
    out_path.write_text(json.dumps(payload, indent=1) + "\n")
    print(json.dumps({k: payload[k] for k in
                      ("census_after_exclusions", "counts", "n_unique_events",
                       "n_multi_label_in_census")}, indent=1))
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
