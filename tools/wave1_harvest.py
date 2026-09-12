#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Wave-1 label harvest (pre-registered on gitgalaxy#2982): reverts and
follow-ups-to-CVE-fixes. Emits an events file run_batch/delta tools consume.

  revert        subject starts with 'Revert' (the exact-negation class)
  cve-followup  message references 'Follow-up to <sha>' where <sha> prefix-
                matches one of the OSV fix commits; the link is recorded so
                W1-H2 can split original fixes into needing/not-needing one.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import EVENTS_DIR, POOL_DIR  # noqa: E402

FOLLOW_RE = re.compile(r"[Ff]ollow-?up to ([0-9a-f]{7,40})")


def _git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)
    return r.stdout.decode("utf-8", errors="replace")  # 1990s curl commits aren't UTF-8


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default="curl")
    ap.add_argument("--base-events", default=str(EVENTS_DIR / "curl.json"))
    ap.add_argument("--out", default=str(EVENTS_DIR / "curl_wave1.json"))
    args = ap.parse_args()

    repo = POOL_DIR / args.repo
    base = json.loads(pathlib.Path(args.base_events).read_text())
    fix_shas = {e["sha"] for e in base["events"] if e["class"] == "security-fix"}
    head = _git(repo, "rev-parse", "HEAD").strip()

    events = []
    # reverts: subject-line match, full history
    for line in _git(repo, "log", "--format=%H\x01%s", "--no-merges").splitlines():
        sha, subj = line.split("\x01", 1)
        if subj.startswith("Revert"):
            events.append({"id": f"revert-{sha[:12]}", "class": "revert",
                           "sha": sha, "summary": subj[:120]})

    # follow-ups to CVE fixes: message body reference, prefix-matched
    raw = _git(repo, "log", "--format=%H\x01%B\x02", "--no-merges")
    n_follow_all = 0
    for chunk in raw.split("\x02"):
        if "\x01" not in chunk:
            continue
        sha, body = chunk.split("\x01", 1)
        sha = sha.strip()
        for m in FOLLOW_RE.finditer(body):
            n_follow_all += 1
            ref = m.group(1)
            target = next((f for f in fix_shas if f.startswith(ref)), None)
            if target:
                events.append({"id": f"followup-{sha[:12]}", "class": "cve-followup",
                               "sha": sha, "follows_fix": target,
                               "summary": body.splitlines()[0][:120]})
                break

    # de-dup by (sha, class)
    seen, unique = set(), []
    for e in events:
        if (e["sha"], e["class"]) in seen:
            continue
        seen.add((e["sha"], e["class"]))
        unique.append(e)

    counts = {}
    for e in unique:
        counts[e["class"]] = counts.get(e["class"], 0) + 1
    out = {"repo": args.repo, "source": "wave1 (gitgalaxy#2982 pre-registration)",
           "pool_head": head, "counts": counts, "events": unique}
    pathlib.Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(counts), f"| follow-up refs seen in history: {n_follow_all} "
          f"| wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
