#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""RW-H1 / RW-H2 — the repowise-derived hypotheses, registered on gitgalaxy#2982
before this tool ran, evaluated on the existing curl event snapshots (no scans).

RW-H1 (effort-aware value): ranking a parent snapshot's files by pre-event
structural exposure achieves HIGHER recall@20%-of-LOC review budget for the
files this event's security fix will touch than ranking by LOC alone.
Registered direction: exposure > LOC; α=0.01; paired sign test over event
snapshots (ties reported, excluded from the test, binomial exact p).

RW-H2 (the recidivism baseline): a file's PRIOR CVE-fix count predicts its
future CVE involvement better than exposure or LOC (recall@budget and pooled
AUC). Evaluated only on fix events with ≥5 prior fix events in the dataset
(the baseline needs history to exist). Registered direction: prior ≥ static.

Known limits, printed with the results: implicated files per event are few
(recalls are coarse), prior-count follows paths (renames break lineage), and
prior-count ties are broken neutrally by path — which handicaps rather than
helps the baseline.

    python tools/rw_analyses.py --events events/curl.json
"""
from __future__ import annotations

import argparse
import json
import math
import pathlib
import sqlite3
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, STRUCTURAL_COLUMNS  # noqa: E402
from delta_report import median  # noqa: E402
from exposure_delta import diff_statuses, rows_for  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import parent_child  # noqa: E402
import subprocess  # noqa: E402


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def sign_test(wins: int, losses: int) -> float:
    """Exact one-sided binomial p for wins out of (wins+losses) at p0=0.5."""
    n = wins + losses
    if n == 0:
        return float("nan")
    return sum(math.comb(n, k) for k in range(wins, n + 1)) / 2 ** n


def recall_at_budget(ranked_paths, loc_by_path, implicated, budget_frac=0.20):
    total = sum(loc_by_path.values()) or 1
    budget = budget_frac * total
    spent, caught = 0.0, 0
    chosen = set()
    for p in ranked_paths:
        if spent >= budget:
            break
        spent += loc_by_path[p] or 0
        chosen.add(p)
    caught = len(implicated & chosen)
    return caught / len(implicated) if implicated else float("nan")


def pooled_auc(obs):
    """obs = [(score, is_pos)]; mid-rank Mann-Whitney AUC."""
    pos = sum(1 for _, y in obs if y)
    neg = len(obs) - pos
    if not pos or not neg:
        return float("nan")
    srt = sorted(obs, key=lambda t: t[0])
    i, rank_sum = 0, 0.0
    while i < len(srt):
        j = i
        while j + 1 < len(srt) and srt[j + 1][0] == srt[i][0]:
            j += 1
        mid = (i + j) / 2 + 1
        rank_sum += mid * sum(1 for k in range(i, j + 1) if srt[k][1])
        i = j + 1
    return (rank_sum - pos * (pos + 1) / 2) / (pos * neg)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True)
    ap.add_argument("--out", default=str(DOCS_DIR / "rw_hypotheses.md"))
    args = ap.parse_args()

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    con = sqlite3.connect(history_db(out_dir_for(repo)))
    con.row_factory = sqlite3.Row

    fixes = [e for e in data["events"] if e["class"] == "security-fix"]
    # chronological order for the prior-count baseline
    dated = []
    for e in fixes:
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            continue
        dated.append((e | {"parent": parent, "child": child,
                           "when": _git(repo, "show", "-s", "--format=%ct", child)}))
    dated.sort(key=lambda e: int(e["when"]))

    per_event = []           # rows for both hypotheses
    prior_counts = defaultdict(int)
    for idx, e in enumerate(dated):
        before = rows_for(con, e["parent"])
        after = rows_for(con, e["child"])
        if not before or not after:
            continue
        statuses = diff_statuses(repo, e["parent"], e["child"])
        implicated = {st["old_path"] for p, st in statuses.items()
                      if st["status"] == "touched" and st["old_path"] in before}
        if implicated:
            loc = {p: (r["total_loc"] or 0) for p, r in before.items()}
            expo = {p: sum((r[f"risk_{c}"] or 0) for c in STRUCTURAL_COLUMNS)
                    for p, r in before.items()}
            prior = {p: prior_counts.get(p, 0) for p in before}
            rank_expo = sorted(before, key=lambda p: (-expo[p], p))
            rank_loc = sorted(before, key=lambda p: (-loc[p], p))
            rank_prior = sorted(before, key=lambda p: (-prior[p], p))
            per_event.append({
                "id": e["id"], "n_prior_events": idx,
                "n_implicated": len(implicated),
                "r_expo": recall_at_budget(rank_expo, loc, implicated),
                "r_loc": recall_at_budget(rank_loc, loc, implicated),
                "r_prior": recall_at_budget(rank_prior, loc, implicated),
                "obs": [(expo[p], loc[p], prior[p], p in implicated) for p in before],
            })
        # prior counts update AFTER evaluation (strictly earlier events only)
        for p in implicated:
            prior_counts[p] += 1

    # ---- RW-H1: exposure vs LOC, all fix events -----------------------------
    w = sum(1 for r in per_event if r["r_expo"] > r["r_loc"])
    l_ = sum(1 for r in per_event if r["r_expo"] < r["r_loc"])
    t = len(per_event) - w - l_
    p_h1 = sign_test(w, l_)
    auc_e = pooled_auc([(o[0], o[3]) for r in per_event for o in r["obs"]])
    auc_l = pooled_auc([(o[1], o[3]) for r in per_event for o in r["obs"]])

    # ---- RW-H2: prior vs exposure/LOC, events with >=5 prior events ---------
    late = [r for r in per_event if r["n_prior_events"] >= 5]
    w2e = sum(1 for r in late if r["r_prior"] > r["r_expo"])
    l2e = sum(1 for r in late if r["r_prior"] < r["r_expo"])
    p2e = sign_test(w2e, l2e)
    w2l = sum(1 for r in late if r["r_prior"] > r["r_loc"])
    l2l = sum(1 for r in late if r["r_prior"] < r["r_loc"])
    p2l = sign_test(w2l, l2l)
    late_obs = [o for r in late for o in r["obs"]]
    auc_p = pooled_auc([(o[2], o[3]) for o in late_obs])
    auc_e2 = pooled_auc([(o[0], o[3]) for o in late_obs])
    auc_l2 = pooled_auc([(o[1], o[3]) for o in late_obs])

    med = lambda k, rows: median([r[k] for r in rows])
    h1_verdict = ("SUPPORTED" if p_h1 < 0.01 and w > l_ else "not supported")
    h2_verdict = ("SUPPORTED" if p2e < 0.01 and w2e > l2e and p2l < 0.01 and w2l > l2l
                  else "not supported")

    md = [f"# RW-H1 / RW-H2 — {data['repo']}\n",
          "Registered on gitgalaxy#2982 before this tool ran; evaluated on existing "
          f"snapshots only. Fix events analyzed: {len(per_event)} "
          f"(median implicated files/event: {med('n_implicated', per_event):.0f}).\n",
          "## RW-H1 — does exposure beat LOC at ordering a 20%-LOC review budget?\n",
          "| ranking | median recall@20%LOC | pooled AUC (descriptive) |",
          "|---|---|---|",
          f"| structural exposure | {med('r_expo', per_event):.3f} | {auc_e:.3f} |",
          f"| LOC | {med('r_loc', per_event):.3f} | {auc_l:.3f} |",
          f"\nPaired per event: exposure wins {w}, LOC wins {l_}, ties {t} "
          f"(ties = both rankings catch/miss the same files). One-sided sign test "
          f"p = {p_h1:.4f}. **RW-H1: {h1_verdict}** (α=0.01, direction exposure > LOC).\n",
          f"## RW-H2 — is prior CVE-fix history the baseline to beat? "
          f"(events with ≥5 prior fixes: n={len(late)})\n",
          "| ranking | median recall@20%LOC | pooled AUC |",
          "|---|---|---|",
          f"| prior CVE-fix count | {med('r_prior', late):.3f} | {auc_p:.3f} |",
          f"| structural exposure | {med('r_expo', late):.3f} | {auc_e2:.3f} |",
          f"| LOC | {med('r_loc', late):.3f} | {auc_l2:.3f} |",
          f"\nPaired: prior vs exposure — wins {w2e}, losses {l2e}, p = {p2e:.4f}; "
          f"prior vs LOC — wins {w2l}, losses {l2l}, p = {p2l:.4f}. "
          f"**RW-H2: {h2_verdict}** (α=0.01, both comparisons, direction prior > static).\n",
          "Limits: recalls are coarse (few implicated files/event); prior counts follow "
          "paths (renames break lineage, handicapping the baseline); prior ties break "
          "neutrally by path. Pooled AUCs are descriptive (repeated files across "
          "snapshots), the paired tests are the registered readings.\n"]
    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")
    print(f"RW-H1 {h1_verdict} (p={p_h1:.4f}; W/L/T {w}/{l_}/{t}) | "
          f"RW-H2 {h2_verdict} (vs expo p={p2e:.4f}, vs LOC p={p2l:.4f}) | wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
