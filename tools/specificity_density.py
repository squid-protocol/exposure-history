#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""EXPLORATORY: is there family-signal beyond SIZE? count vs density vs LOC.

The specificity split scored files by the raw SUM of a family's signal columns,
and AUC(sum) ~ AUC(LOC) — because a raw count scales with size. This asks the
different question "is there signal BEYOND size?" three cheap ways, on curl AND
nDPI, for the families whose signals are actually populated (memory, info-leak;
cert/auth is dead-vocabulary on curl — def_auth is 0 everywhere — flagged, not
scored if coverage is ~0):

  1. AUC(count)   — the raw sum (the specificity-split score), for reference
  2. AUC(density) — sum / total_loc (size divided out) — BUT read with the
     tech_debt caveat (a moving LOC denominator can manufacture a signal;
     gitgalaxy#2979/#2984), which is why (3) is the cleaner "beyond size" read
  3. length-matched pairwise — each positive vs its nearest control file within
     [0.66, 1.5]x LOC: win-rate of the positive carrying MORE count / MORE
     density at ~equal length (no denominator division)

All vs AUC(LOC). **EXPLORATORY — no p-values claimed; on data already seen.** If
density or the length-matched read separates where the raw count did not, that
is registered for repo #3, never scored here (protocol rule 3).

    python tools/specificity_density.py
"""
from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, EVENTS_DIR  # noqa: E402
from delta_report import CWE_FAMILY, median  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import file_rows, parent_child, signal_columns  # noqa: E402

FAMILY_SIGNALS = {
    "memory": ["state_pointers", "state_memory_alloc", "state_cast_hits", "state_danger"],
    "cert/auth": ["arch_crypto", "def_auth"],
    "info-leak": ["arch_io", "arch_api"],
}


def auc(pos, neg):
    """P(pos ranks above neg) + 0.5 ties, over all pairs. Direct, O(n*m)."""
    if not pos or not neg:
        return float("nan")
    wins = ties = 0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1
            elif p == n:
                ties += 1
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def collect(events_path):
    """Return per-family lists of (count, density, loc) records for implicated
    files, tagged by class, at the parent snapshot."""
    data = json.loads(pathlib.Path(events_path).read_text())
    repo = resolve_repo(data["repo"])
    con = sqlite3.connect(f"file:{history_db(out_dir_for(repo))}?mode=ro", uri=True)
    all_cols = set(signal_columns(con, "file_data"))
    # lean: only the columns any family uses (file_rows selects these + total_loc),
    # ~8 cols instead of ~70 -> the big-snapshot reads are ~7x lighter.
    seen, fcols = set(), []
    for sigs in FAMILY_SIGNALS.values():
        for c in sigs:
            if c in all_cols and c not in seen:
                seen.add(c); fcols.append(c)
    fam_idx = {fam: [fcols.index(c) for c in sigs if c in fcols]
               for fam, sigs in FAMILY_SIGNALS.items()}
    # coverage: fraction of file-rows with the family's summed signal > 0
    cover = {}
    for fam, idxs in fam_idx.items():
        if not idxs:
            cover[fam] = 0.0
            continue
        expr = "+".join(fcols[i] for i in idxs)
        nz, tot = con.execute(
            f"SELECT SUM(({expr})>0), COUNT(*) FROM file_data WHERE repo_name=?",
            (repo.name,)).fetchone()
        cover[fam] = (nz or 0) / tot if tot else 0.0

    # class -> family -> [(count, density, loc)]; control keyed under "control"
    recs = defaultdict(lambda: defaultdict(list))
    for e in data["events"]:
        cls = e["class"]
        if cls == "security-fix":
            if not e.get("cwe"):
                continue
            fam = CWE_FAMILY.get(e["cwe"], "other")
            if fam not in FAMILY_SIGNALS:
                continue
            bucket = fam
        elif cls == "control":
            bucket = "control"
        else:
            continue
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            continue
        before = file_rows(con, parent, fcols)
        after = file_rows(con, child, fcols)
        if not before or not after:
            continue
        statuses = diff_statuses(repo, parent, child)
        touched = [(p, st) for p, st in statuses.items()
                   if st["status"] == "touched" and p in after and st["old_path"] in before]
        for _p, st in touched:
            row = before[st["old_path"]]
            loc = row[1] or 0
            if loc <= 0:
                continue
            for fam, idxs in fam_idx.items():
                s = sum((row[2 + i] or 0) for i in idxs)
                recs[bucket][fam].append((s, s / loc, loc))
    con.close()
    return data["repo"], cover, recs


def matched_pairwise(pos, ctrl):
    """Each positive vs nearest control by LOC within [0.66,1.5]x: win-rate that
    the positive carries more count / more density. pos/ctrl are (cnt,den,loc)."""
    ctrl_sorted = sorted(ctrl, key=lambda t: t[2])
    locs = [t[2] for t in ctrl_sorted]
    import bisect
    cnt_w = den_w = n = 0
    for cnt, den, loc in pos:
        lo, hi = 0.66 * loc, 1.5 * loc
        j = bisect.bisect_left(locs, loc)
        best = None
        for k in list(range(j, len(ctrl_sorted))) + list(range(j - 1, -1, -1)):
            c = ctrl_sorted[k]
            if lo <= c[2] <= hi:
                if best is None or abs(c[2] - loc) < abs(best[2] - loc):
                    best = c
                if c[2] > hi and k >= j:
                    break
        if best is None:
            continue
        n += 1
        cnt_w += 1 if cnt > best[0] else (0.5 if cnt == best[0] else 0)
        den_w += 1 if den > best[1] else (0.5 if den == best[1] else 0)
    return (cnt_w / n if n else float("nan"), den_w / n if n else float("nan"), n)


def main() -> int:
    md = ["# Signal beyond size — count vs density vs length (EXPLORATORY)\n",
          "**Exploratory, no p-values claimed; computed on data already seen.** Asks whether a "
          "family's signal carries anything BEYOND file size, which a raw count cannot show "
          "(AUC(count) ≈ AUC(LOC) because a count scales with size). Density divides size out "
          "but can manufacture a signal via a moving denominator (the `tech_debt` lesson, "
          "gitgalaxy#2979/#2984) — so the **length-matched pairwise** column is the cleaner "
          "read. Positives vs the control class, file grain, parent snapshot.\n"]
    for ev in (EVENTS_DIR / "curl.json", EVENTS_DIR / "ndpi.json"):
        if not ev.exists():
            continue
        repo, cover, recs = collect(ev)
        md.append(f"## {repo}\n")
        md.append("| family | coverage | n_pos / n_ctrl | AUC(count) | AUC(density) | AUC(LOC) | "
                  "match win% count | match win% density | n_matched |")
        md.append("|---|---|---|---|---|---|---|---|---|")
        ctrl = recs.get("control", {})
        for fam in ("memory", "cert/auth", "info-leak"):
            pos = recs.get(fam, {}).get(fam, [])
            neg = ctrl.get(fam, [])
            if not pos or not neg:
                md.append(f"| {fam} | {cover.get(fam,0)*100:.1f}% | {len(pos)}/{len(neg)} | "
                          "— | — | — | — | — | — |")
                continue
            a_cnt = auc([p[0] for p in pos], [n[0] for n in neg])
            a_den = auc([p[1] for p in pos], [n[1] for n in neg])
            a_loc = auc([p[2] for p in pos], [n[2] for n in neg])
            mw_cnt, mw_den, nm = matched_pairwise(pos, neg)
            flag = " ⚠dead-vocab" if cover.get(fam, 0) < 0.02 else ""
            md.append(f"| {fam}{flag} | {cover.get(fam,0)*100:.1f}% | {len(pos)}/{len(neg)} | "
                      f"{a_cnt:.3f} | {a_den:.3f} | {a_loc:.3f} | {mw_cnt*100:.0f}% | "
                      f"{mw_den*100:.0f}% | {nm} |")
        md.append("")
        md.append("Reading: AUC(density) or match-win% **materially above** AUC(LOC)/50% ⇒ signal "
                  "beyond size (→ register for repo #3). At/near LOC ⇒ the signal is just size. "
                  "`⚠dead-vocab` = family signal nonzero on <2% of file-rows (uninformative).\n")
    out = DOCS_DIR / "specificity_density_explore.md"
    out.write_text("\n".join(md) + "\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
