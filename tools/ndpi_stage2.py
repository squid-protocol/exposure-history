#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Stage-2 of the nDPI (repo #2) replication battery (gitgalaxy#2982, comment
5648589175; ledger: docs/HYPOTHESES.md "Repo #2 (nDPI) replication — RESULTS",
which lists these three as "owed"). Pre-registered; implemented verbatim here;
verdicts publish either way.

  N-FIRST  Among files at their FIRST CVE (security-fix) event, does pre-event
           structural exposure separate them from size-matched never-CVE files
           better than chance (AUC)? Verdict on nDPI; curl is run alongside as
           EXPLORATORY context only (curl data already seen by this program).
  D-H1'    Branch-per-danger guard deficit at function grain: implicated
           functions carry a lower `struct_branch / (pointers+danger+alloc+
           casts+1)` rate than length-matched same-file siblings; the fix
           raises it (D-H2'). nDPI only (this is nDPI's activation of the
           repo-#2 prediction registered on curl's D-H1 degeneracy).
  EQUIV    TOST/equivalence read on the three nulls the first nDPI battery
           already found non-significant (N-H1 p=0.70, N-H2 p=0.37, N-RW1
           p=0.60): effect size + bootstrap 95% CI, "null replicated" iff
           non-significant AND the CI sits inside the pre-set delta.

All DB access is read-only, WAL-aware (`file:{db}?mode=ro`), never immutable.
Deterministic: every bootstrap uses seed 2982 (gitgalaxy#2982), floor 5000
iterations. stdlib only.

    python tools/ndpi_stage2.py
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import sqlite3
import sys
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, EVENTS_DIR, STRUCTURAL_COLUMNS  # noqa: E402
from delta_report import event_deltas, mann_whitney_u, median, q  # noqa: E402
from exposure_delta import diff_statuses, rows_for  # noqa: E402
from rw_analyses import pooled_auc, recall_at_budget, sign_test  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import hunk_lines_parent_side, parent_child  # noqa: E402

SEED = 2982
ITERS = 5000
RISK_COLS_SQL = ", ".join(f"risk_{c}" for c in STRUCTURAL_COLUMNS)
NSTR = len(STRUCTURAL_COLUMNS)


def open_db(repo_name: str):
    """Read-only, WAL-aware — never immutable (gitgalaxy#2982 guard)."""
    repo = resolve_repo(repo_name)
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return repo, db, con


def commit_dates(con, shas):
    shas = [s for s in dict.fromkeys(shas) if s]
    if not shas:
        return {}
    qmarks = ",".join("?" * len(shas))
    return dict(con.execute(
        f"SELECT commit_hash, commit_date FROM repo_data WHERE commit_hash IN ({qmarks})",
        shas).fetchall())


def fmt(x, nd=4):
    return "n/a" if x is None or (isinstance(x, float) and x != x) else f"{x:.{nd}f}"


# ============================================================== ITEM 1 — N-FIRST
def n_first(data, repo, con, label, iters=ITERS, seed=SEED):
    """First-CVE file profile: pre-event structural exposure vs size-matched
    never-CVE files, AUC. Also AUC(total_loc) for the same pairs (does exposure
    beat a line count). Bootstrap over the matched PAIRS (the sampling unit)."""
    events = data["events"]
    cve_events = [e for e in events if e["class"] in ("security-fix", "introduced")]
    fixes = [e for e in events if e["class"] == "security-fix"]

    # ---- resolve parent/child + rename-aware diff once per CVE-class event
    ev_info = {}
    skip = Counter()
    for e in cve_events:
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            skip[f"{e['class']}: root-commit"] += 1
            continue
        statuses = diff_statuses(repo, parent, child)
        ev_info[e["sha"]] = {"class": e["class"], "parent": parent, "child": child,
                              "statuses": statuses}

    # ---- CVE_TOUCHED: any path that is EVER a touched file (either side of the
    # rename) in ANY security-fix or introduced event -- these can never serve
    # as a "never-CVE" negative, at any snapshot.
    cve_touched = set()
    for info in ev_info.values():
        for p, st in info["statuses"].items():
            if st["status"] == "touched":
                cve_touched.add(p)
                if st["old_path"]:
                    cve_touched.add(st["old_path"])

    # ---- first-CVE event per file: earliest (by fix-commit commit_date) among
    # security-fix events whose parent-snapshot touched-file set contains it.
    fix_child_shas = [ev_info[e["sha"]]["child"] for e in fixes if e["sha"] in ev_info]
    dates = commit_dates(con, fix_child_shas)
    first_seen = {}  # old_path (identity in ITS parent snapshot) -> (date, parent_sha)
    for e in fixes:
        info = ev_info.get(e["sha"])
        if info is None:
            continue
        cdate = dates.get(info["child"])
        if cdate is None:
            continue
        for p, st in info["statuses"].items():
            if st["status"] != "touched" or not st["old_path"]:
                continue
            old = st["old_path"]
            cur = first_seen.get(old)
            if cur is None or cdate < cur[0]:
                first_seen[old] = (cdate, info["parent"])

    # ---- positives: pre-event (parent snapshot) structural exposure + total_loc
    positives = []
    missing_scan = 0
    for old, (cdate, psha) in first_seen.items():
        row = con.execute(
            f"SELECT total_loc, {RISK_COLS_SQL} FROM file_data "
            "WHERE commit_hash = ? AND file_path = ?", (psha, old)).fetchone()
        if row is None:
            missing_scan += 1
            continue
        loc = row[0] or 0
        expo = sum((row[1 + i] or 0) for i in range(NSTR))
        positives.append({"path": old, "parent": psha, "date": cdate, "loc": loc, "expo": expo})

    # ---- never-CVE candidate pool, cached per distinct parent snapshot used
    distinct_parents = sorted({p["parent"] for p in positives})
    pool_by_parent = {}
    for psha in distinct_parents:
        rows = con.execute(
            f"SELECT file_path, total_loc, {RISK_COLS_SQL} FROM file_data "
            "WHERE commit_hash = ?", (psha,)).fetchall()
        pool = []
        for r in rows:
            if r[0] in cve_touched:
                continue
            loc = r[1] or 0
            expo = sum((r[2 + i] or 0) for i in range(NSTR))
            pool.append((r[0], loc, expo))
        pool_by_parent[psha] = pool
    parent_dates = commit_dates(con, distinct_parents)
    global_pool = [(path, loc, expo, psha, parent_dates.get(psha))
                   for psha, pool in pool_by_parent.items() for path, loc, expo in pool]

    def day_gap(d1, d2):
        try:
            import datetime
            return abs((datetime.date.fromisoformat(d1[:10]) -
                        datetime.date.fromisoformat(d2[:10])).days)
        except Exception:
            return float("inf")

    # ---- size-matching: [0.66, 1.5]x total_loc, same snapshot preferred, else
    # the date-nearest snapshot among all fix-event parents in the pool.
    matched, unmatched, source_counts = [], 0, Counter()
    for pos in positives:
        lo, hi = 0.66 * pos["loc"], 1.5 * pos["loc"]
        same = [c for c in pool_by_parent.get(pos["parent"], []) if lo <= c[1] <= hi]
        if same:
            best = min(same, key=lambda c: abs(c[1] - pos["loc"]))
            matched.append((pos, best[1], best[2]))
            source_counts["same-snapshot"] += 1
            continue
        cands = [c for c in global_pool if lo <= c[1] <= hi]
        if cands:
            best = min(cands, key=lambda c: (day_gap(c[4] or "", pos["date"]),
                                              abs(c[1] - pos["loc"])))
            matched.append((pos, best[1], best[2]))
            source_counts["nearby-snapshot"] += 1
        else:
            unmatched += 1

    n = len(matched)
    if n == 0:
        return {"label": label, "n_positives": len(positives), "n_matched": 0,
                "verdict": "n/a (no matched pairs)"}

    obs_auc_expo = pooled_auc([(m[0]["expo"], True) for m in matched]
                               + [(m[2], False) for m in matched])
    obs_auc_loc = pooled_auc([(m[0]["loc"], True) for m in matched]
                              + [(m[1], False) for m in matched])
    obs_lift = obs_auc_expo - obs_auc_loc

    rng = random.Random(seed)
    boot_expo, boot_loc, boot_lift = [], [], []
    for _ in range(iters):
        samp = [matched[rng.randrange(n)] for _ in range(n)]
        a_e = pooled_auc([(m[0]["expo"], True) for m in samp] + [(m[2], False) for m in samp])
        a_l = pooled_auc([(m[0]["loc"], True) for m in samp] + [(m[1], False) for m in samp])
        if a_e == a_e and a_l == a_l:  # skip NaN iterations (degenerate resample)
            boot_expo.append(a_e)
            boot_loc.append(a_l)
            boot_lift.append(a_e - a_l)
    boot_expo.sort()
    boot_loc.sort()
    boot_lift.sort()

    # --- VERIFY: is the separation beyond size, or size leaking through the loose
    # [0.66,1.5]x match? density (expo/loc) divides size out; expo_win@matchedLOC and
    # mean(pos_loc-neg_loc) show whether positives are simply larger within the band.
    pos_den = [m[0]["expo"] / max(m[0]["loc"], 1) for m in matched]
    neg_den = [m[2] / max(m[1], 1) for m in matched]
    auc_den = pooled_auc([(v, True) for v in pos_den] + [(v, False) for v in neg_den])
    den_win = sum(1 if pd > nd else 0.5 if pd == nd else 0 for pd, nd in zip(pos_den, neg_den)) / n
    expo_win = sum(1 if m[0]["expo"] > m[2] else 0.5 if m[0]["expo"] == m[2] else 0 for m in matched) / n
    loc_gap = sum(m[0]["loc"] - m[1] for m in matched) / n
    print(f"[VERIFY {label}] AUC(density)={auc_den:.3f} density_win={den_win:.2f} "
          f"expo_win@matchedLOC={expo_win:.2f} mean(pos_loc-neg_loc)={loc_gap:+.1f}", flush=True)

    verdict_lo = q(boot_expo, 0.01)     # one-sided alpha=0.01 lower bound (decides the verdict)
    ci95 = (q(boot_expo, 0.025), q(boot_expo, 0.975))  # descriptive 95% CI
    lift_ci95 = (q(boot_lift, 0.025), q(boot_lift, 0.975))
    supported = obs_auc_expo > 0.5 and verdict_lo == verdict_lo and verdict_lo > 0.5

    return {
        "label": label, "n_cve_events_skipped": dict(skip), "missing_scan": missing_scan,
        "n_first_cve_files": len(first_seen), "n_positives": len(positives),
        "n_matched": n, "match_sources": dict(source_counts), "n_unmatched": unmatched,
        "auc_expo": obs_auc_expo, "auc_loc": obs_auc_loc, "lift": obs_lift,
        "verdict_lo_alpha01": verdict_lo, "ci95": ci95, "lift_ci95": lift_ci95,
        "n_boot": len(boot_expo),
        "verdict": "SUPPORTED" if supported else "not supported",
    }


# ============================================================== ITEM 2 — D-H1'/D-H2'
def d_h1_prime(data, repo, con):
    """Branch-per-danger guard deficit, function grain. guard rate =
    struct_branch / (state_pointers+state_danger+state_memory_alloc+
    state_cast_hits+1). implicated = functions overlapping the fix's changed
    parent-side lines; siblings = untouched same-file functions, loc-matched
    within [0.66, 1.5]x (identical gate to signal_anatomy.py's Phase D)."""
    fixes = [e for e in data["events"] if e["class"] == "security-fix"]
    FSEL = ("f.func_name, f.start_line, f.loc, f.complexity, f.func_z_score, "
            "f.state_pointers, f.state_danger, f.state_memory_alloc, "
            "f.state_cast_hits, f.struct_branch")
    func_files = []
    n_events_with_hits = 0
    for e in fixes:
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            continue
        statuses = diff_statuses(repo, parent, child)
        touched = [(p, st) for p, st in statuses.items()
                   if st["status"] == "touched" and st["old_path"]]
        if not touched:
            continue
        event_hit = False
        for path, st in touched:
            changed = hunk_lines_parent_side(repo, parent, child, st["old_path"])
            if not changed:
                continue
            frows = con.execute(
                f"SELECT {FSEL} FROM function_data f JOIN file_data fd ON f.file_id = fd.id "
                "WHERE fd.commit_hash = ? AND fd.file_path = ?",
                (parent, st["old_path"])).fetchall()
            if not frows:
                continue
            crows = {r[0]: r for r in con.execute(
                f"SELECT {FSEL} FROM function_data f JOIN file_data fd ON f.file_id = fd.id "
                "WHERE fd.commit_hash = ? AND fd.file_path = ?", (child, path))}
            per_file = []
            for row in frows:
                name, start, loc, cx, z, ptr, danger, alloc, cast, branch = row
                if start is None or loc is None:
                    continue
                span = range(start, start + max(loc, 1))
                hit = any(ln in changed for ln in span)
                event_hit = event_hit or hit
                dl = (ptr or 0) + (danger or 0) + (alloc or 0) + (cast or 0)
                rate = (branch or 0) / (dl + 1)
                post = crows.get(name)
                post_rate = None
                if post is not None:
                    _n, _s, _l, _c, _z, pptr, pdanger, palloc, pcast, pbranch = post
                    pdl = (pptr or 0) + (pdanger or 0) + (palloc or 0) + (pcast or 0)
                    post_rate = (pbranch or 0) / (pdl + 1)
                per_file.append({"hit": hit, "loc": loc or 0, "dl": dl, "branch": branch or 0,
                                  "rate": rate, "post_rate": post_rate})
            if per_file:
                func_files.append(per_file)
        if event_hit:
            n_events_with_hits += 1

    pairs = []
    for per_file in func_files:
        hits = [r for r in per_file if r["hit"]]
        sibs = [r for r in per_file if not r["hit"]]
        for h in hits:
            cand = [s for s in sibs if 0.66 * h["loc"] <= s["loc"] <= 1.5 * h["loc"]]
            if cand:
                best = min(cand, key=lambda s: abs(s["loc"] - h["loc"]))
                pairs.append((h, best))

    if not pairs:
        return {"n_pairs": 0, "verdict_d1": "n/a", "verdict_d2": "n/a"}

    a_rate = [h["rate"] for h, _ in pairs]
    b_rate = [s["rate"] for _, s in pairs]
    _, p_d1 = mann_whitney_u(a_rate, b_rate)          # D-H1': implicated < sibling
    a_dl = [h["dl"] for h, _ in pairs]
    b_dl = [s["dl"] for _, s in pairs]
    _, p_dng = mann_whitney_u(b_dl, a_dl)              # control: sibling < implicated danger

    imp_chg = [h["post_rate"] - h["rate"] for h, _ in pairs if h["post_rate"] is not None]
    sib_chg = [s["post_rate"] - s["rate"] for _, s in pairs if s["post_rate"] is not None]
    _, p_d2 = mann_whitney_u(sib_chg, imp_chg) if imp_chg and sib_chg else (0, float("nan"))

    d1_supported = p_d1 == p_d1 and p_d1 < 0.01 and median(a_rate) < median(b_rate)
    d2_supported = (p_d2 == p_d2 and p_d2 < 0.01
                    and median(imp_chg) > median(sib_chg) if imp_chg and sib_chg else False)

    return {
        "n_events_with_hits": n_events_with_hits, "n_files_with_hits": len(func_files),
        "n_pairs": len(pairs),
        "median_rate_implicated": median(a_rate), "median_rate_sibling": median(b_rate),
        "p_d1": p_d1, "verdict_d1": "SUPPORTED" if d1_supported else "not supported",
        "median_danger_implicated": median(a_dl), "median_danger_sibling": median(b_dl),
        "p_danger_control": p_dng,
        "n_imp_chg": len(imp_chg), "n_sib_chg": len(sib_chg),
        "median_chg_implicated": median(imp_chg) if imp_chg else float("nan"),
        "median_chg_sibling": median(sib_chg) if sib_chg else float("nan"),
        "p_d2": p_d2, "verdict_d2": "SUPPORTED" if d2_supported else "not supported",
    }


# ============================================================== ITEM 3 — equivalence
def bootstrap_two_sample_median_diff(a, b, iters, rng):
    na, nb = len(a), len(b)
    out = []
    for _ in range(iters):
        sa = [a[rng.randrange(na)] for _ in range(na)]
        sb = [b[rng.randrange(nb)] for _ in range(nb)]
        out.append(median(sa) - median(sb))
    out.sort()
    return out


def bootstrap_paired_median(vals, iters, rng):
    n = len(vals)
    out = []
    for _ in range(iters):
        s = [vals[rng.randrange(n)] for _ in range(n)]
        out.append(median(s))
    out.sort()
    return out


def equivalence_nulls(data, repo, con, iters=ITERS, seed=SEED):
    # ---- N-H1 / N-H2: event-mean structural delta, reusing delta_report.event_deltas
    by_class = defaultdict(list)
    skipped = Counter()
    for e in data["events"]:
        if e["class"] not in ("security-fix", "control", "introduced"):
            continue
        d = event_deltas(con, repo, e["sha"])
        if d is None or not d["touched"]:
            skipped[e["class"]] += 1
            continue
        mean_structural = sum(f["structural"] for f in d["touched"]) / len(d["touched"])
        by_class[e["class"]].append(mean_structural)
    fixes, ctrls, intros = (by_class.get("security-fix", []), by_class.get("control", []),
                             by_class.get("introduced", []))

    rng = random.Random(seed)
    _, p_h1 = mann_whitney_u(fixes, ctrls)             # registered: fixes < controls
    eff_h1 = median(fixes) - median(ctrls)
    boot_h1 = bootstrap_two_sample_median_diff(fixes, ctrls, iters, rng)
    ci_h1 = (q(boot_h1, 0.025), q(boot_h1, 0.975))
    equiv_h1 = (p_h1 == p_h1 and p_h1 >= 0.01
                and abs(ci_h1[0]) <= 0.10 and abs(ci_h1[1]) <= 0.10)

    rng = random.Random(seed)  # fresh, deterministic per-item stream
    _, p_h2 = mann_whitney_u(ctrls, intros)            # registered: introduced > controls
    eff_h2 = median(intros) - median(ctrls)
    boot_h2 = bootstrap_two_sample_median_diff(intros, ctrls, iters, rng)
    ci_h2 = (q(boot_h2, 0.025), q(boot_h2, 0.975))
    equiv_h2 = (p_h2 == p_h2 and p_h2 >= 0.01
                and abs(ci_h2[0]) <= 0.10 and abs(ci_h2[1]) <= 0.10)

    # ---- N-RW1: exposure recall@20%LOC - LOC recall@20%LOC, per security-fix event
    fixes_ev = [e for e in data["events"] if e["class"] == "security-fix"]
    diffs, wins, losses, ties = [], 0, 0, 0
    for e in fixes_ev:
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            continue
        before, after = rows_for(con, parent), rows_for(con, child)
        if not before or not after:
            continue
        statuses = diff_statuses(repo, parent, child)
        implicated = {st["old_path"] for p, st in statuses.items()
                      if st["status"] == "touched" and st["old_path"] in before}
        if not implicated:
            continue
        loc = {p: (r["total_loc"] or 0) for p, r in before.items()}
        expo = {p: sum((r[f"risk_{c}"] or 0) for c in STRUCTURAL_COLUMNS) for p, r in before.items()}
        rank_expo = sorted(before, key=lambda p: (-expo[p], p))
        rank_loc = sorted(before, key=lambda p: (-loc[p], p))
        r_e = recall_at_budget(rank_expo, loc, implicated)
        r_l = recall_at_budget(rank_loc, loc, implicated)
        diffs.append(r_e - r_l)
        if r_e > r_l:
            wins += 1
        elif r_e < r_l:
            losses += 1
        else:
            ties += 1
    p_rw1 = sign_test(wins, losses)
    eff_rw1 = median(diffs)
    rng = random.Random(seed)
    boot_rw1 = bootstrap_paired_median(diffs, iters, rng)
    ci_rw1 = (q(boot_rw1, 0.025), q(boot_rw1, 0.975))
    equiv_rw1 = (p_rw1 == p_rw1 and p_rw1 >= 0.01
                 and abs(ci_rw1[0]) <= 0.05 and abs(ci_rw1[1]) <= 0.05)

    return {
        "skipped": dict(skipped),
        "N-H1": {"n_fix": len(fixes), "n_ctrl": len(ctrls), "median_fix": median(fixes),
                 "median_ctrl": median(ctrls), "effect": eff_h1, "p": p_h1, "ci95": ci_h1,
                 "delta": 0.10, "equivalent": equiv_h1, "n_boot": len(boot_h1)},
        "N-H2": {"n_intro": len(intros), "n_ctrl": len(ctrls), "median_intro": median(intros),
                 "median_ctrl": median(ctrls), "effect": eff_h2, "p": p_h2, "ci95": ci_h2,
                 "delta": 0.10, "equivalent": equiv_h2, "n_boot": len(boot_h2)},
        "N-RW1": {"n_events": len(diffs), "wins": wins, "losses": losses, "ties": ties,
                  "median_effect": eff_rw1, "p": p_rw1, "ci95": ci_rw1,
                  "delta": 0.05, "equivalent": equiv_rw1, "n_boot": len(boot_rw1)},
    }


# ==================================================================== report
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ndpi-events", default=str(EVENTS_DIR / "ndpi.json"))
    ap.add_argument("--curl-events", default=str(EVENTS_DIR / "curl.json"))
    ap.add_argument("--iters", type=int, default=ITERS)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--out", default=str(DOCS_DIR / "ndpi_stage2.md"))
    args = ap.parse_args()
    if args.iters < 5000:
        sys.exit("--iters must be >= 5000 (pre-registered floor)")

    ndpi_data = json.loads(pathlib.Path(args.ndpi_events).read_text())
    curl_data = json.loads(pathlib.Path(args.curl_events).read_text())
    ndpi_repo, ndpi_db, ndpi_con = open_db(ndpi_data["repo"])
    curl_repo, curl_db, curl_con = open_db(curl_data["repo"])

    print("running N-FIRST on nDPI (verdict)...", flush=True)
    r1_ndpi = n_first(ndpi_data, ndpi_repo, ndpi_con, "nDPI (verdict)", args.iters, args.seed)
    print("running N-FIRST on curl (exploratory context)...", flush=True)
    r1_curl = n_first(curl_data, curl_repo, curl_con, "curl (EXPLORATORY)", args.iters, args.seed)
    print("running D-H1'/D-H2' on nDPI...", flush=True)
    r2 = d_h1_prime(ndpi_data, ndpi_repo, ndpi_con)
    print("running equivalence/TOST battery on nDPI...", flush=True)
    r3 = equivalence_nulls(ndpi_data, ndpi_repo, ndpi_con, args.iters, args.seed)

    # ------------------------------------------------------------ write doc
    md = ["# nDPI Stage-2 — N-FIRST, D-H1', equivalence CIs\n"]
    md.append(
        "Stage-2 of the nDPI replication battery (gitgalaxy#2982, comment 5648589175; "
        "flagged as owed in `docs/HYPOTHESES.md` \"Repo #2 (nDPI) replication — RESULTS\"). "
        "Pre-registered; implemented verbatim; verdicts publish either way. DB opened "
        "read-only, WAL-aware (`file:{db}?mode=ro`). Bootstraps: seed "
        f"{args.seed}, {args.iters} iterations.\n"
    )

    # ---- N-FIRST -----------------------------------------------------------
    md.append("## N-FIRST — the first-CVE file profile\n")
    md.append(
        "Registered: among files at their FIRST CVE (security-fix) event, pre-event "
        "structural exposure separates them from size-matched never-CVE files better "
        "than chance (AUC). Positive = that file's parent-snapshot structural exposure "
        "(sum of `risk_<STRUCTURAL_COLUMNS>`) and `total_loc`; negative = a never-CVE "
        "file (never touched by any security-fix or introduced event, at any snapshot) "
        "from the same parent snapshot, size-matched within [0.66, 1.5]x total_loc "
        "(falling back to the date-nearest fix-event snapshot when the same snapshot "
        "has no candidate in range). **Age-matching is omitted** — no file-birth-time "
        "data is captured by this harness — a limitation of this test, not a design "
        "choice; report accordingly.\n"
    )
    md.append("Verdict rule: SUPPORTED iff AUC(exposure) > 0.5 AND the one-sided bootstrap "
              "lower bound at alpha=0.01 (1st percentile) excludes 0.5. A descriptive "
              "(two-sided) 95% CI is also shown.\n")
    md.append("| repo | role | first-CVE files | positives scanned | matched pairs "
              "(same/nearby/unmatched) | AUC(exposure) | AUC(LOC) | lift (expo−LOC) | "
              "verdict-bound lo (α=0.01) | 95% CI | verdict |")
    md.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in (r1_ndpi, r1_curl):
        if r.get("n_matched", 0) == 0:
            md.append(f"| {r['label']} | — | {r.get('n_first_cve_files','?')} | "
                      f"{r.get('n_positives','?')} | 0 | n/a | n/a | n/a | n/a | n/a | "
                      f"{r['verdict']} |")
            continue
        src = r["match_sources"]
        md.append(
            f"| {r['label']} | {'VERDICT' if 'nDPI' in r['label'] else 'context'} | "
            f"{r['n_first_cve_files']} | {r['n_positives']} | "
            f"{src.get('same-snapshot',0)}/{src.get('nearby-snapshot',0)}/{r['n_unmatched']} | "
            f"{fmt(r['auc_expo'])} | {fmt(r['auc_loc'])} | {fmt(r['lift'])} | "
            f"{fmt(r['verdict_lo_alpha01'])} | [{fmt(r['ci95'][0])}, {fmt(r['ci95'][1])}] | "
            f"**{r['verdict']}** |"
        )
    md.append("")
    md.append(f"nDPI: {r1_ndpi.get('missing_scan',0)} first-CVE files had no scanned parent-row "
              f"(excluded); skip reasons {r1_ndpi.get('n_cve_events_skipped',{})}. "
              f"curl: {r1_curl.get('missing_scan',0)} missing-scan; skip reasons "
              f"{r1_curl.get('n_cve_events_skipped',{})}. Bootstrap lift 95% CI — nDPI "
              f"[{fmt(r1_ndpi.get('lift_ci95',(float('nan'),)*2)[0])}, "
              f"{fmt(r1_ndpi.get('lift_ci95',(float('nan'),)*2)[1])}], curl "
              f"[{fmt(r1_curl.get('lift_ci95',(float('nan'),)*2)[0])}, "
              f"{fmt(r1_curl.get('lift_ci95',(float('nan'),)*2)[1])}].\n")
    md.append(f"**N-FIRST (nDPI, the verdict): {r1_ndpi['verdict']}.** curl reading is "
              f"**EXPLORATORY context only** (curl data already informed this program's "
              f"prior claims) — never a confirmatory test.\n")

    # ---- D-H1'/D-H2' ---------------------------------------------------------
    md.append("## D-H1' / D-H2' — branch-per-danger guard deficit (function grain, nDPI)\n")
    md.append(
        "Registered: guard rate = `struct_branch / (state_pointers + state_danger + "
        "state_memory_alloc + state_cast_hits + 1)`. D-H1': implicated functions (overlap "
        "the fix's changed parent-side lines) carry a LOWER rate than length-matched "
        "same-file siblings ([0.66, 1.5]x loc, same pairing gate as `signal_anatomy.py` "
        "Phase D). D-H2': the fix RAISES the implicated function's rate more than the "
        "sibling's (surviving, same-named functions only). One-sided MW, α=0.01.\n"
    )
    if r2["n_pairs"] == 0:
        md.append("No loc-matched implicated/sibling pairs found on nDPI — test could not run.\n")
    else:
        md.append("| metric | implicated median | sibling median | n pairs | p (one-sided) | verdict |")
        md.append("|---|---|---|---|---|---|")
        md.append(f"| guard rate (D-H1') | {fmt(r2['median_rate_implicated'],3)} | "
                  f"{fmt(r2['median_rate_sibling'],3)} | {r2['n_pairs']} | {fmt(r2['p_d1'])} | "
                  f"**{r2['verdict_d1']}** |")
        md.append(f"| danger load (control) | {fmt(r2['median_danger_implicated'],1)} | "
                  f"{fmt(r2['median_danger_sibling'],1)} | {r2['n_pairs']} | "
                  f"{fmt(r2['p_danger_control'])} | (context only) |")
        md.append(f"| guard-rate change after fix (D-H2') | "
                  f"{fmt(r2['median_chg_implicated'],4)} (n={r2['n_imp_chg']}) | "
                  f"{fmt(r2['median_chg_sibling'],4)} (n={r2['n_sib_chg']}) | {r2['n_pairs']} | "
                  f"{fmt(r2['p_d2'])} | **{r2['verdict_d2']}** |")
        md.append(f"\nEvents contributing an implicated function: {r2['n_events_with_hits']}; "
                  f"touched files with a hit: {r2['n_files_with_hits']}.\n")
    md.append(f"**D-H1': {r2['verdict_d1']} · D-H2': {r2['verdict_d2']}** (α=0.01, nDPI is "
              f"the verdict repo for this test).\n")

    # ---- Equivalence / TOST ---------------------------------------------------
    md.append("## Equivalence (TOST) read on the three replicated nulls (nDPI)\n")
    md.append(
        "For each: effect size + bootstrap 95% CI (percentile, seed "
        f"{args.seed}, n={args.iters}). \"Null replicated (equivalent)\" iff BOTH "
        "(a) non-significant at α=0.01 in curl's registered direction, AND (b) the 95% CI "
        "lies entirely within the pre-set δ. A flip to significant would be reported as a "
        "new signal, not hidden.\n"
    )
    md.append("| id | effect | n's | p (registered direction) | 95% CI | δ | equivalent? |")
    md.append("|---|---|---|---|---|---|---|")
    h1, h2, rw1 = r3["N-H1"], r3["N-H2"], r3["N-RW1"]
    md.append(f"| **N-H1** median(fix Δ) − median(ctrl Δ) | {fmt(h1['effect'])} | "
              f"fix={h1['n_fix']}, ctrl={h1['n_ctrl']} | {fmt(h1['p'])} | "
              f"[{fmt(h1['ci95'][0])}, {fmt(h1['ci95'][1])}] | ±{h1['delta']:.2f} | "
              f"{'**equivalent-null**' if h1['equivalent'] else 'not equivalent'} |")
    md.append(f"| **N-H2** median(intro Δ) − median(ctrl Δ) | {fmt(h2['effect'])} | "
              f"intro={h2['n_intro']}, ctrl={h2['n_ctrl']} | {fmt(h2['p'])} | "
              f"[{fmt(h2['ci95'][0])}, {fmt(h2['ci95'][1])}] | ±{h2['delta']:.2f} | "
              f"{'**equivalent-null**' if h2['equivalent'] else 'not equivalent'} |")
    md.append(f"| **N-RW1** median(recall_expo − recall_LOC) | {fmt(rw1['median_effect'])} | "
              f"events={rw1['n_events']} (W/L/T {rw1['wins']}/{rw1['losses']}/{rw1['ties']}) | "
              f"{fmt(rw1['p'])} | [{fmt(rw1['ci95'][0])}, {fmt(rw1['ci95'][1])}] | "
              f"±{rw1['delta']:.2f} | {'**equivalent-null**' if rw1['equivalent'] else 'not equivalent'} |")
    md.append(f"\nSkipped events (no usable touched-file diff): {r3['skipped']}.\n")

    md.append("---\n*Regenerate: `python tools/ndpi_stage2.py` — stdlib only, reads only the "
              "events files and the read-only history DBs; deterministic given `--seed` "
              "(default 2982) and `--iters` (default 5000, floor 5000).*")

    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")

    print(f"\nN-FIRST nDPI: AUC(expo)={r1_ndpi.get('auc_expo',float('nan')):.4f} "
          f"AUC(loc)={r1_ndpi.get('auc_loc',float('nan')):.4f} n={r1_ndpi.get('n_matched',0)} "
          f"-> {r1_ndpi['verdict']}")
    print(f"N-FIRST curl (exploratory): AUC(expo)={r1_curl.get('auc_expo',float('nan')):.4f} "
          f"AUC(loc)={r1_curl.get('auc_loc',float('nan')):.4f} n={r1_curl.get('n_matched',0)} "
          f"-> {r1_curl['verdict']}")
    print(f"D-H1' p={r2.get('p_d1',float('nan')):.4f} -> {r2['verdict_d1']} | "
          f"D-H2' p={r2.get('p_d2',float('nan')):.4f} -> {r2['verdict_d2']}")
    print(f"N-H1 equivalent={h1['equivalent']} | N-H2 equivalent={h2['equivalent']} | "
          f"N-RW1 equivalent={rw1['equivalent']}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
