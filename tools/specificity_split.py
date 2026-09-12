#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Held-out curl temporal-split specificity analysis (gitgalaxy#2982, comment
5648804679) — pre-registered design, implemented verbatim.

The question: does the RIGHT raw-exposure signal mark the RIGHT CWE failure
family, out of sample, beyond a plain line-count baseline? Every other rung-6
report in this repo evaluates in-sample (the same events inform direction and
verdict). This one temporally splits curl's own CWE-labeled security-fix
events at their median fix-commit date: the EARLIER half may only be looked
at for direction (no verdict drawn from it), the LATER half carries every
verdict. This is out-of-sample IN TIME within one repo — not a substitute for
a second repo (rung 7's job), but a real held-out test this repo can run on
itself.

Design (verbatim, do not deviate):
  - Events: events/curl.json, class security-fix with a cwe, plus class
    control (the negative pool). `introduced` events are not part of this
    design and are not loaded.
  - DB: dbs/curl_out/curl_galaxy_master.db, opened read-only WAL-aware
    (`sqlite3.connect(f"file:{db}?mode=ro", uri=True)`), never immutable.
  - Split at the MEDIAN fix-commit-date of the CWE-labeled security-fix
    events (repo_data.commit_date for each event's sha, one IN-query).
    Earlier half = derivation (direction only, no verdict). Later half =
    TEST (every verdict below is TEST-half only). The same boundary date is
    then applied to control events too, so the negative pool is temporally
    matched to the test window.
  - Families (delta_report.CWE_FAMILY) and their matched raw file_data
    signal sums (file grain, PARENT-snapshot row only — a file's standing
    before the event, not a delta):
      memory    = state_pointers + state_memory_alloc + state_cast_hits + state_danger
      cert/auth = arch_crypto + def_auth
      info-leak = arch_io + arch_api
    "other"/unlabeled CWEs are dropped from the confirmatory family rows
    (shown as context only) but still count as "non-F CVE files" background
    mass for the defect-lift negative set (b) — they are still real CVEs
    that are not family F.
  - Unit of resolution: touched files (signal_anatomy.parent_child +
    exposure_delta.diff_statuses; touched = status "touched" with old_path
    present in the parent snapshot and path present in the child snapshot,
    the same pattern signal_anatomy.py's main loop uses). Implicated files =
    those touched files, read at the PARENT snapshot only.
  - Metric (TEST half only): for family F, defect-lift = AUC(F-signal) -
    AUC(total_loc) for F-implicated files vs (a) control-implicated files
    and (b) non-F CVE-implicated files. AUC implemented directly (fraction
    of pos>neg pairs + 0.5*ties over n_pos*n_neg; the mid-rank formula this
    reduces to is reused from tools/rw_analyses.pooled_auc, already exact
    and tested in this repo). One-sided bootstrap over EVENTS (not files —
    an event's files are not independent draws), >=2000 iters (default
    5000). SUPPORTED iff lift>0 and the bootstrap lower bound at the
    Bonferroni-corrected one-sided alpha (0.01/3 across the 3 families)
    excludes 0. A separate, purely descriptive one-sided-95% lower bound
    (5th percentile) is also reported in the table alongside the stricter
    verdict bound — see the "CI note" in the generated doc for exactly which
    bound decides the verdict.
  - S-H0 discriminant: 3x3 confusion matrix, rows = families' positives,
    columns = the three matched signal-sets, cell = AUC of that column's
    signal vs controls (test half) for that row's positives. SUPPORTED iff
    every row's argmax is its own diagonal cell.

Usage:
    python tools/specificity_split.py [--events events/curl.json]
        [--db dbs/curl_out/curl_galaxy_master.db] [--iters 5000] [--seed 2982]
        [--out docs/specificity_curl_heldout.md]
"""
from __future__ import annotations

import argparse
import json
import math
import pathlib
import random
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from delta_report import CWE_FAMILY  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from rw_analyses import pooled_auc as auc  # noqa: E402
from scan_pair import resolve_repo  # noqa: E402
from signal_anatomy import file_rows, parent_child, signal_columns  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_EVENTS = REPO_ROOT / "events" / "curl.json"
DEFAULT_DB = REPO_ROOT / "dbs" / "curl_out" / "curl_galaxy_master.db"
DEFAULT_OUT = REPO_ROOT / "docs" / "specificity_curl_heldout.md"

FAMILIES = ["memory", "cert/auth", "info-leak"]
FAMILY_SIGNALS = {
    "memory": ["state_pointers", "state_memory_alloc", "state_cast_hits", "state_danger"],
    "cert/auth": ["arch_crypto", "def_auth"],
    "info-leak": ["arch_io", "arch_api"],
}
NEEDED_COLS = sorted({c for cols in FAMILY_SIGNALS.values() for c in cols})
COL_IDX = {c: i for i, c in enumerate(NEEDED_COLS)}

BONFERRONI_ALPHA = 0.01 / len(FAMILIES)  # verdict bound, family-wise corrected
DESCRIPTIVE_ALPHA = 0.05  # one-sided 95% lower bound, reported for context only
THIN_EVENT_FLOOR = 10  # fewer test-half positive EVENTS than this -> flag as underpowered


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def family_of(cwe):
    if not cwe:
        return "unlabeled"
    return CWE_FAMILY.get(cwe, "other")


def median_helper(xs):
    if not xs:
        return float("nan")
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def percentile(sorted_vals, p):
    """Linear-interpolation percentile, p in [0, 1]. `sorted_vals` must be sorted."""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


# ------------------------------------------------------------------ extraction
def commit_dates(con, shas):
    """repo_data.commit_date for every sha, one IN-query."""
    shas = list(dict.fromkeys(shas))
    q = f"SELECT commit_hash, commit_date FROM repo_data WHERE commit_hash IN ({','.join('?' * len(shas))})"
    return dict(con.execute(q, shas).fetchall())


def implicated_files(con, repo, sha):
    """(status, [file_rec, ...]) — touched files at the PARENT snapshot only.

    status is one of "ok", "root-commit" (no parent), "not-scanned"
    (parent/child missing from file_data), "no-touched-files".
    """
    parent, child = parent_child(repo, sha)
    if parent is None:
        return "root-commit", []
    before = file_rows(con, parent, NEEDED_COLS)
    after = file_rows(con, child, NEEDED_COLS)
    if not before or not after:
        return "not-scanned", []
    statuses = diff_statuses(repo, parent, child)
    touched = [(p, st) for p, st in statuses.items()
               if st["status"] == "touched" and p in after and st["old_path"] in before]
    if not touched:
        return "no-touched-files", []
    recs = []
    for path, st in touched:
        b = before[st["old_path"]]
        total_loc = b[1] or 0
        sums = {fam: sum((b[2 + COL_IDX[c]] or 0) for c in sigs)
                for fam, sigs in FAMILY_SIGNALS.items()}
        recs.append({"path": path, "total_loc": total_loc, **sums})
    return "ok", recs


# ------------------------------------------------------------------ bootstrap
def bootstrap_lifts(pos_events, neg_events, fam, n_iter, rng):
    """Resample EVENTS with replacement (an event's files are not independent
    draws); pool the resampled events' files; return the list of per-iteration
    lift = AUC(F-signal) - AUC(total_loc)."""
    n_pos, n_neg = len(pos_events), len(neg_events)
    lifts = []
    if n_pos == 0 or n_neg == 0:
        return lifts
    for _ in range(n_iter):
        samp_pos = [pos_events[rng.randrange(n_pos)] for _ in range(n_pos)]
        samp_neg = [neg_events[rng.randrange(n_neg)] for _ in range(n_neg)]
        pos_files = [f for ev in samp_pos for f in ev["files"]]
        neg_files = [f for ev in samp_neg for f in ev["files"]]
        if not pos_files or not neg_files:
            continue
        a_sig = auc([(f[fam], True) for f in pos_files] + [(f[fam], False) for f in neg_files])
        a_loc = auc([(f["total_loc"], True) for f in pos_files]
                    + [(f["total_loc"], False) for f in neg_files])
        if math.isnan(a_sig) or math.isnan(a_loc):
            continue
        lifts.append(a_sig - a_loc)
    return lifts


def defect_lift(pos_events, neg_events, fam, n_iter, rng):
    pos_files = [f for ev in pos_events for f in ev["files"]]
    neg_files = [f for ev in neg_events for f in ev["files"]]
    n_pos, n_neg = len(pos_files), len(neg_files)
    a_sig = auc([(f[fam], True) for f in pos_files] + [(f[fam], False) for f in neg_files])
    a_loc = auc([(f["total_loc"], True) for f in pos_files]
                + [(f["total_loc"], False) for f in neg_files])
    lift = a_sig - a_loc
    boots = sorted(bootstrap_lifts(pos_events, neg_events, fam, n_iter, rng))
    ci_desc_lo = percentile(boots, DESCRIPTIVE_ALPHA)
    ci_verdict_lo = percentile(boots, BONFERRONI_ALPHA)
    supported = (lift > 0) and (not math.isnan(ci_verdict_lo)) and (ci_verdict_lo > 0)
    return {
        "n_pos_events": len(pos_events), "n_neg_events": len(neg_events),
        "n_pos_files": n_pos, "n_neg_files": n_neg,
        "auc_signal": a_sig, "auc_loc": a_loc, "lift": lift,
        "n_boot": len(boots), "ci_desc_lo": ci_desc_lo, "ci_verdict_lo": ci_verdict_lo,
        "verdict": "SUPPORTED" if supported else "not supported",
    }


# ------------------------------------------------------------------ report
def fmt(x, nd=4):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default=str(DEFAULT_EVENTS))
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--iters", type=int, default=5000, help="bootstrap iterations (floor 2000)")
    ap.add_argument("--seed", type=int, default=2982)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()
    if args.iters < 2000:
        sys.exit("--iters must be >= 2000 (pre-registered floor)")

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    con = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)

    have = signal_columns(con, "file_data")
    missing = [c for c in NEEDED_COLS if c not in have]
    if missing:
        sys.exit(f"file_data is missing matched-signal columns: {missing}")

    fixes = [e for e in data["events"] if e["class"] == "security-fix" and e.get("cwe")]
    ctrls = [e for e in data["events"] if e["class"] == "control"]

    # ---- split: median fix-commit-date of the CWE-labeled security-fix events
    dates = commit_dates(con, [e["sha"] for e in fixes] + [e["sha"] for e in ctrls])
    missing_dates = [e["id"] for e in fixes + ctrls if e["sha"] not in dates]
    if missing_dates:
        sys.exit(f"no repo_data.commit_date for {len(missing_dates)} events, e.g. {missing_dates[:5]}")

    fix_dates_sorted = sorted(dates[e["sha"]] for e in fixes)
    n_fix = len(fix_dates_sorted)
    boundary_date = fix_dates_sorted[n_fix // 2]  # first TEST-half date, index split on n_fix

    def half_of(e):
        return "derivation" if dates[e["sha"]] < boundary_date else "test"

    # ---- resolve implicated files per event (file grain, parent snapshot)
    events_index = {}  # event_id -> {class, family, half, files}
    skip_reasons = Counter()
    for e in fixes + ctrls:
        status, recs = implicated_files(con, repo, e["sha"])
        if status != "ok":
            skip_reasons[f"{e['class']}: {status}"] += 1
            continue
        fam = family_of(e.get("cwe")) if e["class"] == "security-fix" else None
        events_index[e["id"]] = {
            "class": e["class"], "family": fam, "half": half_of(e), "files": recs,
        }

    def events_where(cls, half, family=None, exclude_family=None):
        out = []
        for ev in events_index.values():
            if ev["class"] != cls or ev["half"] != half:
                continue
            if family is not None and ev["family"] != family:
                continue
            if exclude_family is not None and ev["family"] == exclude_family:
                continue
            out.append(ev)
        return out

    # ---- per-family per-half event counts (context: 'other'/unlabeled included)
    all_fams_ctx = FAMILIES + ["other", "unlabeled"]
    counts = {half: {fam: len(events_where("security-fix", half, family=fam))
                     for fam in all_fams_ctx}
              for half in ("derivation", "test")}
    ctrl_counts = {half: len(events_where("control", half)) for half in ("derivation", "test")}

    # ---- defect-lift (TEST half only), families memory / cert-auth / info-leak
    rng = random.Random(args.seed)
    lift_results = {}  # fam -> {"a": {...vs controls...}, "b": {...vs non-F CVE...}}
    thin = []
    for fam in FAMILIES:
        pos_test = events_where("security-fix", "test", family=fam)
        if len(pos_test) < THIN_EVENT_FLOOR:
            thin.append((fam, len(pos_test)))
        neg_a = events_where("control", "test")
        neg_b = events_where("security-fix", "test", exclude_family=fam)
        lift_results[fam] = {
            "a": defect_lift(pos_test, neg_a, fam, args.iters, rng),
            "b": defect_lift(pos_test, neg_b, fam, args.iters, rng),
        }

    # ---- derivation-half direction-check (no verdict), vs controls only
    deriv_direction = {}
    for fam in FAMILIES:
        pos_d = events_where("security-fix", "derivation", family=fam)
        neg_d = events_where("control", "derivation")
        pos_files = [f for ev in pos_d for f in ev["files"]]
        neg_files = [f for ev in neg_d for f in ev["files"]]
        a_sig = auc([(f[fam], True) for f in pos_files] + [(f[fam], False) for f in neg_files])
        a_loc = auc([(f["total_loc"], True) for f in pos_files]
                    + [(f["total_loc"], False) for f in neg_files])
        deriv_direction[fam] = {
            "n_pos_events": len(pos_d), "n_neg_events": len(neg_d),
            "n_pos_files": len(pos_files), "n_neg_files": len(neg_files),
            "auc_signal": a_sig, "auc_loc": a_loc, "lift": a_sig - a_loc,
        }

    # ---- S-H0 discriminant: 3x3 confusion matrix (test half, vs controls)
    matrix = {}
    neg_ctrl_test = events_where("control", "test")
    neg_ctrl_files = [f for ev in neg_ctrl_test for f in ev["files"]]
    for row_fam in FAMILIES:
        pos_test = events_where("security-fix", "test", family=row_fam)
        pos_files = [f for ev in pos_test for f in ev["files"]]
        matrix[row_fam] = {}
        for col_fam in FAMILIES:
            matrix[row_fam][col_fam] = auc(
                [(f[col_fam], True) for f in pos_files]
                + [(f[col_fam], False) for f in neg_ctrl_files]
            )
    diagonal_ok = all(
        max(matrix[fam], key=lambda c: (matrix[fam][c] if not math.isnan(matrix[fam][c]) else -1)) == fam
        for fam in FAMILIES
    )

    # ---------------------------------------------------------------- write doc
    md = []
    md.append("# Specificity split — curl held-out temporal analysis\n")
    md.append(
        "Held-out curl temporal-split specificity analysis (gitgalaxy#2982, comment "
        "5648804679). Tests whether the RIGHT raw exposure signal marks the RIGHT CWE "
        "failure family, out-of-sample, beyond a plain line-count baseline.\n"
    )
    md.append(
        "**All verdicts below are TEST-half only.** This is temporal out-of-sample "
        "*within one repo* (curl split at its own median fix-commit date) — it is a "
        "genuine held-out test, but it is not a substitute for a second repo (that is "
        "repo #3's job). The derivation half is shown only for direction, never for a "
        "verdict.\n"
    )
    md.append(f"- Events file: `{pathlib.Path(args.events).name}` · DB: `{pathlib.Path(args.db).name}` "
              f"(opened read-only, WAL-aware)")
    md.append(f"- CWE-labeled security-fix events: {len(fixes)} · control events: {len(ctrls)}")
    md.append(f"- Skipped (no usable touched-file diff): "
              + (", ".join(f"{k} ({v})" for k, v in sorted(skip_reasons.items())) or "none"))
    md.append(f"- **Split boundary date: `{boundary_date}`** (index-median of the {n_fix} "
              f"CWE-labeled security-fix dates; earlier = derivation, `>=` boundary = test). "
              f"Same boundary applied to control events.\n")

    md.append("## Per-family event counts, both halves\n")
    md.append("`other`/unlabeled CWEs are dropped from the confirmatory family rows below "
              "(shown here as context only).\n")
    md.append("| family | derivation events | test events |")
    md.append("|---|---|---|")
    for fam in FAMILIES:
        md.append(f"| **{fam}** | {counts['derivation'][fam]} | {counts['test'][fam]} |")
    md.append(f"| other (context) | {counts['derivation']['other']} | {counts['test']['other']} |")
    md.append(f"| unlabeled (context) | {counts['derivation']['unlabeled']} | "
              f"{counts['test']['unlabeled']} |")
    md.append(f"| control (negative pool) | {ctrl_counts['derivation']} | {ctrl_counts['test']} |")
    md.append("")
    if thin:
        md.append("**Underpowered flag**: " + "; ".join(
            f"{fam} has only {n} test-half positive events (< {THIN_EVENT_FLOOR})"
            for fam, n in thin) + " — treat that family's verdict as low-power even if it "
            "clears the bound.\n")

    md.append("## Defect-lift beyond size (TEST half only)\n")
    md.append(
        f"defect-lift = AUC(matched-F-signal) − AUC(total_loc), file grain, parent-snapshot "
        f"scores. One-sided bootstrap over EVENTS (an event's files are not independent "
        f"draws), n={args.iters} iters (seed {args.seed}, floor 2000). **Verdict bound** is "
        f"the bootstrap lower percentile at the Bonferroni-corrected one-sided alpha "
        f"({BONFERRONI_ALPHA:.5f} = 0.01 / {len(FAMILIES)} families); SUPPORTED iff "
        f"lift > 0 AND that bound excludes 0. A separate, purely descriptive one-sided-95% "
        f"lower bound (5th percentile) is also shown for context — it is NOT what decides "
        f"the verdict.\n"
    )
    for fam in FAMILIES:
        md.append(f"### {fam}\n")
        md.append("| negative set | n_pos (events/files) | n_neg (events/files) | "
                  "AUC(signal) | AUC(LOC) | lift | verdict-bound lo "
                  f"(α={BONFERRONI_ALPHA:.5f}) | descriptive 95% lo | verdict |")
        md.append("|---|---|---|---|---|---|---|---|---|")
        for label, key in (("(a) controls", "a"), ("(b) non-F CVE", "b")):
            r = lift_results[fam][key]
            md.append(
                f"| {label} | {r['n_pos_events']}/{r['n_pos_files']} | "
                f"{r['n_neg_events']}/{r['n_neg_files']} | {fmt(r['auc_signal'])} | "
                f"{fmt(r['auc_loc'])} | {fmt(r['lift'])} | {fmt(r['ci_verdict_lo'])} | "
                f"{fmt(r['ci_desc_lo'])} | **{r['verdict']}** |"
            )
        md.append("")

    md.append("## Direction-check, no verdict (derivation half, vs controls)\n")
    md.append("| family | n_pos (events/files) | n_neg (events/files) | AUC(signal) | "
              "AUC(LOC) | lift |")
    md.append("|---|---|---|---|---|---|")
    for fam in FAMILIES:
        d = deriv_direction[fam]
        md.append(f"| {fam} | {d['n_pos_events']}/{d['n_pos_files']} | "
                  f"{d['n_neg_events']}/{d['n_neg_files']} | {fmt(d['auc_signal'])} | "
                  f"{fmt(d['auc_loc'])} | {fmt(d['lift'])} |")
    md.append("")

    md.append("## S-H0 — the specificity discriminant (TEST half, vs controls)\n")
    md.append("Confusion matrix: rows = a family's positives, columns = the three matched "
              "signal-sets. Cell = AUC of that column's signal-set for that row's positives "
              "vs controls. **SUPPORTED iff every row's argmax is its own diagonal cell** "
              "(a family's own matched signal ranks its own failures highest, not just "
              "*a* signal above chance).\n")
    md.append("| positives \\ signal-set | " + " | ".join(FAMILIES) + " |")
    md.append("|---|" + "---|" * len(FAMILIES))
    for row_fam in FAMILIES:
        cells = []
        for col_fam in FAMILIES:
            v = matrix[row_fam][col_fam]
            mark = "**" if col_fam == row_fam else ""
            cells.append(f"{mark}{fmt(v)}{mark}")
        md.append(f"| **{row_fam}** | " + " | ".join(cells) + " |")
    md.append(f"\n**S-H0: {'SUPPORTED' if diagonal_ok else 'not supported'}** — "
              f"{'every' if diagonal_ok else 'not every'} row's argmax lands on the diagonal.\n")

    md.append("---\n*Regenerate: `python tools/specificity_split.py` — stdlib only, reads "
              "only the events file and the read-only history DB; deterministic given "
              "`--seed` (default 2982). Bootstrap resamples EVENTS, not files.*")

    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")

    print(f"boundary date: {boundary_date} (n_fix={n_fix})")
    print(f"test-half counts: " + ", ".join(f"{fam}={counts['test'][fam]}" for fam in FAMILIES)
          + f", control={ctrl_counts['test']}")
    for fam in FAMILIES:
        for label, key in (("ctrl", "a"), ("nonF", "b")):
            r = lift_results[fam][key]
            print(f"  {fam} vs {label}: AUC(sig)={r['auc_signal']:.4f} AUC(loc)={r['auc_loc']:.4f} "
                  f"lift={r['lift']:.4f} verdict_lo={r['ci_verdict_lo']:.4f} -> {r['verdict']}")
    print(f"S-H0 diagonal: {diagonal_ok}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
