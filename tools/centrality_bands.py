#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Centrality-in-the-small-file-regime test (C-H1/C-H2) — PRE-REGISTERED
verbatim on gitgalaxy#2982, comment 5650157545, before this file existed.
Implemented verbatim; verdicts publish either way.

**The question.** repowise-bench's `centrality_experiment.py` found dependency
centrality PARKs in aggregate (flat-to-negative delta over their calibrated
model) but BEATS their shipped health score inside the small-file band —
their Q1 (<=22 LOC): PageRank AUC 0.73 vs shipped 0.53 — with the aggregate
wash explained by large bands (where most positives live) pulling the pooled
number down. Independently, this program's N-FIRST result found the one
structural component surviving size-control was centrality (AUC(density)
0.624, api_exposure-driven), and every metric tested here collapses in
exactly the small-file bands, always on 8-22 positives — never enough to
separate "no signal" from "no power". This test targets that gap directly.

**Data — no rescan, no engine change.** Centrality is already populated in
the scan DB. Unit = file present in a security-fix event's PARENT snapshot
(T0); positive = the fix touches it (diff_statuses parent..child, status
"touched", old_path present in the parent snapshot) — identical convention to
tools/incremental_value.py. The DB is opened read-only, WAL-aware
(`sqlite3.connect(f"file:{db}?mode=ro", uri=True)`).

**Measures** (`file_data`, read directly, no risk_/structural computation
needed): `pagerank_score`, `betweenness_score`, `popularity` (in-degree /
dependents), `import_count` (out-degree), `internal_dependency_links`.
Control: `total_loc`. **`normalized_blast_radius` is EXCLUDED** — verified
below to be exactly `pagerank_score * 1000` (checked over sampled rows: ratio
1000.0 in every case); including it would double-count the same signal as
`pagerank_score`, repeating the coupling-entropy redundancy error this
program has flagged before.

**Row builder — no process-feature walk.** Unlike incremental_value.py, this
test needs no `git log` history walk at all (centrality is a pure T0
structural read), so `collect_events` here is a leaner, walk-free sibling of
incremental_value.collect_events: same parent_child / diff_statuses / skip
semantics (reused so the two tools' event coverage is directly comparable),
but the row builder pulls the five centrality columns (+ total_loc) from
`file_data` at the parent commit instead of calling
`compute_process_features`. This is the "skip it (... or bypass
compute_process_features)" option named in the pre-registration.

**Bands.** Primary = repowise's absolute NLOC bands (<=22 / 23-48 / 49-108 /
>108), banding each row by its OWN `total_loc` — this is what makes our Q1
directly comparable to their 0.73. Secondary = this program's rank-quartile
convention (`incremental_value.rank_quartile_bands`), also banding by
`total_loc`, reported alongside. Both share one small extension of
`within_band_test`'s bootstrap design (`compute_band_stats` below): resample
the EVENT list, band membership fixed from the observed data, but track BOTH
AUC(measure) and AUC(total_loc) per resample so the LIFT (their difference)
has its own bootstrap distribution — `within_band_test` itself only tracks a
single score feature's AUC, not a lift, so a variant was needed rather than a
bare reuse.

**Tests** (one-sided bootstrap over EVENTS, 5000 iters, seed 2982, alpha=0.01):
  - Per measure x band: AUC(measure), AUC(total_loc), lift = AUC(measure) -
    AUC(total_loc), bootstrap lower bound on the lift, n, n_positives.
  - POWER RULE (registered): any band with n_positives < 20 gets NO verdict
    -- labeled UNDERPOWERED, never "not supported". Its AUC/lift are still
    reported descriptively.
  - C-H1: within the small bands (<=22, 23-48), at least one measure has
    AUC>0.5 AND lift>0 with the bootstrap lower bound excluding 0.
    Bonferroni across (measures x powered bands) -- see "effective alpha"
    design note below for how the family is scoped.
  - C-H2 (the shape claim): lift over total_loc decreases monotonically as
    band size increases. Reported as the lift-by-band series per measure
    plus a monotonicity read; see design note for the "any vs all measures"
    ambiguity resolution.
  - Descriptive, no verdict: pooled AUC per measure over all files.

    python tools/centrality_bands.py --events events/curl.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import random
import sqlite3
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, EVENTS_DIR  # noqa: E402
from delta_report import q  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from incremental_value import fmt, pooled_feature_auc, rank_quartile_bands  # noqa: E402
from rw_analyses import pooled_auc  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import parent_child  # noqa: E402

SEED = 2982
ITERS = 5000
ALPHA = 0.01
MIN_POS = 20  # registered power rule: n_positives < 20 in a band -> UNDERPOWERED, no verdict

CENTRALITY_COLUMNS = [
    "pagerank_score", "betweenness_score", "popularity",
    "import_count", "internal_dependency_links",
]
CONTROL_FEATURE = "total_loc"

ABS_CUTS = [22, 48, 108]
ABS_LABELS = ["<=22", "23-48", "49-108", ">108"]
N_BANDS = 4


# ------------------------------------------------------------------ DB plumbing
def centrality_snapshot(con: sqlite3.Connection, sha: str) -> dict[str, dict]:
    """path -> {total_loc, pagerank_score, betweenness_score, popularity,
    import_count, internal_dependency_links} at commit sha, read straight off
    `file_data` -- no risk_/structural aggregation needed for this test
    (contrast with incremental_value.structural_snapshot, which sums the
    STRUCTURAL_COLUMNS risk vector)."""
    cols = ", ".join(CENTRALITY_COLUMNS)
    rows = con.execute(
        f"SELECT file_path, total_loc, {cols} FROM file_data WHERE commit_hash = ?",
        (sha,),
    ).fetchall()
    out = {}
    for r in rows:
        rec = {"total_loc": r[1] or 0}
        for i, c in enumerate(CENTRALITY_COLUMNS):
            rec[c] = r[2 + i] if r[2 + i] is not None else 0.0
        out[r[0]] = rec
    return out


def verify_blast_radius_redundancy(con: sqlite3.Connection) -> dict:
    """Confirms normalized_blast_radius == pagerank_score * 1000 (the
    pre-registration's stated exclusion reason) over every non-null row in
    the DB, not just a sample -- so the doc can state this as checked, not
    assumed."""
    rows = con.execute(
        "SELECT pagerank_score, normalized_blast_radius FROM file_data "
        "WHERE pagerank_score IS NOT NULL AND normalized_blast_radius IS NOT NULL"
    ).fetchall()
    n = len(rows)
    bad = [(pr, nbr) for pr, nbr in rows if abs(nbr - pr * 1000) > 1e-6]
    return {"n_checked": n, "n_mismatch": len(bad), "sample_mismatch": bad[:5]}


# ------------------------------------------------------------------ event assembly (no process walk)
def collect_events(data: dict, repo: pathlib.Path, con: sqlite3.Connection):
    """Same event/skip semantics as incremental_value.collect_events
    (parent_child, structural_snapshot's read pattern, diff_statuses) but
    WITHOUT the git process-feature walk -- centrality is a pure T0
    structural read, so compute_process_features is never called. Returns
    (records, skip, walk_seconds); records[i]["rows"] = [{path, is_pos,
    total_loc, pagerank_score, betweenness_score, popularity, import_count,
    internal_dependency_links}, ...]."""
    skip: Counter = Counter()
    records = []
    t0 = time.time()
    for e in data["events"]:
        if e["class"] != "security-fix":
            continue
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            skip["root commit (no parent)"] += 1
            continue
        snap = centrality_snapshot(con, parent)
        if not snap:
            skip["parent not scanned in DB"] += 1
            continue
        statuses = diff_statuses(repo, parent, child)
        positives = {st["old_path"] for _p, st in statuses.items()
                     if st["status"] == "touched" and st["old_path"] in snap}
        if not positives:
            skip["no touched file present in parent snapshot"] += 1
            continue
        rows = []
        for path, rec in snap.items():
            row = {"path": path, "is_pos": path in positives, "total_loc": rec["total_loc"]}
            for c in CENTRALITY_COLUMNS:
                row[c] = rec[c]
            rows.append(row)
        records.append({"id": e["id"], "parent": parent, "n_files": len(snap),
                         "n_pos": len(positives), "rows": rows})
    walk_seconds = time.time() - t0
    return records, skip, walk_seconds


# ------------------------------------------------------------------ banding
def absolute_bands(values: list[float], cuts: list[float] = ABS_CUTS) -> list[int]:
    """Fixed absolute cut points -> band index (0-based), repowise's
    <=22 / 23-48 / 49-108 / >108 scheme. Unlike rank_quartile_bands, band
    sizes are NOT equal-count here by design -- that is the point (matching
    repowise's own bands for direct Q1 comparability)."""
    bands = []
    for v in values:
        b = len(cuts)
        for i, c in enumerate(cuts):
            if v <= c:
                b = i
                break
        bands.append(b)
    return bands


# ------------------------------------------------------------------ statistics
def band_membership(records, band_feature: str, banding_fn, n_bands: int):
    """Bands rows by `band_feature` (banding_fn decides how) and groups them
    by (event index, band) -- the fixed-from-observed-data membership that
    `within_band_test`'s bootstrap design requires (band assignment is NOT
    recomputed per resample). Also returns each band's (n, n_pos) -- an
    alpha-independent, measure-independent quantity (band membership doesn't
    depend on which centrality measure is later scored), so the Bonferroni
    family (measures x powered bands) can be sized BEFORE running any
    bootstrap at all."""
    flat = [(rec_i, r) for rec_i, rec in enumerate(records) for r in rec["rows"]]
    band_vals = [r[band_feature] for _rec_i, r in flat]
    bands = banding_fn(band_vals)
    per_event_band: dict[tuple[int, int], list[dict]] = defaultdict(list)
    for (rec_i, r), b in zip(flat, bands):
        per_event_band[(rec_i, b)].append(r)
    n_events = len(records)
    band_info = []
    for b in range(n_bands):
        pooled_rows = [r for rec_i in range(n_events) for r in per_event_band.get((rec_i, b), [])]
        band_info.append({"band": b, "n": len(pooled_rows),
                          "n_pos": sum(1 for r in pooled_rows if r["is_pos"])})
    return per_event_band, n_events, band_info


def bootstrap_cell(per_event_band, n_events: int, band: int, score_feature: str,
                    control_feature: str, iters: int, seed: int) -> dict:
    """A lift-tracking sibling of incremental_value.within_band_test: same
    "resample the event list, band membership fixed from observed data"
    bootstrap design, but at each resample it computes AUC(score_feature) AND
    AUC(control_feature) within the band and records their DIFFERENCE (the
    lift), not a single feature's AUC -- within_band_test has no lift
    concept, so this is the "small variant" the pre-registration calls for,
    reusing its exact resampling primitive rather than reimplementing it.
    This is the expensive step (5000 resamples x 2 AUCs); callers checkpoint
    its result to survive being run across several bounded invocations."""
    pooled_rows = [r for rec_i in range(n_events) for r in per_event_band.get((rec_i, band), [])]
    n_b = len(pooled_rows)
    n_pos_b = sum(1 for r in pooled_rows if r["is_pos"])
    obs_score = pooled_auc([(r[score_feature], r["is_pos"]) for r in pooled_rows])
    obs_control = pooled_auc([(r[control_feature], r["is_pos"]) for r in pooled_rows])
    obs_lift = (obs_score - obs_control) if (obs_score == obs_score and obs_control == obs_control) \
        else float("nan")

    rng = random.Random(seed + band)  # distinct, deterministic stream per band (matches within_band_test)
    boot = []
    for _ in range(iters):
        samp_idx = [rng.randrange(n_events) for _ in range(n_events)]
        samp_rows = [r for rec_i in samp_idx for r in per_event_band.get((rec_i, band), [])]
        a = pooled_auc([(r[score_feature], r["is_pos"]) for r in samp_rows])
        c = pooled_auc([(r[control_feature], r["is_pos"]) for r in samp_rows])
        if a == a and c == c:  # skip NaN (degenerate resample: a class missing)
            boot.append(a - c)
    boot.sort()
    return {"band": band, "n": n_b, "n_pos": n_pos_b,
            "auc_score": obs_score, "auc_control": obs_control, "lift": obs_lift,
            "boot": boot}


# ------------------------------------------------------------------ checkpoint cache
def load_cache(path: pathlib.Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_cache(path: pathlib.Path, cache: dict) -> None:
    path.write_text(json.dumps(cache))


def get_or_compute_cell(cache: dict, cache_path: pathlib.Path, scheme_name: str, feature: str,
                        band: int, per_event_band, n_events: int, control_feature: str,
                        iters: int, seed: int, alpha: float) -> dict:
    """Checkpointed wrapper around bootstrap_cell + apply_alpha: each
    (scheme, measure, band) cell is the unit of resumable work (roughly
    10-100s each here), flushed to `cache_path` immediately on completion so
    a run that gets cut off (this box kills long-lived background
    processes -- see docs/HYPOTHESES.md's operational notes) picks up
    mid-measure on the next invocation instead of restarting."""
    key = f"{scheme_name}|{feature}|{band}"
    if key in cache:
        return cache[key]
    raw = bootstrap_cell(per_event_band, n_events, band, feature, control_feature, iters, seed)
    cell = apply_alpha(raw, alpha)
    cell.pop("boot", None)
    cache[key] = cell
    save_cache(cache_path, cache)
    print(f"  [{scheme_name}] {feature} band {band}: n={cell['n']} n_pos={cell['n_pos']} "
          f"auc={fmt(cell['auc_score'])} lift={fmt(cell['lift'])} lo={fmt(cell['lo_bound'])} "
          f"verdict={cell['verdict']}", flush=True)
    return cell


def apply_alpha(cell: dict, alpha: float, min_pos: int = MIN_POS) -> dict:
    """Attach an alpha-specific lower bound / CI / verdict to a
    compute_band_stats cell. Power rule (registered): n_pos < min_pos ->
    UNDERPOWERED, never "not supported", regardless of what the point
    estimate looks like."""
    boot = cell["boot"]
    lo = q(boot, alpha) if boot else float("nan")
    ci95 = (q(boot, 0.025), q(boot, 0.975)) if boot else (float("nan"), float("nan"))
    powered = cell["n_pos"] >= min_pos
    if not powered:
        verdict = "UNDERPOWERED"
    else:
        ok = (cell["auc_score"] == cell["auc_score"] and cell["auc_score"] > 0.5
              and cell["lift"] == cell["lift"] and cell["lift"] > 0
              and lo == lo and lo > 0)
        verdict = "SUPPORTED" if ok else "not supported"
    return {**cell, "lo_bound": lo, "ci95": ci95, "alpha_used": alpha,
            "n_boot": len(boot), "powered": powered, "verdict": verdict}


def build_scheme_table(records, banding_fn, iters: int, seed: int, scheme_name: str,
                       cache: dict, cache_path: pathlib.Path) -> tuple[dict, float, int]:
    """Bands once (cheap), fixes the Bonferroni family (5 measures x powered
    bands IN THIS SCHEME) from that band membership BEFORE any bootstrap
    runs, then fills in each (measure, band) cell -- checkpointed, so a
    partially-completed scheme resumes instead of restarting. Returns
    {measure: [4 band-cell dicts]}, alpha_eff, n_powered."""
    per_event_band, n_events, band_info = band_membership(records, CONTROL_FEATURE, banding_fn, N_BANDS)
    n_powered = sum(1 for bi in band_info if bi["n_pos"] >= MIN_POS)
    alpha_eff = ALPHA / (len(CENTRALITY_COLUMNS) * n_powered) if n_powered else ALPHA
    table = {}
    for feat in CENTRALITY_COLUMNS:
        table[feat] = [
            get_or_compute_cell(cache, cache_path, scheme_name, feat, b, per_event_band,
                                n_events, CONTROL_FEATURE, iters, seed, alpha_eff)
            for b in range(N_BANDS)
        ]
    return table, alpha_eff, n_powered


# ------------------------------------------------------------------ report
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default=str(EVENTS_DIR / "curl.json"))
    ap.add_argument("--out", default=str(DOCS_DIR / "centrality_bands.md"))
    ap.add_argument("--iters", type=int, default=ITERS)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--cache", default=None,
                    help="checkpoint file for completed (scheme,measure,band) bootstrap "
                         "cells -- the 5000-iter x 5-measure x 2-scheme x 4-band bootstrap "
                         "is the expensive part of this tool; resuming from cache lets it "
                         "survive being run across several bounded invocations. Defaults to "
                         "a scratchpad file keyed by events basename/iters/seed.")
    args = ap.parse_args()
    if args.iters < 5000:
        sys.exit("--iters must be >= 5000 (pre-registered floor)")

    cache_path = pathlib.Path(args.cache) if args.cache else pathlib.Path(
        f"/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/"
        f"scratchpad/centrality_bands_cache_"
        f"{pathlib.Path(args.events).stem}_i{args.iters}_s{args.seed}.json")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = load_cache(cache_path)
    print(f"checkpoint cache: {cache_path} ({len(cache)} cells already done)", flush=True)

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)

    blast_check = verify_blast_radius_redundancy(con)

    print(f"collecting centrality snapshots for {data['repo']} events "
          f"(no process-feature walk)...", flush=True)
    records, skip, walk_s = collect_events(data, repo, con)
    flat_rows = [r for rec in records for r in rec["rows"]]
    n_files_total = len(flat_rows)
    n_pos_total = sum(1 for r in flat_rows if r["is_pos"])
    print(f"events usable: {len(records)} | skipped: {dict(skip)} | "
          f"pooled files: {n_files_total} | pooled positives: {n_pos_total} | "
          f"wall-time: {walk_s:.2f}s", flush=True)

    # ---- coverage / degeneracy check ------------------------------------
    coverage = {}
    for feat in CENTRALITY_COLUMNS:
        nz_all = sum(1 for r in flat_rows if r[feat])
        nz_pos = sum(1 for r in flat_rows if r["is_pos"] and r[feat])
        coverage[feat] = {
            "nz_all": nz_all,
            "pct_all": (nz_all / n_files_total * 100) if n_files_total else float("nan"),
            "nz_pos": nz_pos,
            "pct_pos": (nz_pos / n_pos_total * 100) if n_pos_total else float("nan"),
        }

    # ---- descriptive pooled AUC per measure ------------------------------
    pooled = []
    for feat in CENTRALITY_COLUMNS + [CONTROL_FEATURE]:
        auc, pos, neg = pooled_feature_auc(records, feat)
        pooled.append({"feature": feat, "auc": auc, "n_pos": pos, "n_neg": neg})
    pooled_ranked = sorted(pooled, key=lambda r: (r["auc"] if r["auc"] == r["auc"] else -1),
                           reverse=True)

    # ---- primary: absolute NLOC bands -----------------------------------
    print(f"running primary (absolute NLOC) bands x {len(CENTRALITY_COLUMNS)} measures "
          f"({args.iters} boot iters x {N_BANDS} bands each)...", flush=True)
    t0 = time.time()
    abs_table, alpha_eff_abs, n_powered_abs = build_scheme_table(
        records, absolute_bands, args.iters, args.seed, "abs", cache, cache_path)
    abs_s = time.time() - t0

    # ---- secondary: rank-quartile bands -----------------------------------
    print(f"running secondary (rank-quartile) bands x {len(CENTRALITY_COLUMNS)} measures...",
          flush=True)
    t0 = time.time()
    rank_table, alpha_eff_rank, n_powered_rank = build_scheme_table(
        records, rank_quartile_bands, args.iters, args.seed, "rank", cache, cache_path)
    rank_s = time.time() - t0

    # ---- C-H1: within small bands (<=22, 23-48), any measure clears -----
    small_band_idx = [0, 1]  # <=22, 23-48
    small_cells = [(feat, b, abs_table[feat][b]) for feat in CENTRALITY_COLUMNS for b in small_band_idx]
    small_powered = [c for _f, _b, c in small_cells if c["powered"]]
    small_supported = [c for _f, _b, c in small_cells if c["verdict"] == "SUPPORTED"]
    if not small_powered:
        ch1_verdict = "UNDERPOWERED"
    elif small_supported:
        ch1_verdict = "SUPPORTED"
    else:
        ch1_verdict = "not supported"

    # ---- C-H2: lift monotonically decreases as band size increases ------
    ch2_series = {}
    ch2_monotone = {}
    for feat in CENTRALITY_COLUMNS:
        lifts = [abs_table[feat][b]["lift"] for b in range(N_BANDS)]
        ch2_series[feat] = lifts
        if any(v != v for v in lifts):
            ch2_monotone[feat] = None  # undefined: NaN in series
        else:
            ch2_monotone[feat] = all(lifts[i] >= lifts[i + 1] for i in range(N_BANDS - 1))
    any_monotone = any(v for v in ch2_monotone.values() if v is not None)
    all_monotone = all(ch2_monotone.values()) if all(v is not None for v in ch2_monotone.values()) else False
    n_monotone = sum(1 for v in ch2_monotone.values() if v)
    ch2_verdict_any = "SUPPORTED" if any_monotone else "not supported"
    ch2_verdict_all = "SUPPORTED" if all_monotone else "not supported"

    # ---- headline: pagerank in the <=22 band -----------------------------
    pr_small = abs_table["pagerank_score"][0]  # band 0 = <=22
    pr_small_loc_auc = pr_small["auc_control"]

    # ------------------------------------------------------------ write doc
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    md = ["# Centrality in the small-file regime — does it beat LOC where files are small?\n"]
    md.append(
        f"Generated {now} · repo `{data['repo']}` · pool HEAD `{data['pool_head'][:12]}` · "
        f"DB `{pathlib.Path(db).name}` (opened read-only, WAL-aware) · pre-registered "
        "gitgalaxy#2982 comment 5650157545; implemented verbatim; verdicts publish "
        "either way.\n"
    )

    md.append("## Design\n")
    md.append(
        "Unit = file present in a security-fix event's **parent** snapshot (T0); positive = "
        "the fix touches it (`diff_statuses` parent..child, status \"touched\", old_path "
        "present in the parent snapshot) — identical convention to `tools/incremental_value.py`. "
        "No rescan: centrality is already populated in the scan DB. Unlike incremental_value.py "
        "this test needs **no `git log` process-feature walk** — centrality is a pure T0 "
        "structural read — so `collect_events` here is a leaner, walk-free sibling (same "
        "parent_child / diff_statuses / skip semantics, reused directly).\n"
    )
    md.append(
        f"Coverage: **{len(records)}** security-fix events usable (of "
        f"{sum(1 for e in data['events'] if e['class'] == 'security-fix')} in the event set); "
        f"skipped — {dict(skip) if skip else '(none)'}. Pooled candidate files: "
        f"**{n_files_total}**, pooled positives: **{n_pos_total}**. Wall-time: {walk_s:.2f}s "
        "(no history walk, so this is fast by construction).\n"
    )

    md.append("## Measures and the `normalized_blast_radius` exclusion\n")
    md.append(
        f"Measures: `pagerank_score`, `betweenness_score`, `popularity` (in-degree/dependents), "
        f"`import_count` (out-degree), `internal_dependency_links`. Control: `total_loc`. "
        f"**`normalized_blast_radius` is excluded** — verified over every non-null row in the "
        f"DB ({blast_check['n_checked']} rows checked): `normalized_blast_radius == "
        f"pagerank_score * 1000` in {blast_check['n_checked'] - blast_check['n_mismatch']}/"
        f"{blast_check['n_checked']} rows"
        + (f" ({blast_check['n_mismatch']} mismatches, e.g. {blast_check['sample_mismatch']})"
           if blast_check["n_mismatch"] else " — exact, no mismatches")
        + ". Including it alongside `pagerank_score` would double-count the same signal, "
        "repeating this program's earlier coupling-entropy redundancy error.\n"
    )

    md.append("## Coverage / degeneracy check\n")
    md.append(
        "Nonzero rate of each measure, pooled over all candidate files and separately over "
        "positives only — a measure that is near-always zero cannot carry much signal no "
        "matter what its AUC says.\n"
    )
    md.append("| measure | nonzero (all files) | nonzero (positives only) |")
    md.append("|---|---|---|")
    for feat in CENTRALITY_COLUMNS:
        c = coverage[feat]
        md.append(
            f"| `{feat}` | {c['nz_all']}/{n_files_total} ({fmt(c['pct_all'], 1)}%) | "
            f"{c['nz_pos']}/{n_pos_total} ({fmt(c['pct_pos'], 1)}%) |"
        )
    degenerate = [f for f in CENTRALITY_COLUMNS if coverage[f]["pct_all"] < 15]
    if degenerate:
        md.append(
            f"\n**Flagged as sparse:** " + ", ".join(f"`{f}`" for f in degenerate) +
            " — nonzero in well under a majority of files; any AUC computed on these mixes "
            "real discrimination with a large tied-at-zero block, and low positive coverage "
            "in particular caps how much of the pooled signal that measure can possibly "
            "explain. Reported, not hidden.\n"
        )

    md.append("## Descriptive — pooled AUC per measure (no verdict)\n")
    md.append("| rank | feature | AUC | n positives | n negatives |")
    md.append("|---|---|---|---|---|")
    for i, r in enumerate(pooled_ranked, 1):
        md.append(f"| {i} | `{r['feature']}` | {fmt(r['auc'], 4)} | {r['n_pos']} | {r['n_neg']} |")

    def scheme_section(title, table, alpha_eff, n_powered, band_labels, compute_s):
        out = [f"## {title}\n"]
        out.append(
            f"Bootstrap: {args.iters} iters over the EVENT list, seed {args.seed}+band-offset, "
            f"band membership fixed from observed data. **Effective alpha (Bonferroni across "
            f"{len(CENTRALITY_COLUMNS)} measures x {n_powered} powered band"
            f"{'s' if n_powered != 1 else ''} in this scheme): "
            f"{ALPHA}/({len(CENTRALITY_COLUMNS)}x{n_powered}) = {alpha_eff:.6f}**"
            + (" (no band in this scheme is powered — alpha shown is the unadjusted floor, "
               "unused since every cell is UNDERPOWERED)" if n_powered == 0 else "")
            + f". Compute time: {compute_s:.1f}s.\n"
        )
        for feat in CENTRALITY_COLUMNS:
            out.append(f"### `{feat}` vs `total_loc`\n")
            out.append("| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | "
                       "boot lower bound | 95% CI (lift) | verdict |")
            out.append("|---|---|---|---|---|---|---|---|---|")
            for b, cell in enumerate(table[feat]):
                out.append(
                    f"| {band_labels[b]} | {cell['n']} | {cell['n_pos']} | "
                    f"{fmt(cell['auc_score'])} | {fmt(cell['auc_control'])} | "
                    f"{fmt(cell['lift'])} | {fmt(cell['lo_bound'])} | "
                    f"[{fmt(cell['ci95'][0])}, {fmt(cell['ci95'][1])}] | "
                    f"{'**' + cell['verdict'] + '**' if cell['verdict'] == 'SUPPORTED' else cell['verdict']} |"
                )
            out.append("")
        return out

    rank_labels = [f"Q{b+1} (rank quartile of total_loc)" for b in range(N_BANDS)]
    md += scheme_section("Primary — absolute NLOC bands (repowise scheme)",
                         abs_table, alpha_eff_abs, n_powered_abs, ABS_LABELS, abs_s)
    md += scheme_section("Secondary — rank-quartile bands (this program's convention)",
                         rank_table, alpha_eff_rank, n_powered_rank, rank_labels, rank_s)

    md.append("## C-H1 — does at least one measure beat `total_loc` in a small band?\n")
    md.append(
        f"**Claim**: within the small-file bands (`<=22`, `23-48`, absolute scheme), at least "
        f"one of the 5 centrality measures has AUC>0.5 AND lift>0 with the bootstrap lower "
        f"bound (at the Bonferroni-adjusted alpha {alpha_eff_abs:.6f}) excluding 0.\n"
    )
    md.append("| measure | band | n | n pos | AUC | lift | lower bound | powered | verdict |")
    md.append("|---|---|---|---|---|---|---|---|---|")
    for feat, b, cell in small_cells:
        md.append(
            f"| `{feat}` | {ABS_LABELS[b]} | {cell['n']} | {cell['n_pos']} | "
            f"{fmt(cell['auc_score'])} | {fmt(cell['lift'])} | {fmt(cell['lo_bound'])} | "
            f"{'yes' if cell['powered'] else 'no'} | "
            f"{'**' + cell['verdict'] + '**' if cell['verdict'] == 'SUPPORTED' else cell['verdict']} |"
        )
    md.append(f"\n**C-H1: {'**' + ch1_verdict + '**' if ch1_verdict != 'not supported' else ch1_verdict}.** "
              + (f"{len(small_supported)}/{len(small_cells)} (measure, small-band) cells clear the "
                 f"Bonferroni bound." if small_powered else
                 "Neither small band clears the n_positives>=20 power floor for any measure — "
                 "per the registered power rule this is reported as UNDERPOWERED, not as a null.")
              + "\n")

    md.append("## C-H2 — does the lift concentrate in small files? (the shape claim)\n")
    md.append(
        "**Claim**: `lift = AUC(measure) - AUC(total_loc)` decreases monotonically as the "
        "absolute band's file-size ceiling increases (`<=22` -> `23-48` -> `49-108` -> `>108`). "
        "The pre-registration does not state whether the claim needs ANY measure to show this "
        "shape or ALL of them — both readings are reported, following this repo's own "
        "convention for resolving that exact ambiguity in `tools/incremental_value.py`.\n"
    )
    md.append("| measure | lift `<=22` | lift `23-48` | lift `49-108` | lift `>108` | monotone non-increasing? |")
    md.append("|---|---|---|---|---|---|")
    for feat in CENTRALITY_COLUMNS:
        lifts = ch2_series[feat]
        mono = ch2_monotone[feat]
        mono_s = "n/a (NaN in series)" if mono is None else ("**yes**" if mono else "no")
        md.append(f"| `{feat}` | " + " | ".join(fmt(v) for v in lifts) + f" | {mono_s} |")
    md.append(
        f"\n**C-H2: {n_monotone}/{len(CENTRALITY_COLUMNS)} measures show a strictly monotone "
        f"non-increasing lift-by-band series.** Reading (any measure): "
        f"{'**' + ch2_verdict_any + '**' if ch2_verdict_any == 'SUPPORTED' else ch2_verdict_any} · "
        f"reading (all measures): "
        f"{'**' + ch2_verdict_all + '**' if ch2_verdict_all == 'SUPPORTED' else ch2_verdict_all}.\n"
    )

    md.append("## The headline number\n")
    md.append(
        f"**PageRank in the `<=22` band: AUC = {fmt(pr_small['auc_score'])}** vs "
        f"AUC(`total_loc`) = {fmt(pr_small_loc_auc)} in the same band (lift = "
        f"{fmt(pr_small['lift'])}, n={pr_small['n']}, n_pos={pr_small['n_pos']}, "
        f"{'powered' if pr_small['powered'] else 'UNDERPOWERED'}).\n"
    )
    md.append(
        "**Comparison to repowise's Q1**: their PageRank AUC 0.73 vs their shipped score's "
        f"0.53 inside Q1 (<=22 LOC). Here, PageRank's AUC against `total_loc` specifically "
        f"(not their 24-biomarker shipped score, which is a different, richer baseline) is "
        f"{fmt(pr_small['auc_score'])} vs {fmt(pr_small_loc_auc)} — "
        + ("the same direction as their result: centrality separates positives from "
           "non-positives noticeably better than raw LOC does, right where repowise says the "
           "signal lives."
           if pr_small["lift"] == pr_small["lift"] and pr_small["lift"] > 0 else
           "the OPPOSITE direction from their result: LOC is at least as strong as PageRank "
           "here, in the same nominal band where repowise reports its win.")
        + " Note the baselines differ (`total_loc` here vs their full shipped composite there), "
        "so this is a directional cross-check, not a literal reproduction of their 0.73/0.53 "
        "pair.\n"
    )

    md.append("## Design notes / ambiguity resolutions\n")
    md.append(
        "- **Effective alpha is scoped per banding scheme, over ALL 4 bands in that scheme, "
        "not just the two small bands named in C-H1.** The pre-registration says \"Bonferroni "
        "across (measures x powered bands)\" without restricting the band count to the small "
        "ones; scoping the correction to the full primary table (5 measures x however many of "
        "the 4 absolute bands are powered) is the more conservative reading and keeps one "
        "consistent threshold for every cell in a given table, rather than requiring two "
        "different lower-bound numbers for the same small-band cells depending on which claim "
        "is being read off them.\n"
        "- **C-H2's \"any vs all measures\" reading is genuinely ambiguous** in the "
        "registration text (which says \"centrality's lift... decreases monotonically\", "
        "singular) — both readings are reported per test rather than silently picking one, "
        "mirroring `tools/incremental_value.py`'s own resolution of the identical ambiguity "
        "for IV-H1/IV-H2.\n"
        "- **Band membership (both schemes) is by each row's own `total_loc`**, not by any "
        "centrality measure — this is what repowise's absolute scheme means by \"small files\", "
        "and it is what keeps the two schemes (absolute cut points vs rank quartiles) directly "
        "comparable to each other, since they band the same underlying quantity two different "
        "ways.\n"
        "- **`AUC(total_loc)` inside a `total_loc`-banded group is attenuated toward 0.5 by "
        "construction** (narrower bands compress the LOC range available to discriminate on) "
        "— the same effect this program flagged in the N-FIRST analysis "
        "(`docs/HYPOTHESES.md`, \"AUC(LOC)~=0.50 is forced by matching\"). The lift figure "
        "already nets this out; the raw `AUC(total_loc)` column is reported for transparency, "
        "not as a fair independent baseline read in isolation.\n"
        "- **No process-feature git walk.** Centrality columns are read once per event's "
        "parent commit directly from `file_data`; `compute_process_features` "
        "(`tools/incremental_value.py`) is never called, per the pre-registration's explicit "
        "permission to skip it entirely.\n"
    )

    md.append("---\n*Regenerate: `python tools/centrality_bands.py --events events/curl.json` "
              "— stdlib only, no rescan, no git history walk.*")

    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")

    print(f"\nblast-radius redundancy check: {blast_check['n_checked']} rows, "
          f"{blast_check['n_mismatch']} mismatches")
    print(f"pooled AUC ranking: " + ", ".join(f"{r['feature']}={fmt(r['auc'])}" for r in pooled_ranked))
    print(f"C-H1: {ch1_verdict} (effective alpha abs scheme = {alpha_eff_abs:.6f}, "
          f"n_powered_abs_bands={n_powered_abs})")
    print(f"C-H2: any={ch2_verdict_any} all={ch2_verdict_all} "
          f"({n_monotone}/{len(CENTRALITY_COLUMNS)} monotone)")
    print(f"headline: pagerank <=22 AUC={fmt(pr_small['auc_score'])} vs "
          f"total_loc AUC={fmt(pr_small_loc_auc)} (lift={fmt(pr_small['lift'])}, "
          f"n={pr_small['n']}, n_pos={pr_small['n_pos']}, powered={pr_small['powered']})")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
