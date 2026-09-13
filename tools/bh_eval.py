#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Overnight bug-label expansion (B-H1..B-H3) — PRE-REGISTERED verbatim on
gitgalaxy#2982, comment 5651082895, before this file existed. Implemented
verbatim; verdicts publish either way.

**The question.** C-H1/C-H2 (tools/centrality_bands.py) and HV-H1/HV-H3
(tools/hcm_variants.py) ran on curl's CVE-fix labels, where the small-file
NLOC bands (<=22, 23-48) are chronically underpowered (1-4 positives). This
program's own richer defect census (`Fixes #<n>` / `Bug: <url>` / commit
messages containing "regression") pools three label classes — 307 regression
+ 500 `Fixes #` + 300 `Bug:` commits, 1,107 unique events after SHA dedup —
to power those bands, and gives HCM1_LD_30 (the winner of the CVE-label
sweep, hcm_variants.py) an out-of-selection check on data it was not chosen
against.

**Data — no rescan, no engine change.** Per-class counts (307/500/300) match
the events file (`events/curl_bugs.json`) exactly; `class` is single-valued
per event (`labels` is the list-valued multi-label field used for the
Phase-M exploratory question elsewhere, not for this test — pooling here
means: treat all three classes as one positive population, not: filter by
label). Unit = file present in an event's **parent** snapshot (T0); positive
= the fix touches it (`diff_statuses` parent..child, status "touched",
old_path present in the parent snapshot) — identical convention to
`tools/incremental_value.py` / `tools/centrality_bands.py`. The DB
(`dbs/curl_out/curl_galaxy_master.db`) is opened read-only, WAL-aware
(`sqlite3.connect(f"file:{db}?mode=ro", uri=True)`); all 1,107 events' parent
+ child snapshots are already scanned (0 failures) — this tool reads only,
never scans.

**B-H1 — the powered small-file centrality test.** Absolute NLOC bands
(<=22 / 23-48 / 49-108 / >108, `centrality_bands.absolute_bands`'s cut
points, reused not reimplemented). Within each **powered** small band
(<=22, 23-48; power rule: n_positives<20 -> UNDERPOWERED, no verdict), for
each of the 5 centrality measures (`pagerank_score`, `betweenness_score`,
`popularity`, `import_count`, `internal_dependency_links`;
`normalized_blast_radius` excluded — verified redundant with
`pagerank_score` in `centrality_bands.py`, not re-verified here since the
measures are read from the same DB columns): AUC(measure), AUC(total_loc),
lift = their difference, one-sided event-bootstrap (5000 iters) lower bound
on the lift, Bonferroni alpha = 0.01/(5 x n_powered_small_bands) — **the
correction family is scoped to the two SMALL bands only**, per the
pre-registration text's literal "5 x n_powered_small_bands" (unlike
`centrality_bands.py`'s own C-H1, which scopes its family to all 4 bands as
a stated ambiguity resolution — no ambiguity here, the text is explicit).
SUPPORTED iff >=1 measure clears AUC>0.5 AND lift lower bound>0 in EACH
powered small band (AND-across-bands / OR-across-measures: each powered
small band must have its own qualifying measure, not necessarily the same
one). The two large bands (49-108, >108) are also computed, at the same
small-band alpha, for context and reuse by B-H2 — NOT part of the B-H1
Bonferroni family or its verdict.

**B-H2 — the monotone shape (confirmatory).** PageRank only, all 4 absolute
bands, ONE JOINT bootstrap: each resample draws ONE set of resampled events
and computes all 4 bands' lifts from that SAME draw (unlike B-H1's
per-cell-independent resampling) so the three adjacent comparisons (lift
band0>band1>band2>band3) are evaluated on correlated draws. SUPPORTED iff
all three adjacent decreases hold in >=99% of the 5000 resamples.

**B-H3 — HCM out-of-selection validation.** `HCM1_LD_30` (attribution HCM1
= p_i*H share-weighted, decay LD = linear max(0,1-age_days/365), period=30d)
is **computed by calling `hcm_variants.raw_commit_walk` and
`hcm_variants.compute_all_variants` directly and reading out the
`HCM1_LD_30` key** — not reimplemented, so it is frozen byte-for-byte
identical to its CVE-label definition. Walk cache (`hcmwalk_cache/`, keyed
by parent sha) is the SAME directory `hcm_variants.py` uses, reused
verbatim; new parents from this event set just add entries. Pooled over ALL
files in all parent snapshots (no banding): AUC(HCM1_LD_30), AUC(total_loc),
lift, one-sided 5000-iter event-bootstrap lower bound (alpha=0.01, single
comparison, no Bonferroni). SUPPORTED iff lift>0 and the bound excludes 0.

**Scale (~1,100 events x ~2,300 files ~= 2.5M pooled rows) and the numpy
engine.** The pure-Python sort-based AUC (`rw_analyses.pooled_auc`, used by
every earlier tool in this repo) does not finish at this scale. `auc_numpy`
reimplements the identical mid-rank Mann-Whitney formula
(`AUC = (rank_sum_pos - n_pos*(n_pos+1)/2) / (n_pos*n_neg)`, ties -> average
rank) via `numpy` argsort + `bincount`-grouped tie averaging — verified
against `rw_analyses.pooled_auc` on 20 randomized tie-heavy trials before
this file was written (exact match, <1e-9). The bootstrap precomputes, per
(banding scheme, band), a "compacted" pooled array per feature (rows in
that band, contiguous per event, in event order) plus each event's (start,
size) into that array; `ragged_gather_indices` turns a per-resample list of
chosen event indices into the concatenated row-index array in pure numpy
(no per-event Python-level concatenation loop).

**Multiprocessing (added per orchestrator amendment, 12-core box).** A
`multiprocessing.get_context("fork").Pool(processes=--workers, default 10)`
is created in the PARENT after the per-band/pooled numpy arrays are built
and stashed in module-level globals (`_BAND_POOLS`/`_ALL_POOL`/`_N_EVENTS`)
— Linux fork gives every worker a copy-on-write view of those arrays with
no pickling per task; only small scalar task tuples cross the pool boundary.
  - **B-H1** parallelizes ACROSS CELLS: each of the 5 measures x 4 bands =
    20 (measure, band) cells is one task, each running its OWN full serial
    `--iters`-length bootstrap inside a worker (`_worker_bh1_cell`); results
    stream back via `imap_unordered` and the PARENT writes the checkpoint
    cache as each result lands — workers never touch the cache file. Each
    cell gets a distinct deterministic seed
    `base_seed + feat_idx*4 + band` (documented so `bh1|<feat>|<band>` is
    reproducible standalone, replacing the earlier single-process draft's
    accidental one-seed-for-every-cell bug).
  - **B-H2/B-H3** parallelize ACROSS RESAMPLE CHUNKS: `--iters` is split into
    `--workers` chunks (5000/10 = 500 each by default); each chunk runs in
    its own worker with seed `base_seed + 1000*chunk_id`
    (`_worker_chunk_joint` / `_worker_chunk_lift`) and returns only its raw
    per-iteration lift array(s); the parent `np.concatenate`s all chunks
    into the full bootstrap distribution before computing percentiles /
    the monotonicity fraction. This is a fixed, reproducible substitute for
    a single serial RNG stream, not a claim that it produces bit-identical
    draws to a serial run at the same seed — what matters is that it is
    itself fixed and rerunnable.

**Checkpointing.** Every expensive unit (one B-H1 cell, the B-H2 joint
bootstrap, the B-H3 pooled bootstrap) is cached to
`scratchpad/bh_eval_cache_<events-stem>_i<iters>_s<seed>[_lim<N>].json`
immediately on completion — a NEW cache file, never the CVE-label runs'
caches (`centrality_bands_cache_*.json`; `hcmwalk_cache/` IS shared by
design per the pre-registration, everything else is not). The `_lim<N>`
suffix (only present with `--limit`) keeps the sanity-subset run's cache
from colliding with the full run's — the default (unlimited) invocation
produces exactly `bh_eval_cache_curl_bugs_i5000_s2982.json`.

    python tools/bh_eval.py --events events/curl_bugs.json
    python tools/bh_eval.py --events events/curl_bugs.json --limit 30   # sanity subset
"""
from __future__ import annotations

import argparse
import datetime
import json
import multiprocessing
import pathlib
import sqlite3
import sys
import time
from collections import Counter

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from centrality_bands import (  # noqa: E402
    ABS_CUTS, ABS_LABELS, CENTRALITY_COLUMNS, MIN_POS,
    centrality_snapshot,
)
from exposure_delta import diff_statuses  # noqa: E402
from hcm_variants import HCMWALK_CACHE, compute_all_variants, raw_commit_walk  # noqa: E402
from incremental_value import LOG_COMMIT_CAP, WINDOW_DAYS, fmt  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import parent_child  # noqa: E402
from _engine import DOCS_DIR, EVENTS_DIR  # noqa: E402

SEED = 2982
ITERS = 5000
ALPHA = 0.01
N_ABS_BANDS = 4
SMALL_BAND_IDX = [0, 1]  # <=22, 23-48
HCM_VARIANT = "HCM1_LD_30"
HCM_FEATURE = "hcm1_ld_30"  # row-dict / numpy-column key for the same quantity
CLASS_SET = {"regression", "bugfix-fixes", "bugfix-bug"}
N_WORKERS_DEFAULT = 10

SCRATCH_DIR = pathlib.Path(
    "/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad"
)


# ================================================================== event assembly
def collect_events(data: dict, repo: pathlib.Path, con: sqlite3.Connection,
                    class_set: set, window_days: int, commit_cap: int,
                    limit: int | None = None):
    """Local collect_events variant (per the pre-registration's data note):
    accepts a CLASS SET rather than incremental_value.collect_events's
    hardcoded `e["class"] != "security-fix"` filter, so the three bug-label
    classes can be pooled as one positive population. Row builder pulls both
    the 5 centrality columns (`centrality_bands.centrality_snapshot`, no
    reimplementation) AND HCM1_LD_30 (via `hcm_variants.raw_commit_walk` +
    `compute_all_variants`, same leakage-free ancestors-only walk shape,
    same on-disk cache). Returns (records, skip, walk_seconds)."""
    skip: Counter = Counter()
    records = []
    t0 = time.time()
    n_seen = 0
    for e in data["events"]:
        if e["class"] not in class_set:
            continue
        if limit is not None and n_seen >= limit:
            break
        n_seen += 1
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
        walk = raw_commit_walk(repo, parent, window_days, commit_cap)
        variant_scores = compute_all_variants(walk["commits"], walk["parent_epoch"], window_days)
        hcm = variant_scores[HCM_VARIANT]
        rows = []
        for path, rec in snap.items():
            row = {
                "path": path, "is_pos": path in positives,
                "total_loc": rec["total_loc"], HCM_FEATURE: hcm.get(path, 0.0),
            }
            for c in CENTRALITY_COLUMNS:
                row[c] = rec[c]
            rows.append(row)
        records.append({"id": e["id"], "class": e["class"], "parent": parent,
                         "n_files": len(snap), "n_pos": len(positives), "rows": rows})
    walk_seconds = time.time() - t0
    return records, skip, walk_seconds


# ================================================================== numpy AUC engine
def auc_numpy(scores: np.ndarray, labels: np.ndarray) -> float:
    """Mid-rank Mann-Whitney AUC, numpy-vectorized. Identical formula to
    rw_analyses.pooled_auc (AUC = (rank_sum_pos - n_pos*(n_pos+1)/2) /
    (n_pos*n_neg), ties -> average rank) -- verified against it on 20
    randomized tie-heavy trials before this file was written."""
    n = scores.size
    n_pos = int(labels.sum())
    n_neg = n - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = np.argsort(scores)
    s_sorted = scores[order]
    labels_sorted = labels[order]
    pos_rank_positions = np.arange(1, n + 1, dtype=np.float64)
    change = np.empty(n, dtype=bool)
    change[0] = True
    if n > 1:
        change[1:] = s_sorted[1:] != s_sorted[:-1]
    group_id = np.cumsum(change) - 1
    sums = np.bincount(group_id, weights=pos_rank_positions)
    counts = np.bincount(group_id)
    avg_rank = sums / counts
    ranks = avg_rank[group_id]
    rank_sum_pos = ranks[labels_sorted].sum()
    return float((rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def percentile_q(sorted_arr: np.ndarray, frac: float) -> float:
    """Same nearest-rank method as delta_report.q (not linear interpolation),
    applied to an already-ascending-sorted numpy array."""
    if sorted_arr.size == 0:
        return float("nan")
    i = int(round(frac * (sorted_arr.size - 1)))
    i = max(0, min(sorted_arr.size - 1, i))
    return float(sorted_arr[i])


def ragged_gather_indices(starts: np.ndarray, sizes: np.ndarray) -> np.ndarray:
    """Given `starts`/`sizes` describing a (possibly-repeated, possibly-zero)
    list of chosen groups into some pooled array, returns the concatenated
    row-index array -- the "precompute per-event row slices as numpy arrays"
    vectorization the pre-registration's scale note asks for: this replaces
    a per-resample Python-level loop building `np.concatenate([...])` over
    ~1000 event slices with one vectorized cumsum/repeat pass."""
    mask = sizes > 0
    starts = starts[mask]
    sizes = sizes[mask]
    if starts.size == 0:
        return np.empty(0, dtype=np.int64)
    cum = np.cumsum(sizes)
    total = int(cum[-1])
    flags = np.zeros(total, dtype=np.int64)
    flags[cum[:-1]] = 1
    group_id = np.cumsum(flags)
    group_offset0 = cum - sizes
    offset_in_group = np.arange(total, dtype=np.int64) - group_offset0[group_id]
    return np.repeat(starts, sizes) + offset_in_group


def event_offsets(event_id: np.ndarray, n_events: int) -> tuple[np.ndarray, np.ndarray]:
    """event_id (row -> originating event index, rows already contiguous per
    event) -> (start, size) per event index 0..n_events-1 into that pooled
    array (size 0 for an event with no rows in this pool)."""
    sizes = np.bincount(event_id, minlength=n_events).astype(np.int64)
    starts = np.concatenate(([0], np.cumsum(sizes)[:-1])).astype(np.int64)
    return starts, sizes


def flatten_records(records: list, feature_names: list[str]):
    """records[i]["rows"] (list of per-file dicts, event order preserved) ->
    parallel numpy arrays (total_loc, is_pos, event_id, {feature: array}),
    rows contiguous per event (required by event_offsets/ragged_gather)."""
    total_loc_l, is_pos_l, event_id_l = [], [], []
    feat_l = {f: [] for f in feature_names}
    for ei, rec in enumerate(records):
        for r in rec["rows"]:
            total_loc_l.append(r["total_loc"])
            is_pos_l.append(r["is_pos"])
            event_id_l.append(ei)
            for f in feature_names:
                feat_l[f].append(r[f])
    total_loc = np.asarray(total_loc_l, dtype=np.float64)
    is_pos = np.asarray(is_pos_l, dtype=bool)
    event_id = np.asarray(event_id_l, dtype=np.int64)
    feats = {f: np.asarray(v, dtype=np.float64) for f, v in feat_l.items()}
    return total_loc, is_pos, event_id, feats


def band_pool(mask: np.ndarray, total_loc: np.ndarray, is_pos: np.ndarray,
              event_id: np.ndarray, feats: dict, n_events: int):
    """Compact the flat pooled arrays down to `mask`'s rows (event order
    preserved) and compute that subset's (start, size) per event -- one
    "BandArrays" unit reused by the B-H1 per-band cells and B-H2's joint
    bootstrap alike."""
    tl = total_loc[mask]
    ip = is_pos[mask]
    eid = event_id[mask]
    fs = {f: v[mask] for f, v in feats.items()}
    starts, sizes = event_offsets(eid, n_events)
    return {"total_loc": tl, "is_pos": ip, "feats": fs, "starts": starts, "sizes": sizes,
            "n": int(tl.size), "n_pos": int(ip.sum())}


def chunk_sizes(total: int, n_chunks: int) -> list[int]:
    base, rem = divmod(total, n_chunks)
    return [base + (1 if i < rem else 0) for i in range(n_chunks)]


# ================================================================== bootstrap engine
def bootstrap_chunk_lift(measure_pool: np.ndarray, control_pool: np.ndarray,
                          is_pos_pool: np.ndarray, starts: np.ndarray, sizes: np.ndarray,
                          n_events: int, iters_chunk: int, seed: int) -> np.ndarray:
    """One chunk (or the whole run, if iters_chunk==total) of the lift
    bootstrap: returns the raw per-iteration lift array, NaN where a
    resample degenerated (a class vanished). No percentile/verdict work
    here -- that happens once, in the parent, after all chunks (possibly
    from different worker processes) are concatenated."""
    rng = np.random.default_rng(seed)
    boot = np.full(iters_chunk, np.nan, dtype=np.float64)
    for it in range(iters_chunk):
        chosen = rng.integers(0, n_events, n_events)
        idx = ragged_gather_indices(starts[chosen], sizes[chosen])
        if idx.size == 0:
            continue
        am = auc_numpy(measure_pool[idx], is_pos_pool[idx])
        ac = auc_numpy(control_pool[idx], is_pos_pool[idx])
        if am == am and ac == ac:
            boot[it] = am - ac
    return boot


def finalize_lift_cell(n: int, n_pos: int, obs_auc_m: float, obs_auc_c: float,
                        boot: np.ndarray, alpha: float, min_pos: int = MIN_POS) -> dict:
    """Observed stats + a (possibly multi-chunk-merged) raw bootstrap array
    -> the full reported cell (lo_bound, CI, power rule, verdict)."""
    obs_lift = (obs_auc_m - obs_auc_c) if (obs_auc_m == obs_auc_m and obs_auc_c == obs_auc_c) \
        else float("nan")
    valid = np.sort(boot[~np.isnan(boot)])
    lo = percentile_q(valid, alpha)
    ci95 = (percentile_q(valid, 0.025), percentile_q(valid, 0.975))
    powered = n_pos >= min_pos
    if not powered:
        verdict = "UNDERPOWERED"
    else:
        ok = (obs_auc_m == obs_auc_m and obs_auc_m > 0.5
              and obs_lift == obs_lift and obs_lift > 0
              and lo == lo and lo > 0)
        verdict = "SUPPORTED" if ok else "not supported"
    return {"n": int(n), "n_pos": int(n_pos), "auc_score": obs_auc_m, "auc_control": obs_auc_c,
            "lift": obs_lift, "lo_bound": lo, "ci95": ci95, "alpha_used": alpha,
            "n_boot": int(valid.size), "powered": powered, "verdict": verdict}


def bootstrap_lift_cell(measure_pool: np.ndarray, control_pool: np.ndarray,
                         is_pos_pool: np.ndarray, starts: np.ndarray, sizes: np.ndarray,
                         n_events: int, iters: int, seed: int, alpha: float,
                         min_pos: int = MIN_POS) -> dict:
    """A single cell's FULL serial bootstrap (used by each B-H1 worker task,
    one cell per call, one seed per call)."""
    n = measure_pool.size
    n_pos = int(is_pos_pool.sum())
    obs_auc_m = auc_numpy(measure_pool, is_pos_pool)
    obs_auc_c = auc_numpy(control_pool, is_pos_pool)
    boot = bootstrap_chunk_lift(measure_pool, control_pool, is_pos_pool, starts, sizes,
                                n_events, iters, seed)
    return finalize_lift_cell(n, n_pos, obs_auc_m, obs_auc_c, boot, alpha, min_pos)


def bh1_cell_seed(base_seed: int, feat_idx: int, band: int) -> int:
    """Distinct, deterministic per-(measure,band) seed for B-H1 -- each cell
    is one independent worker task, so each needs its own RNG stream (a
    single shared seed across all 20 cells would make every cell replay the
    identical resampled-event sequence, which is not wrong per cell but
    departs from every sibling tool's "distinct stream per unit" convention
    and would not parallelize meaningfully differently from a serial run)."""
    return base_seed + feat_idx * N_ABS_BANDS + band


# ============================================================ multiprocessing workers
# Populated in the PARENT, before Pool() creation, so `fork` gives every
# worker a copy-on-write view with zero pickling of the (multi-hundred-MB)
# per-band arrays -- only the small task tuples below cross the pool boundary.
_BAND_POOLS: list | None = None
_ALL_POOL: dict | None = None
_N_EVENTS: int | None = None


def _set_worker_globals(band_pools: list, all_pool: dict, n_events: int) -> None:
    global _BAND_POOLS, _ALL_POOL, _N_EVENTS
    _BAND_POOLS, _ALL_POOL, _N_EVENTS = band_pools, all_pool, n_events


def _worker_bh1_cell(task):
    feat, b, iters, seed, alpha, min_pos = task
    bp = _BAND_POOLS[b]
    t0 = time.time()
    cell = bootstrap_lift_cell(bp["feats"][feat], bp["total_loc"], bp["is_pos"],
                               bp["starts"], bp["sizes"], _N_EVENTS, iters, seed, alpha, min_pos)
    cell["compute_s"] = time.time() - t0
    return feat, b, cell


def _worker_chunk_lift(task):
    """B-H3 chunk worker: one band-pool key ("all" for the pooled/unbanded
    population), one feature, iters_chunk resamples, one seed -> raw lift
    array for this chunk only."""
    pool_key, feature, iters_chunk, seed = task
    bp = _ALL_POOL if pool_key == "all" else _BAND_POOLS[pool_key]
    return bootstrap_chunk_lift(bp["feats"][feature], bp["total_loc"], bp["is_pos"],
                                bp["starts"], bp["sizes"], _N_EVENTS, iters_chunk, seed)


def _worker_chunk_joint(task):
    """B-H2 chunk worker: iters_chunk resamples, EACH iteration drawing ONE
    shared resampled-event set applied to all 4 bands (joint/correlated
    within an iteration, the whole point of B-H2) -> (iters_chunk, 4) lift
    array for this chunk only."""
    iters_chunk, seed = task
    pr_bands = [bp["feats"]["pagerank_score"] for bp in _BAND_POOLS]
    ctrl_bands = [bp["total_loc"] for bp in _BAND_POOLS]
    pos_bands = [bp["is_pos"] for bp in _BAND_POOLS]
    starts_bands = [bp["starts"] for bp in _BAND_POOLS]
    sizes_bands = [bp["sizes"] for bp in _BAND_POOLS]
    rng = np.random.default_rng(seed)
    lifts = np.full((iters_chunk, 4), np.nan, dtype=np.float64)
    for it in range(iters_chunk):
        chosen = rng.integers(0, _N_EVENTS, _N_EVENTS)
        for b in range(4):
            idx = ragged_gather_indices(starts_bands[b][chosen], sizes_bands[b][chosen])
            if idx.size == 0:
                continue
            am = auc_numpy(pr_bands[b][idx], pos_bands[b][idx])
            ac = auc_numpy(ctrl_bands[b][idx], pos_bands[b][idx])
            if am == am and ac == ac:
                lifts[it, b] = am - ac
    return lifts


# ================================================================== checkpoint cache
def load_cache(path: pathlib.Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_cache(path: pathlib.Path, cache: dict) -> None:
    path.write_text(json.dumps(cache))


def _jsonable(cell: dict) -> dict:
    out = {}
    for k, v in cell.items():
        if isinstance(v, tuple):
            out[k] = list(v)
        elif isinstance(v, (np.floating, np.integer)):
            out[k] = v.item()
        else:
            out[k] = v
    return out


# ================================================================== report
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default=str(EVENTS_DIR / "curl_bugs.json"))
    ap.add_argument("--out", default=str(DOCS_DIR / "bh_eval.md"))
    ap.add_argument("--iters", type=int, default=ITERS)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--window-days", type=int, default=WINDOW_DAYS)
    ap.add_argument("--commit-cap", type=int, default=LOG_COMMIT_CAP)
    ap.add_argument("--limit", type=int, default=None,
                    help="use only the first N class-matching events (sanity subset runs)")
    ap.add_argument("--workers", type=int, default=N_WORKERS_DEFAULT,
                    help="fork-pool size: B-H1 parallelizes across (measure,band) cells, "
                         "B-H2/B-H3 across resample chunks of this many workers")
    ap.add_argument("--cache", default=None)
    args = ap.parse_args()
    if args.iters < 5000:
        sys.exit("--iters must be >= 5000 (pre-registered floor)")

    stem = pathlib.Path(args.events).stem
    lim_suffix = f"_lim{args.limit}" if args.limit is not None else ""
    cache_path = pathlib.Path(args.cache) if args.cache else SCRATCH_DIR / (
        f"bh_eval_cache_{stem}_i{args.iters}_s{args.seed}{lim_suffix}.json")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = load_cache(cache_path)
    print(f"checkpoint cache: {cache_path} ({len(cache)} cells already done)", flush=True)

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)

    class_counts_file = Counter(e["class"] for e in data["events"])
    print(f"events file class counts: {dict(class_counts_file)} "
          f"(pre-registration: regression=307, bugfix-fixes=500, bugfix-bug=300)", flush=True)

    print(f"collecting events for {data['repo']} (classes={sorted(CLASS_SET)}"
          f"{f', limit={args.limit}' if args.limit else ''})...", flush=True)
    records, skip, walk_s = collect_events(
        data, repo, con, CLASS_SET, args.window_days, args.commit_cap, args.limit)
    n_files_total = sum(rec["n_files"] for rec in records)
    n_pos_total = sum(rec["n_pos"] for rec in records)
    n_events_matching = sum(1 for e in data["events"] if e["class"] in CLASS_SET)
    print(f"events usable: {len(records)} (of {n_events_matching} class-matching"
          f"{f', limited to first ' + str(args.limit) if args.limit else ''}) | "
          f"skipped: {dict(skip)} | pooled files: {n_files_total} | "
          f"pooled positives: {n_pos_total} | walk wall-time: {walk_s:.1f}s", flush=True)

    if not records:
        sys.exit("no usable events -- aborting")

    # ---- flatten to numpy pooled arrays -----------------------------------
    feature_names = CENTRALITY_COLUMNS + [HCM_FEATURE]
    t0 = time.time()
    total_loc, is_pos, event_id, feats = flatten_records(records, feature_names)
    n_events = len(records)
    flatten_s = time.time() - t0
    print(f"flattened {total_loc.size} pooled rows across {n_events} events "
          f"({flatten_s:.1f}s)", flush=True)

    band_labels = np.searchsorted(np.asarray(ABS_CUTS, dtype=np.float64), total_loc, side="left")
    band_pools = [band_pool(band_labels == b, total_loc, is_pos, event_id, feats, n_events)
                  for b in range(N_ABS_BANDS)]
    all_pool = band_pool(np.ones_like(total_loc, dtype=bool), total_loc, is_pos, event_id,
                          feats, n_events)

    n_pos_by_band = [bp["n_pos"] for bp in band_pools]
    n_by_band = [bp["n"] for bp in band_pools]
    print("band sizes (n / n_pos): " +
          ", ".join(f"{ABS_LABELS[b]}={n_by_band[b]}/{n_pos_by_band[b]}"
                    for b in range(N_ABS_BANDS)), flush=True)

    n_powered_small = sum(1 for b in SMALL_BAND_IDX if n_pos_by_band[b] >= MIN_POS)
    alpha_eff_bh1 = ALPHA / (len(CENTRALITY_COLUMNS) * n_powered_small) if n_powered_small \
        else ALPHA

    # ---- fork pool: created AFTER the big arrays exist, so workers inherit
    # them via copy-on-write with zero pickling ------------------------------
    _set_worker_globals(band_pools, all_pool, n_events)
    ctx = multiprocessing.get_context("fork")
    pool = ctx.Pool(processes=args.workers)
    print(f"fork pool: {args.workers} workers", flush=True)

    try:
        # ---- B-H1: 20 (measure, band) cells, parallel across cells --------
        print(f"running B-H1 ({len(CENTRALITY_COLUMNS)} measures x {N_ABS_BANDS} bands, "
              f"{args.iters} iters each, alpha_eff={alpha_eff_bh1:.6f} "
              f"[n_powered_small_bands={n_powered_small}])...", flush=True)
        bh1_table: dict[str, list] = {feat: [None] * N_ABS_BANDS for feat in CENTRALITY_COLUMNS}
        tasks = []
        for feat_idx, feat in enumerate(CENTRALITY_COLUMNS):
            for b in range(N_ABS_BANDS):
                key = f"bh1|{feat}|{b}"
                if key in cache:
                    cell = cache[key]
                    bh1_table[feat][b] = cell
                    print(f"  [B-H1] {feat} {ABS_LABELS[b]}: CACHED n={cell['n']} "
                          f"n_pos={cell['n_pos']} auc={fmt(cell['auc_score'])} "
                          f"lift={fmt(cell['lift'])} verdict={cell['verdict']}", flush=True)
                    continue
                seed = bh1_cell_seed(args.seed, feat_idx, b)
                tasks.append((feat, b, args.iters, seed, alpha_eff_bh1, MIN_POS))

        if tasks:
            for feat, b, cell in pool.imap_unordered(_worker_bh1_cell, tasks):
                key = f"bh1|{feat}|{b}"
                cache[key] = _jsonable(cell)
                save_cache(cache_path, cache)
                bh1_table[feat][b] = cache[key]
                print(f"  [B-H1] {feat} {ABS_LABELS[b]}: n={cell['n']} n_pos={cell['n_pos']} "
                      f"auc={fmt(cell['auc_score'])} lift={fmt(cell['lift'])} "
                      f"lo={fmt(cell['lo_bound'])} verdict={cell['verdict']} "
                      f"({cell.get('compute_s', 0):.2f}s)", flush=True)

        # B-H1 verdict: for EACH powered small band, does >=1 measure clear?
        small_band_status = {}
        for b in SMALL_BAND_IDX:
            if n_pos_by_band[b] < MIN_POS:
                small_band_status[b] = "UNDERPOWERED"
                continue
            clears = any(bh1_table[feat][b]["verdict"] == "SUPPORTED" for feat in CENTRALITY_COLUMNS)
            small_band_status[b] = "SUPPORTED" if clears else "not supported"
        powered_small_statuses = [v for v in small_band_status.values() if v != "UNDERPOWERED"]
        if not powered_small_statuses:
            bh1_verdict = "UNDERPOWERED"
        elif all(v == "SUPPORTED" for v in powered_small_statuses):
            bh1_verdict = "SUPPORTED"
        else:
            bh1_verdict = "not supported"

        # ---- B-H2: joint bootstrap, PageRank, all 4 bands, chunked --------
        print(f"running B-H2 (joint bootstrap, pagerank_score, {N_ABS_BANDS} bands, "
              f"{args.iters} iters across {args.workers} chunks)...", flush=True)
        if "bh2_joint_pagerank" in cache:
            bh2 = cache["bh2_joint_pagerank"]
            print(f"  [B-H2] CACHED lifts={[fmt(v) for v in bh2['obs_lifts']]} "
                  f"frac_monotone={fmt(bh2['frac_monotone'])} "
                  f"verdict={'SUPPORTED' if bh2['supported'] else 'not supported'}", flush=True)
        else:
            t0 = time.time()
            obs_lifts = []
            for b in range(N_ABS_BANDS):
                bp = band_pools[b]
                am = auc_numpy(bp["feats"]["pagerank_score"], bp["is_pos"])
                ac = auc_numpy(bp["total_loc"], bp["is_pos"])
                obs_lifts.append((am - ac) if (am == am and ac == ac) else float("nan"))
            sizes = chunk_sizes(args.iters, args.workers)
            tasks = [(sz, args.seed + 1000 * i) for i, sz in enumerate(sizes)]
            lift_chunks = pool.map(_worker_chunk_joint, tasks)
            combined = np.concatenate(lift_chunks, axis=0)
            valid = combined[~np.isnan(combined).any(axis=1)]
            if valid.shape[0] == 0:
                frac_monotone = float("nan")
            else:
                monotone = ((valid[:, 0] > valid[:, 1]) & (valid[:, 1] > valid[:, 2])
                            & (valid[:, 2] > valid[:, 3]))
                frac_monotone = float(monotone.mean())
            supported = frac_monotone == frac_monotone and frac_monotone >= 0.99
            bh2 = {"obs_lifts": obs_lifts, "n_valid": int(valid.shape[0]), "n_iters": args.iters,
                   "frac_monotone": frac_monotone, "supported": supported,
                   "compute_s": time.time() - t0}
            cache["bh2_joint_pagerank"] = _jsonable(bh2)
            save_cache(cache_path, cache)
            print(f"  [B-H2] lifts={[fmt(v) for v in bh2['obs_lifts']]} "
                  f"frac_monotone={fmt(bh2['frac_monotone'])} "
                  f"n_valid={bh2['n_valid']}/{bh2['n_iters']} "
                  f"verdict={'SUPPORTED' if bh2['supported'] else 'not supported'} "
                  f"({bh2['compute_s']:.2f}s)", flush=True)

        # ---- B-H3: pooled HCM1_LD_30 vs total_loc, no banding, chunked ----
        print(f"running B-H3 (pooled, HCM1_LD_30 vs total_loc, {args.iters} iters across "
              f"{args.workers} chunks, n={all_pool['n']} n_pos={all_pool['n_pos']})...",
              flush=True)
        if "bh3_hcm1_ld_30" in cache:
            bh3 = cache["bh3_hcm1_ld_30"]
        else:
            t0 = time.time()
            obs_auc_m = auc_numpy(all_pool["feats"][HCM_FEATURE], all_pool["is_pos"])
            obs_auc_c = auc_numpy(all_pool["total_loc"], all_pool["is_pos"])
            sizes = chunk_sizes(args.iters, args.workers)
            tasks = [("all", HCM_FEATURE, sz, args.seed + 1000 * i) for i, sz in enumerate(sizes)]
            boot_chunks = pool.map(_worker_chunk_lift, tasks)
            combined = np.concatenate(boot_chunks)
            bh3 = finalize_lift_cell(all_pool["n"], all_pool["n_pos"], obs_auc_m, obs_auc_c,
                                     combined, ALPHA)
            bh3["compute_s"] = time.time() - t0
            cache["bh3_hcm1_ld_30"] = _jsonable(bh3)
            save_cache(cache_path, cache)
        bh3_verdict = "SUPPORTED" if (bh3["lift"] == bh3["lift"] and bh3["lift"] > 0
                                       and bh3["lo_bound"] == bh3["lo_bound"]
                                       and bh3["lo_bound"] > 0) else "not supported"
        print(f"  [B-H3] n={bh3['n']} n_pos={bh3['n_pos']} auc={fmt(bh3['auc_score'])} "
              f"lift={fmt(bh3['lift'])} lo={fmt(bh3['lo_bound'])} verdict={bh3_verdict} "
              f"({bh3.get('compute_s', 0):.2f}s)", flush=True)
    finally:
        pool.close()
        pool.join()

    total_compute_s = (
        sum(bh1_table[f][b].get("compute_s", 0) for f in CENTRALITY_COLUMNS for b in range(4))
        + bh2.get("compute_s", 0) + bh3.get("compute_s", 0)
    )

    # ------------------------------------------------------------ write doc
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    md = ["# B-H1..B-H3 — bug-label expansion (power for the small-file bands)\n"]
    md.append(
        f"Generated {now} · repo `{data['repo']}` · pool HEAD `{data['pool_head'][:12]}` · "
        f"DB `{pathlib.Path(db).name}` (opened read-only, WAL-aware) · pre-registered "
        "gitgalaxy#2982 comment 5651082895; implemented verbatim; verdicts publish "
        "either way. **Do not commit** per operator instruction; this doc is a local "
        "artifact of an unattended run.\n"
    )
    md.append("## Leakage-free design\n")
    md.append(
        "Centrality columns and `total_loc` are read from the existing scan DB at each "
        "event's **parent** commit (T0) — no rescan. HCM1_LD_30 is computed fresh from the "
        "pool clone via `git log <parent> --since=<parent_date-"
        f"{args.window_days}d> -n {args.commit_cap} --no-merges`, ancestors of parent ONLY "
        "(`hcm_variants.raw_commit_walk`, called directly, not reimplemented) — no "
        "information from the fix commit or anything after it can enter any feature. "
        f"Walk cache (`{HCMWALK_CACHE}`) is the SAME directory `hcm_variants.py` uses, "
        "reused verbatim per the pre-registration.\n"
    )
    md.append(
        f"Coverage: **{len(records)}** events usable (of **{n_events_matching}** "
        f"class-matching in the event set{f', limited to the first {args.limit}' if args.limit else ''}"
        f"); skipped — {dict(skip) if skip else '(none)'}. Pooled candidate files: "
        f"**{n_files_total}**, pooled positives: **{n_pos_total}**. Event-file class counts "
        f"in `{pathlib.Path(args.events).name}`: {dict(class_counts_file)}. HCM walk "
        f"wall-time: {walk_s:.1f}s (cached per parent sha, shared with hcm_variants.py's own "
        f"cache).\n"
    )
    md.append(
        f"Band sizes (absolute NLOC scheme): " +
        ", ".join(f"`{ABS_LABELS[b]}` n={n_by_band[b]} n_pos={n_pos_by_band[b]} "
                  f"({'powered' if n_pos_by_band[b] >= MIN_POS else 'UNDERPOWERED'})"
                  for b in range(N_ABS_BANDS)) + f". Powered small bands: {n_powered_small}/2 "
        f"-> B-H1 Bonferroni alpha = 0.01/(5 x {n_powered_small}) = {alpha_eff_bh1:.6f}"
        + (" (unused floor value shown; every small-band cell is UNDERPOWERED)"
           if n_powered_small == 0 else "") + ".\n"
    )
    md.append(
        f"**Parallel execution**: fork pool, {args.workers} workers. B-H1's 20 (measure,band) "
        "cells each ran their own full serial bootstrap in one worker, seeded "
        "`base_seed + feat_idx*4 + band` (distinct per cell). B-H2/B-H3 each split "
        f"`--iters` into {args.workers} chunks (sizes {chunk_sizes(args.iters, args.workers)}), "
        "seeded `base_seed + 1000*chunk_id`, concatenated in the parent before computing "
        "percentiles/the monotonicity fraction.\n"
    )

    md.append("## B-H1 — powered small-file centrality test\n")
    md.append(
        "Per measure x band: AUC(measure), AUC(total_loc), lift, one-sided event-bootstrap "
        f"({args.iters} iters) lower bound on the lift. Bonferroni family = 5 measures x "
        "powered SMALL bands only (<=22, 23-48) — large bands shown for context, not part "
        "of the family or the verdict.\n"
    )
    for feat in CENTRALITY_COLUMNS:
        md.append(f"### `{feat}` vs `total_loc`\n")
        md.append("| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | "
                  "boot lower bound | 95% CI (lift) | powered | verdict |")
        md.append("|---|---|---|---|---|---|---|---|---|---|")
        for b, cell in enumerate(bh1_table[feat]):
            context = "" if b in SMALL_BAND_IDX else " (context)"
            md.append(
                f"| {ABS_LABELS[b]}{context} | {cell['n']} | {cell['n_pos']} | "
                f"{fmt(cell['auc_score'])} | {fmt(cell['auc_control'])} | {fmt(cell['lift'])} | "
                f"{fmt(cell['lo_bound'])} | [{fmt(cell['ci95'][0])}, {fmt(cell['ci95'][1])}] | "
                f"{'yes' if cell['powered'] else 'no'} | "
                f"{'**' + cell['verdict'] + '**' if cell['verdict'] == 'SUPPORTED' else cell['verdict']} |"
            )
        md.append("")
    md.append(
        f"**B-H1 per-small-band status:** " +
        ", ".join(f"`{ABS_LABELS[b]}`={small_band_status[b]}" for b in SMALL_BAND_IDX) + "\n\n"
        f"**B-H1: {'**' + bh1_verdict + '**' if bh1_verdict == 'SUPPORTED' else bh1_verdict}.** "
        "SUPPORTED iff >=1 measure clears AUC>0.5 and lift lower bound>0 in EACH powered "
        "small band.\n"
    )

    md.append("## B-H2 — the monotone shape (confirmatory)\n")
    md.append(
        f"PageRank only, all 4 absolute bands, ONE joint bootstrap ({args.iters} iters) — "
        "each resample draws one shared set of resampled events and computes all 4 bands' "
        "lifts from it, so the ordering claim is evaluated on correlated draws, not 4 "
        "independent per-band bounds. SUPPORTED iff lift band0>band1>band2>band3 holds in "
        ">=99% of resamples.\n"
    )
    md.append("| band | observed lift (PageRank − total_loc) |")
    md.append("|---|---|")
    for b in range(N_ABS_BANDS):
        md.append(f"| `{ABS_LABELS[b]}` | {fmt(bh2['obs_lifts'][b])} |")
    md.append(
        f"\n**Fraction of {bh2['n_valid']}/{bh2['n_iters']} valid resamples with strict "
        f"monotone decrease: {fmt(bh2['frac_monotone'])}** (threshold >=0.99). "
        f"**B-H2: {'**SUPPORTED**' if bh2['supported'] else 'not supported'}.**\n"
    )

    md.append("## B-H3 — HCM1_LD_30 out-of-selection validation\n")
    md.append(
        f"Pooled over all {bh3['n']} candidate files across all {len(records)} parent "
        f"snapshots (n_pos={bh3['n_pos']}), no banding. One-sided event-bootstrap "
        f"({args.iters} iters, alpha={ALPHA}, single comparison, no Bonferroni).\n"
    )
    md.append("| n | n pos | AUC(HCM1_LD_30) | AUC(total_loc) | lift | boot lower bound "
              "(α) | 95% CI | verdict |")
    md.append("|---|---|---|---|---|---|---|---|")
    md.append(
        f"| {bh3['n']} | {bh3['n_pos']} | {fmt(bh3['auc_score'])} | {fmt(bh3['auc_control'])} | "
        f"{fmt(bh3['lift'])} | {fmt(bh3['lo_bound'])} | "
        f"[{fmt(bh3['ci95'][0])}, {fmt(bh3['ci95'][1])}] | "
        f"{'**' + bh3_verdict + '**' if bh3_verdict == 'SUPPORTED' else bh3_verdict} |"
    )
    md.append(f"\n**B-H3: {'**SUPPORTED**' if bh3_verdict == 'SUPPORTED' else bh3_verdict}.**\n")

    md.append("## Design notes / ambiguity resolutions\n")
    md.append(
        "- **B-H1's Bonferroni family is scoped to the 2 small bands only** (5 measures x "
        "n_powered_small_bands), per the pre-registration's literal text — unlike "
        "`centrality_bands.py`'s C-H1, which scopes its family to all 4 bands as a stated "
        "ambiguity resolution; no such ambiguity exists here.\n"
        "- **The two large bands are reported at the same small-band alpha**, for "
        "at-a-glance comparability and because B-H2 reuses their point estimates — they "
        "carry no verdict of their own and are excluded from B-H1's SUPPORTED determination.\n"
        "- **B-H1's SUPPORTED rule reads as AND-across-bands, OR-across-measures**: each "
        "powered small band needs its OWN qualifying measure — both powered bands must "
        "clear it independently for the overall claim.\n"
        "- **B-H2 uses ONE shared resampled-event draw per iteration across all 4 bands** — "
        "a joint bootstrap, deliberately NOT four independent per-band streams (B-H1's "
        "design): the claim is about simultaneous ordering within one resample.\n"
        "- **Multiprocessing seeding is fixed but NOT a serial-stream-equivalence claim.** "
        "B-H1 cells use `base_seed + feat_idx*4 + band`; B-H2/B-H3 chunk seeds use "
        "`base_seed + 1000*chunk_id`. Both are deterministic and rerunnable, but a serial "
        "single-process run at the same `--seed` will NOT reproduce bit-identical draws — "
        "what the pre-registration's seed=2982 buys here is reproducibility of THIS "
        "(parallel) procedure, not cross-procedure identity.\n"
        "- **The numpy AUC engine (`auc_numpy`) replaces `rw_analyses.pooled_auc`** "
        "(pure-Python, does not finish at ~2.5M pooled rows) with an identical-formula, "
        "vectorized reimplementation — verified against the original on 20 randomized "
        "tie-heavy trials (exact match) before this file was written.\n"
        "- **HCM1_LD_30 is never reimplemented** — `hcm_variants.raw_commit_walk` and "
        "`compute_all_variants` are called directly and the `HCM1_LD_30` key is read out, "
        "so this test is byte-for-byte frozen to its CVE-label definition by construction.\n"
    )

    md.append(f"---\n*Regenerate: `python tools/bh_eval.py --events events/curl_bugs.json` "
              f"— stdlib+numpy only; HCM walks cached under `{HCMWALK_CACHE}` (shared with "
              f"hcm_variants.py) keyed by parent sha; bootstrap cells checkpointed to "
              f"`{cache_path}`. Bootstrap compute time this run: {total_compute_s:.1f}s "
              f"wall-clock summed across workers (cells loaded from cache report 0s).*")

    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")

    print(f"\nB-H1: {bh1_verdict} (alpha_eff={alpha_eff_bh1:.6f}, "
          f"n_powered_small_bands={n_powered_small})")
    print(f"B-H2: {'SUPPORTED' if bh2['supported'] else 'not supported'} "
          f"(frac_monotone={fmt(bh2['frac_monotone'])})")
    print(f"B-H3: {bh3_verdict} (lift={fmt(bh3['lift'])}, lo={fmt(bh3['lo_bound'])})")
    print(f"total bootstrap compute time (summed across workers): {total_compute_s:.1f}s")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
