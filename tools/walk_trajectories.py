#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Keyword-trajectory panel analysis over the 219-release curl walk (tc#3 +
the 2026-09-13 scope-expansion comment): "make keywords temporal."

EXPLORATORY THROUGHOUT. No p-values are claimed anywhere in this tool's
output; every table is descriptive. Suggestive patterns are candidates for
pre-registration on repo #3 (openssl), not findings in themselves.

Every predictor that has survived this program so far is temporal
(recidivism, HCM/change-entropy); every keyword signal tested so far was
static and reduced to file size. This tool builds actual per-file keyword
TIME SERIES across the 219 chronological release snapshots
(walks/curl_walk.json, already fully scanned into the master DB -- no new
scans run here) and asks four questions:

  1. Trajectory features (slope of danger/alloc over the last 8 releases,
     the alloc/cleanup pairing ratio and its drift, keyword volatility),
     computed leakage-free (releases <= t only).
  2. Outcome linkage: do trajectory features beat total_loc AND a churn
     proxy at ranking (file, t) pairs by whether a fix-class event
     (security-fix / bugfix-fixes / bugfix-bug / regression) touches that
     file in (t, t+4 releases]? Pooled AUC + a pre/post-2015 era split.
  3. Post-fix trajectory shape: for files with >=2 fix events, does the
     post-fix danger/alloc trajectory (rebound vs. stay-down over the next
     8 releases) differ between recidivists (another fix within 12
     releases) and non-recidivists? Descriptive table.
  4. Survival sketch: median releases-until-next-fix stratified by
     pairing-ratio tercile at the fix release. Descriptive, censoring noted.

Two measurement caveats discovered during panel construction and handled
explicitly (see PANEL CAVEATS below the imports):

  - PATH IDENTITY IS UNSTABLE ACROSS 26 YEARS. Only 6 file_paths survive
    from the 2000 snapshot to the 2026 snapshot untouched (curl's layout is
    almost completely different: 39 files -> 1,144 files). Trajectories are
    built per raw file_path and are valid ONLY over a file's own CONTIGUOUS
    presence window in the release sequence -- gaps are never stitched, and
    a reappearance under the same path after an absence starts a fresh run.
    No cross-repo rename-chasing is attempted (out of scope here).
  - THE ALLOC/CLEANUP CLIFF. Between curl-8_17_0 (2025-11-05) and
    curl-8_18_0 (2026-01-07), summed state_memory_alloc across all C files
    drops 1197 -> 171 and def_cleanup 913 -> 155 IN ONE RELEASE STEP, while
    total_loc keeps growing and every other keyword column (state_danger,
    state_pointers, struct_branch, state_cast_hits) and pagerank_score stay
    continuous. The real curl history in that window is a genuine,
    widespread allocator-wrapping refactor (many "use curlx allocator
    instead of malloc/free" commits) -- a real code change whose effect on
    literal malloc()/free()-family keyword hits is a vocabulary cliff, not
    an engine bug. Per the recon call: this is a cliff across MANY files in
    ONE step, so alloc/cleanup-derived features are TRUNCATED at the last
    clean release (curl-8_17_0) and this is reported, not papered over.

    python tools/walk_trajectories.py --sanity            # ~15 releases, foreground
    python tools/walk_trajectories.py                     # full 219-release run
"""
from __future__ import annotations

import argparse
import bisect
import json
import multiprocessing
import pathlib
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict
from datetime import date, datetime

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, REPO_ROOT  # noqa: E402
from delta_report import median  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from rw_analyses import pooled_auc  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import parent_child  # noqa: E402

SCRATCH = pathlib.Path(
    "/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664"
    "/scratchpad/walk_cache"
)
SCRATCH.mkdir(parents=True, exist_ok=True)

WALKS_DIR = REPO_ROOT / "walks"
EVENTS_DIR = REPO_ROOT / "events"

KEYWORD_COLS = ["state_memory_alloc", "def_cleanup", "state_pointers",
                "struct_branch", "state_danger", "state_cast_hits"]
PANEL_COLS = ["total_loc"] + KEYWORD_COLS + ["pagerank_score"]
# columns immune to the alloc/cleanup cliff -- used for danger-side and
# volatility features so those stay valid across the full 219-release panel
SAFE_ACTIVITY_COLS = ["state_pointers", "struct_branch", "state_danger", "state_cast_hits"]

FIX_CLASSES = {"security-fix", "bugfix-fixes", "bugfix-bug", "regression"}
LOOKBACK = 8          # releases, for slope/volatility/churn-proxy features
FORWARD_WINDOW = 4    # releases, for the outcome-linkage window (t, t+4]
RECID_WINDOW = 12     # releases, "another fix soon" for the recidivism split
POST_FIX_HORIZON = 8  # releases, post-fix trajectory-shape lookahead
MIN_RUN_REPORT = 16   # contiguous-run length used only for the coverage headline
ALLOC_CLIFF_REF = "curl-8_18_0"  # first release on the wrong side of the cliff
ERA_SPLIT = date(2015, 1, 1)

N_WORKERS_DEFAULT = 10


# ================================================================== db helpers
def db_uri(path: pathlib.Path) -> str:
    return f"file:{path}?mode=ro"


def parse_walk_date(s: str) -> date:
    return datetime.fromisoformat(s).date()


def parse_db_date(s: str) -> date:
    # repo_data.commit_date is a plain 'YYYY-MM-DD' string
    return datetime.strptime(s, "%Y-%m-%d").date()


# ============================================================ panel: fork-pool fetch
def _worker_fetch_release(task):
    """One release: own read-only sqlite connection, own query. Returns
    (idx, {file_path: [col values in PANEL_COLS order]})."""
    db_path, repo_name, idx, sha = task
    con = sqlite3.connect(db_uri(pathlib.Path(db_path)), uri=True)
    try:
        sel = ", ".join(["file_path"] + PANEL_COLS)
        cur = con.execute(
            f"SELECT {sel} FROM file_data "
            "WHERE repo_name = ? AND commit_hash = ? AND language = 'c'",
            (repo_name, sha),
        )
        rows = {r[0]: list(r[1:]) for r in cur.fetchall()}
    finally:
        con.close()
    return idx, rows


def build_panel(db_path: pathlib.Path, repo_name: str, revisions: list[dict],
                 workers: int, cache_path: pathlib.Path) -> dict:
    """release_idx -> {file_path: [PANEL_COLS values]}. Cached to scratchpad."""
    if cache_path.exists():
        raw = json.loads(cache_path.read_text())
        if raw.get("n_releases") == len(revisions) and raw.get("db") == str(db_path):
            print(f"panel cache hit: {cache_path} ({len(revisions)} releases)", flush=True)
            return {int(k): v for k, v in raw["panel"].items()}

    tasks = [(str(db_path), repo_name, r["idx"], r["sha"]) for r in revisions]
    ctx = multiprocessing.get_context("fork")
    panel: dict[int, dict] = {}
    t0 = time.time()
    with ctx.Pool(processes=workers) as pool:
        for i, (idx, rows) in enumerate(pool.imap_unordered(_worker_fetch_release, tasks), 1):
            panel[idx] = rows
            if i % 50 == 0 or i == len(tasks):
                print(f"  panel fetch {i}/{len(tasks)} ({time.time() - t0:.1f}s)", flush=True)
    cache_path.write_text(json.dumps(
        {"n_releases": len(revisions), "db": str(db_path), "panel": panel}))
    print(f"panel built: {len(revisions)} releases in {time.time() - t0:.1f}s "
          f"-> cached at {cache_path}", flush=True)
    return panel


# ============================================================ per-file trajectories
class FileTraj:
    __slots__ = ("idx", "cols", "runs")

    def __init__(self, idx: np.ndarray, cols: dict[str, np.ndarray]):
        self.idx = idx
        self.cols = cols
        # contiguous runs: list of (start_release_idx, end_release_idx) inclusive,
        # split wherever the release index sequence isn't consecutive -- gaps are
        # never stitched (recon guidance: path identity is not stable long-run).
        runs = []
        if idx.size:
            start = idx[0]
            prev = idx[0]
            for v in idx[1:]:
                if v != prev + 1:
                    runs.append((int(start), int(prev)))
                    start = v
                prev = v
            runs.append((int(start), int(prev)))
        self.runs = runs

    def run_containing(self, t: int) -> tuple[int, int] | None:
        for s, e in self.runs:
            if s <= t <= e:
                return s, e
        return None

    def pos_of(self, t: int) -> int:
        return int(np.searchsorted(self.idx, t))

    def val(self, col: str, t: int) -> float | None:
        p = self.pos_of(t)
        if p < self.idx.size and self.idx[p] == t:
            return float(self.cols[col][p])
        return None


def build_trajectories(panel: dict[int, dict], n_releases: int) -> dict[str, FileTraj]:
    by_file: dict[str, list[tuple[int, list[float]]]] = defaultdict(list)
    for idx in range(n_releases):
        for path, vals in panel.get(idx, {}).items():
            by_file[path].append((idx, vals))
    traj = {}
    for path, obs in by_file.items():
        obs.sort(key=lambda o: o[0])
        idx_arr = np.array([o[0] for o in obs], dtype=np.int64)
        cols = {c: np.array([o[1][i] for o in obs], dtype=np.float64)
                for i, c in enumerate(PANEL_COLS)}
        traj[path] = FileTraj(idx_arr, cols)
    return traj


# ============================================================ events: fork-pool touch
def _worker_event_touch(task):
    repo_str, sha = task
    repo = pathlib.Path(repo_str)
    parent, child = parent_child(repo, sha)
    if parent is None:
        return sha, None
    try:
        statuses = diff_statuses(repo, parent, child)
    except subprocess.CalledProcessError:
        return sha, None
    touched_new = {p for p, st in statuses.items() if st["status"] == "touched"}
    touched_old = {st["old_path"] for p, st in statuses.items()
                   if st["status"] == "touched" and st["old_path"]}
    return sha, {"new": sorted(touched_new), "old": sorted(touched_old)}


def load_fix_events(event_files: list[pathlib.Path]) -> list[dict]:
    out = []
    for f in event_files:
        data = json.loads(f.read_text())
        for e in data["events"]:
            if e["class"] in FIX_CLASSES:
                out.append({"id": e["id"], "class": e["class"], "sha": e["sha"], "src": f.name})
    return out


def harvest_touched_files(repo: pathlib.Path, events: list[dict], workers: int,
                           cache_path: pathlib.Path) -> dict[str, dict]:
    cache = {}
    if cache_path.exists():
        cache = json.loads(cache_path.read_text())
    todo = [e["sha"] for e in events if e["sha"] not in cache]
    if todo:
        ctx = multiprocessing.get_context("fork")
        tasks = [(str(repo), sha) for sha in todo]
        t0 = time.time()
        with ctx.Pool(processes=workers) as pool:
            for i, (sha, touch) in enumerate(pool.imap_unordered(_worker_event_touch, tasks), 1):
                cache[sha] = touch
                if i % 200 == 0 or i == len(todo):
                    print(f"  event touch {i}/{len(todo)} ({time.time() - t0:.1f}s)", flush=True)
        cache_path.write_text(json.dumps(cache))
        print(f"touched-file harvest: {len(todo)} new, {len(cache) - len(todo)} cached "
              f"({time.time() - t0:.1f}s)", flush=True)
    else:
        print(f"touched-file cache hit: {cache_path} ({len(cache)} events)", flush=True)
    return cache


def commit_dates(db_path: pathlib.Path, repo_name: str) -> dict[str, str]:
    con = sqlite3.connect(db_uri(db_path), uri=True)
    try:
        cur = con.execute(
            "SELECT commit_hash, commit_date FROM repo_data WHERE repo_name = ?", (repo_name,))
        return dict(cur.fetchall())
    finally:
        con.close()


# ================================================================== feature computation
def linfit_slope(x: np.ndarray, y: np.ndarray) -> float:
    if x.size < 2 or np.all(y == y[0]):
        return 0.0 if x.size >= 2 else float("nan")
    return float(np.polyfit(x, y, 1)[0])


def cumulative_growth(vals: np.ndarray) -> np.ndarray:
    """Cumulative sum of positive deltas only ("growth"), aligned with vals."""
    d = np.diff(vals, prepend=vals[0])
    d = np.clip(d, 0, None)
    d[0] = 0.0
    return np.cumsum(d)


def build_rows(traj: dict[str, FileTraj], n_releases: int, alloc_valid_max_idx: int,
               events_by_idx: dict[int, set], release_dates: list[date]) -> list[dict]:
    """One row per (file, t) with t+FORWARD_WINDOW <= n_releases-1, gated on an
    8-release contiguous lookback (t-7..t all present in the SAME run --
    required for churn/slope features, applied uniformly so every feature in
    the AUC table is scored on the identical row population)."""
    rows = []
    last_idx = n_releases - 1
    # rolling forward-outcome union per t, O(n_releases * FORWARD_WINDOW)
    outcome_union = {}
    for t in range(0, last_idx - FORWARD_WINDOW + 1):
        u = set()
        for k in range(t + 1, t + FORWARD_WINDOW + 1):
            u |= events_by_idx.get(k, set())
        outcome_union[t] = u

    for path, ft in traj.items():
        for t in ft.idx:
            t = int(t)
            if t > last_idx - FORWARD_WINDOW:
                continue
            run = ft.run_containing(t)
            if run is None or t - run[0] < LOOKBACK - 1:
                continue  # need 8 consecutive points t-7..t in the same run
            p_now = ft.pos_of(t)
            p_back = ft.pos_of(t - (LOOKBACK - 1))
            window_idx = ft.idx[p_back:p_now + 1]
            if window_idx.size != LOOKBACK or window_idx[0] != t - LOOKBACK + 1:
                continue

            total_loc_t = float(ft.cols["total_loc"][p_now])
            loc_win = ft.cols["total_loc"][p_back:p_now + 1]
            churn_proxy_8 = float(np.sum(np.diff(loc_win) != 0))

            danger_win = ft.cols["state_danger"][p_back:p_now + 1]
            danger_slope_8 = linfit_slope(window_idx.astype(np.float64), danger_win)

            activity_win = sum(ft.cols[c][p_back:p_now + 1] for c in SAFE_ACTIVITY_COLS)
            keyword_volatility_8 = float(np.std(np.diff(activity_win))) if activity_win.size > 1 \
                else float("nan")

            pagerank_t = float(ft.cols["pagerank_score"][p_now])

            alloc_ok = t <= alloc_valid_max_idx
            alloc_slope_8 = pairing_ratio_t = pairing_ratio_drift_8 = float("nan")
            if alloc_ok:
                alloc_win = ft.cols["state_memory_alloc"][p_back:p_now + 1]
                alloc_slope_8 = linfit_slope(window_idx.astype(np.float64), alloc_win)

                run_start = run[0]
                p_run_start = ft.pos_of(run_start)
                alloc_run = ft.cols["state_memory_alloc"][p_run_start:p_now + 1]
                cleanup_run = ft.cols["def_cleanup"][p_run_start:p_now + 1]
                cum_alloc = cumulative_growth(alloc_run)
                cum_cleanup = cumulative_growth(cleanup_run)
                pairing_ratio_t = float(cum_alloc[-1] / max(cum_cleanup[-1], 1.0))

                t_prev8 = t - LOOKBACK
                if t_prev8 >= run_start and t_prev8 <= alloc_valid_max_idx:
                    p_prev8 = ft.pos_of(t_prev8)
                    if p_prev8 < ft.idx.size and ft.idx[p_prev8] == t_prev8:
                        rel = p_prev8 - p_run_start
                        pairing_ratio_prev8 = float(
                            cum_alloc[rel] / max(cum_cleanup[rel], 1.0))
                        pairing_ratio_drift_8 = pairing_ratio_t - pairing_ratio_prev8

            era = "pre-2015" if release_dates[t] < ERA_SPLIT else "post-2015"
            outcome = 1 if path in outcome_union.get(t, ()) else 0

            rows.append({
                "path": path, "t": t, "era": era, "outcome": outcome,
                "total_loc_t": total_loc_t, "churn_proxy_8": churn_proxy_8,
                "danger_slope_8": danger_slope_8, "alloc_slope_8": alloc_slope_8,
                "pairing_ratio_t": pairing_ratio_t,
                "pairing_ratio_drift_8": pairing_ratio_drift_8,
                "keyword_volatility_8": keyword_volatility_8,
                "pagerank_t": pagerank_t,
            })
    return rows


FEATURES_FOR_AUC = [
    ("total_loc_t", "baseline: total_loc at t"),
    ("churn_proxy_8", "baseline: # releases file changed in last 8 (LOC-delta count)"),
    ("danger_slope_8", "trajectory: slope of state_danger over last 8 releases"),
    ("alloc_slope_8", "trajectory: slope of state_memory_alloc over last 8 releases "
                       "(gated at the alloc/cleanup cliff)"),
    ("pairing_ratio_t", "trajectory: cum. alloc-growth / cum. cleanup-growth since "
                         "run start (gated)"),
    ("pairing_ratio_drift_8", "trajectory: pairing ratio drift over last 8 releases (gated)"),
    ("keyword_volatility_8", "trajectory: std of deltas, pointers+branch+danger+cast composite"),
    ("pagerank_t", "bonus: pagerank_score at t"),
]


def auc_table_for(rows: list[dict]) -> list[dict]:
    out = []
    for feat, desc in FEATURES_FOR_AUC:
        obs = [(r[feat], r["outcome"]) for r in rows if r[feat] == r[feat]]  # drop NaN
        auc = pooled_auc(obs)
        out.append({"feature": feat, "desc": desc, "n": len(obs),
                    "n_pos": sum(1 for _, y in obs if y), "auc": auc})
    return out


# ================================================================== task 3 / task 4
def match_event_to_file(traj: dict[str, FileTraj], touch: dict) -> str | None:
    if not touch:
        return None
    for p in touch["new"]:
        if p in traj:
            return p
    for p in touch["old"]:
        if p in traj:
            return p
    return None


def build_fix_event_rows(fix_events, touched, dates_by_sha, revisions_dates, traj):
    """Per fix event: matched file, release_idx r (bisect: first release date
    >= event date), and whether it landed inside the panel at all."""
    out = []
    rdates = revisions_dates
    for e in fix_events:
        touch = touched.get(e["sha"])
        path = match_event_to_file(traj, touch)
        if path is None:
            continue
        raw_date = dates_by_sha.get(e["sha"])
        if raw_date is None:
            continue
        edate = parse_db_date(raw_date)
        r = bisect.bisect_left(rdates, edate)
        if r >= len(rdates):
            continue  # event postdates the whole panel
        out.append({"id": e["id"], "class": e["class"], "path": path, "r": r})
    return out


def post_fix_shape_table(fix_rows, traj, alloc_valid_max_idx):
    by_file = defaultdict(list)
    for row in fix_rows:
        by_file[row["path"]].append(row)
    for lst in by_file.values():
        lst.sort(key=lambda r: r["r"])

    recid, nonrecid = [], []
    for path, lst in by_file.items():
        if len(lst) < 2:
            continue
        ft = traj[path]
        for i, ev in enumerate(lst):
            r = ev["r"]
            run = ft.run_containing(r)
            if run is None:
                continue
            recidivist = any(0 < (o["r"] - r) <= RECID_WINDOW for o in lst if o is not ev)
            r8 = r + POST_FIX_HORIZON
            danger_delta = alloc_delta = float("nan")
            if run[1] >= r8:
                danger_delta = ft.val("state_danger", r8) - ft.val("state_danger", r)
                if r8 <= alloc_valid_max_idx:
                    alloc_delta = (ft.val("state_memory_alloc", r8)
                                   - ft.val("state_memory_alloc", r))
            rec = {"path": path, "r": r, "danger_delta": danger_delta,
                   "alloc_delta": alloc_delta}
            (recid if recidivist else nonrecid).append(rec)
    return recid, nonrecid


def summarize_group(rows, key):
    vals = [r[key] for r in rows if r[key] == r[key]]
    if not vals:
        return {"n": 0, "median": float("nan"), "pct_rebound": float("nan")}
    return {"n": len(vals), "median": median(vals),
            "pct_rebound": 100.0 * sum(1 for v in vals if v > 0) / len(vals)}


def survival_table(fix_rows, traj, alloc_valid_max_idx):
    by_file = defaultdict(list)
    for row in fix_rows:
        by_file[row["path"]].append(row)
    for lst in by_file.values():
        lst.sort(key=lambda r: r["r"])

    entries = []  # (pairing_ratio, gap_or_None)
    for path, lst in by_file.items():
        ft = traj[path]
        for i, ev in enumerate(lst):
            r = ev["r"]
            if r > alloc_valid_max_idx:
                continue
            run = ft.run_containing(r)
            if run is None:
                continue
            p_now = ft.pos_of(r)
            p_run_start = ft.pos_of(run[0])
            alloc_run = ft.cols["state_memory_alloc"][p_run_start:p_now + 1]
            cleanup_run = ft.cols["def_cleanup"][p_run_start:p_now + 1]
            cum_alloc = cumulative_growth(alloc_run)
            cum_cleanup = cumulative_growth(cleanup_run)
            pr = float(cum_alloc[-1] / max(cum_cleanup[-1], 1.0))
            gap = lst[i + 1]["r"] - r if i + 1 < len(lst) else None
            entries.append((pr, gap))

    if not entries:
        return []
    ratios = np.array([e[0] for e in entries])
    t1, t2 = np.quantile(ratios, [1 / 3, 2 / 3])
    buckets = {"low": [], "mid": [], "high": []}
    for pr, gap in entries:
        b = "low" if pr <= t1 else ("mid" if pr <= t2 else "high")
        buckets[b].append(gap)
    out = []
    for b in ("low", "mid", "high"):
        gaps = buckets[b]
        censored = sum(1 for g in gaps if g is None)
        uncensored = [g for g in gaps if g is not None]
        out.append({"tercile": b, "n": len(gaps), "n_censored": censored,
                    "median_gap": median(uncensored) if uncensored else float("nan")})
    return out, (t1, t2)


# ================================================================== report
def fmt_auc(v):
    return "nan" if v != v else f"{v:.3f}"


def write_report(out_path, revisions, traj, coverage, auc_all, auc_pre, auc_post,
                  recid, nonrecid, surv_table, surv_terciles, cliff_idx, cliff_found,
                  runtime_s, n_fix_events, n_fix_matched):
    md = []
    md.append("# Keyword-trajectory panel analysis — curl, 219-release walk\n")
    md.append(
        "**EXPLORATORY.** tc#3 + the 2026-09-13 scope-expansion comment "
        "(\"make keywords temporal\"). No p-values anywhere below; every table is "
        "descriptive. Suggestive patterns are repo-#3 (openssl) pre-registration "
        "candidates, not findings.\n")
    md.append(
        f"Panel: {len(revisions)} releases, {revisions[0]['date'][:10]} -> "
        f"{revisions[-1]['date'][:10]}. Coverage (files x releases): "
        f"{coverage['n_files']} distinct C file_paths ever observed, "
        f"{coverage['n_file_release_cells']} (file,release) cells, "
        f"{coverage['n_qualifying_16']} files with a contiguous run >= "
        f"{MIN_RUN_REPORT} releases (**that's the real panel** for the trajectory "
        f"features below) out of {coverage['n_qualifying_any']} with any run >= "
        f"{LOOKBACK}. Only {coverage['n_full_span']} file_paths persist from the "
        f"2000 snapshot to the 2026 snapshot unbroken — path identity is not stable "
        f"across curl's 26-year layout churn (39 -> 1,144 files), so trajectories are "
        f"scored per contiguous run only, never stitched across a gap.\n")
    if cliff_found:
        md.append(
            f"**The alloc/cleanup cliff**: between curl-8_17_0 (2025-11-05) and "
            f"{ALLOC_CLIFF_REF} (release idx {cliff_idx}), summed state_memory_alloc "
            "across all C files drops ~86% and def_cleanup ~83% in ONE release step "
            "while total_loc keeps growing and every other keyword column stays "
            "continuous — real curl history shows a wide allocator-wrapping refactor in "
            "that window (many \"use curlx allocator instead of malloc/free\" commits): a "
            "real code change that reads as a vocabulary cliff to literal malloc/free-"
            "family keyword matching, not an engine bug. All alloc/cleanup-derived "
            f"features (alloc_slope_8, pairing_ratio_t, pairing_ratio_drift_8, the "
            f"post-fix alloc column, the survival sketch) are **truncated at release idx "
            f"{cliff_idx - 1} (curl-8_17_0)** and NaN beyond it — reported, not papered "
            "over.\n")
    else:
        md.append(
            f"**The alloc/cleanup cliff** ({ALLOC_CLIFF_REF}, ~86%/83% one-step drop "
            "in state_memory_alloc/def_cleanup, documented on the full run) is not "
            "reached within this truncated (--limit/--sanity) panel, so no "
            "alloc/cleanup gating was applied here — this is a plumbing check, not a "
            "real read.\n")
    md.append(f"Runtime: {runtime_s:.1f}s. Fix-class events loaded: {n_fix_events} "
              f"(security-fix/bugfix-fixes/bugfix-bug/regression only — wave1 "
              f"revert/cve-followup excluded by definition); matched to a panel "
              f"file + release: {n_fix_matched}.\n")

    md.append("## 1-2. Trajectory features vs. total_loc / churn-proxy baselines "
              "(outcome: touched by a fix-class event in (t, t+4])\n")
    md.append("Row population is identical across every feature in this table (an "
              "8-release contiguous lookback is required to compute ANY of them, "
              "applied uniformly) so the AUC comparison is apples-to-apples. Pooled "
              "AUC = rank-based (Mann-Whitney), descriptive only.\n")

    def emit_auc(title, table):
        md.append(f"### {title}\n")
        md.append("| feature | n | n_pos | AUC |")
        md.append("|---|---|---|---|")
        for row in table:
            md.append(f"| {row['feature']} ({row['desc']}) | {row['n']} | "
                      f"{row['n_pos']} | {fmt_auc(row['auc'])} |")
        md.append("")

    emit_auc("Pooled (all eras)", auc_all)
    emit_auc("Pre-2015", auc_pre)
    emit_auc("Post-2015", auc_post)

    baseline_aucs = {r["feature"]: r["auc"] for r in auc_all
                     if r["feature"] in ("total_loc_t", "churn_proxy_8")}
    valid_baselines = [v for v in baseline_aucs.values() if v == v]
    best_baseline = max(valid_baselines) if valid_baselines else float("nan")
    beaters = [r["feature"] for r in auc_all
               if r["feature"] not in ("total_loc_t", "churn_proxy_8")
               and r["auc"] == r["auc"] and best_baseline == best_baseline
               and r["auc"] > best_baseline]
    if best_baseline != best_baseline:
        md.append("**Headline**: degenerate — no positives in this slice (baselines "
                  "themselves are NaN); not a real read (sanity/--limit run or an "
                  "era/window with zero matched fix events).\n")
    elif beaters:
        md.append(f"**Headline**: {', '.join(beaters)} beat both baselines "
                  f"(best baseline AUC {best_baseline:.3f}) in the pooled read — "
                  "EXPLORATORY, a repo-#3 pre-registration candidate.\n")
    else:
        md.append(f"**Headline**: no trajectory feature beats both baselines "
                  f"(best baseline AUC {best_baseline:.3f}) in the pooled read — "
                  "consistent with the program's standing wall (everything "
                  "structural reduces to size).\n")

    md.append("## 3. Post-fix trajectory shape: recidivists vs. non-recidivists\n")
    md.append("Files with >=2 matched fix events; per fix event, delta = "
              f"value at (fix release + {POST_FIX_HORIZON}) minus value at fix "
              f"release, within the same contiguous run. Recidivist = another fix "
              f"on the same file within {RECID_WINDOW} releases. Descriptive only.\n")
    md.append("| group | n events | median danger delta | % danger rebound "
              "(>0) | n (alloc, gated) | median alloc delta | % alloc rebound |")
    md.append("|---|---|---|---|---|---|---|")
    for name, rows in (("recidivist", recid), ("non-recidivist", nonrecid)):
        d = summarize_group(rows, "danger_delta")
        a = summarize_group(rows, "alloc_delta")
        md.append(f"| {name} | {d['n']} | {fmt_auc(d['median'])} | "
                  f"{fmt_auc(d['pct_rebound'])} | {a['n']} | {fmt_auc(a['median'])} | "
                  f"{fmt_auc(a['pct_rebound'])} |")
    md.append("")

    md.append("## 4. Survival sketch: releases-until-next-fix by pairing-ratio tercile\n")
    md.append("Pairing ratio at the fix release (gated at the alloc/cleanup cliff); "
              "terciles cut on the pooled fix-event population; gap = releases to "
              "the NEXT matched fix event on the same file (None if the file's last "
              "fix in-panel, i.e. right-censored). Descriptive only.\n")
    if surv_table:
        t1, t2 = surv_terciles
        md.append(f"Tercile cuts: low <= {t1:.3f} <= mid <= {t2:.3f} <= high.\n")
        md.append("| tercile | n | n censored | median releases-until-next-fix "
                  "(uncensored) |")
        md.append("|---|---|---|---|")
        for row in surv_table:
            md.append(f"| {row['tercile']} | {row['n']} | {row['n_censored']} | "
                      f"{fmt_auc(row['median_gap'])} |")
    else:
        md.append("(no eligible fix events pre-cliff with a matched trajectory)\n")

    md.append("\n---\n*Generated by `tools/walk_trajectories.py`. DB "
              "`dbs/curl_out/curl_galaxy_master.db` opened read-only, WAL-aware. "
              "Panel + event-touch caches under "
              f"`{SCRATCH}` (10-worker fork pools for both the per-release DB fetch "
              "and the per-event git-diff touched-file harvest). EXPLORATORY "
              "throughout — no confirmatory claim is made in this document.*")
    out_path.write_text("\n".join(md) + "\n")
    print(f"wrote {out_path}")


# ================================================================== main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--walk", default=str(WALKS_DIR / "curl_walk.json"))
    ap.add_argument("--events", nargs="+", default=[
        str(EVENTS_DIR / "curl.json"), str(EVENTS_DIR / "curl_bugs.json"),
        str(EVENTS_DIR / "curl_wave1.json")])
    ap.add_argument("--out", default=str(DOCS_DIR / "walk_trajectories.md"))
    ap.add_argument("--workers", type=int, default=N_WORKERS_DEFAULT)
    ap.add_argument("--limit", type=int, default=0,
                    help="use only the first N releases (0 = all 219)")
    ap.add_argument("--sanity", action="store_true", help="shorthand for --limit 15")
    ap.add_argument("--event-limit", type=int, default=0,
                    help="cap fix events processed (0 = all); sanity runs only")
    args = ap.parse_args()
    if args.sanity and not args.limit:
        args.limit = 15

    t_start = time.time()
    walk = json.loads(pathlib.Path(args.walk).read_text())
    repo = resolve_repo(walk["repo"])
    db = history_db(out_dir_for(repo))
    print(f"repo={repo} db={db}", flush=True)

    revisions = walk["revisions"]
    if args.limit:
        revisions = revisions[:args.limit]
    for i, r in enumerate(revisions):
        r["idx"] = i
    n_releases = len(revisions)
    release_dates = [parse_walk_date(r["date"]) for r in revisions]
    print(f"panel: {n_releases} releases ({revisions[0]['date'][:10]} -> "
          f"{revisions[-1]['date'][:10]})", flush=True)

    suffix = f"_lim{args.limit}" if args.limit else "_full"
    panel_cache = SCRATCH / f"panel_raw{suffix}.json"
    panel = build_panel(db, repo.name, revisions, args.workers, panel_cache)
    traj = build_trajectories(panel, n_releases)

    # -------- coverage stats
    n_files = len(traj)
    n_cells = sum(ft.idx.size for ft in traj.values())
    n_full_span = sum(1 for ft in traj.values()
                      if 0 in ft.idx and (n_releases - 1) in ft.idx)
    n_qual16 = sum(1 for ft in traj.values()
                   if any(e - s + 1 >= MIN_RUN_REPORT for s, e in ft.runs))
    n_qual8 = sum(1 for ft in traj.values()
                  if any(e - s + 1 >= LOOKBACK for s, e in ft.runs))
    coverage = {"n_files": n_files, "n_file_release_cells": n_cells,
               "n_full_span": n_full_span, "n_qualifying_16": n_qual16,
               "n_qualifying_any": n_qual8}
    print(f"coverage: {n_files} files, {n_cells} (file,release) cells, "
          f"{n_qual16} with a run >= {MIN_RUN_REPORT}, {n_full_span} span the "
          f"whole panel unbroken", flush=True)

    # -------- alloc cliff index (empirical; falls back to end-of-panel if the
    # cliff release isn't in a --limit'd sanity run)
    ref_to_idx = {r["ref"]: r["idx"] for r in revisions}
    cliff_found = ALLOC_CLIFF_REF in ref_to_idx
    cliff_idx = ref_to_idx.get(ALLOC_CLIFF_REF, n_releases)
    alloc_valid_max_idx = cliff_idx - 1

    # -------- events
    fix_events = load_fix_events([pathlib.Path(p) for p in args.events])
    if args.event_limit:
        fix_events = fix_events[:args.event_limit]
    print(f"fix-class events loaded: {len(fix_events)}", flush=True)
    touch_cache = SCRATCH / "event_touch_cache.json"
    touched = harvest_touched_files(repo, fix_events, args.workers, touch_cache)
    dates_by_sha = commit_dates(db, repo.name)

    events_by_idx: dict[int, set] = defaultdict(set)
    fix_rows = build_fix_event_rows(fix_events, touched, dates_by_sha, release_dates, traj)
    for row in fix_rows:
        events_by_idx[row["r"]].add(row["path"])
    print(f"fix events matched to a panel file+release: {len(fix_rows)} / "
          f"{len(fix_events)}", flush=True)

    # -------- task 1-2: trajectory features + outcome-linkage AUC
    rows = build_rows(traj, n_releases, alloc_valid_max_idx, events_by_idx, release_dates)
    print(f"(file,t) rows built: {len(rows)}", flush=True)
    auc_all = auc_table_for(rows)
    auc_pre = auc_table_for([r for r in rows if r["era"] == "pre-2015"])
    auc_post = auc_table_for([r for r in rows if r["era"] == "post-2015"])

    # -------- task 3: post-fix trajectory shape
    recid, nonrecid = post_fix_shape_table(fix_rows, traj, alloc_valid_max_idx)

    # -------- task 4: survival sketch
    surv_result = survival_table(fix_rows, traj, alloc_valid_max_idx)
    surv_table_, surv_terciles = surv_result if surv_result else ([], (float("nan"),) * 2)

    runtime_s = time.time() - t_start
    out_path = pathlib.Path(args.out)
    write_report(out_path, revisions, traj, coverage, auc_all, auc_pre, auc_post,
                recid, nonrecid, surv_table_, surv_terciles, cliff_idx, cliff_found,
                runtime_s, len(fix_events), len(fix_rows))
    print(f"total runtime: {runtime_s:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
