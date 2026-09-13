#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Incremental-value test (IV-H1/IV-H2) — PRE-REGISTERED verbatim on
gitgalaxy#2982, comment 5649564429, before this file existed. Implemented
verbatim; verdicts publish either way.

**The question**: does GitGalaxy's STRUCTURAL layer add defect-lift ON TOP OF
a PROCESS baseline? Repowise-bench's top defect predictors are process
(co_change_scatter, change_entropy, ownership) ahead of every structural
smell. This program's scans run with GITGALAXY_DISABLE_GIT_HISTORY=1, so
churn/ownership are neutral zero constants in the DB (see tools/_engine.py's
SCAN_ENV) — process features here are computed FRESH from the pool clone's
git history, never read from the DB.

**Design — leakage-free by construction.** Per security-fix event, T0 is the
PARENT commit. Structural exposure and total_loc come from the existing DB
row at T0 (a completed scan; no rescan). Process features come from
`git log <parent> ...`, which walks ONLY <parent>'s ancestors — no commit at
or after the event can leak in. Unit = file in a parent snapshot; positive =
a file the fix touches (diff_statuses parent..child, status "touched",
old_path present in the parent snapshot). Candidate pool = every file_data
row at the parent commit (the rank set) — the same file may recur across
nearby events' snapshots (expected pseudo-replication, same discipline as
every other rung-6 tool in this repo); the sampling unit for the confirmatory
bootstrap is nonetheless the EVENT, per the pre-registration.

Process features, computed from one `git log <parent>` walk per event
(ancestors only, cached to disk keyed by parent sha):
  - churn: commit count touching the file (no breadth filter — matches the
    chronometer prototype, which increments churn/author maps unconditionally)
  - ownership_entropy: Shannon entropy (bits) of the file's author distribution
  - co_change_scatter: number of DISTINCT co-changed partners, commits touching
    more than COCHANGE_MAX_BREADTH files excluded (mass reformats are noise —
    identical threshold to gitgalaxy's chronometer._record_cochange on branch
    feat/cochange-entropy, gitgalaxy/metrics/chronometer.py)
  - change_entropy: Shannon entropy (bits) of the co-change partner distribution

Window: `--since <parent_date - WINDOW_DAYS>` (WINDOW_DAYS=365, matching the
chronometer prototype's own `--since=1.year` default) ANDed with a hard
`-n LOG_COMMIT_CAP` (4000) ceiling, `--no-merges` (again matching the
prototype). Both bounds active simultaneously; see docs/incremental_value.md
for the measured walk cost.

Tests (alpha=0.01, one-sided bootstrap over EVENTS, 5000 iters, seed 2982):
  1. Descriptive (no verdict): pooled single-feature AUC for total_loc,
     churn, ownership_entropy, co_change_scatter, change_entropy,
     structural_exposure. Positives vs non-positive files, pooled over all
     event snapshots. Ranks the six.
  2. IV-H1 (the real question): quartile-stratify files by the STRONGEST
     process feature (picked by step 1's AUC); within each band, AUC of
     structural_exposure. SUPPORTED iff AUC>0.5 and the one-sided bootstrap
     lower bound (alpha/4 percentile, Bonferroni across 4 bands) excludes 0.5.
  3. IV-H2 (the mirror): quartile-stratify by structural_exposure; within
     each band, AUC of the strongest process feature. Same rule.

Quartile bands are assigned by RANK (equal-count bins over the pooled
candidate-file population), not by value-quantile cut points: the process
features are heavily zero-inflated under a bounded ancestors-only window (most
files in any one snapshot were not touched in the last year), so a
value-quantile split would collapse into a single degenerate edge. This is
a resolution of an ambiguity in the pre-registration text ("quartiles"),
called out again in the generated doc.

    python tools/incremental_value.py --events events/curl.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import pathlib
import random
import sqlite3
import subprocess
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, EVENTS_DIR, STRUCTURAL_COLUMNS  # noqa: E402
from delta_report import median, q  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from rw_analyses import pooled_auc  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import parent_child  # noqa: E402

SEED = 2982
ITERS = 5000
ALPHA = 0.01
WINDOW_DAYS = 365
LOG_COMMIT_CAP = 4000
COCHANGE_MAX_BREADTH = 50  # gitgalaxy chronometer._record_cochange threshold

PROCESS_FEATURES = ["churn", "ownership_entropy", "co_change_scatter", "change_entropy"]
ALL_FEATURES = ["total_loc"] + PROCESS_FEATURES + ["structural_exposure"]

CACHE_DIR = pathlib.Path(
    "/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/"
    "scratchpad/procfeat_cache"
)


# ------------------------------------------------------------------ git plumbing
def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout


def commit_epoch(repo: pathlib.Path, sha: str) -> int:
    return int(_git(repo, "show", "-s", "--format=%ct", sha).strip())


def shannon_entropy_bits(counts) -> float:
    vals = [c for c in counts if c > 0]
    total = sum(vals)
    if total <= 0:
        return 0.0
    h = 0.0
    for c in vals:
        p = c / total
        h -= p * math.log2(p)
    return h


def compute_process_features(repo: pathlib.Path, parent: str,
                              window_days: int = WINDOW_DAYS,
                              commit_cap: int = LOG_COMMIT_CAP,
                              cache_dir: pathlib.Path = CACHE_DIR) -> dict:
    """Per-file churn/ownership_entropy/co_change_scatter/change_entropy from
    `git log <parent> ...` — ancestors of parent ONLY, leakage-free by
    construction. Cached to <cache_dir>/<parent>.json."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{parent}.json"
    if cache_file.exists():
        return json.loads(cache_file.read_text())

    pdate = commit_epoch(repo, parent)
    since_iso = datetime.datetime.utcfromtimestamp(
        pdate - window_days * 86400).strftime("%Y-%m-%d")
    out = subprocess.run(
        ["git", "-C", str(repo), "log", parent, f"--since={since_iso}",
         "-n", str(commit_cap), "--no-merges", "--name-only",
         "--pretty=format:@@|%H|%ct|%an"],
        capture_output=True, text=True, check=True,
    ).stdout

    churn: Counter = Counter()
    authors: dict[str, Counter] = defaultdict(Counter)
    cochange: dict[str, Counter] = defaultdict(Counter)
    n_commits = 0
    cur_author = "?"
    cur_files: list[str] = []

    def flush():
        n = len(cur_files)
        if 2 <= n <= COCHANGE_MAX_BREADTH:
            for f in cur_files:
                partners = cochange[f]
                for g in cur_files:
                    if g != f:
                        partners[g] += 1

    for line in out.splitlines():
        if line.startswith("@@|"):
            flush()
            cur_files = []
            n_commits += 1
            parts = line.split("|", 3)
            cur_author = parts[3] if len(parts) > 3 else "?"
            continue
        path = line.strip()
        if not path:
            continue
        churn[path] += 1
        authors[path][cur_author] += 1
        cur_files.append(path)
    flush()

    files: dict[str, dict] = {}
    for path in set(churn) | set(cochange):
        partners = cochange.get(path, {})
        scatter = len(partners)
        files[path] = {
            "churn": churn.get(path, 0),
            "ownership_entropy": round(shannon_entropy_bits(authors.get(path, {}).values()), 6),
            "co_change_scatter": scatter,
            "change_entropy": round(shannon_entropy_bits(partners.values()), 6) if scatter >= 2 else 0.0,
        }

    result = {"parent": parent, "since": since_iso, "window_days": window_days,
              "commit_cap": commit_cap, "n_commits_walked": n_commits, "files": files}
    cache_file.write_text(json.dumps(result))
    return result


ZERO_PROC = {"churn": 0, "ownership_entropy": 0.0, "co_change_scatter": 0, "change_entropy": 0.0}


# ------------------------------------------------------------------ DB plumbing
def structural_snapshot(con: sqlite3.Connection, sha: str) -> dict[str, tuple[float, float]]:
    """path -> (structural_exposure, total_loc) at commit sha, from file_data."""
    cols = ", ".join(f"risk_{c}" for c in STRUCTURAL_COLUMNS)
    rows = con.execute(
        f"SELECT file_path, total_loc, {cols} FROM file_data WHERE commit_hash = ?", (sha,)
    ).fetchall()
    out = {}
    for r in rows:
        expo = sum((r[2 + i] or 0) for i in range(len(STRUCTURAL_COLUMNS)))
        out[r[0]] = (expo, r[1] or 0)
    return out


# ------------------------------------------------------------------ event assembly
def collect_events(data: dict, repo: pathlib.Path, con: sqlite3.Connection,
                    window_days: int, commit_cap: int):
    """Returns (event_records, skip_counter, walk_seconds).
    event_records[i] = {"id": str, "n_files": int, "n_pos": int,
                         "rows": [ {path, is_pos, total_loc, structural_exposure,
                                    churn, ownership_entropy, co_change_scatter,
                                    change_entropy} ... ] }"""
    skip = Counter()
    records = []
    t0 = time.time()
    for e in data["events"]:
        if e["class"] != "security-fix":
            continue
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            skip["root commit (no parent)"] += 1
            continue
        snap = structural_snapshot(con, parent)
        if not snap:
            skip["parent not scanned in DB"] += 1
            continue
        statuses = diff_statuses(repo, parent, child)
        positives = {st["old_path"] for _p, st in statuses.items()
                     if st["status"] == "touched" and st["old_path"] in snap}
        if not positives:
            skip["no touched file present in parent snapshot"] += 1
            continue
        proc = compute_process_features(repo, parent, window_days, commit_cap)["files"]
        rows = []
        for path, (expo, loc) in snap.items():
            pf = proc.get(path, ZERO_PROC)
            rows.append({
                "path": path, "is_pos": path in positives,
                "total_loc": loc, "structural_exposure": expo,
                "churn": pf["churn"], "ownership_entropy": pf["ownership_entropy"],
                "co_change_scatter": pf["co_change_scatter"],
                "change_entropy": pf["change_entropy"],
            })
        records.append({"id": e["id"], "parent": parent, "n_files": len(snap),
                         "n_pos": len(positives), "rows": rows})
    walk_seconds = time.time() - t0
    return records, skip, walk_seconds


# ------------------------------------------------------------------ statistics
def rank_quartile_bands(values: list[float]) -> list[int]:
    """Equal-COUNT quartile bands (0=lowest .. 3=highest) by stable rank —
    value-quantile cut points collapse when a feature is heavily zero-inflated
    (see module docstring)."""
    n = len(values)
    order = sorted(range(n), key=lambda i: (values[i], i))
    bands = [0] * n
    edges = [i * n // 4 for i in range(5)]
    for b in range(4):
        for idx in order[edges[b]:edges[b + 1]]:
            bands[idx] = b
    return bands


def fmt(x, nd=4):
    return "n/a" if x is None or (isinstance(x, float) and x != x) else f"{x:.{nd}f}"


def pooled_feature_auc(records, feature: str) -> tuple[float, int, int]:
    obs = [(r[feature], r["is_pos"]) for rec in records for r in rec["rows"]]
    pos = sum(1 for _, y in obs if y)
    neg = len(obs) - pos
    return pooled_auc(obs), pos, neg


def within_band_test(records, band_feature: str, score_feature: str,
                      iters: int, seed: int, n_bands: int = 4):
    """Quartile-stratify pooled (feature=band_feature) files by rank; within
    each band, AUC of `score_feature` discriminating positives. Bootstraps
    over EVENTS (resampling the event list with replacement); band membership
    is fixed from the OBSERVED pooled population (not recomputed per
    resample) so the bands mean the same thing across iterations."""
    flat = [(rec_i, r) for rec_i, rec in enumerate(records) for r in rec["rows"]]
    band_vals = [r[band_feature] for _rec_i, r in flat]
    bands = rank_quartile_bands(band_vals)

    # per (event index, band) -> list of (score, is_pos)
    per_event_band: dict[tuple[int, int], list[tuple[float, bool]]] = defaultdict(list)
    for (rec_i, r), b in zip(flat, bands):
        per_event_band[(rec_i, b)].append((r[score_feature], r["is_pos"]))

    n_events = len(records)
    results = []
    for b in range(n_bands):
        pooled = [pair for rec_i in range(n_events) for pair in per_event_band.get((rec_i, b), [])]
        n_b = len(pooled)
        n_pos_b = sum(1 for _, y in pooled if y)
        obs_auc = pooled_auc(pooled)

        rng = random.Random(seed + b)  # distinct, deterministic stream per band
        boot = []
        for _ in range(iters):
            samp_idx = [rng.randrange(n_events) for _ in range(n_events)]
            samp = [pair for rec_i in samp_idx for pair in per_event_band.get((rec_i, b), [])]
            a = pooled_auc(samp)
            if a == a:  # skip NaN (degenerate resample: a class missing)
                boot.append(a)
        boot.sort()
        alpha_band = ALPHA / n_bands  # Bonferroni across the 4 bands
        lo_bound = q(boot, alpha_band) if boot else float("nan")
        ci95 = (q(boot, 0.025), q(boot, 0.975)) if boot else (float("nan"), float("nan"))
        supported = (obs_auc == obs_auc and obs_auc > 0.5
                     and lo_bound == lo_bound and lo_bound > 0.5)
        results.append({
            "band": b, "n": n_b, "n_pos": n_pos_b, "auc": obs_auc,
            "lo_bound": lo_bound, "alpha_band": alpha_band, "ci95": ci95,
            "n_boot": len(boot), "supported": supported,
        })
    return results


# ------------------------------------------------------------------ report
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default=str(EVENTS_DIR / "curl.json"))
    ap.add_argument("--out", default=str(DOCS_DIR / "incremental_value.md"))
    ap.add_argument("--iters", type=int, default=ITERS)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--window-days", type=int, default=WINDOW_DAYS)
    ap.add_argument("--commit-cap", type=int, default=LOG_COMMIT_CAP)
    args = ap.parse_args()
    if args.iters < 5000:
        sys.exit("--iters must be >= 5000 (pre-registered floor)")

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = None

    print(f"walking process-feature history for {data['repo']} events "
          f"(window={args.window_days}d, cap={args.commit_cap} commits, "
          f"cache={CACHE_DIR})...", flush=True)
    records, skip, walk_s = collect_events(data, repo, con, args.window_days, args.commit_cap)
    n_files_total = sum(rec["n_files"] for rec in records)
    n_pos_total = sum(rec["n_pos"] for rec in records)
    print(f"events usable: {len(records)} | skipped: {dict(skip)} | "
          f"pooled files: {n_files_total} | pooled positives: {n_pos_total} | "
          f"walk wall-time: {walk_s:.1f}s", flush=True)

    # ---- Step 1: descriptive pooled single-feature AUC -----------------------
    step1 = []
    for feat in ALL_FEATURES:
        auc, pos, neg = pooled_feature_auc(records, feat)
        step1.append({"feature": feat, "auc": auc, "n_pos": pos, "n_neg": neg})
    step1_ranked = sorted(step1, key=lambda r: (r["auc"] if r["auc"] == r["auc"] else -1),
                          reverse=True)
    strongest_process = max(
        (r for r in step1 if r["feature"] in PROCESS_FEATURES),
        key=lambda r: r["auc"] if r["auc"] == r["auc"] else -1,
    )["feature"]
    print(f"strongest process feature (by step-1 AUC): {strongest_process}", flush=True)

    # ---- IV-H1: bands of strongest process feature, AUC(structural_exposure)
    print(f"running IV-H1 (bands of {strongest_process}, score=structural_exposure, "
          f"{args.iters} boot iters x 4 bands)...", flush=True)
    t0 = time.time()
    iv_h1 = within_band_test(records, strongest_process, "structural_exposure",
                              args.iters, args.seed)
    iv_h1_s = time.time() - t0

    # ---- IV-H2: bands of structural_exposure, AUC(strongest process feature)
    print(f"running IV-H2 (bands of structural_exposure, score={strongest_process}, "
          f"{args.iters} boot iters x 4 bands)...", flush=True)
    t0 = time.time()
    iv_h2 = within_band_test(records, "structural_exposure", strongest_process,
                              args.iters, args.seed)
    iv_h2_s = time.time() - t0

    def headline(results):
        """The pre-registration gives a per-band Bonferroni-corrected verdict
        rule but does not say whether the OVERALL claim needs ALL bands or
        ANY band to clear it — genuinely ambiguous, so both readings are
        reported rather than collapsed into an invented middle label."""
        n_sup = sum(1 for r in results if r["supported"])
        all_sup = n_sup == len(results)
        any_sup = n_sup > 0
        return {
            "n_supported": n_sup, "n_bands": len(results),
            "strict_all_bands": "SUPPORTED" if all_sup else "not supported",
            "any_band": "SUPPORTED" if any_sup else "not supported",
        }
    h1_verdict = headline(iv_h1)
    h2_verdict = headline(iv_h2)

    # ------------------------------------------------------------ write doc
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    md = ["# Incremental-value test — does structure add lift over process?\n"]
    md.append(
        f"Generated {now} · repo `{data['repo']}` · pool HEAD `{data['pool_head'][:12]}` · "
        f"DB `{pathlib.Path(db).name}` (opened read-only, WAL-aware) · pre-registered "
        "gitgalaxy#2982 comment 5649564429; implemented verbatim; verdicts publish "
        "either way.\n"
    )
    md.append("## Leakage-free design\n")
    md.append(
        "Structural exposure and `total_loc` are read from the existing scan DB at each "
        "security-fix event's **parent** commit (T0) — no rescan. Process features "
        "(`churn`, `ownership_entropy`, `co_change_scatter`, `change_entropy`) are computed "
        "fresh from the pool clone via `git log <parent> --since=<parent_date-"
        f"{args.window_days}d> -n {args.commit_cap} --no-merges --name-only "
        "--pretty=format:\"@@|%H|%ct|%an\"` — starting AT the parent and walking only its "
        "ancestors, so no information from the fix commit or anything after it can enter "
        "the process features. This is necessary because scans in this program run with "
        "`GITGALAXY_DISABLE_GIT_HISTORY=1` (tools/_engine.py), which pegs churn/ownership "
        "to zero in every DB row — process signal for this test could not come from the DB "
        "even if leakage were not a concern.\n"
    )
    md.append(
        f"**Window**: {args.window_days} days before the parent's own commit date, capped "
        f"at {args.commit_cap} commits, `--no-merges` — matching the chronometer "
        "prototype's own `--since=1.year`/`--no-merges` default on engine branch "
        "`feat/cochange-entropy` (`gitgalaxy/metrics/chronometer.py`). Measured walk "
        f"wall-time for all {len(records)} usable events (one `git log` per distinct "
        f"parent, cached to disk keyed by parent sha): **{walk_s:.1f}s** on first run "
        "(subsequent runs read the cache and are near-instant). No window reduction was "
        "needed.\n"
    )
    md.append(
        "`co_change_scatter`/`change_entropy` ignore commits touching more than "
        f"{COCHANGE_MAX_BREADTH} files (mass reformats), identical to the chronometer "
        "prototype's `_record_cochange` gate. `churn`/`ownership_entropy` have no such "
        "filter (matching the prototype, which increments its churn/author maps "
        "unconditionally). `ownership_entropy` and `change_entropy` are reported as raw "
        "Shannon entropy in **bits**, not the engine's downstream 0–100 `min(H*32, 100)` "
        "scaled ownership score (`signal_processor._calc_ownership_entropy`) — the "
        "pre-registration text asks for entropy directly.\n"
    )
    md.append(
        f"Coverage: {len(records)} security-fix events usable (of "
        f"{sum(1 for e in data['events'] if e['class'] == 'security-fix')} in the event "
        f"set); skipped — {dict(skip) if skip else '(none)'}. Pooled candidate files "
        f"(sum of parent-snapshot sizes across usable events; a file recurs across nearby "
        f"events' snapshots by design, same pseudo-replication convention as every other "
        f"rung-6 tool here): **{n_files_total}**, pooled positives: **{n_pos_total}**.\n"
    )

    md.append("## 1 · Descriptive — single-feature pooled AUC (no verdict)\n")
    md.append(
        "Positives (fix-touched files) vs non-positive files, pooled over all usable "
        "parent snapshots. Ranks the six features; no significance claimed here.\n"
    )
    md.append("| rank | feature | AUC | n positives | n negatives |")
    md.append("|---|---|---|---|---|")
    for i, r in enumerate(step1_ranked, 1):
        md.append(f"| {i} | `{r['feature']}` | {fmt(r['auc'], 4)} | {r['n_pos']} | {r['n_neg']} |")
    md.append(f"\n**Strongest process feature: `{strongest_process}`** (highest AUC among "
              f"`{'`, `'.join(PROCESS_FEATURES)}`) — this is the stratifying feature for "
              "IV-H1 and the scored feature for IV-H2.\n")

    md.append("## 2 · IV-H1 — does structure add lift within process bands? (the real question)\n")
    md.append(
        f"Files stratified into quartile bands (equal-COUNT, by RANK — see design note "
        f"below) of `{strongest_process}`, pooled over all usable snapshots. Within each "
        f"band: AUC of `structural_exposure` separating positives from non-positives. "
        f"SUPPORTED iff AUC>0.5 AND the one-sided bootstrap lower bound at the "
        f"Bonferroni-adjusted alpha ({ALPHA}/4 = {ALPHA/4:.4f} percentile) excludes 0.5. "
        f"Bootstrap resamples the **event list** (not files) {args.iters} times, seed "
        f"{args.seed}+band-offset; band membership is fixed from the observed pooled data "
        f"(not recomputed per resample). Compute time: {iv_h1_s:.1f}s.\n"
    )
    md.append("| band (`" + strongest_process + "` quartile) | n files | n positives | "
              "AUC | boot lower bound (α/4) | 95% CI | n boot | verdict |")
    md.append("|---|---|---|---|---|---|---|---|")
    for r in iv_h1:
        md.append(
            f"| Q{r['band']+1} (lowest={r['band']==0}) | {r['n']} | {r['n_pos']} | "
            f"{fmt(r['auc'])} | {fmt(r['lo_bound'])} | "
            f"[{fmt(r['ci95'][0])}, {fmt(r['ci95'][1])}] | {r['n_boot']} | "
            f"{'**SUPPORTED**' if r['supported'] else 'not supported'} |"
        )
    md.append(
        f"\n**IV-H1: {h1_verdict['n_supported']}/{h1_verdict['n_bands']} bands clear the "
        f"Bonferroni bound.** The pre-registration states the per-band Bonferroni-corrected "
        f"verdict rule but does not say whether the OVERALL claim requires ALL bands or ANY "
        f"band to clear it — an ambiguity, resolved here by reporting both readings rather "
        f"than inventing a middle label: **strict (all 4 bands): "
        f"{h1_verdict['strict_all_bands']}** · **weak (any band): {h1_verdict['any_band']}**.\n"
    )

    md.append("## 3 · IV-H2 — the mirror: does process add lift within structure bands?\n")
    md.append(
        f"Files stratified into quartile bands of `structural_exposure`; within each band, "
        f"AUC of `{strongest_process}` (the same strongest process feature from step 1). "
        f"Same verdict rule, same bootstrap design. Compute time: {iv_h2_s:.1f}s.\n"
    )
    md.append("| band (`structural_exposure` quartile) | n files | n positives | "
              f"AUC(`{strongest_process}`) | boot lower bound (α/4) | 95% CI | n boot | verdict |")
    md.append("|---|---|---|---|---|---|---|---|")
    for r in iv_h2:
        md.append(
            f"| Q{r['band']+1} (lowest={r['band']==0}) | {r['n']} | {r['n_pos']} | "
            f"{fmt(r['auc'])} | {fmt(r['lo_bound'])} | "
            f"[{fmt(r['ci95'][0])}, {fmt(r['ci95'][1])}] | {r['n_boot']} | "
            f"{'**SUPPORTED**' if r['supported'] else 'not supported'} |"
        )
    md.append(
        f"\n**IV-H2: {h2_verdict['n_supported']}/{h2_verdict['n_bands']} bands clear the "
        f"Bonferroni bound** — **strict (all 4 bands): {h2_verdict['strict_all_bands']}** · "
        f"**weak (any band): {h2_verdict['any_band']}**.\n"
    )

    md.append("## Design notes / ambiguity resolutions\n")
    md.append(
        "- **Quartile bands are rank-based (equal count), not value-quantile cut points.** "
        "Process features under a bounded 1-year ancestors-only window are heavily "
        "zero-inflated (most files in any snapshot were not touched in the last year); a "
        "value-quantile split would collapse edges onto a single tied value. Rank "
        "quartiles guarantee ~n/4 files per band at the cost of splitting some tied "
        "values across adjacent bands — reported, not hidden.\n"
        "- **Band membership is fixed from the observed pooled population**, not "
        "recomputed inside the bootstrap loop, so a band means the same thing across all "
        "5000 resamples; only which events (and therefore which of that band's files) are "
        "present varies per resample, per the pre-registration's stated sampling unit "
        "(event, not file).\n"
        "- **`ownership_entropy`/`change_entropy` reported in raw bits**, not the engine's "
        "downstream 0-100 scaled ownership score — the registration text says \"Shannon "
        "entropy (bits)\" explicitly for `ownership_entropy`, and mirroring the chronometer "
        "prototype's `get_cochange_metrics` for `change_entropy` (which is already raw "
        "bits, unscaled).\n"
        "- **\"Strongest process feature\" picked by raw step-1 AUC** (not "
        "distance-from-0.5), i.e. the single highest AUC among the four process features, "
        "per a literal reading of \"pick by the step-1 AUC\".\n"
        "- **The overall IV-H1/IV-H2 verdict (all bands vs. any band) is ambiguous in the "
        "pre-registration.** \"Bonferroni across the 4 bands\" clearly sets each band's "
        "individual significance threshold, but the text never states whether the "
        "registered claim needs every band to clear it (structure adds lift uniformly "
        "across the whole process range) or just one (structure adds lift somewhere). Both "
        "readings are reported per test rather than picking one silently.\n"
    )

    md.append("---\n*Regenerate: `python tools/incremental_value.py --events events/curl.json` "
              "— stdlib only; process-feature git walks cached under "
              f"`{CACHE_DIR}` keyed by parent sha.*")

    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")
    print(f"\nStep 1 ranking: " + ", ".join(f"{r['feature']}={fmt(r['auc'])}" for r in step1_ranked))
    print(f"IV-H1 ({strongest_process} bands, score=structural_exposure): " +
          ", ".join(f"Q{r['band']+1} auc={fmt(r['auc'])} lo={fmt(r['lo_bound'])} "
                    f"n={r['n']}/pos={r['n_pos']}" for r in iv_h1) +
          f" -> {h1_verdict['n_supported']}/{h1_verdict['n_bands']} bands "
          f"(strict={h1_verdict['strict_all_bands']}, any={h1_verdict['any_band']})")
    print(f"IV-H2 (structural_exposure bands, score={strongest_process}): " +
          ", ".join(f"Q{r['band']+1} auc={fmt(r['auc'])} lo={fmt(r['lo_bound'])} "
                    f"n={r['n']}/pos={r['n_pos']}" for r in iv_h2) +
          f" -> {h2_verdict['n_supported']}/{h2_verdict['n_bands']} bands "
          f"(strict={h2_verdict['strict_all_bands']}, any={h2_verdict['any_band']})")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
