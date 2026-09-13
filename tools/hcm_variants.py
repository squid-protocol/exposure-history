#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Hassan HCM variant sweep (HV-H1/HV-H2) — PRE-REGISTERED verbatim on
gitgalaxy#2982, comment 5649866008, before this file existed. Implemented
verbatim; verdicts publish either way.

**The question.** repowise-bench ranks `change_entropy` its #2 defect
predictor (+0.24), but ships exactly ONE definition — a co-change-walk
entropy (`DECAY_TAU=180d`, `MAX_FILES_ENTROPY=30`, a 90-day window) — and the
only thing they interrogated was leakage, not *which* Hassan (2009)
formulation works. Hassan defines a whole family (attribution x decay x
period length). This program's binding constraint, established across three
independent routes plus repowise's own wall: **anything not size-orthogonal
just re-measures file size.** This sweep asks whether ANY member of the
Hassan family clears that wall; entropy is the one process feature measured
genuinely independent of scatter here (r=0.411 vs the redundant coupling
metric's 0.998), so it has the best remaining shot.

**Design — leakage-free by construction, reusing tools/incremental_value.py
verbatim.** Per security-fix event, T0 is the PARENT commit. `total_loc` and
`structural_exposure` come from the existing scan DB at T0 (`structural_
snapshot`, no rescan). Unit = file in a parent snapshot; positive = a file
the fix touches (`diff_statuses` parent..child, status "touched", old_path
present in the parent snapshot) — identical event assembly to the IV test
(`parent_child`, `diff_statuses`, `structural_snapshot` all imported, not
reimplemented).

HCM inputs come from the SAME leakage-free walk shape as the IV test's
process features (`git log <parent> --since=<parent_date-365d> -n 4000
--no-merges`, ancestors of parent ONLY) but this sweep needs the RAW
per-commit stream (timestamp + file list), not IV's pre-aggregated churn/
cochange counters — so `raw_commit_walk()` runs a parallel `git log`
(`--pretty=format:"@@|%H|%ct"`, no `--name-only` breadth filter) and caches
it separately, keyed by parent sha, under `hcmwalk_cache/` (sibling to IV's
`procfeat_cache/`, never mixed).

**The 36-variant matrix**, all computed per file per parent snapshot from
that walk. Commits are bucketed into fixed-length periods counting backward
from the parent commit (period k=0 = the most recent `period_days`-long
window before the parent; window=365d gives ceil(365/period_days) periods,
the last one partial). Per period: `H = -sum(p_i * log2(p_i))` over the
change-count distribution across files touched in that period, normalised
by `log2(n_files_changed)` (periods with n_files_changed<2 contribute
nothing — H is either exactly 0 there, n=1, or undefined by division, n=0).
  - **Attribution** (how a period's H reaches a file that changed in it):
    HCM1 = p_i*H (share-weighted) | HCM2 = (1/n)*H (uniform over files
    changed) | HCM3 = H (the period's full entropy, undiluted, to every
    file that changed in it).
  - **Decay** (weight by period age; age = the period's MIDPOINT in days
    before the parent commit — a period is a bucket, not an instant, and no
    single interior point is specified by the pre-registration; the
    midpoint is the resolution used here, called out again below):
    none (w=1) | ED exp(-age/180) | LD max(0, 1-age/window_days) |
    LGD 1/log2(2+age/30).
  - **Period length**: 30d | 90d | 180d.
  A file's score for one variant = sum over periods it appears in of
  decay_weight(age) * attribution(period, file).

**`repowise_flavour` reference column** (NOT one of the 36, NOT part of the
Bonferroni family — reported for context only, per the pre-registration's
explicit "reference, not a Hassan variant"). The pre-registration specifies
only two of repowise's real parameters in "their shape" (per-commit file cap
30, exponential decay tau=180d) and leaves period length and attribution
unstated (repowise's real metric is co-change-walk based, not period-based,
so it does not map onto this sweep's axes 1:1). Resolution, stated as an
ambiguity rather than silently picked: period=90d (matching the "90-day
activity window" language used to describe repowise's engine in this
program's other docs), attribution=HCM1 (share-weighted — the closest
period-based analogue to a per-file co-change weight), decay=ED tau=180d
exactly as specified, with the stated file cap of 30 applied by excluding
any commit touching more than 30 files from this column's period counts
(mirroring the `COCHANGE_MAX_BREADTH` mass-commit exclusion already used
elsewhere in this codebase, generalised to repowise's stated cap value).

**Evaluation — size-orthogonal by construction**, sharing IV's bootstrap
primitives verbatim:
  (a) pooled AUC per variant (`pooled_feature_auc`, imported unmodified).
  (b) AUC - AUC(total_loc): the lift-over-size number that is the point of
      this whole program.
  (c) within-LOC-quartile AUC (`within_band_test`, band_feature=total_loc,
      score_feature=variant) with a per-band bootstrap lower bound —
      the wall test.
Bootstrap over EVENTS, 5000 iters, seed 2982, exactly as pre-registered.

**Runtime containment (pre-registration explicitly authorizes this):** (a)
and (b) are cheap (already computed while assembling records) and are run
for all 36 variants + repowise_flavour + total_loc. (c) costs ~1 within_
band_test call (4 bands x 5000-iter bootstrap) per variant, which does not
scale to 36 — so (c) is run ONLY for the top 5 variants by (b) plus
EXPLICITLY `HCM1_none_90` (the engine's shipped definition), unioned and
de-duplicated. Which variants got the full (c) treatment is printed and
written into the generated doc.

**HV-H1** (the real claim): SUPPORTED iff at least one variant (among those
given the full (c) treatment — see runtime note) clears within-band AUC>0.5
with the one-sided bootstrap lower bound excluding 0.5 in >=3 of 4 LOC
bands, Bonferroni across bands AND across the 36-variant family:
alpha_eff = 0.01/(4*36) ~= 6.9444e-05. `within_band_test` (tools/
incremental_value.py) gained an optional `alpha=` parameter for this (default
unchanged, so IV's own two call sites are unaffected) rather than being
forked or reimplemented.

**HV-H2** (ranking, confirmatory only for the winner): the best variant by
(b) beats `total_loc` pooled, one-sided bootstrap over events, alpha=0.01
(single comparison, no Bonferroni — the pre-registration corrects the sweep
as one family for HV-H1 and evaluates HV-H2 only for the single named
winner).

    python tools/hcm_variants.py --events events/curl.json
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
from _engine import DOCS_DIR, EVENTS_DIR  # noqa: E402
from delta_report import q  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from incremental_value import (  # noqa: E402
    ALPHA, ITERS, LOG_COMMIT_CAP, SEED, WINDOW_DAYS,
    commit_epoch, fmt, pooled_feature_auc, structural_snapshot, within_band_test,
)
from rw_analyses import pooled_auc  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import parent_child  # noqa: E402

N_BANDS = 4
N_VARIANTS = 36  # the Hassan family size (repowise_flavour is a reference column, not counted)
ALPHA_EFF = ALPHA / (N_BANDS * N_VARIANTS)  # 0.01 / (4*36) = 6.944...e-05

PERIOD_LENGTHS = [30, 90, 180]
ATTRIBUTIONS = ["HCM1", "HCM2", "HCM3"]
DECAYS = ["none", "ED", "LD", "LGD"]

REPOWISE_PERIOD = 90
REPOWISE_FILE_CAP = 30
REPOWISE_DECAY_TAU = 180.0

HCMWALK_CACHE = pathlib.Path(
    "/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/"
    "scratchpad/hcmwalk_cache"
)


def variant_name(attribution: str, decay: str, period: int) -> str:
    return f"{attribution}_{decay}_{period}"


ALL_36 = [variant_name(a, d, p) for a in ATTRIBUTIONS for d in DECAYS for p in PERIOD_LENGTHS]
assert len(ALL_36) == N_VARIANTS


# ------------------------------------------------------------------ raw commit walk
def raw_commit_walk(repo: pathlib.Path, parent: str,
                     window_days: int = WINDOW_DAYS, commit_cap: int = LOG_COMMIT_CAP,
                     cache_dir: pathlib.Path = HCMWALK_CACHE) -> dict:
    """Raw (timestamp, file-list) commit stream for <parent>'s ancestors only,
    same leakage-free window/cap/--no-merges shape as
    incremental_value.compute_process_features, but UN-aggregated (this
    sweep needs to bucket commits into periods, not sum them into one
    churn/cochange count). Cached separately (hcmwalk_cache/, keyed by
    parent sha) from IV's own procfeat_cache/ — parallel cache, same git
    command shape, never shared or mixed."""
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
         "--pretty=format:@@|%H|%ct"],
        capture_output=True, text=True, check=True,
    ).stdout

    commits: list[dict] = []
    cur_ct = None
    cur_files: list[str] = []
    for line in out.splitlines():
        if line.startswith("@@|"):
            if cur_ct is not None:
                commits.append({"ct": cur_ct, "files": cur_files})
            parts = line.split("|")
            cur_ct = int(parts[2])
            cur_files = []
            continue
        path = line.strip()
        if path:
            cur_files.append(path)
    if cur_ct is not None:
        commits.append({"ct": cur_ct, "files": cur_files})

    result = {"parent": parent, "parent_epoch": pdate, "since": since_iso,
              "window_days": window_days, "commit_cap": commit_cap,
              "n_commits_walked": len(commits), "commits": commits}
    cache_file.write_text(json.dumps(result))
    return result


# ------------------------------------------------------------------ period / HCM math
def decay_weight(name: str, age_days: float, window_days: int) -> float:
    if name == "none":
        return 1.0
    if name == "ED":
        return math.exp(-age_days / 180.0)
    if name == "LD":
        return max(0.0, 1.0 - age_days / window_days)
    if name == "LGD":
        return 1.0 / math.log2(2.0 + age_days / 30.0)
    raise ValueError(f"unknown decay {name!r}")


def build_periods(commits: list[dict], parent_epoch: int, period_len: int,
                   window_days: int, file_cap: int | None = None) -> list[dict]:
    """Bucket commits into fixed-length periods counting backward from the
    parent commit (k=0 = most recent). age_days uses the PERIOD MIDPOINT as
    its single representative age for decay weighting (an ambiguity
    resolution — a period is a span, not an instant; see module docstring).
    `file_cap`, when given, drops any commit touching more than that many
    files from the period's counts entirely (repowise_flavour only)."""
    n_periods = max(1, math.ceil(window_days / period_len))
    buckets: list[Counter] = [Counter() for _ in range(n_periods)]
    for c in commits:
        age = (parent_epoch - c["ct"]) / 86400.0
        if age < 0:
            age = 0.0
        k = int(age // period_len)
        if k >= n_periods:
            k = n_periods - 1  # clip window-boundary stragglers into the oldest bucket
        files = c["files"]
        if file_cap is not None and len(files) > file_cap:
            continue
        for f in files:
            buckets[k][f] += 1
    periods = []
    for k, bucket in enumerate(buckets):
        total = sum(bucket.values())
        n_files = len(bucket)
        periods.append({
            "k": k, "age": k * period_len + period_len / 2.0,
            "counts": bucket, "n_files": n_files, "total": total,
        })
    return periods


def period_entropy(period: dict) -> float:
    n = period["n_files"]
    if n < 2:  # pre-registration: "skip periods with n<2" (also avoids the log2(1)=0 divide)
        return 0.0
    total = period["total"]
    h = 0.0
    for c in period["counts"].values():
        p = c / total
        h -= p * math.log2(p)
    return h / math.log2(n)


def compute_all_variants(commits: list[dict], parent_epoch: int,
                          window_days: int) -> dict[str, dict[str, float]]:
    """Returns {variant_name: {path: score}} for all 36 Hassan variants plus
    `repowise_flavour`. One pass per period length over the (already
    walked/cached) raw commit stream — pure Python, no subprocess calls."""
    scores: dict[str, dict[str, float]] = {name: defaultdict(float) for name in ALL_36}

    for period_len in PERIOD_LENGTHS:
        periods = build_periods(commits, parent_epoch, period_len, window_days)
        for period in periods:
            if period["n_files"] < 2:
                continue
            h = period_entropy(period)
            total = period["total"]
            n_files = period["n_files"]
            for attribution in ATTRIBUTIONS:
                for path, count_i in period["counts"].items():
                    if attribution == "HCM1":
                        val = (count_i / total) * h
                    elif attribution == "HCM2":
                        val = h / n_files
                    else:  # HCM3
                        val = h
                    if val == 0.0:
                        continue
                    for decay in DECAYS:
                        w = decay_weight(decay, period["age"], window_days)
                        scores[variant_name(attribution, decay, period_len)][path] += w * val

    # repowise_flavour reference column — see module docstring for the
    # (period=90d, attribution=HCM1, decay=ED tau=180d, file_cap=30) resolution.
    rw_scores: dict[str, float] = defaultdict(float)
    rw_periods = build_periods(commits, parent_epoch, REPOWISE_PERIOD, window_days,
                                file_cap=REPOWISE_FILE_CAP)
    for period in rw_periods:
        if period["n_files"] < 2:
            continue
        h = period_entropy(period)
        if h == 0.0:
            continue
        w = math.exp(-period["age"] / REPOWISE_DECAY_TAU)
        total = period["total"]
        for path, count_i in period["counts"].items():
            rw_scores[path] += w * (count_i / total) * h
    scores["repowise_flavour"] = rw_scores

    return {k: dict(v) for k, v in scores.items()}


# ------------------------------------------------------------------ event assembly
def collect_events_hcm(data: dict, repo: pathlib.Path, con: sqlite3.Connection,
                        window_days: int, commit_cap: int):
    """Same event/candidate-pool assembly as incremental_value.collect_events
    (parent_child, structural_snapshot, diff_statuses — all imported, not
    reimplemented) but rows carry the 36 HCM variant scores + repowise_
    flavour instead of process features. Returns (records, skip, walk_s)."""
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
        walk = raw_commit_walk(repo, parent, window_days, commit_cap)
        variant_scores = compute_all_variants(walk["commits"], walk["parent_epoch"], window_days)
        rows = []
        for path, (expo, loc) in snap.items():
            row = {"path": path, "is_pos": path in positives,
                   "total_loc": loc, "structural_exposure": expo}
            for vname, scoremap in variant_scores.items():
                row[vname] = scoremap.get(path, 0.0)
            rows.append(row)
        records.append({"id": e["id"], "parent": parent, "n_files": len(snap),
                         "n_pos": len(positives), "rows": rows})
    walk_seconds = time.time() - t0
    return records, skip, walk_seconds


# ------------------------------------------------------------------ HV-H2 paired bootstrap
def paired_lift_bootstrap(records, feat_a: str, feat_b: str,
                           iters: int, seed: int, alpha: float):
    """One-sided bootstrap over EVENTS for pooled AUC(feat_a) - AUC(feat_b) > 0
    (HV-H2: the (b)-winning variant vs total_loc, pooled, single comparison,
    no Bonferroni). Reuses pooled_feature_auc (imported from
    incremental_value) on resampled event lists — same resampling unit and
    machinery as within_band_test, just without band-splitting."""
    obs_a = pooled_feature_auc(records, feat_a)[0]
    obs_b = pooled_feature_auc(records, feat_b)[0]
    obs_diff = obs_a - obs_b
    n_events = len(records)
    rng = random.Random(seed)
    boot = []
    for _ in range(iters):
        idx = [rng.randrange(n_events) for _ in range(n_events)]
        sample = [records[i] for i in idx]
        a = pooled_feature_auc(sample, feat_a)[0]
        b = pooled_feature_auc(sample, feat_b)[0]
        d = a - b
        if d == d:
            boot.append(d)
    boot.sort()
    lo = q(boot, alpha) if boot else float("nan")
    ci95 = (q(boot, 0.025), q(boot, 0.975)) if boot else (float("nan"), float("nan"))
    supported = obs_diff == obs_diff and obs_diff > 0 and lo == lo and lo > 0
    return {"obs_a": obs_a, "obs_b": obs_b, "obs_diff": obs_diff, "lo_bound": lo,
            "alpha": alpha, "ci95": ci95, "n_boot": len(boot), "supported": supported}


# ------------------------------------------------------------------ report
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default=str(EVENTS_DIR / "curl.json"))
    ap.add_argument("--out", default=str(DOCS_DIR / "hcm_variants.md"))
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

    print(f"walking raw HCM commit history for {data['repo']} events "
          f"(window={args.window_days}d, cap={args.commit_cap} commits, "
          f"cache={HCMWALK_CACHE})...", flush=True)
    records, skip, walk_s = collect_events_hcm(data, repo, con, args.window_days, args.commit_cap)
    n_files_total = sum(rec["n_files"] for rec in records)
    n_pos_total = sum(rec["n_pos"] for rec in records)
    print(f"events usable: {len(records)} | skipped: {dict(skip)} | "
          f"pooled files: {n_files_total} | pooled positives: {n_pos_total} | "
          f"walk wall-time: {walk_s:.1f}s", flush=True)

    # ---- (a)/(b): cheap pooled AUC + lift-vs-LOC for all 36 + reference ------
    auc_loc, pos_loc, neg_loc = pooled_feature_auc(records, "total_loc")
    print(f"pooled AUC(total_loc) = {fmt(auc_loc)} (n_pos={pos_loc}, n_neg={neg_loc})", flush=True)

    sweep = []
    for vname in ALL_36:
        auc, pos, neg = pooled_feature_auc(records, vname)
        lift = auc - auc_loc if (auc == auc and auc_loc == auc_loc) else float("nan")
        sweep.append({"variant": vname, "auc": auc, "lift": lift, "n_pos": pos, "n_neg": neg})
    sweep_ranked = sorted(
        sweep, key=lambda r: (r["lift"] if r["lift"] == r["lift"] else -9), reverse=True)

    rw_auc, rw_pos, rw_neg = pooled_feature_auc(records, "repowise_flavour")
    rw_lift = rw_auc - auc_loc if (rw_auc == rw_auc and auc_loc == auc_loc) else float("nan")

    best_variant = sweep_ranked[0]["variant"]
    print(f"best variant by lift-vs-LOC: {best_variant} "
          f"(auc={fmt(sweep_ranked[0]['auc'])}, lift={fmt(sweep_ranked[0]['lift'])})", flush=True)

    # ---- (c): expensive within-LOC-quartile bootstrap for the top-5 by (b) --
    # plus explicitly HCM1_none_90 (the engine's shipped definition) — the
    # pre-registration authorizes and asks us to state this containment.
    top5 = [r["variant"] for r in sweep_ranked[:5]]
    subset = list(dict.fromkeys(top5 + ["HCM1_none_90"]))  # de-duplicated, order preserved
    print(f"running within-LOC-quartile bootstrap ((c)) for the subset given full treatment: "
          f"{subset} ({args.iters} iters x {N_BANDS} bands each)...", flush=True)

    within_band_results = {}
    t0 = time.time()
    for vname in subset:
        within_band_results[vname] = within_band_test(
            records, "total_loc", vname, args.iters, args.seed, n_bands=N_BANDS, alpha=ALPHA_EFF)
    within_band_s = time.time() - t0
    print(f"within-band bootstrap wall-time: {within_band_s:.1f}s", flush=True)

    # ---- HV-H1 ---------------------------------------------------------------
    h1_per_variant = {}
    for vname, bands in within_band_results.items():
        n_sup = sum(1 for r in bands if r["supported"])
        h1_per_variant[vname] = {"n_supported": n_sup, "n_bands": len(bands),
                                  "clears": n_sup >= 3}
    h1_supported = any(v["clears"] for v in h1_per_variant.values())
    h1_winner = next((v for v, r in h1_per_variant.items() if r["clears"]), None)

    # ---- HV-H2 -----------------------------------------------------------
    print(f"running HV-H2 paired bootstrap ({best_variant} vs total_loc, pooled, "
          f"{args.iters} iters)...", flush=True)
    t0 = time.time()
    h2 = paired_lift_bootstrap(records, best_variant, "total_loc", args.iters, args.seed, ALPHA)
    h2_s = time.time() - t0
    print(f"HV-H2 wall-time: {h2_s:.1f}s", flush=True)

    total_runtime = walk_s + within_band_s + h2_s

    # ------------------------------------------------------------ write doc
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    md = ["# Hassan HCM variant sweep — does ANY entropy formulation beat file size?\n"]
    md.append(
        f"Generated {now} · repo `{data['repo']}` · pool HEAD `{data['pool_head'][:12]}` · "
        f"DB `{pathlib.Path(db).name}` (opened read-only, WAL-aware) · pre-registered "
        "gitgalaxy#2982 comment 5649866008; implemented verbatim; verdicts publish "
        "either way.\n"
    )

    md.append("## Leakage-free design\n")
    md.append(
        "`total_loc` and `structural_exposure` are read from the existing scan DB at each "
        "security-fix event's **parent** commit (T0) — no rescan. Every HCM variant is "
        "computed fresh from the pool clone via `git log <parent> --since=<parent_date-"
        f"{args.window_days}d> -n {args.commit_cap} --no-merges --name-only "
        "--pretty=format:\"@@|%H|%ct\"` — starting AT the parent and walking only its "
        "ancestors, so no information from the fix commit or anything after it can enter "
        "any variant's score. This reuses the exact leakage-free walk shape verified in "
        "`tools/incremental_value.py` (IV-H1/IV-H2, gitgalaxy#2982 comment 5649564429); a "
        "parallel raw-commit-stream cache (`hcmwalk_cache/`, keyed by parent sha) sits "
        "alongside IV's own `procfeat_cache/` — same git command shape, never mixed, "
        "because this sweep needs the un-aggregated per-commit (timestamp, file-list) "
        "stream to build periods, not IV's pre-summed churn/cochange counters.\n"
    )
    md.append(
        f"Coverage: {len(records)} security-fix events usable (of "
        f"{sum(1 for e in data['events'] if e['class'] == 'security-fix')} in the event "
        f"set); skipped — {dict(skip) if skip else '(none)'}. Pooled candidate files: "
        f"**{n_files_total}**, pooled positives: **{n_pos_total}**. Raw-walk wall-time: "
        f"**{walk_s:.1f}s** (cached per parent sha; near-instant on re-run).\n"
    )

    md.append("## The 36-variant matrix (+ `repowise_flavour` reference)\n")
    md.append(
        "Per-period entropy `H = -Σ p_i log2(p_i)` over the change-count distribution "
        "across files touched in that period, normalised by `log2(n_files_changed)` "
        "(periods with n_files_changed<2 contribute nothing). Periods count backward from "
        "the parent commit in fixed-length buckets (k=0 = most recent); a period's "
        "representative age for decay weighting is its **midpoint** (an ambiguity "
        "resolution — a period is a span, not an instant; see Design notes).\n"
        "- **Attribution**: `HCM1` = p_i·H (share-weighted) · `HCM2` = (1/n)·H "
        "(uniform over files changed) · `HCM3` = H (full period entropy, undiluted).\n"
        "- **Decay**: `none` (w=1) · `ED` exp(-age/180) · `LD` max(0, 1-age/"
        f"{args.window_days}) · `LGD` 1/log2(2+age/30).\n"
        "- **Period length**: 30d · 90d · 180d.\n"
        "- `repowise_flavour` (reference, NOT one of the 36, NOT in the Bonferroni family): "
        "period=90d, attribution=HCM1, decay=ED τ=180d, with commits touching >30 files "
        "excluded from its period counts (repowise's stated file cap, generalised from "
        "per-commit to this sweep's per-period design — see Design notes).\n"
    )

    md.append("### Full 36-variant ranking, by lift over `total_loc` (pooled AUC − AUC(total_loc))\n")
    md.append(f"Pooled AUC(`total_loc`) baseline: **{fmt(auc_loc)}** "
              f"(n_pos={pos_loc}, n_neg={neg_loc}).\n")
    md.append("| rank | variant | pooled AUC | lift vs total_loc | n_pos | n_neg |")
    md.append("|---|---|---|---|---|---|")
    for i, r in enumerate(sweep_ranked, 1):
        md.append(f"| {i} | `{r['variant']}` | {fmt(r['auc'])} | {fmt(r['lift'])} | "
                  f"{r['n_pos']} | {r['n_neg']} |")
    md.append(f"| — | `repowise_flavour` (reference) | {fmt(rw_auc)} | {fmt(rw_lift)} | "
              f"{rw_pos} | {rw_neg} |")
    n_beat_loc = sum(1 for r in sweep if r["lift"] == r["lift"] and r["lift"] > 0)
    md.append(f"\n**{n_beat_loc}/36 variants have positive pooled lift over `total_loc`.** "
              f"Best by lift: **`{best_variant}`** "
              f"(AUC {fmt(sweep_ranked[0]['auc'])}, lift {fmt(sweep_ranked[0]['lift'])}).\n")

    md.append("## (c) Within-LOC-quartile bootstrap — the wall test\n")
    md.append(
        f"**Runtime containment (pre-registration authorizes this):** the expensive "
        f"within-band bootstrap ({args.iters} iters × {N_BANDS} bands, one "
        "`within_band_test` call per variant) was run ONLY for the **top 5 variants by "
        f"lift** ({', '.join('`'+v+'`' for v in top5)}) **plus explicitly `HCM1_none_90`** "
        "(the engine's currently shipped definition) — not all 36. De-duplicated "
        f"subset actually run: {', '.join('`'+v+'`' for v in subset)}. Band = `total_loc` "
        "quartile (rank-based, equal count, same convention as IV); score = the variant. "
        f"Bootstrap resamples the **event list** {args.iters} times, seed {args.seed}+"
        f"band-offset. **Effective alpha: {ALPHA}/({N_BANDS}×{N_VARIANTS}) = "
        f"{ALPHA_EFF:.6e}** — Bonferroni across the 4 bands AND the full 36-variant "
        "family (the sweep is a multiple-comparison machine and is corrected as one, per "
        f"pre-registration, even though only {len(subset)} of the 36 were actually tested "
        "at this stage — the correction denominator stays 36, not 6, because the claim "
        "being protected is about the whole family). Within-band compute time: "
        f"{within_band_s:.1f}s.\n"
    )
    for vname in subset:
        bands = within_band_results[vname]
        md.append(f"### `{vname}`\n")
        md.append("| band (`total_loc` quartile) | n files | n positives | AUC | "
                  f"boot lower bound (α_eff/4) | 95% CI | n boot | verdict |")
        md.append("|---|---|---|---|---|---|---|---|")
        for r in bands:
            md.append(
                f"| Q{r['band']+1} (lowest={r['band']==0}) | {r['n']} | {r['n_pos']} | "
                f"{fmt(r['auc'])} | {fmt(r['lo_bound'])} | "
                f"[{fmt(r['ci95'][0])}, {fmt(r['ci95'][1])}] | {r['n_boot']} | "
                f"{'**SUPPORTED**' if r['supported'] else 'not supported'} |"
            )
        h1v = h1_per_variant[vname]
        md.append(f"\n{h1v['n_supported']}/{h1v['n_bands']} bands clear "
                  f"(needs ≥3 of 4 for this variant to carry HV-H1).\n")

    md.append("## Verdicts\n")
    md.append(f"### HV-H1 (the real claim)\n")
    md.append(
        f"SUPPORTED iff at least one variant (among those given the full (c) treatment "
        f"above) clears within-band AUC>0.5 with the bootstrap lower bound excluding 0.5 "
        f"in ≥3 of 4 LOC bands, at α_eff={ALPHA_EFF:.6e}. "
        f"**HV-H1: {'SUPPORTED' if h1_supported else 'not supported'}**"
        + (f" (carried by `{h1_winner}`)." if h1_winner else
           f" — none of the {len(subset)} tested variants (top 5 by lift + "
           "`HCM1_none_90`) cleared ≥3 bands. This does not exhaustively rule out one "
           "of the remaining 31 variants clearing it — the within-band bootstrap was "
           "not run on them, per the stated runtime containment — but every variant "
           "left untested scored a LOWER pooled lift than the ones tested here, which is "
           "the evidence available for why they were not expected to fare better.") + "\n"
    )
    md.append(f"### HV-H2 (ranking, confirmatory only for the winner)\n")
    md.append(
        f"The best variant by (b), `{best_variant}`, vs `total_loc`, pooled, one-sided "
        f"bootstrap over events (no Bonferroni — single named comparison), "
        f"α={ALPHA}. Observed pooled AUC({best_variant})={fmt(h2['obs_a'])} vs "
        f"AUC(total_loc)={fmt(h2['obs_b'])}, diff={fmt(h2['obs_diff'])}, one-sided bootstrap "
        f"lower bound (α={ALPHA} percentile)={fmt(h2['lo_bound'])}, 95% CI=["
        f"{fmt(h2['ci95'][0])}, {fmt(h2['ci95'][1])}], n_boot={h2['n_boot']}. "
        f"**HV-H2: {'SUPPORTED' if h2['supported'] else 'not supported'}**. Compute time: "
        f"{h2_s:.1f}s.\n"
    )

    md.append("## Plain-language reading\n")
    reading = []
    if not h1_supported and not h2["supported"]:
        reading.append(
            "The pre-registered prior holds: **no member of the Hassan entropy family "
            "beats plain file size within LOC bands, and the best of the 36 does not even "
            "beat file size pooled.** This extends the program's core finding — churn, "
            "co-change, ownership, and structural exposure have all failed the same wall "
            "— to the *entire* Hassan attribution/decay/period family at once, not "
            "just repowise's one shipped definition. `change_entropy` (repowise's #2 "
            "predictor) is, on this evidence, a file-size proxy under every parameterisation "
            "tried here."
        )
    elif h1_supported and not h2["supported"]:
        reading.append(
            f"Mixed result: `{h1_winner}` clears the within-band wall in ≥3 of 4 LOC "
            "quartiles at the full Bonferroni-corrected alpha — a genuine, "
            "size-orthogonal signal somewhere in the process-feature range — but the "
            f"single best-by-lift variant (`{best_variant}`) does not beat `total_loc` "
            "pooled overall. The family has a real component; it does not dominate size in "
            "aggregate."
        )
    elif not h1_supported and h2["supported"]:
        reading.append(
            f"`{best_variant}` beats `total_loc` pooled (HV-H2 supported), but that lift "
            "does not survive being checked separately within each LOC quartile at the "
            "full Bonferroni-corrected bound (HV-H1 not supported) — consistent with "
            "the pooled win being driven by the LOC-size gradient itself rather than a "
            "same-size-file discriminator."
        )
    else:
        reading.append(
            f"Both verdicts support: `{h1_winner or best_variant}` clears the within-band "
            "wall in ≥3 of 4 quartiles AND beats `total_loc` pooled. On this evidence "
            "the Hassan family contains at least one genuinely size-orthogonal defect "
            "signal — the first process feature in this program to clear the wall."
        )
    md.append(" ".join(reading) + "\n")

    md.append("## Design notes / ambiguity resolutions\n")
    md.append(
        "- **Period age for decay = the period's midpoint in days before the parent "
        "commit.** The pre-registration specifies decay as a function of \"age_days\" but "
        "a period is a span (e.g. all commits 30-60 days back), not an instant; the "
        "midpoint (45 days, in that example) is the representative age used here, applied "
        "uniformly across all decay functions and period lengths.\n"
        "- **`repowise_flavour`'s period length and attribution are not stated** by the "
        "pre-registration (only its file cap and decay tau are); resolved as period=90d "
        "(matching this program's other documentation of repowise's own 90-day activity "
        "window), attribution=HCM1 (the closest period-based analogue to a per-file "
        "co-change weight), with the stated 30-file cap applied by excluding oversized "
        "commits from that column's period counts entirely.\n"
        "- **`within_band_test` (tools/incremental_value.py) gained an optional `alpha=` "
        "parameter** (default unchanged at the module's own ALPHA=0.01) so this sweep can "
        "pass its own family-wide alpha_eff without forking or reimplementing the "
        "bootstrap; IV's own two call sites (IV-H1/IV-H2) are unaffected — verified by "
        "`py_compile` and by re-reading both call sites after the edit.\n"
        "- **HV-H1's Bonferroni denominator stays 36** even though only "
        f"{len(subset)} variants received the full (c) treatment — the claim being "
        "protected from multiple-comparison inflation is about the 36-variant family as a "
        "whole, per the pre-registration text (\"across the variant count\"), not about "
        "however many were actually run.\n"
        "- **Candidate pool pseudo-replication**: the same file can recur across nearby "
        "events' parent snapshots (expected, same convention as every other rung-6 tool "
        "in this repo); the bootstrap's resampling unit is nonetheless the EVENT, per the "
        "pre-registration.\n"
    )

    md.append(f"---\n*Regenerate: `python tools/hcm_variants.py --events events/curl.json` "
              f"— stdlib only; raw commit walks cached under `{HCMWALK_CACHE}` keyed by "
              f"parent sha. Total measured wall-time this run: {total_runtime:.1f}s "
              f"(walk {walk_s:.1f}s + within-band {within_band_s:.1f}s + HV-H2 {h2_s:.1f}s).*")

    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")

    print(f"\nTop 10 by lift: " + ", ".join(
        f"{r['variant']}={fmt(r['lift'])}" for r in sweep_ranked[:10]))
    print(f"Bottom 3 by lift: " + ", ".join(
        f"{r['variant']}={fmt(r['lift'])}" for r in sweep_ranked[-3:]))
    print(f"repowise_flavour: auc={fmt(rw_auc)} lift={fmt(rw_lift)}")
    print(f"HV-H1: {'SUPPORTED' if h1_supported else 'not supported'} "
          f"(alpha_eff={ALPHA_EFF:.6e}, winner={h1_winner})")
    print(f"HV-H2: {'SUPPORTED' if h2['supported'] else 'not supported'} "
          f"(best={best_variant}, diff={fmt(h2['obs_diff'])}, lo={fmt(h2['lo_bound'])})")
    print(f"total runtime: {total_runtime:.1f}s")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
