#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Keyword-first exploratory analysis, all 8 scanned event classes (curl).

EXPLORATORY / post-hoc, no p-values anywhere. Reuses the wave1_analysis.py /
signal_anatomy.py pass-1 machinery (identical touched-file signal-delta
extraction) but widens it in two ways:

  * ALL 8 classes already in the DB: security-fix, control, introduced
    (events/curl.json); revert, cve-followup (events/curl_wave1.json);
    bugfix-fixes, bugfix-bug, regression (events/curl_bugs.json).
  * Per-event stats now also carry touched file PATHS, per-signal SUMS (not
    just the mean), and the commit subject -- needed for Part B's inversion
    (pool by which files NET-ADD a construct, then look at what else is true
    of that pool) and Part C's co-movement structure.

Three deliverables in one report (docs/keyword_pools_explore.md):
  A. the owed per-class grammar table (does an ordinary bug fix carry the
     CVE fix-grammar, or not)
  B. keyword-first pools -- the inversion: pool by ANCHOR SIGNAL net-add,
     read off class composition / area profile / co-added signals
  C. signal co-movement structure -- Spearman correlation, single-linkage
     clustering, cluster-vs-net-LOC (which clusters are just "size in
     disguise")

Per-event stats are cached to dbs/keyword_pools_cache.json (keyed by sha;
gitignored, so reruns after the first are instant and nothing here is ever
committed by accident).

The compute pass parallelizes ACROSS EVENTS with a fork-context
multiprocessing.Pool (default 10 workers) -- each event's stats (a git diff
+ two file_rows sqlite queries) are independent. Each worker opens its own
read-only WAL-aware sqlite connection lazily (connections don't survive a
fork); only the parent process ever writes the cache file.

Usage:
    python tools/keyword_pools.py --limit 40        # foreground sanity run
    python tools/keyword_pools.py                   # full run (~2-4 min @ 10 workers)
    python tools/keyword_pools.py --skip-compute     # report only, cache as-is
    python tools/keyword_pools.py --workers 4        # smaller pool
"""
from __future__ import annotations

import argparse
import json
import math
import multiprocessing
import pathlib
import sqlite3
import subprocess
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DBS_DIR, DOCS_DIR, EVENTS_DIR  # noqa: E402
from delta_report import median, spearman  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import file_rows, parent_child, signal_columns  # noqa: E402

EVENT_FILES = ["curl.json", "curl_wave1.json", "curl_bugs.json"]
CACHE_PATH = DBS_DIR / "keyword_pools_cache.json"
OUT_PATH = DOCS_DIR / "keyword_pools_explore.md"

CLASS_ORDER = ["security-fix", "regression", "bugfix-bug", "bugfix-fixes",
               "control", "introduced", "revert", "cve-followup"]

GRAMMAR_SIGNALS = ["struct_branch", "state_pointers", "state_memory_alloc",
                    "state_cast_hits", "def_safety", "state_bailout_hits",
                    "arch_io", "arch_time", "def_test", "def_doc",
                    "state_planned_debt"]

ANCHOR_SIGNALS = ["struct_branch", "state_pointers", "state_memory_alloc",
                   "state_cast_hits", "def_safety", "state_bailout_hits",
                   "arch_io", "arch_api", "arch_crypto", "arch_time",
                   "def_test", "state_planned_debt"]

CO_ADD_THRESHOLD = 0.25   # Part B: report co-added signals present in >= this share of the pool
CLUSTER_THRESHOLD = 0.6   # Part C: single-linkage edge if |rho| >= this
SIZE_PROXY_THRESHOLD = 0.5  # Part C: cluster counts as "size in disguise" if |rho w/ net-LOC| >= this
ACTIVE_SIGNAL_FLOOR = 0.03  # Part C: drop signals that move in < this share of events
TOP_N_ACTIVE = 25


# ------------------------------------------------------------------ extraction
def commit_subject(repo, sha) -> str:
    out = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%s", sha],
                          capture_output=True).stdout
    return out.decode("utf-8", errors="replace").strip()


def event_stats_full(con, repo, fcols, sha):
    """Like wave1_analysis.event_stats, but also returns touched file paths,
    per-signal SUMS, and the commit subject."""
    parent, child = parent_child(repo, sha)
    if parent is None:
        return None
    before = file_rows(con, parent, fcols)
    after = file_rows(con, child, fcols)
    if not before or not after:
        return None
    statuses = diff_statuses(repo, parent, child)
    touched = [(p, st) for p, st in statuses.items()
               if st["status"] == "touched" and p in after and st["old_path"] in before]
    if not touched:
        return None
    sum_delta = {c: 0 for c in fcols}
    ev_delta = defaultdict(list)
    ev_loc = []
    touched_paths = []
    for path, st in touched:
        b, a = before[st["old_path"]], after[path]
        ev_loc.append((a[1] or 0) - (b[1] or 0))
        touched_paths.append(path)
        for i, c in enumerate(fcols):
            d = (a[2 + i] or 0) - (b[2 + i] or 0)
            ev_delta[c].append(d)
            sum_delta[c] += d
    mean_delta = {c: sum(ev_delta[c]) / len(ev_delta[c]) for c in fcols}
    netloc = sum(ev_loc) / len(ev_loc)
    return {
        "sha": sha, "n_touched": len(touched),
        "mean_delta": mean_delta, "sum_delta": sum_delta,
        "netloc": netloc, "touched_paths": touched_paths,
        "subject": commit_subject(repo, sha),
    }


# ------------------------------------------------------------------ worker pool
# Parallelize ACROSS EVENTS: each event's stats (a git diff + two file_rows
# sqlite queries) are independent. sqlite connections must not cross a fork,
# so each worker opens its OWN read-only WAL-aware connection lazily, on
# first use, from globals set once by the pool initializer (fork copies the
# parent's memory at Pool-creation time; the initializer just records the
# path/repo/fcols so each worker can open its own handle later). Workers
# never touch the cache file -- only the parent writes it.
_worker_con = None
_worker_db_path = None
_worker_repo = None
_worker_fcols = None


def _worker_init(db_path: str, repo_path: str, fcols: list[str]) -> None:
    global _worker_db_path, _worker_repo, _worker_fcols
    _worker_db_path = db_path
    _worker_repo = pathlib.Path(repo_path)
    _worker_fcols = fcols


def _worker_compute(sha: str):
    global _worker_con
    if _worker_con is None:
        _worker_con = sqlite3.connect(f"file:{_worker_db_path}?mode=ro", uri=True)
    return sha, event_stats_full(_worker_con, _worker_repo, _worker_fcols, sha)


def loose(st):
    return st["sum_delta"]["struct_branch"] > 0 or st["sum_delta"]["state_pointers"] > 0


def strict(st):
    return st["sum_delta"]["struct_branch"] > 0 and st["sum_delta"]["state_pointers"] > 0


def fixshaped(st):
    return loose(st) and not (st["sum_delta"]["state_cast_hits"] > 0
                               or st["sum_delta"]["state_memory_alloc"] > 0)


def path_prefix2(path: str) -> str:
    parts = path.split("/")
    if len(parts) >= 2:
        pre = "/".join(parts[:2])
        return pre if "." in parts[1] else pre + "/"
    return parts[0]


def is_test_path(path: str) -> bool:
    return path.startswith("tests/")


# ------------------------------------------------------------------ cache
def load_cache(path: pathlib.Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_cache(cache: dict, path: pathlib.Path) -> None:
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cache))
    tmp.replace(path)


def load_all_events():
    events = []
    for fname in EVENT_FILES:
        d = json.loads((EVENTS_DIR / fname).read_text())
        for e in d["events"]:
            events.append(e)
    return events


def select_events(events, limit):
    if not limit:
        return events
    per_class = {}
    picked = []
    for e in events:
        c = e["class"]
        if per_class.get(c, 0) >= limit:
            continue
        per_class[c] = per_class.get(c, 0) + 1
        picked.append(e)
    return picked


def compute_all(events, db_path, repo, fcols, cache, cache_path,
                 flush_every=50, workers=10):
    t0 = time.time()
    todo = []
    seen_shas = set()
    for e in events:
        sha = e["sha"]
        if sha in seen_shas:
            continue
        seen_shas.add(sha)
        if sha not in cache:
            todo.append(sha)
    n_new = 0
    n_null_new = 0
    total = len(events)
    if not todo:
        print(f"compute done: {total} events, 0 newly computed (all cached) in 0s", flush=True)
        return 0.0

    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(processes=min(workers, len(todo)), initializer=_worker_init,
                   initargs=(str(db_path), str(repo), fcols)) as pool:
        for sha, st in pool.imap_unordered(_worker_compute, todo, chunksize=4):
            cache[sha] = st
            n_new += 1
            if st is None:
                n_null_new += 1
            if n_new % flush_every == 0:
                save_cache(cache, cache_path)
                elapsed = time.time() - t0
                rate = n_new / elapsed if elapsed else 0
                print(f"... {n_new}/{len(todo)} newly computed "
                      f"({n_null_new} null) in {elapsed:.0f}s ({rate:.2f}/s)", flush=True)
    save_cache(cache, cache_path)
    elapsed = time.time() - t0
    print(f"compute done: {total} events ({len(todo)} newly computed via {workers}-way pool, "
          f"{n_null_new} null) in {elapsed:.0f}s", flush=True)
    return elapsed


def build_results(events, cache):
    results = []
    for e in events:
        st = cache.get(e["sha"])
        if st is None:
            continue
        results.append({**e, "stats": st})
    return results


# ------------------------------------------------------------------ Part A
def part_a(results, md):
    by_class = defaultdict(list)
    for r in results:
        by_class[r["class"]].append(r["stats"])
    classes = [c for c in CLASS_ORDER if by_class.get(c)]

    md.append("## Part A -- the owed per-class grammar table\n")
    md.append("Median per-event signal delta (mean over a commit's touched files, then median "
               "across events of that class), median net-LOC, and the composite rates, one "
               "table, classes as columns. `loose` = struct_branch net-added OR state_pointers "
               "net-added; `strict` = both; `fix-shaped` = loose AND NOT (state_cast_hits or "
               "state_memory_alloc net-added) -- the same composite defined in "
               "signal_anatomy.py / wave1_analysis.py, applied here to all 8 classes.\n")
    md.append("| quantity | " + " | ".join(classes) + " |")
    md.append("|---|" + "---|" * len(classes))
    md.append("| n | " + " | ".join(str(len(by_class[c])) for c in classes) + " |")
    for sig in GRAMMAR_SIGNALS:
        row = [f"{median([st['mean_delta'][sig] for st in by_class[c]]):+.3f}" for c in classes]
        md.append(f"| {sig} | " + " | ".join(row) + " |")
    md.append("| median net-LOC | " + " | ".join(
        f"{median([st['netloc'] for st in by_class[c]]):+.1f}" for c in classes) + " |")
    for label, fn in (("loose rate (branch+ or ptr+)", loose),
                       ("strict rate (branch+ and ptr+)", strict),
                       ("fix-shaped rate", fixshaped)):
        row = [f"{100 * sum(1 for st in by_class[c] if fn(st)) / len(by_class[c]):.0f}%"
               for c in classes]
        md.append(f"| {label} | " + " | ".join(row) + " |")
    md.append("")

    # headline prose: security-fix vs regression vs bugfix-bug vs bugfix-fixes
    def rate(c, fn):
        lst = by_class.get(c, [])
        return 100 * sum(1 for st in lst if fn(st)) / len(lst) if lst else float("nan")

    focus = ["security-fix", "regression", "bugfix-bug", "bugfix-fixes"]
    focus = [c for c in focus if by_class.get(c)]
    fs_rates = {c: rate(c, fixshaped) for c in focus}
    loose_rates = {c: rate(c, loose) for c in focus}
    md.append("**Headline (security-fix vs regression vs bugfix-bug vs bugfix-fixes):** "
               "fix-shaped rate = " + ", ".join(f"{c} {fs_rates[c]:.0f}%" for c in focus)
               + "; loose rate = " + ", ".join(f"{c} {loose_rates[c]:.0f}%" for c in focus) + ". "
               + ("Ordinary bug fixes land close to security-fix on this composite -- the "
                  "CVE fix-grammar is not CVE-specific, it is what a C bug fix generically "
                  "looks like." if focus and max(fs_rates.values()) - min(fs_rates.values()) < 15
                  else "The classes separate on this composite rather than converging -- "
                  "security-fix does not sit inside the same band as the ordinary bug-fix "
                  "classes." if focus else "")
               + "\n")
    return classes, by_class


# ------------------------------------------------------------------ Part B
def part_b(results, md):
    n_base = len(results)
    by_class_count = Counter(r["class"] for r in results)
    base_class_pct = {c: 100 * by_class_count.get(c, 0) / n_base for c in CLASS_ORDER}

    all_touched = [p for r in results for p in r["stats"]["touched_paths"]]
    n_touched_base = len(all_touched)
    base_prefix_counts = Counter(path_prefix2(p) for p in all_touched)
    base_test_share = 100 * sum(1 for p in all_touched if is_test_path(p)) / n_touched_base

    base_add_rate = {}
    for s in ANCHOR_SIGNALS:
        base_add_rate[s] = None  # filled lazily below, but we need it for ALL signals for co-add table
    fcols_seen = set()
    for r in results:
        fcols_seen.update(r["stats"]["sum_delta"].keys())
    base_add_rate = {s: sum(1 for r in results if r["stats"]["sum_delta"].get(s, 0) > 0) / n_base
                      for s in fcols_seen}

    md.append("## Part B -- keyword-first pools (the inversion)\n")
    md.append(f"Baseline: all {n_base} analyzed events, {n_touched_base} touched-file instances. "
               f"Baseline class composition: " + ", ".join(
                   f"{c} {base_class_pct[c]:.0f}%" for c in CLASS_ORDER if base_class_pct.get(c))
               + f". Baseline test-file share (touched files under `tests/`): "
               f"{base_test_share:.0f}%. Co-added signals reported at >= {int(CO_ADD_THRESHOLD*100)}% "
               "pool prevalence.\n")

    pool_summaries = []
    for anchor in ANCHOR_SIGNALS:
        pool = [r for r in results if r["stats"]["sum_delta"].get(anchor, 0) > 0]
        n = len(pool)
        md.append(f"### `{anchor}` net-add pool (n={n}, {100*n/n_base:.0f}% of all events)\n")
        if n == 0:
            md.append("_empty pool -- no event net-adds this signal in this data._\n")
            pool_summaries.append((anchor, n, None, None, None))
            continue

        pool_class_count = Counter(r["class"] for r in pool)
        md.append("**Class composition** (pool% vs baseline%): " + ", ".join(
            f"{c} {100*pool_class_count.get(c,0)/n:.0f}% (base {base_class_pct.get(c,0):.0f}%)"
            for c in CLASS_ORDER if base_class_pct.get(c)) + "\n")

        pool_touched = [p for r in pool for p in r["stats"]["touched_paths"]]
        n_pt = len(pool_touched)
        pool_prefix_counts = Counter(path_prefix2(p) for p in pool_touched)
        top6 = pool_prefix_counts.most_common(6)
        md.append("**Area profile** (top 6 path prefixes, pool% vs baseline%): " + ", ".join(
            f"`{pre}` {100*cnt/n_pt:.0f}% (base {100*base_prefix_counts.get(pre,0)/n_touched_base:.0f}%)"
            for pre, cnt in top6) + "\n")

        pool_netloc = median([r["stats"]["netloc"] for r in pool])
        pool_test_share = 100 * sum(1 for p in pool_touched if is_test_path(p)) / n_pt
        md.append(f"**Median net-LOC:** {pool_netloc:+.1f} (baseline over all events: "
                   f"{median([r['stats']['netloc'] for r in results]):+.1f}). "
                   f"**Test-file share:** {pool_test_share:.0f}% (baseline {base_test_share:.0f}%)\n")

        co_rates = []
        for s in fcols_seen:
            if s == anchor:
                continue
            rate_pool = sum(1 for r in pool if r["stats"]["sum_delta"].get(s, 0) > 0) / n
            if rate_pool >= CO_ADD_THRESHOLD:
                co_rates.append((rate_pool, s, base_add_rate.get(s, 0)))
        co_rates.sort(reverse=True)
        top_co = co_rates[:6]
        if top_co:
            md.append("**Co-added signals** (pool rate vs baseline rate): " + ", ".join(
                f"{s} {100*rp:.0f}% (base {100*rb:.0f}%)" for rp, s, rb in top_co) + "\n")
        else:
            md.append(f"**Co-added signals:** none clear >= {int(CO_ADD_THRESHOLD*100)}% pool prevalence.\n")

        exemplars = sorted(pool, key=lambda r: abs(r["stats"]["netloc"]))[:3]
        md.append("**Exemplars** (shortest net-LOC, purest cases): " + "; ".join(
            f"`{e['sha'][:10]}` ({e['class']}, {e['stats']['netloc']:+.0f} LOC) "
            f"\"{e['stats']['subject'][:80]}\"" for e in exemplars) + "\n")

        pool_summaries.append((anchor, n, pool_class_count, top6, top_co))
    return pool_summaries, base_class_pct, base_test_share


# ------------------------------------------------------------------ Part C
def part_c(results, fcols, md):
    n = len(results)
    move_rate = {}
    for s in fcols:
        moved = sum(1 for r in results if r["stats"]["mean_delta"].get(s, 0.0) != 0.0)
        move_rate[s] = moved / n
    dropped = sorted([s for s in fcols if move_rate[s] < ACTIVE_SIGNAL_FLOOR])
    active = sorted([s for s in fcols if move_rate[s] >= ACTIVE_SIGNAL_FLOOR],
                     key=lambda s: -move_rate[s])
    chosen = active[:TOP_N_ACTIVE]

    md.append("## Part C -- signal co-movement structure\n")
    md.append(f"Spearman rank correlation of per-event mean signal deltas, over all {n} analyzed "
               f"events, restricted to the {len(chosen)} most-active signals among those moving in "
               f">= {int(ACTIVE_SIGNAL_FLOOR*100)}% of events. "
               f"{len(dropped)} signals dropped for moving in < {int(ACTIVE_SIGNAL_FLOOR*100)}% "
               "of events: " + ", ".join(dropped) + ".\n")

    vec = {s: [r["stats"]["mean_delta"][s] for r in results] for s in chosen}
    netloc_vec = [r["stats"]["netloc"] for r in results]

    pairs = []
    for i in range(len(chosen)):
        for j in range(i + 1, len(chosen)):
            a, b = chosen[i], chosen[j]
            rho = spearman(vec[a], vec[b])
            if rho == rho:  # not nan
                pairs.append((abs(rho), rho, a, b))
    pairs.sort(reverse=True)
    top12 = pairs[:12]
    md.append("**Top 12 correlated pairs** (|rho| descending):\n")
    md.append("| signal a | signal b | rho |")
    md.append("|---|---|---|")
    for _, rho, a, b in top12:
        md.append(f"| {a} | {b} | {rho:+.2f} |")
    md.append("")

    # single-linkage clustering at |rho| >= CLUSTER_THRESHOLD
    parent = {s: s for s in chosen}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for _, rho, a, b in pairs:
        if abs(rho) >= CLUSTER_THRESHOLD:
            union(a, b)

    groups = defaultdict(list)
    for s in chosen:
        groups[find(s)].append(s)
    clusters = [sorted(members) for members in groups.values() if len(members) >= 2]
    clusters.sort(key=len, reverse=True)

    md.append(f"**Single-linkage clusters at |rho| >= {CLUSTER_THRESHOLD}:** "
               f"{len(clusters)} multi-member cluster(s); "
               f"{sum(1 for members in groups.values() if len(members) == 1)} signals have no "
               f"partner at this threshold.\n")

    cluster_rows = []
    for idx, members in enumerate(clusters, 1):
        agg = [sum(vec[s][k] for s in members) for k in range(n)]
        rho_loc = spearman(agg, netloc_vec)
        size_proxy = abs(rho_loc) >= SIZE_PROXY_THRESHOLD
        md.append(f"- **cluster {idx}** {{{', '.join(members)}}} -- correlation of the "
                   f"summed cluster delta with net-LOC: rho={rho_loc:+.2f} "
                   f"({'SIZE PROXY' if size_proxy else 'co-moves beyond size'}, "
                   f"threshold |rho|>={SIZE_PROXY_THRESHOLD})")
        cluster_rows.append((members, rho_loc, size_proxy))
    md.append("")
    return chosen, dropped, top12, cluster_rows


# ------------------------------------------------------------------ report
def write_report(results, fcols, out_path, elapsed_compute, n_events_total, n_null):
    md = ["# Keyword-first exploratory analysis -- curl (gitgalaxy#2982)\n",
          "**EXPLORATORY -- computed post-hoc on data already analyzed; no hypothesis tests, "
          "no p-values.** Patterns here are candidates for *registration* on unseen data "
          "(repo #3), never claims.\n",
          "Known label caveats carried forward: roughly half of `Fixes #` commits are not "
          "code-bug fixes (docs/build/deprecation commits get the same trailer); "
          "~31% of touched files across this corpus are tests/docs, not implementation; "
          "class pooling is heterogeneous (bugfix-fixes/bugfix-bug/regression were drawn "
          "by commit-message label, not by hand-verified bug content -- see "
          "docs/HYPOTHESES.md's overnight bug-label expansion section).\n",
          f"Events: {n_events_total} in the three source files "
          f"(events/curl.json, events/curl_wave1.json, events/curl_bugs.json); "
          f"{len(results)} yielded usable touched-file stats ({n_null} skipped -- root "
          "commits, unscanned parents, or no touched files after rename resolution). "
          f"Compute pass this run: {elapsed_compute:.0f}s "
          f"(most/all events already cached from a prior run if this is small).\n"]

    classes, by_class = part_a(results, md)
    pool_summaries, base_class_pct, base_test_share = part_b(results, md)
    chosen, dropped, top12, cluster_rows = part_c(results, fcols, md)

    md.append("---\n*Regenerate: `python tools/keyword_pools.py` (cache at "
               "`dbs/keyword_pools_cache.json`, gitignored). Not committed.*")
    out_path.write_text("\n".join(md) + "\n")
    return classes, by_class, pool_summaries, chosen, dropped, top12, cluster_rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=0, help="cap events per class (sanity run)")
    ap.add_argument("--cache", default=str(CACHE_PATH))
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--skip-compute", action="store_true",
                     help="report only from existing cache, compute nothing new")
    ap.add_argument("--workers", type=int, default=10, help="pool size for the compute pass")
    args = ap.parse_args()

    all_events = load_all_events()
    events = select_events(all_events, args.limit)

    base = json.loads((EVENTS_DIR / "curl.json").read_text())
    repo = resolve_repo(base["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # WAL-aware, never immutable
    fcols = signal_columns(con, "file_data")
    con.close()  # parent doesn't need it; workers (or serial fallback) open their own

    cache_path = pathlib.Path(args.cache)
    cache = load_cache(cache_path)

    elapsed = 0.0
    if not args.skip_compute:
        elapsed = compute_all(events, db, repo, fcols, cache, cache_path, workers=args.workers)

    results = build_results(events, cache)
    n_null = sum(1 for e in events if cache.get(e["sha"]) is None)

    out_path = pathlib.Path(args.out)
    (classes, by_class, pool_summaries, chosen, dropped,
     top12, cluster_rows) = write_report(results, fcols, out_path, elapsed, len(events), n_null)

    print(f"wrote {out_path}")
    print(f"classes: " + ", ".join(f"{c} {len(by_class[c])}" for c in classes))
    print(f"Part C: {len(chosen)} active signals, {len(dropped)} dropped (<{ACTIVE_SIGNAL_FLOOR:.0%}), "
          f"{len(cluster_rows)} clusters")
    for members, rho_loc, size_proxy in cluster_rows:
        print(f"  cluster {{{', '.join(members)}}} rho(net-LOC)={rho_loc:+.2f} "
              f"{'[SIZE PROXY]' if size_proxy else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
