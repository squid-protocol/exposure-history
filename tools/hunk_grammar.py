#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Hunk-level grammar analysis (gitgalaxy#2982, tc#34): score the PATCH, not
the file.

EXPLORATORY -- no p-values, no hypothesis test. Every grammar result to date
(signal_anatomy.py, wave1_analysis.py, keyword_pools.py) ran at FILE grain:
before/after keyword-count deltas over every file a commit touched. That is
diluted two ways -- ~31% of touched files across the corpus are bystanders
(tests/docs, not implementation), and even a kept file's delta blends the fix
with any unrelated edits in the same file. This drops one level: for each
event, take ONLY the added (+) and removed (-) lines of its own diff --
`git diff -U0 <sha>^..<sha>` -- restricted to .c/.h files outside
tests/docs/.github/scripts, and count keyword hits on that text directly. No
before/after DB snapshot is used; the patch text is scored on its own.

Two questions ride on this (tc#34):
  1. Does the fix-shaped gradient (security-fix > bugfix-fixes > bugfix-bug >
     regression > control > revert, file grain: 66/53/48/46/38/13%) WIDEN at
     hunk grain (dilution was hiding a sharper signal) or COLLAPSE (the file-
     grain gradient was a bystander-file artifact)?
  2. The classifier's refined claim -- "a fix adds branches WITHOUT new
     allocations" -- tested exactly: does the patch's ADDED lines carry any
     memory_alloc / explicit_casts hit, by class?

Keyword extraction uses the ENGINE'S OWN C rules, not a private
reimplementation -- run with system python3 and
    PYTHONPATH=<gitgalaxy checkout>
    from gitgalaxy.standards.language_standards import LANGUAGE_DEFINITIONS
    LANGUAGE_DEFINITIONS["c"]["rules"]
(the engine's regex rule layer is zero-dependency; this repo's own venv is
not on the import path for gitgalaxy, hence PYTHONPATH rather than a normal
import). Rule-name -> file_data column mapping is
gitgalaxy/recorders/record_keeper.py's SHORT_KEY_MAP; the headline signals
used here (the file-grain report's GRAMMAR_SIGNALS columns, plus the two
extra concepts tc#34 names -- danger, cleanup):

    rule key (c.py)       file_data column (record_keeper.py)   concept
    -------------------    -----------------------------------   -------
    branch                  struct_branch                        branch
    pointers                state_pointers                       pointers
    memory_alloc            state_memory_alloc                   alloc
    explicit_casts           state_cast_hits                      casts
    safety                  def_safety                           safety
    panics_and_aborts       state_bailout_hits                   bailouts
    high_risk_execution      state_danger                         danger
    cleanup                 def_cleanup                          cleanup

Per event: added-count and removed-count per headline signal (regex findall
over the patch's added-lines text and removed-lines text separately), net =
added - removed. Hunk-grain composites (mirroring keyword_pools.py's file-
grain composites exactly, substituting patch counts for file-delta counts):
    loose_h     = branch net > 0 OR pointers net > 0
    strict_h    = branch net > 0 AND pointers net > 0
    fixshaped_h = loose_h AND NOT (alloc ADDED > 0 OR casts ADDED > 0)
(the alloc/cast veto uses ADDED, not net, per tc#34: "no NEW allocations in
the patch" is about what the fix introduces, not the net across the diff.)

Events: events/curl.json + events/curl_wave1.json + events/curl_bugs.json,
all 8 classes, ~1762 total. Diffs are read from the uncommitted pool clone
(tools/_engine.py POOL_DIR / "curl"), never this repo. Per-event results are
cached to SCRATCH_CACHE (see below) keyed by sha; only the parent process
ever writes the cache (fork-pool workers are read-only). Compute
parallelizes ACROSS EVENTS with a 10-way fork-context multiprocessing.Pool
-- each event is one `git diff` subprocess, independent of the others.

Usage:
    python tools/hunk_grammar.py --limit 40      # foreground sanity run
    python tools/hunk_grammar.py                 # full run
    python tools/hunk_grammar.py --skip-compute  # report only, cache as-is
    python tools/hunk_grammar.py --workers 10
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import pathlib
import re
import subprocess
import sys
import time
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, EVENTS_DIR, GITGALAXY_PATH, POOL_DIR  # noqa: E402
from delta_report import median  # noqa: E402

# ------------------------------------------------------------------ engine rules
# System python3, not this repo's venv -- the engine's regex rule layer is
# zero-dependency, so PYTHONPATH alone is enough; no galaxyscope binary or DB
# involved anywhere in this tool.
sys.path.insert(0, str(GITGALAXY_PATH))
from gitgalaxy.standards.language_standards import LANGUAGE_DEFINITIONS  # noqa: E402

C_RULES = LANGUAGE_DEFINITIONS["c"]["rules"]

# rule key (c.py) -> (file_data column it feeds, short concept label)
HEADLINE_RULES = {
    "branch": ("struct_branch", "branch"),
    "pointers": ("state_pointers", "pointers"),
    "memory_alloc": ("state_memory_alloc", "alloc"),
    "explicit_casts": ("state_cast_hits", "casts"),
    "safety": ("def_safety", "safety"),
    "panics_and_aborts": ("state_bailout_hits", "bailouts"),
    "high_risk_execution": ("state_danger", "danger"),
    "cleanup": ("def_cleanup", "cleanup"),
}
RULE_KEYS = list(HEADLINE_RULES.keys())

CLASS_ORDER = ["security-fix", "regression", "bugfix-bug", "bugfix-fixes",
               "control", "introduced", "revert", "cve-followup"]
EVENT_FILES = ["curl.json", "curl_wave1.json", "curl_bugs.json"]

EXCLUDE_PREFIXES = ("tests/", "docs/", ".github/", "scripts/")
KEEP_EXTENSIONS = (".c", ".h")

SCRATCH_CACHE = pathlib.Path(
    "/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664"
    "/scratchpad/hunk_cache.json"
)
OUT_PATH = DOCS_DIR / "hunk_grammar.md"
FILE_GRAIN_PATH = DOCS_DIR / "keyword_pools_explore.md"
KEYWORD_POOLS_CACHE = pathlib.Path(__file__).parent.parent / "dbs" / "keyword_pools_cache.json"


# ------------------------------------------------------------------ diff parsing
def parse_diff_sections(diff_text: str):
    """Split a -U0 unified diff into per-file sections. Returns a list of
    dicts: {path, old_path, new_path, added_text, removed_text}. `path` is
    new_path (or old_path for a pure deletion) -- the identity used for
    extension/prefix filtering."""
    if not diff_text:
        return []
    chunks = diff_text.split("\ndiff --git ")
    out = []
    for i, chunk in enumerate(chunks):
        text = chunk if i == 0 else "diff --git " + chunk
        if not text.startswith("diff --git "):
            continue
        old_path = new_path = None
        added, removed = [], []
        for ln in text.split("\n"):
            if ln.startswith("--- "):
                p = ln[4:]
                old_path = None if p in ("/dev/null", "") else (p[2:] if p[:2] in ("a/", "b/") else p)
            elif ln.startswith("+++ "):
                p = ln[4:]
                new_path = None if p in ("/dev/null", "") else (p[2:] if p[:2] in ("a/", "b/") else p)
            elif ln.startswith("+++") or ln.startswith("---"):
                continue
            elif ln.startswith("+"):
                added.append(ln[1:])
            elif ln.startswith("-"):
                removed.append(ln[1:])
        path = new_path or old_path
        if path is None:
            continue
        out.append({
            "path": path, "old_path": old_path, "new_path": new_path,
            "added_text": "\n".join(added), "removed_text": "\n".join(removed),
            "n_added": len(added), "n_removed": len(removed),
        })
    return out


def classify_path(path: str) -> str:
    """'kept' | 'excluded_path' | 'excluded_ext'."""
    if any(path.startswith(pfx) for pfx in EXCLUDE_PREFIXES):
        return "excluded_path"
    if not path.endswith(KEEP_EXTENSIONS):
        return "excluded_ext"
    return "kept"


# ------------------------------------------------------------------ per-event compute
def event_stats(repo: pathlib.Path, sha: str):
    """Returns one of:
    None                       -- parent unresolvable (root commit etc.)
    {"bystander_only": True,..} -- diff fine, but zero kept .c/.h files
    {..full stats..}            -- >=1 kept file, headline signal counts
    """
    diff = subprocess.run(
        ["git", "-C", str(repo), "diff", "-U0", f"{sha}^..{sha}"],
        capture_output=True,
    )
    if diff.returncode != 0:
        return None
    text = diff.stdout.decode("utf-8", errors="replace")
    sections = parse_diff_sections(text)
    n_total = len(sections)
    reasons = defaultdict(int)
    kept = []
    for s in sections:
        r = classify_path(s["path"])
        reasons[r] += 1
        if r == "kept":
            kept.append(s)

    base = {
        "n_files_total": n_total,
        "n_kept": len(kept),
        "n_excl_path": reasons["excluded_path"],
        "n_excl_ext": reasons["excluded_ext"],
    }
    if not kept:
        return {**base, "bystander_only": True}

    added_text = "\n".join(s["added_text"] for s in kept)
    removed_text = "\n".join(s["removed_text"] for s in kept)
    n_added_lines = sum(s["n_added"] for s in kept)
    n_removed_lines = sum(s["n_removed"] for s in kept)

    added_counts = {k: len(C_RULES[k].findall(added_text)) for k in RULE_KEYS}
    removed_counts = {k: len(C_RULES[k].findall(removed_text)) for k in RULE_KEYS}

    return {
        **base,
        "bystander_only": False,
        "n_added_lines": n_added_lines,
        "n_removed_lines": n_removed_lines,
        "netloc": n_added_lines - n_removed_lines,
        "added": added_counts,
        "removed": removed_counts,
    }


# ------------------------------------------------------------------ composites
def net(st, key):
    return st["added"][key] - st["removed"][key]


def loose_h(st):
    return net(st, "branch") > 0 or net(st, "pointers") > 0


def strict_h(st):
    return net(st, "branch") > 0 and net(st, "pointers") > 0


def fixshaped_h(st):
    return loose_h(st) and not (st["added"]["memory_alloc"] > 0 or st["added"]["explicit_casts"] > 0)


# ------------------------------------------------------------------ worker pool
_worker_repo = None


def _worker_init(repo_path: str) -> None:
    global _worker_repo
    _worker_repo = pathlib.Path(repo_path)


def _worker_compute(sha: str):
    return sha, event_stats(_worker_repo, sha)


def load_cache(path: pathlib.Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_cache(cache: dict, path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cache))
    tmp.replace(path)


def load_all_events():
    events = []
    seen = set()
    for fname in EVENT_FILES:
        d = json.loads((EVENTS_DIR / fname).read_text())
        for e in d["events"]:
            if e["sha"] in seen:
                continue
            seen.add(e["sha"])
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


def compute_all(events, repo, cache, cache_path, flush_every=100, workers=10):
    t0 = time.time()
    todo = [e["sha"] for e in events if e["sha"] not in cache]
    if not todo:
        print(f"compute done: {len(events)} events, 0 newly computed (all cached) in 0s", flush=True)
        return 0.0

    ctx = multiprocessing.get_context("fork")
    n_new = 0
    with ctx.Pool(processes=min(workers, len(todo)), initializer=_worker_init,
                   initargs=(str(repo),)) as pool:
        for sha, st in pool.imap_unordered(_worker_compute, todo, chunksize=4):
            cache[sha] = st
            n_new += 1
            if n_new % flush_every == 0:
                save_cache(cache, cache_path)
                elapsed = time.time() - t0
                print(f"... {n_new}/{len(todo)} newly computed in {elapsed:.0f}s "
                      f"({n_new/elapsed:.1f}/s)", flush=True)
    save_cache(cache, cache_path)
    elapsed = time.time() - t0
    print(f"compute done: {len(events)} events ({len(todo)} newly computed via "
          f"{workers}-way pool) in {elapsed:.0f}s", flush=True)
    return elapsed


def build_results(events, cache):
    usable, bystander, no_parent = [], [], []
    for e in events:
        st = cache.get(e["sha"])
        if st is None:
            no_parent.append(e)
        elif st.get("bystander_only"):
            bystander.append({**e, "stats": st})
        else:
            usable.append({**e, "stats": st})
    return usable, bystander, no_parent


# ------------------------------------------------------------------ file-grain comparison data
def parse_file_grain_table(path: pathlib.Path):
    """Pull Part A's markdown table out of keyword_pools_explore.md: {quantity: {class: raw_str}}."""
    if not path.exists():
        return None, None
    text = path.read_text()
    m = re.search(r"## Part A.*?\n(\| quantity \|.*?)\n\n", text, re.S)
    if not m:
        return None, None
    lines = [ln for ln in m.group(1).splitlines() if ln.startswith("|")]
    header = [c.strip() for c in lines[0].strip("|").split("|")]
    classes = header[1:]
    table = {}
    for ln in lines[2:]:
        cells = [c.strip() for c in ln.strip("|").split("|")]
        quantity, vals = cells[0], cells[1:]
        table[quantity] = dict(zip(classes, vals))
    return table, classes


def file_grain_alloc_cast_rates(cache_path: pathlib.Path, all_events):
    """% of events per class whose FILE-grain sum_delta net-adds memory_alloc /
    cast_hits (the same cache keyword_pools.py already produced), for table 2's
    file-grain reference column."""
    if not cache_path.exists():
        return None
    fg_cache = json.loads(cache_path.read_text())
    by_class = defaultdict(list)
    for e in all_events:
        st = fg_cache.get(e["sha"])
        if st is None:
            continue
        by_class[e["class"]].append(st)
    rates = {}
    for c, lst in by_class.items():
        if not lst:
            continue
        alloc_pct = 100 * sum(1 for st in lst if st["sum_delta"].get("state_memory_alloc", 0) > 0) / len(lst)
        cast_pct = 100 * sum(1 for st in lst if st["sum_delta"].get("state_cast_hits", 0) > 0) / len(lst)
        rates[c] = {"n": len(lst), "alloc_pct": alloc_pct, "cast_pct": cast_pct}
    return rates


# ------------------------------------------------------------------ report
def fmt_pct(n, d):
    return f"{100*n/d:.0f}%" if d else "n/a"


def write_report(usable, bystander, no_parent, all_events, md_path: pathlib.Path):
    by_class = defaultdict(list)
    for r in usable:
        by_class[r["class"]].append(r["stats"])
    classes = [c for c in CLASS_ORDER if by_class.get(c)]

    fg_table, fg_classes = parse_file_grain_table(FILE_GRAIN_PATH)
    fg_alloc = file_grain_alloc_cast_rates(KEYWORD_POOLS_CACHE, all_events)

    md = []
    md.append("# Hunk-level grammar analysis -- curl (gitgalaxy#2982, tc#34)\n")
    md.append("**EXPLORATORY -- no hypothesis test, no p-values.** Scores the PATCH: only the "
               "added (+) and removed (-) lines of each event's own diff (`git diff -U0 "
               "<sha>^..<sha>`), restricted to `.c`/`.h` files outside `tests/`, `docs/`, "
               "`.github/`, `scripts/`. Every prior grammar table (signal_anatomy.py, "
               "wave1_analysis.py, keyword_pools.py) scored the FILE: a before/after keyword-"
               "count delta over every file a commit touched, diluted by bystander files "
               "(tests/docs, ~31% of touched files corpus-wide) and by unrelated edits mixed "
               "into a kept file. This tool removes both dilution sources at once.\n")
    md.append("Label caveats carried forward unchanged from keyword_pools_explore.md: roughly "
               "half of `Fixes #` commits are not code-bug fixes (docs/build/deprecation "
               "commits get the same trailer); `bugfix-fixes`/`bugfix-bug`/`regression` were "
               "drawn by commit-message label, not hand-verified bug content.\n")

    n_all = len(all_events)
    md.append(f"**Events:** {n_all} loaded from events/curl.json + events/curl_wave1.json + "
               f"events/curl_bugs.json (deduped by sha). **{len(no_parent)}** had no resolvable "
               f"parent (root commit / unreachable object) and were dropped entirely. "
               f"**{len(bystander)}** resolved a diff but touched zero `.c`/`.h` files outside "
               f"tests/docs/.github/scripts (\"bystander-only\" commits -- e.g. a pure "
               f"test/doc/CI change under a `Fixes #`/security-fix/revert label) and are "
               f"excluded from every table below. **{len(usable)}** are usable (>=1 kept "
               f"file).\n")

    n_files_total = sum(r["stats"]["n_files_total"] for r in usable) + \
        sum(r["stats"]["n_files_total"] for r in bystander)
    n_files_kept = sum(r["stats"]["n_kept"] for r in usable)
    n_files_excl_path = sum(r["stats"]["n_excl_path"] for r in usable) + \
        sum(r["stats"]["n_excl_path"] for r in bystander)
    n_files_excl_ext = sum(r["stats"]["n_excl_ext"] for r in usable) + \
        sum(r["stats"]["n_excl_ext"] for r in bystander)
    md.append(f"**File-level exclusions** (usable + bystander-only events combined, "
               f"{n_files_total} touched-file instances total): **{n_files_kept}** kept "
               f"(.c/.h outside excluded dirs), **{n_files_excl_path}** excluded by path "
               f"(tests/docs/.github/scripts), **{n_files_excl_ext}** excluded by extension "
               f"(not .c/.h) -- "
               f"{fmt_pct(n_files_excl_path, n_files_total)} of all touched files were path-"
               f"excluded, {fmt_pct(n_files_excl_ext, n_files_total)} were non-C.\n")

    # -------------------------------------------------- Table 1a: signal medians
    md.append("## Table 1a -- hunk-grain per-signal medians (added-count, net-count)\n")
    md.append("Median across events of that class. `net` = added - removed, patch-only (no "
               "file-level before/after).\n")
    md.append("| signal | quantity | " + " | ".join(classes) + " |")
    md.append("|---|---|" + "---|" * len(classes))
    for rule_key, (col, label) in HEADLINE_RULES.items():
        for kind in ("added", "net"):
            if kind == "added":
                row = [median([st["added"][rule_key] for st in by_class[c]]) for c in classes]
            else:
                row = [median([net(st, rule_key) for st in by_class[c]]) for c in classes]
            row_str = " | ".join(f"{v:+.1f}" for v in row)
            md.append(f"| {label} (`{rule_key}`/`{col}`) | {kind} | {row_str} |")
    md.append("| net-LOC (kept files) | net | " + " | ".join(
        f"{median([st['netloc'] for st in by_class[c]]):+.1f}" for c in classes) + " |")
    md.append("")

    # -------------------------------------------------- Table 1b: composite rates side by side
    md.append("## Table 1b -- composite rates, file-grain vs hunk-grain, side by side\n")
    md.append("File-grain rows pulled verbatim from docs/keyword_pools_explore.md Part A "
               "(same composite definitions, applied to whole touched-file deltas). Hunk-grain "
               "rows are this tool's patch-only equivalent. `fix-shaped` = `loose` AND NOT "
               "(alloc ADDED>0 OR casts ADDED>0) -- file-grain vetoes on NET, hunk-grain on "
               "ADDED (tc#34's exact ask).\n")
    md.append("| composite | grain | " + " | ".join(classes) + " |")
    md.append("|---|---|" + "---|" * len(classes))
    fg_row_names = {"loose": "loose rate (branch+ or ptr+)",
                     "strict": "strict rate (branch+ and ptr+)",
                     "fix-shaped": "fix-shaped rate"}
    hg_fns = {"loose": loose_h, "strict": strict_h, "fix-shaped": fixshaped_h}
    for label, fg_key in fg_row_names.items():
        if fg_table and fg_key in fg_table:
            fg_row = " | ".join(fg_table[fg_key].get(c, "n/a") for c in classes)
        else:
            fg_row = " | ".join("n/a" for _ in classes)
        md.append(f"| {label} | file | {fg_row} |")
        hg_row = " | ".join(fmt_pct(sum(1 for st in by_class[c] if hg_fns[label](st)), len(by_class[c]))
                             for c in classes)
        md.append(f"| {label} | hunk | {hg_row} |")
    md.append("")

    # -------------------------------------------------- Table 2: alloc clause isolated
    md.append("## Table 2 -- the alloc clause isolated\n")
    md.append("Per class: % of events whose PATCH's ADDED lines contain >=1 `memory_alloc` hit; "
               "% with >=1 `explicit_casts` hit. File-grain reference column: % of events whose "
               "whole-touched-file NET delta (dbs/keyword_pools_cache.json `sum_delta`, "
               "produced by tools/keyword_pools.py) is >0 for the same two signals -- diluted "
               "by bystander files/unrelated edits, this is the number hunk-grain is meant to "
               "sharpen.\n")
    md.append("| class | n (hunk) | alloc added>0 (hunk) | alloc net>0 (file) | casts added>0 (hunk) | casts net>0 (file) |")
    md.append("|---|---|---|---|---|---|")
    for c in classes:
        lst = by_class[c]
        n = len(lst)
        alloc_h = fmt_pct(sum(1 for st in lst if st["added"]["memory_alloc"] > 0), n)
        cast_h = fmt_pct(sum(1 for st in lst if st["added"]["explicit_casts"] > 0), n)
        if fg_alloc and c in fg_alloc:
            alloc_f = f"{fg_alloc[c]['alloc_pct']:.0f}%"
            cast_f = f"{fg_alloc[c]['cast_pct']:.0f}%"
        else:
            alloc_f = cast_f = "n/a"
        md.append(f"| {c} | {n} | {alloc_h} | {alloc_f} | {cast_h} | {cast_f} |")
    md.append("")

    # -------------------------------------------------- Table 3: gradient verdict
    md.append("## Table 3 -- the gradient comparison\n")
    focus = ["security-fix", "bugfix-fixes", "bugfix-bug", "regression", "control", "revert"]
    focus = [c for c in focus if c in classes]
    hg_fs = {c: 100 * sum(1 for st in by_class[c] if fixshaped_h(st)) / len(by_class[c]) for c in focus}
    fg_fs = {}
    if fg_table and "fix-shaped rate" in fg_table:
        for c in focus:
            raw = fg_table["fix-shaped rate"].get(c, "").rstrip("%")
            try:
                fg_fs[c] = float(raw)
            except ValueError:
                pass
    hg_gap = hg_fs.get("security-fix", float("nan")) - hg_fs.get("control", float("nan"))
    fg_gap = fg_fs.get("security-fix", float("nan")) - fg_fs.get("control", float("nan"))
    verdict = "WIDEN" if hg_gap > fg_gap else ("COLLAPSE" if hg_gap < fg_gap else "UNCHANGED")
    md.append(f"file-grain fix-shaped%: " + ", ".join(f"{c} {fg_fs.get(c, float('nan')):.0f}%" for c in focus) + "\n")
    md.append(f"hunk-grain fix-shaped%: " + ", ".join(f"{c} {hg_fs.get(c, float('nan')):.0f}%" for c in focus) + "\n")
    md.append(f"**security-fix minus control gap:** file-grain {fg_gap:+.0f}pp -> hunk-grain "
               f"{hg_gap:+.0f}pp -- the gap **{verdict}s** at hunk grain "
               f"({'bystander dilution was hiding a sharper signal' if verdict == 'WIDEN' else 'the file-grain gradient reads as bystander-file/whole-file-dilution artifact once the patch alone is scored' if verdict == 'COLLAPSE' else 'no material change'}).\n")

    md.append("---\n*Regenerate: `python tools/hunk_grammar.py`. Cache: "
               f"`{SCRATCH_CACHE}` (scratchpad, not committed). Stdlib only + engine "
               "regex rules via PYTHONPATH; no DB, no galaxyscope binary.*")

    md_path.write_text("\n".join(md) + "\n")
    print(f"wrote {md_path}")
    return hg_gap, fg_gap, verdict


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=0, help="cap events per class (sanity run)")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--skip-compute", action="store_true")
    ap.add_argument("--out", default=str(OUT_PATH))
    args = ap.parse_args()

    repo = POOL_DIR / "curl"
    if not repo.exists():
        sys.exit(f"pool repo not found: {repo}")

    all_events = load_all_events()
    events = select_events(all_events, args.limit)
    cache = load_cache(SCRATCH_CACHE)

    if not args.skip_compute:
        compute_all(events, repo, cache, SCRATCH_CACHE, workers=args.workers)

    usable, bystander, no_parent = build_results(events, cache)
    print(f"usable={len(usable)} bystander_only={len(bystander)} no_parent={len(no_parent)} "
          f"(of {len(events)} selected)")

    write_report(usable, bystander, no_parent, events, pathlib.Path(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
