# Hunk-level grammar analysis -- curl (gitgalaxy#2982, tc#34)

**EXPLORATORY -- no hypothesis test, no p-values.** Scores the PATCH: only the added (+) and removed (-) lines of each event's own diff (`git diff -U0 <sha>^..<sha>`), restricted to `.c`/`.h` files outside `tests/`, `docs/`, `.github/`, `scripts/`. Every prior grammar table (signal_anatomy.py, wave1_analysis.py, keyword_pools.py) scored the FILE: a before/after keyword-count delta over every file a commit touched, diluted by bystander files (tests/docs, ~31% of touched files corpus-wide) and by unrelated edits mixed into a kept file. This tool removes both dilution sources at once.

Label caveats carried forward unchanged from keyword_pools_explore.md: roughly half of `Fixes #` commits are not code-bug fixes (docs/build/deprecation commits get the same trailer); `bugfix-fixes`/`bugfix-bug`/`regression` were drawn by commit-message label, not hand-verified bug content.

**Events:** 1756 loaded from events/curl.json + events/curl_wave1.json + events/curl_bugs.json (deduped by sha). **1** had no resolvable parent (root commit / unreachable object) and were dropped entirely. **391** resolved a diff but touched zero `.c`/`.h` files outside tests/docs/.github/scripts ("bystander-only" commits -- e.g. a pure test/doc/CI change under a `Fixes #`/security-fix/revert label) and are excluded from every table below. **1364** are usable (>=1 kept file).

**File-level exclusions** (usable + bystander-only events combined, 6188 touched-file instances total): **3529** kept (.c/.h outside excluded dirs), **2140** excluded by path (tests/docs/.github/scripts), **519** excluded by extension (not .c/.h) -- 35% of all touched files were path-excluded, 8% were non-C.

## Table 1a -- hunk-grain per-signal medians (added-count, net-count)

Median across events of that class. `net` = added - removed, patch-only (no file-level before/after).

| signal | quantity | security-fix | regression | bugfix-bug | bugfix-fixes | control | introduced | revert | cve-followup |
|---|---|---|---|---|---|---|---|---|---|
| branch (`branch`/`struct_branch`) | added | +3.0 | +2.0 | +2.0 | +3.0 | +2.0 | +29.0 | +1.0 | +0.0 |
| branch (`branch`/`struct_branch`) | net | +1.0 | +0.0 | +1.0 | +1.0 | +0.0 | +12.0 | +0.0 | +0.0 |
| pointers (`pointers`/`state_pointers`) | added | +4.0 | +1.0 | +1.0 | +3.0 | +1.0 | +38.5 | +1.0 | +0.0 |
| pointers (`pointers`/`state_pointers`) | net | +1.0 | +0.0 | +0.0 | +1.0 | +0.0 | +18.0 | +0.0 | +0.0 |
| alloc (`memory_alloc`/`state_memory_alloc`) | added | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +1.0 | +0.0 | +0.0 |
| alloc (`memory_alloc`/`state_memory_alloc`) | net | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| casts (`explicit_casts`/`state_cast_hits`) | added | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| casts (`explicit_casts`/`state_cast_hits`) | net | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| safety (`safety`/`def_safety`) | added | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +1.0 | +0.0 | +0.0 |
| safety (`safety`/`def_safety`) | net | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| bailouts (`panics_and_aborts`/`state_bailout_hits`) | added | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| bailouts (`panics_and_aborts`/`state_bailout_hits`) | net | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| danger (`high_risk_execution`/`state_danger`) | added | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| danger (`high_risk_execution`/`state_danger`) | net | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| cleanup (`cleanup`/`def_cleanup`) | added | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| cleanup (`cleanup`/`def_cleanup`) | net | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| net-LOC (kept files) | net | +4.0 | +1.0 | +2.0 | +3.0 | +2.0 | +61.5 | -2.0 | -1.0 |

## Table 1b -- composite rates, file-grain vs hunk-grain, side by side

File-grain rows pulled verbatim from docs/keyword_pools_explore.md Part A (same composite definitions, applied to whole touched-file deltas). Hunk-grain rows are this tool's patch-only equivalent. `fix-shaped` = `loose` AND NOT (alloc ADDED>0 OR casts ADDED>0) -- file-grain vetoes on NET, hunk-grain on ADDED (tc#34's exact ask).

| composite | grain | security-fix | regression | bugfix-bug | bugfix-fixes | control | introduced | revert | cve-followup |
|---|---|---|---|---|---|---|---|---|---|
| loose | file | 71% | 50% | 52% | 62% | 45% | 71% | 18% | 20% |
| loose | hunk | 71% | 58% | 60% | 71% | 51% | 86% | 21% | 23% |
| strict | file | 45% | 22% | 24% | 33% | 21% | 55% | 8% | 13% |
| strict | hunk | 44% | 27% | 31% | 39% | 24% | 71% | 8% | 15% |
| fix-shaped | file | 66% | 46% | 48% | 53% | 38% | 40% | 13% | 20% |
| fix-shaped | hunk | 57% | 49% | 49% | 56% | 39% | 28% | 10% | 23% |

## Table 2 -- the alloc clause isolated

Per class: % of events whose PATCH's ADDED lines contain >=1 `memory_alloc` hit; % with >=1 `explicit_casts` hit. File-grain reference column: % of events whose whole-touched-file NET delta (dbs/keyword_pools_cache.json `sum_delta`, produced by tools/keyword_pools.py) is >0 for the same two signals -- diluted by bystander files/unrelated edits, this is the number hunk-grain is meant to sharpen.

| class | n (hunk) | alloc added>0 (hunk) | alloc net>0 (file) | casts added>0 (hunk) | casts net>0 (file) |
|---|---|---|---|---|---|
| security-fix | 181 | 10% | 2% | 8% | 3% |
| regression | 238 | 5% | 3% | 6% | 3% |
| bugfix-bug | 209 | 9% | 3% | 6% | 3% |
| bugfix-fixes | 365 | 6% | 2% | 14% | 8% |
| control | 147 | 5% | 2% | 14% | 7% |
| introduced | 134 | 51% | 19% | 46% | 24% |
| revert | 77 | 9% | 3% | 18% | 5% |
| cve-followup | 13 | 8% | 0% | 0% | 0% |

## Table 3 -- the gradient comparison

file-grain fix-shaped%: security-fix 66%, bugfix-fixes 53%, bugfix-bug 48%, regression 46%, control 38%, revert 13%

hunk-grain fix-shaped%: security-fix 57%, bugfix-fixes 56%, bugfix-bug 49%, regression 49%, control 39%, revert 10%

**security-fix minus control gap:** file-grain +28pp -> hunk-grain +18pp -- the gap **COLLAPSEs** at hunk grain (the file-grain gradient reads as bystander-file/whole-file-dilution artifact once the patch alone is scored).

---
*Regenerate: `python tools/hunk_grammar.py`. Cache: `/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad/hunk_cache.json` (scratchpad, not committed). Stdlib only + engine regex rules via PYTHONPATH; no DB, no galaxyscope binary.*
