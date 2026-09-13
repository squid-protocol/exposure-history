# Signal anatomy — ndpi

Raw-signal layer vs CVE ground truth. Events analyzed: control 96, introduced 68, security-fix 112. Median event net-LOC: control +2, introduced +4, security-fix +1.

## 1 · The grammar of a security fix (signal deltas, fixes vs controls)

Per-signal mean delta over touched files, per event (median across events). One-sided MW in the direction the medians differ; sorted by p.

| signal | fixes Δ | controls Δ | introduced Δ | p (fix vs ctrl) |
|---|---|---|---|---|
| state_graveyard | +0.00 | +0.00 | +0.00 | 0.0542 |
| struct_func_start | +0.00 | +0.00 | +0.00 | 0.0554 |
| state_pointers | +0.00 | +0.00 | +1.00 | 0.0790 |
| state_heat_triggers | +0.00 | +0.00 | +0.00 | 0.0958 |
| struct_args | +0.00 | +0.00 | +0.00 | 0.0991 |
| arch_globals | +0.00 | +0.00 | +0.00 | 0.1111 |
| state_planned_debt | +0.00 | +0.00 | +0.00 | 0.1383 |
| def_doc | +0.00 | +0.00 | +0.00 | 0.1422 |
| state_fragile_debt | +0.00 | +0.00 | +0.00 | 0.1422 |
| state_danger | +0.00 | +0.00 | +0.00 | 0.1798 |
| state_memory_alloc | +0.00 | +0.00 | +0.00 | 0.1798 |
| struct_closures | +0.00 | +0.00 | +0.00 | 0.1798 |
| state_flux | +0.00 | +0.00 | +0.06 | 0.2283 |
| arch_import | +0.00 | +0.00 | +0.00 | 0.2596 |
| struct_branch | +0.54 | +0.00 | +1.00 | 0.2843 |
| arch_io | +0.00 | +0.00 | +0.00 | 0.2975 |
| state_safety_neg | +0.00 | +0.00 | +0.00 | 0.3000 |
| struct_class_start | +0.00 | +0.00 | +0.00 | 0.3074 |
| arch_api | +0.00 | +0.00 | +0.00 | 0.4137 |
| def_safety | +0.00 | +0.00 | +0.00 | 0.4979 |

## 1b · Signature prevalence (EXPLORATORY — descriptive shares, no p-values claimed; class-discrimination confirmatory tests belong to Phase M / repo #2)

Share of events whose touched files NET-added (or removed) each construct.

| construct | security-fix | control | introduced |
|---|---|---|---|
| +struct_branch | 56% | 47% | 60% |
| +state_pointers | 41% | 46% | 65% |
| +def_safety | 6% | 6% | 29% |
| +state_cast_hits | 5% | 2% | 15% |
| +state_memory_alloc | 1% | 0% | 3% |
| -state_pointers | 6% | 7% | 12% |
| -struct_branch | 4% | 5% | 15% |
| loose signature (branch+ or ptr+) | 63% | 61% | 74% |
| strict signature (branch+ and ptr+) | 34% | 31% | 51% |
| fix-shaped (branch/ptr+ WITHOUT new allocs/casts) | 58% | 59% | 59% |

Reading: no single feature is a fingerprint (71% of fixes add branch-or-ptr, but so do 45% of controls). The DIFFERENTIAL is the lead: introductions match fixes on branches/pointers but differ sharply on allocations and casts — 'pointer/branch-heavy WITHOUT new allocs/casts' is fix-shaped; the same WITH them is feature-shaped, which is where vulnerabilities are born. Multi-feature classification is the ML dataset's job, not a threshold's.

## 2 · Assumed vs observed — where CVE files stand per signal, before the event

Median pre-event percentile of implicated files per signal (ranked among all files in the parent snapshot), fix-class vs the control-file baseline. A large gap in either direction is a keyword whose risk association differs from the 'change happens in hot files' baseline; sorted by |gap|.

| signal | CVE-fix files | control files | gap |
|---|---|---|---|
| def_safety | 0 | 97 | -97 |
| bitwise_ops | 0 | 94 | -94 |
| state_safety_neg | 0 | 93 | -93 |
| state_print_hits | 0 | 93 | -93 |
| state_cast_hits | 0 | 93 | -93 |
| arch_globals | 0 | 93 | -93 |
| state_planned_debt | 0 | 90 | -90 |
| def_doc | 0 | 89 | -89 |
| state_heat_triggers | 0 | 89 | -89 |
| state_unreferenced | 22 | 94 | -72 |
| arch_import | 22 | 93 | -71 |
| struct_func_start | 75 | 96 | -22 |
| arch_api | 75 | 96 | -21 |
| def_encapsulation | 77 | 97 | -20 |
| struct_short_vars | 78 | 94 | -17 |

## 3 · The vulnerable function — implicated vs same-file siblings (parent snapshot)

Functions overlapping a fix's changed lines (n=243) vs untouched siblings in the same files (n=9429):

| metric | implicated median | sibling median | p (sib < imp) |
|---|---|---|---|
| complexity | 22.00 | 3.00 | 0.0000 |
| z-score | 1.00 | -0.29 | 0.0000 |
| loc | 80.00 | 16.00 | 0.0000 |

If implicated functions stand out from their own file's siblings, the instrument localizes below file granularity — the sharpest claim rung 7 could make.

**Length-bias gate (loc-matched pairs, n=149, sibling within 0.66–1.5× loc in the same file):**

| metric | implicated median | matched sibling median | p (sib < imp) |
|---|---|---|---|
| complexity | 17.00 | 15.00 | 0.3880 |
| z-score | 0.48 | 0.51 | 0.4516 |
| loc (match check) | 65.00 | 67.00 | 0.4261 |

Pairwise: implicated more complex than its length-matched sibling in 78/149 pairs (7 ties). If the gate holds, complexity separates future-patched functions at equal length — a real below-file signal, not hunk-area bias.

### Phase D — the guard deficit (pre-registered)

guard rate = (def_safety + bailouts) / (pointers + danger + memory_alloc + casts + 1), function grain, parent snapshot, loc-matched pairs.

| metric | implicated | matched sibling | p (one-sided, registered direction) |
|---|---|---|---|
| guard rate (D-H1) | 0.000 | 0.000 | 0.6959 |
| danger load (control) | 19.0 | 20.0 | 0.4729 |
| guard-rate change after fix (D-H2) | +0.0000 (n=149) | +0.0000 (n=149) | 0.9990 |

**D-H1 (vulnerable = under-guarded relative to danger): not supported** · **D-H2 (the fix closes the deficit): not supported** (α=0.01, directions registered on gitgalaxy#2982 before this table was generated).

---
*Counts are the engine's own extraction (persisted per commit in file_data/function_data); no diff-text keyword matching involved. Regenerate: `python tools/signal_anatomy.py --events events/curl.json`.*
