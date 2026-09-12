# Signal anatomy — curl

Raw-signal layer vs CVE ground truth. Events analyzed: control 168, introduced 118, security-fix 182. Median event net-LOC: control +2, introduced +6, security-fix +3.

## 1 · The grammar of a security fix (signal deltas, fixes vs controls)

Per-signal mean delta over touched files, per event (median across events). One-sided MW in the direction the medians differ; sorted by p.

| signal | fixes Δ | controls Δ | introduced Δ | p (fix vs ctrl) |
|---|---|---|---|---|
| state_pointers | +0.33 | +0.00 | +1.58 | 0.0001 |
| struct_branch | +0.73 | +0.00 | +0.63 | 0.0004 |
| state_flux | +0.00 | +0.00 | +0.33 | 0.0211 |
| struct_args | +0.00 | +0.00 | +0.16 | 0.0310 |
| struct_func_start | +0.00 | +0.00 | +0.00 | 0.0316 |
| arch_events | +0.00 | +0.00 | +0.00 | 0.0356 |
| def_safety | +0.00 | +0.00 | +0.00 | 0.0671 |
| def_doc | +0.00 | +0.00 | +0.00 | 0.0794 |
| state_fragile_debt | +0.00 | +0.00 | +0.00 | 0.0794 |
| struct_class_start | +0.00 | +0.00 | +0.00 | 0.1046 |
| struct_generics | +0.00 | +0.00 | +0.00 | 0.1061 |
| state_danger | +0.00 | +0.00 | +0.00 | 0.1503 |
| arch_concurrency | +0.00 | +0.00 | +0.00 | 0.1698 |
| state_planned_debt | +0.00 | +0.00 | +0.00 | 0.1698 |
| struct_comprehensions | +0.00 | +0.00 | +0.00 | 0.1698 |
| arch_api | +0.00 | +0.00 | +0.00 | 0.1787 |
| state_heat_triggers | +0.00 | +0.00 | +0.00 | 0.2073 |
| def_test | +0.00 | +0.00 | +0.00 | 0.2323 |
| arch_import | +0.00 | +0.00 | +0.00 | 0.3646 |
| state_graveyard | +0.00 | +0.00 | +0.00 | 0.3716 |

## 2 · Assumed vs observed — where CVE files stand per signal, before the event

Median pre-event percentile of implicated files per signal (ranked among all files in the parent snapshot), fix-class vs the control-file baseline. A large gap in either direction is a keyword whose risk association differs from the 'change happens in hot files' baseline; sorted by |gap|.

| signal | CVE-fix files | control files | gap |
|---|---|---|---|
| state_safety_neg | 79 | 0 | +79 |
| state_graveyard | 89 | 79 | +10 |
| def_encapsulation | 92 | 84 | +8 |
| state_cast_hits | 87 | 80 | +7 |
| struct_func_start | 92 | 87 | +5 |
| state_heat_triggers | 83 | 78 | +5 |
| struct_class_start | 94 | 89 | +5 |
| arch_import | 94 | 89 | +5 |
| struct_macros | 89 | 84 | +5 |
| struct_args | 92 | 87 | +5 |
| struct_short_vars | 85 | 81 | +4 |
| struct_branch | 92 | 88 | +4 |
| state_pointers | 95 | 91 | +4 |
| state_flux | 92 | 89 | +4 |
| struct_var_decl | 93 | 89 | +4 |

## 3 · The vulnerable function — implicated vs same-file siblings (parent snapshot)

Functions overlapping a fix's changed lines (n=579) vs untouched siblings in the same files (n=10913):

| metric | implicated median | sibling median | p (sib < imp) |
|---|---|---|---|
| complexity | 13.00 | 4.00 | 0.0000 |
| z-score | 0.57 | -0.29 | 0.0000 |
| loc | 65.00 | 23.00 | 0.0000 |

If implicated functions stand out from their own file's siblings, the instrument localizes below file granularity — the sharpest claim rung 7 could make.

**Length-bias gate (loc-matched pairs, n=433, sibling within 0.66–1.5× loc in the same file):**

| metric | implicated median | matched sibling median | p (sib < imp) |
|---|---|---|---|
| complexity | 11.00 | 11.00 | 0.7216 |
| z-score | 0.16 | 0.23 | 0.7517 |
| loc (match check) | 51.00 | 50.00 | 0.4014 |

Pairwise: implicated more complex than its length-matched sibling in 179/433 pairs (59 ties). If the gate holds, complexity separates future-patched functions at equal length — a real below-file signal, not hunk-area bias.

### Phase D — the guard deficit (pre-registered)

guard rate = (def_safety + bailouts) / (pointers + danger + memory_alloc + casts + 1), function grain, parent snapshot, loc-matched pairs.

| metric | implicated | matched sibling | p (one-sided, registered direction) |
|---|---|---|---|
| guard rate (D-H1) | 0.000 | 0.000 | 0.2175 |
| danger load (control) | 20.0 | 17.0 | 0.0321 |
| guard-rate change after fix (D-H2) | +0.0000 (n=414) | +0.0000 (n=433) | 0.8687 |

**D-H1 (vulnerable = under-guarded relative to danger): not supported** · **D-H2 (the fix closes the deficit): not supported** (α=0.01, directions registered on gitgalaxy#2982 before this table was generated).

---
*Counts are the engine's own extraction (persisted per commit in file_data/function_data); no diff-text keyword matching involved. Regenerate: `python tools/signal_anatomy.py --events events/curl.json`.*
