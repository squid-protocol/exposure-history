# Signal anatomy — curl

Raw-signal layer vs CVE ground truth. Events analyzed: control 47, introduced 98, security-fix 138. Median event net-LOC: control +2, introduced +6, security-fix +3.

## 1 · The grammar of a security fix (signal deltas, fixes vs controls)

Per-signal mean delta over touched files, per event (median across events). One-sided MW in the direction the medians differ; sorted by p.

| signal | fixes Δ | controls Δ | introduced Δ | p (fix vs ctrl) |
|---|---|---|---|---|
| state_pointers | +0.45 | +0.00 | +1.64 | 0.0026 |
| struct_branch | +1.00 | +0.00 | +1.00 | 0.0201 |
| def_safety | +0.00 | +0.00 | +0.00 | 0.0216 |
| arch_events | +0.00 | +0.00 | +0.00 | 0.0445 |
| state_danger | +0.00 | +0.00 | +0.00 | 0.0445 |
| struct_args | +0.00 | +0.00 | +0.17 | 0.0447 |
| def_doc | +0.00 | +0.00 | +0.00 | 0.0536 |
| struct_func_start | +0.00 | +0.00 | +0.00 | 0.0604 |
| state_flux | +0.00 | +0.00 | +0.37 | 0.0942 |
| struct_generics | +0.00 | +0.00 | +0.00 | 0.1209 |
| state_heat_triggers | +0.00 | +0.00 | +0.00 | 0.1227 |
| arch_globals | +0.00 | +0.00 | +0.00 | 0.1308 |
| struct_decorators | +0.00 | +0.00 | +0.00 | 0.2362 |
| struct_class_start | +0.00 | +0.00 | +0.00 | 0.2386 |
| arch_api | +0.00 | +0.00 | +0.00 | 0.2484 |
| state_safety_neg | +0.00 | +0.00 | +0.00 | 0.2660 |
| state_memory_alloc | +0.00 | +0.00 | +0.00 | 0.2768 |
| arch_concurrency | +0.00 | +0.00 | +0.00 | 0.2839 |
| state_fragile_debt | +0.00 | +0.00 | +0.00 | 0.2839 |
| state_planned_debt | +0.00 | +0.00 | +0.00 | 0.2839 |

## 2 · Assumed vs observed — where CVE files stand per signal, before the event

Median pre-event percentile of implicated files per signal (ranked among all files in the parent snapshot), fix-class vs the control-file baseline. A large gap in either direction is a keyword whose risk association differs from the 'change happens in hot files' baseline; sorted by |gap|.

| signal | CVE-fix files | control files | gap |
|---|---|---|---|
| bitwise_ops | 86 | 0 | +86 |
| state_safety_neg | 81 | 0 | +81 |
| state_unreferenced | 23 | 46 | -23 |
| def_encapsulation | 92 | 78 | +14 |
| state_flux | 92 | 82 | +10 |
| state_graveyard | 89 | 79 | +10 |
| def_safety | 91 | 82 | +9 |
| struct_var_decl | 93 | 85 | +8 |
| state_cast_hits | 88 | 81 | +8 |
| struct_func_start | 92 | 84 | +8 |
| struct_snake_case | 93 | 86 | +7 |
| arch_import | 94 | 88 | +7 |
| struct_branch | 93 | 87 | +6 |
| arch_globals | 64 | 58 | +6 |
| struct_short_vars | 87 | 81 | +6 |

## 3 · The vulnerable function — implicated vs same-file siblings (parent snapshot)

Functions overlapping a fix's changed lines (n=493) vs untouched siblings in the same files (n=9133):

| metric | implicated median | sibling median | p (sib < imp) |
|---|---|---|---|
| complexity | 13.00 | 4.00 | 0.0000 |
| z-score | 0.53 | -0.29 | 0.0000 |
| loc | 62.00 | 23.00 | 0.0000 |

If implicated functions stand out from their own file's siblings, the instrument localizes below file granularity — the sharpest claim rung 7 could make.

**Length-bias gate (loc-matched pairs, n=376, sibling within 0.66–1.5× loc in the same file):**

| metric | implicated median | matched sibling median | p (sib < imp) |
|---|---|---|---|
| complexity | 10.00 | 10.00 | 0.6986 |
| z-score | 0.19 | 0.25 | 0.7018 |
| loc (match check) | 50.00 | 47.50 | 0.4105 |

Pairwise: implicated more complex than its length-matched sibling in 156/376 pairs (53 ties). If the gate holds, complexity separates future-patched functions at equal length — a real below-file signal, not hunk-area bias.

---
*Counts are the engine's own extraction (persisted per commit in file_data/function_data); no diff-text keyword matching involved. Regenerate: `python tools/signal_anatomy.py --events events/curl.json`.*
