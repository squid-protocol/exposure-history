# Signal anatomy — curl

Raw-signal layer vs CVE ground truth. Events analyzed: control 47, introduced 86, security-fix 119. Median event net-LOC: control +2, introduced +6, security-fix +4.

## 1 · The grammar of a security fix (signal deltas, fixes vs controls)

Per-signal mean delta over touched files, per event (median across events). One-sided MW in the direction the medians differ; sorted by p.

| signal | fixes Δ | controls Δ | introduced Δ | p (fix vs ctrl) |
|---|---|---|---|---|
| state_pointers | +0.75 | +0.00 | +1.71 | 0.0014 |
| struct_branch | +1.00 | +0.00 | +0.95 | 0.0172 |
| def_safety | +0.00 | +0.00 | +0.00 | 0.0203 |
| struct_args | +0.00 | +0.00 | +0.17 | 0.0346 |
| struct_func_start | +0.00 | +0.00 | +0.00 | 0.0369 |
| state_flux | +0.17 | +0.00 | +0.40 | 0.0562 |
| arch_events | +0.00 | +0.00 | +0.00 | 0.0573 |
| state_danger | +0.00 | +0.00 | +0.00 | 0.0573 |
| def_doc | +0.00 | +0.00 | +0.00 | 0.0599 |
| struct_generics | +0.00 | +0.00 | +0.00 | 0.1035 |
| arch_globals | +0.00 | +0.00 | +0.00 | 0.1293 |
| state_heat_triggers | +0.00 | +0.00 | +0.00 | 0.1772 |
| state_memory_alloc | +0.00 | +0.00 | +0.00 | 0.1832 |
| struct_class_start | +0.00 | +0.00 | +0.00 | 0.1904 |
| arch_api | +0.00 | +0.00 | +0.00 | 0.1975 |
| arch_concurrency | +0.00 | +0.00 | +0.00 | 0.2692 |
| def_telemetry | +0.00 | +0.00 | +0.00 | 0.2692 |
| state_fragile_debt | +0.00 | +0.00 | +0.00 | 0.2692 |
| state_planned_debt | +0.00 | +0.00 | +0.00 | 0.2692 |
| struct_comprehensions | +0.00 | +0.00 | +0.00 | 0.2692 |

## 2 · Assumed vs observed — where CVE files stand per signal, before the event

Median pre-event percentile of implicated files per signal (ranked among all files in the parent snapshot), fix-class vs the control-file baseline. A large gap in either direction is a keyword whose risk association differs from the 'change happens in hot files' baseline; sorted by |gap|.

| signal | CVE-fix files | control files | gap |
|---|---|---|---|
| bitwise_ops | 86 | 0 | +86 |
| state_safety_neg | 81 | 0 | +81 |
| def_encapsulation | 92 | 78 | +14 |
| state_flux | 93 | 82 | +10 |
| state_graveyard | 89 | 79 | +10 |
| def_safety | 91 | 82 | +8 |
| struct_func_start | 92 | 84 | +8 |
| struct_var_decl | 93 | 85 | +8 |
| state_cast_hits | 88 | 81 | +7 |
| struct_snake_case | 93 | 86 | +7 |
| arch_import | 94 | 88 | +7 |
| struct_branch | 93 | 87 | +6 |
| arch_globals | 64 | 58 | +6 |
| struct_short_vars | 87 | 81 | +6 |
| struct_macros | 90 | 85 | +6 |

## 3 · The vulnerable function — implicated vs same-file siblings (parent snapshot)

Functions overlapping a fix's changed lines (n=468) vs untouched siblings in the same files (n=8642):

| metric | implicated median | sibling median | p (sib < imp) |
|---|---|---|---|
| complexity | 13.00 | 4.00 | 0.0000 |
| z-score | 0.50 | -0.29 | 0.0000 |
| loc | 59.50 | 23.00 | 0.0000 |

If implicated functions stand out from their own file's siblings, the instrument localizes below file granularity — the sharpest claim rung 7 could make.

---
*Counts are the engine's own extraction (persisted per commit in file_data/function_data); no diff-text keyword matching involved. Regenerate: `python tools/signal_anatomy.py --events events/curl.json`.*
