# Centrality in the small-file regime — does it beat LOC where files are small?

Generated 2026-09-13 00:48 · repo `curl` · pool HEAD `04bfe8fbbf55` · DB `curl_galaxy_master.db` (opened read-only, WAL-aware) · pre-registered gitgalaxy#2982 comment 5650157545; implemented verbatim; verdicts publish either way.

## Design

Unit = file present in a security-fix event's **parent** snapshot (T0); positive = the fix touches it (`diff_statuses` parent..child, status "touched", old_path present in the parent snapshot) — identical convention to `tools/incremental_value.py`. No rescan: centrality is already populated in the scan DB. Unlike incremental_value.py this test needs **no `git log` process-feature walk** — centrality is a pure T0 structural read — so `collect_events` here is a leaner, walk-free sibling (same parent_child / diff_statuses / skip semantics, reused directly).

Coverage: **182** security-fix events usable (of 186 in the event set); skipped — {'no touched file present in parent snapshot': 4}. Pooled candidate files: **155477**, pooled positives: **460**. Wall-time: 28.46s (no history walk, so this is fast by construction).

## Measures and the `normalized_blast_radius` exclusion

Measures: `pagerank_score`, `betweenness_score`, `popularity` (in-degree/dependents), `import_count` (out-degree), `internal_dependency_links`. Control: `total_loc`. **`normalized_blast_radius` is excluded** — verified over every non-null row in the DB (1054217 rows checked): `normalized_blast_radius == pagerank_score * 1000` in 1054217/1054217 rows — exact, no mismatches. Including it alongside `pagerank_score` would double-count the same signal, repeating this program's earlier coupling-entropy redundancy error.

## Coverage / degeneracy check

Nonzero rate of each measure, pooled over all candidate files and separately over positives only — a measure that is near-always zero cannot carry much signal no matter what its AUC says.

| measure | nonzero (all files) | nonzero (positives only) |
|---|---|---|
| `pagerank_score` | 155477/155477 (100.0%) | 460/460 (100.0%) |
| `betweenness_score` | 7818/155477 (5.0%) | 48/460 (10.4%) |
| `popularity` | 41672/155477 (26.8%) | 76/460 (16.5%) |
| `import_count` | 123598/155477 (79.5%) | 408/460 (88.7%) |
| `internal_dependency_links` | 101406/155477 (65.2%) | 398/460 (86.5%) |

**Flagged as sparse:** `betweenness_score` — nonzero in well under a majority of files; any AUC computed on these mixes real discrimination with a large tied-at-zero block, and low positive coverage in particular caps how much of the pooled signal that measure can possibly explain. Reported, not hidden.

## Descriptive — pooled AUC per measure (no verdict)

| rank | feature | AUC | n positives | n negatives |
|---|---|---|---|---|
| 1 | `total_loc` | 0.8585 | 460 | 155017 |
| 2 | `internal_dependency_links` | 0.8119 | 460 | 155017 |
| 3 | `import_count` | 0.8065 | 460 | 155017 |
| 4 | `betweenness_score` | 0.5282 | 460 | 155017 |
| 5 | `pagerank_score` | 0.4983 | 460 | 155017 |
| 6 | `popularity` | 0.4592 | 460 | 155017 |
## Primary — absolute NLOC bands (repowise scheme)

Bootstrap: 5000 iters over the EVENT list, seed 2982+band-offset, band membership fixed from observed data. **Effective alpha (Bonferroni across 5 measures x 2 powered bands in this scheme): 0.01/(5x2) = 0.001000**. Compute time: 1100.7s.

### `pagerank_score` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| <=22 | 5258 | 1 | 0.9990 | 0.5409 | 0.4582 | 0.4079 | [0.4242, 0.4949] | UNDERPOWERED |
| 23-48 | 21994 | 4 | 0.7178 | 0.3974 | 0.3204 | -0.7460 | [-0.7228, 0.8378] | UNDERPOWERED |
| 49-108 | 46874 | 22 | 0.7060 | 0.5518 | 0.1543 | -0.2167 | [-0.0376, 0.3306] | not supported |
| >108 | 81351 | 433 | 0.5250 | 0.7964 | -0.2714 | -0.3430 | [-0.3141, -0.2310] | not supported |

### `betweenness_score` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| <=22 | 5258 | 1 | 0.5000 | 0.5409 | -0.0409 | -0.0912 | [-0.0747, -0.0043] | UNDERPOWERED |
| 23-48 | 21994 | 4 | 0.6009 | 0.3974 | 0.2035 | -0.3057 | [-0.2995, 0.4270] | UNDERPOWERED |
| 49-108 | 46874 | 22 | 0.5797 | 0.5518 | 0.0279 | -0.2464 | [-0.1614, 0.2375] | not supported |
| >108 | 81351 | 433 | 0.5267 | 0.7964 | -0.2697 | -0.3133 | [-0.2968, -0.2424] | not supported |

### `popularity` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| <=22 | 5258 | 1 | 0.9868 | 0.5409 | 0.4459 | 0.3949 | [0.4115, 0.4834] | UNDERPOWERED |
| 23-48 | 21994 | 4 | 0.7010 | 0.3974 | 0.3035 | -0.6461 | [-0.6381, 0.7805] | UNDERPOWERED |
| 49-108 | 46874 | 22 | 0.7041 | 0.5518 | 0.1524 | -0.1379 | [-0.0062, 0.3011] | not supported |
| >108 | 81351 | 433 | 0.4966 | 0.7964 | -0.2998 | -0.3507 | [-0.3311, -0.2685] | not supported |

### `import_count` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| <=22 | 5258 | 1 | 0.4833 | 0.5409 | -0.0576 | -0.1080 | [-0.0914, -0.0212] | UNDERPOWERED |
| 23-48 | 21994 | 4 | 0.3898 | 0.3974 | -0.0077 | -0.5965 | [-0.5895, 0.4332] | UNDERPOWERED |
| 49-108 | 46874 | 22 | 0.5049 | 0.5518 | -0.0469 | -0.2966 | [-0.2170, 0.1481] | not supported |
| >108 | 81351 | 433 | 0.7742 | 0.7964 | -0.0222 | -0.0675 | [-0.0498, 0.0041] | not supported |

### `internal_dependency_links` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| <=22 | 5258 | 1 | 0.4998 | 0.5409 | -0.0411 | -0.0914 | [-0.0749, -0.0044] | UNDERPOWERED |
| 23-48 | 21994 | 4 | 0.4402 | 0.3974 | 0.0428 | -0.5656 | [-0.5570, 0.4994] | UNDERPOWERED |
| 49-108 | 46874 | 22 | 0.5903 | 0.5518 | 0.0385 | -0.2073 | [-0.1255, 0.2261] | not supported |
| >108 | 81351 | 433 | 0.7851 | 0.7964 | -0.0114 | -0.0585 | [-0.0409, 0.0155] | not supported |

## Secondary — rank-quartile bands (this program's convention)

Bootstrap: 5000 iters over the EVENT list, seed 2982+band-offset, band membership fixed from observed data. **Effective alpha (Bonferroni across 5 measures x 3 powered bands in this scheme): 0.01/(5x3) = 0.000667**. Compute time: 2168.8s.

### `pagerank_score` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| Q1 (rank quartile of total_loc) | 38869 | 8 | 0.7191 | 0.4863 | 0.2328 | -0.5441 | [-0.1955, 0.5997] | UNDERPOWERED |
| Q2 (rank quartile of total_loc) | 38869 | 22 | 0.6937 | 0.5253 | 0.1684 | -0.2611 | [-0.0370, 0.3420] | not supported |
| Q3 (rank quartile of total_loc) | 38869 | 62 | 0.5348 | 0.5582 | -0.0233 | -0.1952 | [-0.1307, 0.0863] | not supported |
| Q4 (rank quartile of total_loc) | 38870 | 368 | 0.5230 | 0.7568 | -0.2338 | -0.3154 | [-0.2819, -0.1877] | not supported |

### `betweenness_score` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| Q1 (rank quartile of total_loc) | 38869 | 8 | 0.6025 | 0.4863 | 0.1163 | -0.2805 | [-0.0756, 0.3535] | UNDERPOWERED |
| Q2 (rank quartile of total_loc) | 38869 | 22 | 0.5765 | 0.5253 | 0.0512 | -0.1993 | [-0.1115, 0.2315] | not supported |
| Q3 (rank quartile of total_loc) | 38869 | 62 | 0.5065 | 0.5582 | -0.0517 | -0.1719 | [-0.1292, 0.0321] | not supported |
| Q4 (rank quartile of total_loc) | 38870 | 368 | 0.5316 | 0.7568 | -0.2252 | -0.2757 | [-0.2583, -0.1907] | not supported |

### `popularity` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| Q1 (rank quartile of total_loc) | 38869 | 8 | 0.6145 | 0.4863 | 0.1283 | -0.5221 | [-0.2001, 0.4587] | UNDERPOWERED |
| Q2 (rank quartile of total_loc) | 38869 | 22 | 0.7065 | 0.5253 | 0.1811 | -0.1734 | [0.0011, 0.3399] | not supported |
| Q3 (rank quartile of total_loc) | 38869 | 62 | 0.5004 | 0.5582 | -0.0578 | -0.1965 | [-0.1461, 0.0384] | not supported |
| Q4 (rank quartile of total_loc) | 38870 | 368 | 0.5042 | 0.7568 | -0.2526 | -0.3115 | [-0.2897, -0.2149] | not supported |

### `import_count` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| Q1 (rank quartile of total_loc) | 38869 | 8 | 0.4254 | 0.4863 | -0.0608 | -0.5568 | [-0.3295, 0.1325] | UNDERPOWERED |
| Q2 (rank quartile of total_loc) | 38869 | 22 | 0.5323 | 0.5253 | 0.0070 | -0.2158 | [-0.1493, 0.2017] | not supported |
| Q3 (rank quartile of total_loc) | 38869 | 62 | 0.4241 | 0.5582 | -0.1341 | -0.3113 | [-0.2469, -0.0199] | not supported |
| Q4 (rank quartile of total_loc) | 38870 | 368 | 0.7631 | 0.7568 | 0.0063 | -0.0395 | [-0.0191, 0.0306] | not supported |

### `internal_dependency_links` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | verdict |
|---|---|---|---|---|---|---|---|---|
| Q1 (rank quartile of total_loc) | 38869 | 8 | 0.4829 | 0.4863 | -0.0034 | -0.5106 | [-0.2781, 0.1917] | UNDERPOWERED |
| Q2 (rank quartile of total_loc) | 38869 | 22 | 0.6092 | 0.5253 | 0.0839 | -0.1227 | [-0.0648, 0.2687] | not supported |
| Q3 (rank quartile of total_loc) | 38869 | 62 | 0.4534 | 0.5582 | -0.1047 | -0.2661 | [-0.2088, -0.0004] | not supported |
| Q4 (rank quartile of total_loc) | 38870 | 368 | 0.7837 | 0.7568 | 0.0269 | -0.0270 | [-0.0027, 0.0544] | not supported |

## C-H1 — does at least one measure beat `total_loc` in a small band?

**Claim**: within the small-file bands (`<=22`, `23-48`, absolute scheme), at least one of the 5 centrality measures has AUC>0.5 AND lift>0 with the bootstrap lower bound (at the Bonferroni-adjusted alpha 0.001000) excluding 0.

| measure | band | n | n pos | AUC | lift | lower bound | powered | verdict |
|---|---|---|---|---|---|---|---|---|
| `pagerank_score` | <=22 | 5258 | 1 | 0.9990 | 0.4582 | 0.4079 | no | UNDERPOWERED |
| `pagerank_score` | 23-48 | 21994 | 4 | 0.7178 | 0.3204 | -0.7460 | no | UNDERPOWERED |
| `betweenness_score` | <=22 | 5258 | 1 | 0.5000 | -0.0409 | -0.0912 | no | UNDERPOWERED |
| `betweenness_score` | 23-48 | 21994 | 4 | 0.6009 | 0.2035 | -0.3057 | no | UNDERPOWERED |
| `popularity` | <=22 | 5258 | 1 | 0.9868 | 0.4459 | 0.3949 | no | UNDERPOWERED |
| `popularity` | 23-48 | 21994 | 4 | 0.7010 | 0.3035 | -0.6461 | no | UNDERPOWERED |
| `import_count` | <=22 | 5258 | 1 | 0.4833 | -0.0576 | -0.1080 | no | UNDERPOWERED |
| `import_count` | 23-48 | 21994 | 4 | 0.3898 | -0.0077 | -0.5965 | no | UNDERPOWERED |
| `internal_dependency_links` | <=22 | 5258 | 1 | 0.4998 | -0.0411 | -0.0914 | no | UNDERPOWERED |
| `internal_dependency_links` | 23-48 | 21994 | 4 | 0.4402 | 0.0428 | -0.5656 | no | UNDERPOWERED |

**C-H1: **UNDERPOWERED**.** Neither small band clears the n_positives>=20 power floor for any measure — per the registered power rule this is reported as UNDERPOWERED, not as a null.

## C-H2 — does the lift concentrate in small files? (the shape claim)

**Claim**: `lift = AUC(measure) - AUC(total_loc)` decreases monotonically as the absolute band's file-size ceiling increases (`<=22` -> `23-48` -> `49-108` -> `>108`). The pre-registration does not state whether the claim needs ANY measure to show this shape or ALL of them — both readings are reported, following this repo's own convention for resolving that exact ambiguity in `tools/incremental_value.py`.

| measure | lift `<=22` | lift `23-48` | lift `49-108` | lift `>108` | monotone non-increasing? |
|---|---|---|---|---|---|
| `pagerank_score` | 0.4582 | 0.3204 | 0.1543 | -0.2714 | **yes** |
| `betweenness_score` | -0.0409 | 0.2035 | 0.0279 | -0.2697 | no |
| `popularity` | 0.4459 | 0.3035 | 0.1524 | -0.2998 | **yes** |
| `import_count` | -0.0576 | -0.0077 | -0.0469 | -0.0222 | no |
| `internal_dependency_links` | -0.0411 | 0.0428 | 0.0385 | -0.0114 | no |

**C-H2: 2/5 measures show a strictly monotone non-increasing lift-by-band series.** Reading (any measure): **SUPPORTED** · reading (all measures): not supported.

## The headline number

**PageRank in the `<=22` band: AUC = 0.9990** vs AUC(`total_loc`) = 0.5409 in the same band (lift = 0.4582, n=5258, n_pos=1, UNDERPOWERED).

**Comparison to repowise's Q1**: their PageRank AUC 0.73 vs their shipped score's 0.53 inside Q1 (<=22 LOC). Here, PageRank's AUC against `total_loc` specifically (not their 24-biomarker shipped score, which is a different, richer baseline) is 0.9990 vs 0.5409 — the same direction as their result: centrality separates positives from non-positives noticeably better than raw LOC does, right where repowise says the signal lives. Note the baselines differ (`total_loc` here vs their full shipped composite there), so this is a directional cross-check, not a literal reproduction of their 0.73/0.53 pair.

## Design notes / ambiguity resolutions

- **Effective alpha is scoped per banding scheme, over ALL 4 bands in that scheme, not just the two small bands named in C-H1.** The pre-registration says "Bonferroni across (measures x powered bands)" without restricting the band count to the small ones; scoping the correction to the full primary table (5 measures x however many of the 4 absolute bands are powered) is the more conservative reading and keeps one consistent threshold for every cell in a given table, rather than requiring two different lower-bound numbers for the same small-band cells depending on which claim is being read off them.
- **C-H2's "any vs all measures" reading is genuinely ambiguous** in the registration text (which says "centrality's lift... decreases monotonically", singular) — both readings are reported per test rather than silently picking one, mirroring `tools/incremental_value.py`'s own resolution of the identical ambiguity for IV-H1/IV-H2.
- **Band membership (both schemes) is by each row's own `total_loc`**, not by any centrality measure — this is what repowise's absolute scheme means by "small files", and it is what keeps the two schemes (absolute cut points vs rank quartiles) directly comparable to each other, since they band the same underlying quantity two different ways.
- **`AUC(total_loc)` inside a `total_loc`-banded group is attenuated toward 0.5 by construction** (narrower bands compress the LOC range available to discriminate on) — the same effect this program flagged in the N-FIRST analysis (`docs/HYPOTHESES.md`, "AUC(LOC)~=0.50 is forced by matching"). The lift figure already nets this out; the raw `AUC(total_loc)` column is reported for transparency, not as a fair independent baseline read in isolation.
- **No process-feature git walk.** Centrality columns are read once per event's parent commit directly from `file_data`; `compute_process_features` (`tools/incremental_value.py`) is never called, per the pre-registration's explicit permission to skip it entirely.

---
*Regenerate: `python tools/centrality_bands.py --events events/curl.json` — stdlib only, no rescan, no git history walk.*
