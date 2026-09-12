# Exposure history report — ndpi

Generated 2026-09-12 18:06 · engine scans temporally ablated (asserted: max |temporal Δ| = 0.0) · DB `ndpi_galaxy_master.db` · events pinned to pool HEAD `778771158557`

## Coverage

| class | analyzed | pending/skipped | of harvested |
|---|---|---|---|
| security-fix | 112 | 0 | 121 |
| control | 96 | 0 | 111 |
| introduced | 68 | 0 | 73 |

## Pre-registered hypotheses (gitgalaxy#2982; unit = event, mean structural Δ over its touched files)

| test | n | median Δ | vs | n | median Δ | p (one-sided MW) | verdict at α=0.01 |
|---|---|---|---|---|---|---|---|
| **H1** fixes < controls | 112 | +0.000 | controls | 96 | +0.000 | 0.6978 | not supported |
| **H2** introduced > controls | 68 | +0.000 | controls | 96 | +0.000 | 0.3670 | not supported |

Per-file pooled secondary (pseudo-replicated, labeled as such): H1 p = 0.9453 over 324 fix-file vs 162 control-file deltas; H2 p = 0.8084.

## H3 — which vectors carry it (event-level medians)

| vector | fixes | controls | introduced | H1 p |
|---|---|---|---|---|
| verification | +0.000 | +0.000 | +0.000 | 0.1260 |
| dead_code | +0.000 | +0.000 | -0.000 | 0.2375 |
| documentation | +0.000 | +0.000 | +0.000 | 0.2989 |
| tech_debt | +0.000 | +0.000 | -0.010 | 0.4100 |
| state_flux | +0.000 | +0.000 | +0.000 | 0.6391 |
| concurrency | +0.000 | +0.000 | +0.000 | 0.6948 |
| safety_score | +0.000 | +0.000 | +0.000 | 0.7058 |
| cognitive_load | +0.000 | +0.000 | +0.008 | 0.8324 |
| api_exposure | -0.000 | -0.000 | -0.004 | 0.8647 |
| spec_match | +0.000 | +0.000 | +0.000 | nan |
| secrets_risk | +0.000 | +0.000 | +0.000 | nan |

## Sign split — does a fix *reduce* exposure?

| class | Δ<0 (reduced) | Δ>0 (raised) | Δ=0 |
|---|---|---|---|
| security-fix | 41 (37%) | 43 (38%) | 28 |
| control | 38 (40%) | 35 (36%) | 23 |
| introduced | 29 (43%) | 31 (46%) | 8 |

The first pilot sample predicted this split: guard code added by a fix reads as complexity (dead_code, cognitive_load), so a security fix RAISING structural exposure is not a scan error — whether the *distribution* differs from controls is what H1 asks.

## Severity gradient (security fixes)

| severity | n | median Δ | p25 | p75 |
|---|---|---|---|---|
| ? | 7 | +0.011 | +0.000 | +0.102 |

## Top movers (security fixes, event mean Δ)

| direction | CVE | Δ | files touched |
|---|---|---|---|
| ↓ largest drop | OSV-2024-469 | -36.260 | 2 |
| ↓ largest drop | OSV-2022-1055 | -34.819 | 1 |
| ↓ largest drop | OSV-2020-1015 | -3.698 | 4 |
| ↓ largest drop | OSV-2020-1131 | -1.913 | 1 |
| ↓ largest drop | OSV-2020-342 | -1.603 | 3 |
| ↑ largest rise | OSV-2024-293 | +96.493 | 1 |
| ↑ largest rise | OSV-2020-956 | +13.941 | 1 |
| ↑ largest rise | OSV-2020-1827 | +13.234 | 3 |
| ↑ largest rise | OSV-2020-18 | +6.614 | 1 |
| ↑ largest rise | OSV-2023-102 | +2.412 | 1 |

## CVE hotspot files (appearances across fix+introduced events)

| file | events |
|---|---|
| `src/lib/ndpi_main.c` | 63 |
| `example/reader_util.c` | 41 |
| `src/lib/protocols/tls.c` | 37 |
| `src/include/ndpi_typedefs.h` | 33 |
| `example/ndpiReader.c` | 28 |
| `src/lib/protocols/http.c` | 26 |
| `src/lib/ndpi_utils.c` | 16 |
| `src/lib/protocols/dns.c` | 13 |
| `src/lib/protocols/kerberos.c` | 12 |
| `example/reader_util.h` | 11 |

## Are the outliers where security events happen?

Each implicated file's **structural-exposure percentile within its parent snapshot** (all files ranked, before the event was known). Random targeting reads ~50; if GitGalaxy's high-exposure files are where CVEs live, security classes read high — a rung-7 preview from rung-6 data.

| class | files | median pre-event percentile | p25 | p75 |
|---|---|---|---|---|
| security-fix | 324 | 77.7 | 47.8 | 91.7 |
| introduced | 242 | 82.6 | 39.1 | 96.2 |
| control | 162 | 82.7 | 33.4 | 97.3 |

fix-files sit above control-files with one-sided MW p = 0.6019 (controls < fixes).

## CWE × vector — which exposure vector flags which weakness type?

Median **pre-event per-vector percentile** of implicated files (each file ranked per vector among all files in its parent snapshot). Reading guide: a high cell means files that later carried this weakness class already stood out on that vector before the event. Control-file rows give the baseline 'changed files look like this anyway' profile.

| class (events) | cognitive_load | safety_score | state_flux | api_exposure | verification | tech_debt | documentation | concurrency |
|---|---|---|---|---|---|---|---|---|
| unlabeled (180) | 84 | 85 | 75 | 71 | 65 | 42 | 26 | 0 |
| control baseline (96) | 81 | 87 | 82 | 81 | 65 | 42 | 24 | 0 |

**Fix-delta by weakness family** (median event Δ, security fixes only): 
unlabeled +0.000 (n=112)

## First look over time (event-sampled snapshots, 5-year eras)

Repo-mean structural exposure and implicated-file percentiles per era. **Caveats before believing a trend**: sampling is event-biased (snapshots exist where CVEs were fixed/introduced), the codebase grows (absolute scores drift with file size — percentiles are the robust reading), and deleted files leave the panel (survivorship). The phase-W walk replaces this with a uniform panel.

| era | snapshots | repo files (median) | repo-mean structural exposure (median) | implicated-file percentile (median) |
|---|---|---|---|---|
| 2015–2019 | 25 | 228 | 389.04 | 62.6 |
| 2020–2024 | 228 | 264 | 358.69 | 79.2 |
| 2025–2029 | 23 | 611 | 252.50 | 80.9 |

## Commit anatomy — what fixes and introductions physically are

| class | n | commits touching any TODO/FIXME/HACK | net markers | median net LOC | net-growing |
|---|---|---|---|---|---|
| security-fix | 112 | 4 | +0 | +2 | 66/112 (59%) |
| control | 96 | 5 | +4 | +2 | 63/96 (66%) |
| introduced | 68 | 6 | +2 | +18 | 49/68 (72%) |

**The tech_debt autopsy**: the H3 tech_debt drop in fixes coexists with fixes almost never touching a debt marker — the drop is the DENSITY DENOMINATOR (same markers over more lines; fixes net-add code). A formula artifact in the #2655/#2979 shape, caught by this table. The introduced side is real: vulnerability-introducing commits are large feature additions that carry new debt markers with them.

## Dwell time — how long vulnerabilities lurk

Introduced → fixed, n = 71 CVEs with both commits: median **0.0 years** (p25 0.0y, p75 0.1y, max 1.6y). The strategic number for rung 7: a predictive instrument has a years-long window in which flagging the file would have mattered.

## Security-system signals on implicated files

- **Credential shunt** (`has_credentials` / `risk_secrets_risk=100`): fires on 0 file-rows across history — test keys and CA tooling (e.g. ) — but on **0 of 197 CVE/control-implicated files**. The secrets surface and the vulnerability surface are orthogonal in curl: CVEs live in protocol code, credentials in test fixtures.
- **ML threat layer** (`ai_threat_score`, `is_malware`, `binary_anomaly`, `obfuscation_flag`): all zero in these scans — the scan environment lacks the ML dependencies (the engine's known security_auditor ML-deps gap), so this layer is UNEXERCISED here, not exonerated. A full-deps rerun is the test.
- **Granular lens counts** (`sec_tainted_injection`, `sec_db_hooks`, …) are not persisted to the scan DB (audit-JSON only) — adding them to `file_data` (or capturing audit JSONs in the harness) is the enabling change for a per-CVE injection-surface analysis. Filed as future work in the epic.

## Instrument controls

- **Untouched-file spillover** (files the commit did not touch; expected ~0, graph ripple via api_exposure is the legitimate exception): n = 90540, median |Δ| = 0.000000, p99 = 0.0000, max = 0.4928.
- **LOC coupling** on touched files (is Δ just size change?): Spearman ρ = -0.228 over 486 files. The length-leak lesson says watch this; a high ρ routes to the score-contract program, not to a corpus tweak.
- **Temporal ablation**: asserted exactly 0.0 across every delta in this run.

---
*Regenerate: `python tools/delta_report.py --events events/curl.json` — reads only the events file and the history DB; every number above is a pure function of those two artifacts.*
