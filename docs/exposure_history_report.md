# Exposure history report — curl

Generated 2026-09-12 09:30 · engine scans temporally ablated (asserted: max |temporal Δ| = 0.0) · DB `curl_galaxy_master.db` · events pinned to pool HEAD `04bfe8fbbf55` · **PRELIMINARY — batch incomplete**

## Coverage

| class | analyzed | pending/skipped | of harvested |
|---|---|---|---|
| security-fix | 59 | 126 | 186 |
| control | 46 | 135 | 185 |
| introduced | 45 | 87 | 137 |

## Pre-registered hypotheses (gitgalaxy#2982; unit = event, mean structural Δ over its touched files)

| test | n | median Δ | vs | n | median Δ | p (one-sided MW) | verdict at α=0.01 |
|---|---|---|---|---|---|---|---|
| **H1** fixes < controls | 59 | +0.018 | controls | 46 | +0.000 | 0.4819 | not supported |
| **H2** introduced > controls | 45 | +0.000 | controls | 46 | +0.000 | 0.7750 | not supported |

Per-file pooled secondary (pseudo-replicated, labeled as such): H1 p = 0.1018 over 165 fix-file vs 137 control-file deltas; H2 p = 0.9931.

## H3 — which vectors carry it (event-level medians)

| vector | fixes | controls | introduced | H1 p |
|---|---|---|---|---|
| tech_debt | -0.004 | +0.000 | -0.009 | 0.0028 |
| api_exposure | -0.000 | +0.000 | -0.001 | 0.0500 |
| dead_code | -0.000 | +0.000 | -0.003 | 0.0806 |
| safety_score | +0.000 | +0.000 | +0.000 | 0.0948 |
| concurrency | +0.000 | +0.000 | +0.000 | 0.3741 |
| state_flux | +0.000 | +0.000 | +0.000 | 0.4140 |
| verification | +0.000 | +0.000 | +0.000 | 0.5117 |
| documentation | +0.000 | +0.000 | +0.000 | 0.5212 |
| secrets_risk | +0.000 | +0.000 | +0.000 | 0.7418 |
| cognitive_load | +0.018 | +0.000 | +0.000 | 0.9692 |
| spec_match | +0.000 | +0.000 | +0.000 | nan |

## Sign split — does a fix *reduce* exposure?

| class | Δ<0 (reduced) | Δ>0 (raised) | Δ=0 |
|---|---|---|---|
| security-fix | 22 (37%) | 32 (54%) | 5 |
| control | 15 (33%) | 20 (43%) | 11 |
| introduced | 22 (49%) | 20 (44%) | 3 |

The first pilot sample predicted this split: guard code added by a fix reads as complexity (dead_code, cognitive_load), so a security fix RAISING structural exposure is not a scan error — whether the *distribution* differs from controls is what H1 asks.

## Severity gradient (security fixes)

| severity | n | median Δ | p25 | p75 |
|---|---|---|---|---|
| Medium | 19 | +0.110 | +0.000 | +1.555 |
| Low | 40 | +0.000 | -0.125 | +0.161 |

## Top movers (security fixes, event mean Δ)

| direction | CVE | Δ | files touched |
|---|---|---|---|
| ↓ largest drop | CURL-CVE-2025-0725 | -4.300 | 1 |
| ↓ largest drop | CURL-CVE-2025-13034 | -1.594 | 1 |
| ↓ largest drop | CURL-CVE-2026-11564 | -1.038 | 3 |
| ↓ largest drop | CURL-CVE-2026-9080 | -0.874 | 1 |
| ↓ largest drop | CURL-CVE-2026-8926 | -0.792 | 4 |
| ↑ largest rise | CURL-CVE-2026-11586 | +47.112 | 2 |
| ↑ largest rise | CURL-CVE-2026-5545 | +16.400 | 1 |
| ↑ largest rise | CURL-CVE-2026-11856 | +14.130 | 5 |
| ↑ largest rise | CURL-CVE-2026-8925 | +7.079 | 1 |
| ↑ largest rise | CURL-CVE-2024-11053 | +2.368 | 3 |

## CVE hotspot files (appearances across fix+introduced events)

| file | events |
|---|---|
| `lib/url.c` | 30 |
| `lib/urldata.h` | 26 |
| `lib/vtls/openssl.c` | 14 |
| `lib/setopt.c` | 14 |
| `lib/http.c` | 12 |
| `include/curl/curl.h` | 10 |
| `configure.ac` | 9 |
| `lib/version.c` | 9 |
| `lib/Makefile.inc` | 9 |
| `lib/vtls/gtls.c` | 8 |

## Are the outliers where security events happen?

Each implicated file's **structural-exposure percentile within its parent snapshot** (all files ranked, before the event was known). Random targeting reads ~50; if GitGalaxy's high-exposure files are where CVEs live, security classes read high — a rung-7 preview from rung-6 data.

| class | files | median pre-event percentile | p25 | p75 |
|---|---|---|---|---|
| security-fix | 165 | 87.4 | 50.5 | 92.2 |
| introduced | 357 | 80.3 | 43.3 | 91.6 |
| control | 137 | 86.1 | 48.6 | 92.2 |

fix-files sit above control-files with one-sided MW p = 0.1915 (controls < fixes).

## CWE × vector — which exposure vector flags which weakness type?

Median **pre-event per-vector percentile** of implicated files (each file ranked per vector among all files in its parent snapshot). Reading guide: a high cell means files that later carried this weakness class already stood out on that vector before the event. Control-file rows give the baseline 'changed files look like this anyway' profile.

| class (events) | cognitive_load | safety_score | state_flux | api_exposure | verification | tech_debt | documentation | concurrency |
|---|---|---|---|---|---|---|---|---|
| other (32) | 83 | 71 | 82 | 58 | 83 | 78 | 54 | 0 |
| cert/auth (30) | 85 | 70 | 80 | 51 | 84 | 75 | 55 | 0 |
| info-leak (24) | 89 | 80 | 83 | 51 | 82 | 77 | 56 | 0 |
| memory (18) | 81 | 69 | 82 | 61 | 84 | 77 | 50 | 0 |
| control baseline (46) | 86 | 71 | 83 | 53 | 84 | 77 | 57 | 0 |

**Fix-delta by weakness family** (median event Δ, security fixes only): 
other +0.026 (n=18) · cert/auth +0.000 (n=17) · info-leak +0.036 (n=14) · memory +0.009 (n=10)

## First look over time (event-sampled snapshots, 5-year eras)

Repo-mean structural exposure and implicated-file percentiles per era. **Caveats before believing a trend**: sampling is event-biased (snapshots exist where CVEs were fixed/introduced), the codebase grows (absolute scores drift with file size — percentiles are the robust reading), and deleted files leave the panel (survivorship). The phase-W walk replaces this with a uniform panel.

| era | snapshots | repo files (median) | repo-mean structural exposure (median) | implicated-file percentile (median) |
|---|---|---|---|---|
| 2000–2004 | 3 | 165 | 220.68 | 22.0 |
| 2005–2009 | 2 | 341 | 237.20 | 72.0 |
| 2010–2014 | 4 | 581 | 273.88 | 49.4 |
| 2015–2019 | 7 | 620 | 269.69 | 79.1 |
| 2020–2024 | 26 | 981 | 274.42 | 84.9 |
| 2025–2029 | 108 | 1066 | 279.05 | 86.6 |

## Instrument controls

- **Untouched-file spillover** (files the commit did not touch; expected ~0, graph ripple via api_exposure is the legitimate exception): n = 146977, median |Δ| = 0.000000, p99 = 0.0000, max = 29.7754.
- **LOC coupling** on touched files (is Δ just size change?): Spearman ρ = -0.149 over 302 files. The length-leak lesson says watch this; a high ρ routes to the score-contract program, not to a corpus tweak.
- **Temporal ablation**: asserted exactly 0.0 across every delta in this run.

---
*Regenerate: `python tools/delta_report.py --events events/curl.json` — reads only the events file and the history DB; every number above is a pure function of those two artifacts.*
