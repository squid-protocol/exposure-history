# Exposure history report — curl

Generated 2026-09-12 09:12 · engine scans temporally ablated (asserted: max |temporal Δ| = 0.0) · DB `curl_galaxy_master.db` · events pinned to pool HEAD `04bfe8fbbf55` · **PRELIMINARY — batch incomplete**

## Coverage

| class | analyzed | pending/skipped | of harvested |
|---|---|---|---|
| security-fix | 50 | 135 | 186 |
| control | 46 | 135 | 185 |
| introduced | 45 | 87 | 137 |

## Pre-registered hypotheses (gitgalaxy#2982; unit = event, mean structural Δ over its touched files)

| test | n | median Δ | vs | n | median Δ | p (one-sided MW) | verdict at α=0.01 |
|---|---|---|---|---|---|---|---|
| **H1** fixes < controls | 50 | +0.018 | controls | 46 | +0.000 | 0.5772 | not supported |
| **H2** introduced > controls | 45 | +0.000 | controls | 46 | +0.000 | 0.7750 | not supported |

Per-file pooled secondary (pseudo-replicated, labeled as such): H1 p = 0.1669 over 147 fix-file vs 137 control-file deltas; H2 p = 0.9931.

## H3 — which vectors carry it (event-level medians)

| vector | fixes | controls | introduced | H1 p |
|---|---|---|---|---|
| tech_debt | -0.005 | +0.000 | -0.009 | 0.0007 |
| api_exposure | -0.000 | +0.000 | -0.001 | 0.0770 |
| dead_code | -0.000 | +0.000 | -0.003 | 0.0888 |
| safety_score | +0.000 | +0.000 | +0.000 | 0.0958 |
| concurrency | +0.000 | +0.000 | +0.000 | 0.3632 |
| state_flux | +0.000 | +0.000 | +0.000 | 0.4601 |
| verification | +0.000 | +0.000 | +0.000 | 0.5127 |
| documentation | +0.000 | +0.000 | +0.000 | 0.5850 |
| secrets_risk | +0.000 | +0.000 | +0.000 | 0.8562 |
| cognitive_load | +0.016 | +0.000 | +0.000 | 0.9709 |
| spec_match | +0.000 | +0.000 | +0.000 | nan |

## Sign split — does a fix *reduce* exposure?

| class | Δ<0 (reduced) | Δ>0 (raised) | Δ=0 |
|---|---|---|---|
| security-fix | 18 (36%) | 28 (56%) | 4 |
| control | 15 (33%) | 20 (43%) | 11 |
| introduced | 22 (49%) | 20 (44%) | 3 |

The first pilot sample predicted this split: guard code added by a fix reads as complexity (dead_code, cognitive_load), so a security fix RAISING structural exposure is not a scan error — whether the *distribution* differs from controls is what H1 asks.

## Severity gradient (security fixes)

| severity | n | median Δ | p25 | p75 |
|---|---|---|---|---|
| Medium | 16 | +0.082 | +0.000 | +1.555 |
| Low | 34 | +0.009 | -0.083 | +0.162 |

## Top movers (security fixes, event mean Δ)

| direction | CVE | Δ | files touched |
|---|---|---|---|
| ↓ largest drop | CURL-CVE-2025-13034 | -1.594 | 1 |
| ↓ largest drop | CURL-CVE-2026-11564 | -1.038 | 3 |
| ↓ largest drop | CURL-CVE-2026-9080 | -0.874 | 1 |
| ↓ largest drop | CURL-CVE-2026-8926 | -0.792 | 4 |
| ↓ largest drop | CURL-CVE-2026-6253 | -0.514 | 3 |
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
| `lib/easy.c` | 8 |

## Are the outliers where security events happen?

Each implicated file's **structural-exposure percentile within its parent snapshot** (all files ranked, before the event was known). Random targeting reads ~50; if GitGalaxy's high-exposure files are where CVEs live, security classes read high — a rung-7 preview from rung-6 data.

| class | files | median pre-event percentile | p25 | p75 |
|---|---|---|---|---|
| security-fix | 147 | 87.5 | 50.7 | 92.2 |
| introduced | 357 | 80.3 | 43.3 | 91.6 |
| control | 137 | 86.1 | 48.6 | 92.2 |

fix-files sit above control-files with one-sided MW p = 0.1647 (controls < fixes).

## First look over time (event-sampled snapshots, 5-year eras)

Repo-mean structural exposure and implicated-file percentiles per era. **Caveats before believing a trend**: sampling is event-biased (snapshots exist where CVEs were fixed/introduced), the codebase grows (absolute scores drift with file size — percentiles are the robust reading), and deleted files leave the panel (survivorship). The phase-W walk replaces this with a uniform panel.

| era | snapshots | repo files (median) | repo-mean structural exposure (median) | implicated-file percentile (median) |
|---|---|---|---|---|
| 2000–2004 | 3 | 165 | 220.68 | 22.0 |
| 2005–2009 | 2 | 341 | 237.20 | 72.0 |
| 2010–2014 | 4 | 581 | 273.88 | 49.4 |
| 2015–2019 | 7 | 620 | 269.69 | 79.1 |
| 2020–2024 | 20 | 909 | 272.89 | 84.9 |
| 2025–2029 | 105 | 1067 | 279.05 | 86.8 |

## Instrument controls

- **Untouched-file spillover** (files the commit did not touch; expected ~0, graph ripple via api_exposure is the legitimate exception): n = 137855, median |Δ| = 0.000000, p99 = 0.0000, max = 29.7754.
- **LOC coupling** on touched files (is Δ just size change?): Spearman ρ = -0.130 over 284 files. The length-leak lesson says watch this; a high ρ routes to the score-contract program, not to a corpus tweak.
- **Temporal ablation**: asserted exactly 0.0 across every delta in this run.

---
*Regenerate: `python tools/delta_report.py --events events/curl.json` — reads only the events file and the history DB; every number above is a pure function of those two artifacts.*
