# Exposure history report — curl

Generated 2026-09-12 09:51 · engine scans temporally ablated (asserted: max |temporal Δ| = 0.0) · DB `curl_galaxy_master.db` · events pinned to pool HEAD `04bfe8fbbf55` · **PRELIMINARY — batch incomplete**

## Coverage

| class | analyzed | pending/skipped | of harvested |
|---|---|---|---|
| security-fix | 91 | 93 | 186 |
| control | 46 | 135 | 185 |
| introduced | 68 | 62 | 137 |

## Pre-registered hypotheses (gitgalaxy#2982; unit = event, mean structural Δ over its touched files)

| test | n | median Δ | vs | n | median Δ | p (one-sided MW) | verdict at α=0.01 |
|---|---|---|---|---|---|---|---|
| **H1** fixes < controls | 91 | +0.002 | controls | 46 | +0.000 | 0.3575 | not supported |
| **H2** introduced > controls | 68 | +0.001 | controls | 46 | +0.000 | 0.4265 | not supported |

Per-file pooled secondary (pseudo-replicated, labeled as such): H1 p = 0.0699 over 248 fix-file vs 137 control-file deltas; H2 p = 0.9861.

## H3 — which vectors carry it (event-level medians)

| vector | fixes | controls | introduced | H1 p |
|---|---|---|---|---|
| tech_debt | -0.003 | +0.000 | -0.003 | 0.0122 |
| safety_score | -0.002 | +0.000 | +0.000 | 0.0254 |
| api_exposure | -0.000 | +0.000 | -0.001 | 0.0798 |
| dead_code | +0.000 | +0.000 | -0.001 | 0.1191 |
| state_flux | +0.000 | +0.000 | +0.000 | 0.2516 |
| verification | +0.000 | +0.000 | +0.000 | 0.2924 |
| concurrency | +0.000 | +0.000 | +0.000 | 0.3987 |
| documentation | +0.000 | +0.000 | +0.000 | 0.5095 |
| secrets_risk | +0.000 | +0.000 | +0.000 | 0.7908 |
| cognitive_load | +0.008 | +0.000 | +0.000 | 0.9432 |
| spec_match | +0.000 | +0.000 | +0.000 | nan |

## Sign split — does a fix *reduce* exposure?

| class | Δ<0 (reduced) | Δ>0 (raised) | Δ=0 |
|---|---|---|---|
| security-fix | 36 (40%) | 48 (53%) | 7 |
| control | 15 (33%) | 20 (43%) | 11 |
| introduced | 27 (40%) | 34 (50%) | 7 |

The first pilot sample predicted this split: guard code added by a fix reads as complexity (dead_code, cognitive_load), so a security fix RAISING structural exposure is not a scan error — whether the *distribution* differs from controls is what H1 asks.

## Severity gradient (security fixes)

| severity | n | median Δ | p25 | p75 |
|---|---|---|---|---|
| High | 1 | -0.102 | -0.102 | -0.102 |
| Medium | 32 | +0.010 | +0.000 | +0.297 |
| Low | 58 | +0.000 | -0.137 | +0.161 |

## Top movers (security fixes, event mean Δ)

| direction | CVE | Δ | files touched |
|---|---|---|---|
| ↓ largest drop | CURL-CVE-2023-28321 | -25.978 | 3 |
| ↓ largest drop | CURL-CVE-2023-46219 | -12.882 | 1 |
| ↓ largest drop | CURL-CVE-2025-0725 | -4.300 | 1 |
| ↓ largest drop | CURL-CVE-2025-13034 | -1.594 | 1 |
| ↓ largest drop | CURL-CVE-2026-11564 | -1.038 | 3 |
| ↑ largest rise | CURL-CVE-2026-11586 | +47.112 | 2 |
| ↑ largest rise | CURL-CVE-2026-5545 | +16.400 | 1 |
| ↑ largest rise | CURL-CVE-2026-11856 | +14.130 | 5 |
| ↑ largest rise | CURL-CVE-2026-8925 | +7.079 | 1 |
| ↑ largest rise | CURL-CVE-2024-2379 | +5.583 | 1 |

## CVE hotspot files (appearances across fix+introduced events)

| file | events |
|---|---|
| `lib/url.c` | 41 |
| `lib/urldata.h` | 41 |
| `lib/setopt.c` | 21 |
| `include/curl/curl.h` | 18 |
| `lib/http.c` | 18 |
| `lib/vtls/openssl.c` | 17 |
| `lib/cookie.c` | 13 |
| `configure.ac` | 13 |
| `lib/Makefile.inc` | 13 |
| `tests/data/Makefile.inc` | 11 |

## Are the outliers where security events happen?

Each implicated file's **structural-exposure percentile within its parent snapshot** (all files ranked, before the event was known). Random targeting reads ~50; if GitGalaxy's high-exposure files are where CVEs live, security classes read high — a rung-7 preview from rung-6 data.

| class | files | median pre-event percentile | p25 | p75 |
|---|---|---|---|---|
| security-fix | 248 | 87.6 | 50.5 | 93.2 |
| introduced | 496 | 80.2 | 40.2 | 91.8 |
| control | 137 | 86.1 | 48.6 | 92.2 |

fix-files sit above control-files with one-sided MW p = 0.0998 (controls < fixes).

## CWE × vector — which exposure vector flags which weakness type?

Median **pre-event per-vector percentile** of implicated files (each file ranked per vector among all files in its parent snapshot). Reading guide: a high cell means files that later carried this weakness class already stood out on that vector before the event. Control-file rows give the baseline 'changed files look like this anyway' profile.

| class (events) | cognitive_load | safety_score | state_flux | api_exposure | verification | tech_debt | documentation | concurrency |
|---|---|---|---|---|---|---|---|---|
| other (58) | 83 | 73 | 83 | 54 | 83 | 77 | 54 | 0 |
| cert/auth (41) | 84 | 68 | 80 | 49 | 83 | 76 | 54 | 0 |
| info-leak (30) | 90 | 80 | 84 | 51 | 83 | 77 | 55 | 0 |
| memory (30) | 83 | 70 | 83 | 59 | 83 | 77 | 51 | 0 |
| control baseline (46) | 86 | 71 | 83 | 53 | 84 | 77 | 57 | 0 |

**Fix-delta by weakness family** (median event Δ, security fixes only): 
other +0.002 (n=34) · cert/auth +0.000 (n=23) · info-leak +0.010 (n=19) · memory +0.001 (n=15)

## First look over time (event-sampled snapshots, 5-year eras)

Repo-mean structural exposure and implicated-file percentiles per era. **Caveats before believing a trend**: sampling is event-biased (snapshots exist where CVEs were fixed/introduced), the codebase grows (absolute scores drift with file size — percentiles are the robust reading), and deleted files leave the panel (survivorship). The phase-W walk replaces this with a uniform panel.

| era | snapshots | repo files (median) | repo-mean structural exposure (median) | implicated-file percentile (median) |
|---|---|---|---|---|
| 2000–2004 | 5 | 165 | 198.55 | 27.8 |
| 2005–2009 | 7 | 215 | 229.93 | 44.6 |
| 2010–2014 | 5 | 575 | 273.48 | 51.2 |
| 2015–2019 | 8 | 620 | 269.89 | 82.2 |
| 2020–2024 | 72 | 899 | 273.16 | 86.1 |
| 2025–2029 | 108 | 1066 | 279.05 | 86.6 |

## Commit anatomy — what fixes and introductions physically are

| class | n | commits touching any TODO/FIXME/HACK | net markers | median net LOC | net-growing |
|---|---|---|---|---|---|
| security-fix | 91 | 0 | +0 | +8 | 70/91 (77%) |
| control | 46 | 0 | +0 | +4 | 31/46 (67%) |
| introduced | 68 | 12 | +10 | +92 | 59/68 (87%) |

**The tech_debt autopsy**: the H3 tech_debt drop in fixes coexists with fixes almost never touching a debt marker — the drop is the DENSITY DENOMINATOR (same markers over more lines; fixes net-add code). A formula artifact in the #2655/#2979 shape, caught by this table. The introduced side is real: vulnerability-introducing commits are large feature additions that carry new debt markers with them.

## Dwell time — how long vulnerabilities lurk

Introduced → fixed, n = 137 CVEs with both commits: median **4.5 years** (p25 1.3y, p75 11.4y, max 25.2y). The strategic number for rung 7: a predictive instrument has a years-long window in which flagging the file would have mattered.

## Security-system signals on implicated files

- **Credential shunt** (`has_credentials` / `risk_secrets_risk=100`): fires on 5679 file-rows across history — test keys and CA tooling (e.g. `mk-ca-bundle.pl`, `data-httpsig-ed25519.key`, `data-httpsig-hmac-sha256.key`, `schannel_verify.c`) — but on **3 of 290 CVE/control-implicated files**. The secrets surface and the vulnerability surface are orthogonal in curl: CVEs live in protocol code, credentials in test fixtures.
- **ML threat layer** (`ai_threat_score`, `is_malware`, `binary_anomaly`, `obfuscation_flag`): all zero in these scans — the scan environment lacks the ML dependencies (the engine's known security_auditor ML-deps gap), so this layer is UNEXERCISED here, not exonerated. A full-deps rerun is the test.
- **Granular lens counts** (`sec_tainted_injection`, `sec_db_hooks`, …) are not persisted to the scan DB (audit-JSON only) — adding them to `file_data` (or capturing audit JSONs in the harness) is the enabling change for a per-CVE injection-surface analysis. Filed as future work in the epic.

## Instrument controls

- **Untouched-file spillover** (files the commit did not touch; expected ~0, graph ripple via api_exposure is the legitimate exception): n = 190214, median |Δ| = 0.000000, p99 = 0.0000, max = 29.7754.
- **LOC coupling** on touched files (is Δ just size change?): Spearman ρ = -0.192 over 385 files. The length-leak lesson says watch this; a high ρ routes to the score-contract program, not to a corpus tweak.
- **Temporal ablation**: asserted exactly 0.0 across every delta in this run.

---
*Regenerate: `python tools/delta_report.py --events events/curl.json` — reads only the events file and the history DB; every number above is a pure function of those two artifacts.*
