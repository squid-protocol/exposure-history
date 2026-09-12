# Exposure history report — curl

Generated 2026-09-12 11:29 · engine scans temporally ablated (asserted: max |temporal Δ| = 0.0) · DB `curl_galaxy_master.db` · events pinned to pool HEAD `04bfe8fbbf55` · **PRELIMINARY — batch incomplete**

## Coverage

| class | analyzed | pending/skipped | of harvested |
|---|---|---|---|
| security-fix | 182 | 0 | 186 |
| control | 168 | 0 | 185 |
| introduced | 118 | 1 | 137 |

## Pre-registered hypotheses (gitgalaxy#2982; unit = event, mean structural Δ over its touched files)

| test | n | median Δ | vs | n | median Δ | p (one-sided MW) | verdict at α=0.01 |
|---|---|---|---|---|---|---|---|
| **H1** fixes < controls | 182 | +0.000 | controls | 168 | +0.000 | 0.7732 | not supported |
| **H2** introduced > controls | 118 | +0.007 | controls | 168 | +0.000 | 0.0227 | not supported |

Per-file pooled secondary (pseudo-replicated, labeled as such): H1 p = 0.2466 over 460 fix-file vs 415 control-file deltas; H2 p = 0.9528.

## H3 — which vectors carry it (event-level medians)

| vector | fixes | controls | introduced | H1 p |
|---|---|---|---|---|
| tech_debt | -0.003 | +0.000 | -0.003 | 0.0011 |
| safety_score | -0.002 | +0.000 | +0.000 | 0.0072 |
| dead_code | -0.001 | +0.000 | -0.002 | 0.0986 |
| state_flux | +0.000 | +0.000 | +0.000 | 0.1132 |
| spec_match | +0.000 | +0.000 | +0.000 | 0.1503 |
| api_exposure | -0.000 | +0.000 | +0.000 | 0.2717 |
| concurrency | +0.000 | +0.000 | +0.000 | 0.5114 |
| verification | +0.000 | +0.000 | +0.000 | 0.5821 |
| secrets_risk | +0.000 | +0.000 | +0.000 | 0.8033 |
| documentation | +0.000 | +0.000 | +0.000 | 0.8307 |
| cognitive_load | +0.006 | +0.000 | +0.000 | 0.9898 |

## Sign split — does a fix *reduce* exposure?

| class | Δ<0 (reduced) | Δ>0 (raised) | Δ=0 |
|---|---|---|---|
| security-fix | 76 (42%) | 87 (48%) | 19 |
| control | 72 (43%) | 62 (37%) | 34 |
| introduced | 45 (38%) | 61 (52%) | 12 |

The first pilot sample predicted this split: guard code added by a fix reads as complexity (dead_code, cognitive_load), so a security fix RAISING structural exposure is not a scan error — whether the *distribution* differs from controls is what H1 asks.

## Severity gradient (security fixes)

| severity | n | median Δ | p25 | p75 |
|---|---|---|---|---|
| Critical | 1 | -87.497 | -87.497 | -87.497 |
| High | 27 | +0.000 | -0.095 | +0.140 |
| Medium | 79 | +0.003 | -0.012 | +0.148 |
| Low | 75 | +0.000 | -0.148 | +0.074 |

## Top movers (security fixes, event mean Δ)

| direction | CVE | Δ | files touched |
|---|---|---|---|
| ↓ largest drop | CURL-CVE-2013-0249 | -87.497 | 1 |
| ↓ largest drop | CURL-CVE-2023-28321 | -25.978 | 3 |
| ↓ largest drop | CURL-CVE-2023-46219 | -12.882 | 1 |
| ↓ largest drop | CURL-CVE-2016-8615 | -11.574 | 1 |
| ↓ largest drop | CURL-CVE-2025-0725 | -4.300 | 1 |
| ↑ largest rise | CURL-CVE-2026-11586 | +47.112 | 2 |
| ↑ largest rise | CURL-CVE-2026-5545 | +16.400 | 1 |
| ↑ largest rise | CURL-CVE-2026-11856 | +14.130 | 5 |
| ↑ largest rise | CURL-CVE-2026-8925 | +7.079 | 1 |
| ↑ largest rise | CURL-CVE-2016-5419 | +6.097 | 3 |

## CVE hotspot files (appearances across fix+introduced events)

| file | events |
|---|---|
| `lib/url.c` | 74 |
| `lib/urldata.h` | 62 |
| `lib/http.c` | 32 |
| `include/curl/curl.h` | 30 |
| `lib/vtls/openssl.c` | 28 |
| `tests/data/Makefile.inc` | 27 |
| `lib/setopt.c` | 24 |
| `lib/Makefile.inc` | 23 |
| `lib/cookie.c` | 22 |
| `configure.ac` | 22 |

## Are the outliers where security events happen?

Each implicated file's **structural-exposure percentile within its parent snapshot** (all files ranked, before the event was known). Random targeting reads ~50; if GitGalaxy's high-exposure files are where CVEs live, security classes read high — a rung-7 preview from rung-6 data.

| class | files | median pre-event percentile | p25 | p75 |
|---|---|---|---|---|
| security-fix | 460 | 86.2 | 51.8 | 92.2 |
| introduced | 816 | 83.9 | 42.3 | 92.0 |
| control | 415 | 86.5 | 48.8 | 92.5 |

fix-files sit above control-files with one-sided MW p = 0.5675 (controls < fixes).

## CWE × vector — which exposure vector flags which weakness type?

Median **pre-event per-vector percentile** of implicated files (each file ranked per vector among all files in its parent snapshot). Reading guide: a high cell means files that later carried this weakness class already stood out on that vector before the event. Control-file rows give the baseline 'changed files look like this anyway' profile.

| class (events) | cognitive_load | safety_score | state_flux | api_exposure | verification | tech_debt | documentation | concurrency |
|---|---|---|---|---|---|---|---|---|
| memory (97) | 84 | 73 | 82 | 49 | 82 | 76 | 51 | 0 |
| other (94) | 85 | 75 | 82 | 51 | 82 | 76 | 53 | 0 |
| cert/auth (60) | 85 | 69 | 80 | 48 | 82 | 76 | 54 | 0 |
| info-leak (49) | 87 | 80 | 83 | 49 | 82 | 76 | 54 | 0 |
| control baseline (168) | 87 | 72 | 83 | 50 | 83 | 77 | 54 | 0 |

**Fix-delta by weakness family** (median event Δ, security fixes only): 
other +0.000 (n=58) · memory +0.001 (n=56) · cert/auth +0.000 (n=35) · info-leak +0.000 (n=33)

## First look over time (event-sampled snapshots, 5-year eras)

Repo-mean structural exposure and implicated-file percentiles per era. **Caveats before believing a trend**: sampling is event-biased (snapshots exist where CVEs were fixed/introduced), the codebase grows (absolute scores drift with file size — percentiles are the robust reading), and deleted files leave the panel (survivorship). The phase-W walk replaces this with a uniform panel.

| era | snapshots | repo files (median) | repo-mean structural exposure (median) | implicated-file percentile (median) |
|---|---|---|---|---|
| 2000–2004 | 8 | 76 | 216.44 | 25.3 |
| 2005–2009 | 16 | 222 | 230.02 | 38.3 |
| 2010–2014 | 50 | 574 | 273.45 | 80.1 |
| 2015–2019 | 115 | 681 | 270.80 | 86.1 |
| 2020–2024 | 170 | 842 | 271.19 | 85.8 |
| 2025–2029 | 109 | 1066 | 279.05 | 86.6 |

## Commit anatomy — what fixes and introductions physically are

| class | n | commits touching any TODO/FIXME/HACK | net markers | median net LOC | net-growing |
|---|---|---|---|---|---|
| security-fix | 182 | 1 | -1 | +6 | 140/182 (77%) |
| control | 168 | 2 | +2 | +3 | 110/168 (65%) |
| introduced | 118 | 22 | +86 | +98 | 101/118 (86%) |

**The tech_debt autopsy**: the H3 tech_debt drop in fixes coexists with fixes almost never touching a debt marker — the drop is the DENSITY DENOMINATOR (same markers over more lines; fixes net-add code). A formula artifact in the #2655/#2979 shape, caught by this table. The introduced side is real: vulnerability-introducing commits are large feature additions that carry new debt markers with them.

## Dwell time — how long vulnerabilities lurk

Introduced → fixed, n = 137 CVEs with both commits: median **4.5 years** (p25 1.3y, p75 11.4y, max 25.2y). The strategic number for rung 7: a predictive instrument has a years-long window in which flagging the file would have mattered.

## Security-system signals on implicated files

- **Credential shunt** (`has_credentials` / `risk_secrets_risk=100`): fires on 16406 file-rows across history — test keys and CA tooling (e.g. `mk-ca-bundle.pl`, `data-httpsig-ed25519.key`, `data-httpsig-hmac-sha256.key`, `schannel_verify.c`) — but on **6 of 392 CVE/control-implicated files**. The secrets surface and the vulnerability surface are orthogonal in curl: CVEs live in protocol code, credentials in test fixtures.
- **ML threat layer** (`ai_threat_score`, `is_malware`, `binary_anomaly`, `obfuscation_flag`): all zero in these scans — the scan environment lacks the ML dependencies (the engine's known security_auditor ML-deps gap), so this layer is UNEXERCISED here, not exonerated. A full-deps rerun is the test.
- **Granular lens counts** (`sec_tainted_injection`, `sec_db_hooks`, …) are not persisted to the scan DB (audit-JSON only) — adding them to `file_data` (or capturing audit JSONs in the harness) is the enabling change for a per-CVE injection-surface analysis. Filed as future work in the epic.

## Instrument controls

- **Untouched-file spillover** (files the commit did not touch; expected ~0, graph ripple via api_exposure is the legitimate exception): n = 375265, median |Δ| = 0.000000, p99 = 0.0000, max = 29.7754.
- **LOC coupling** on touched files (is Δ just size change?): Spearman ρ = -0.187 over 875 files. The length-leak lesson says watch this; a high ρ routes to the score-contract program, not to a corpus tweak.
- **Temporal ablation**: asserted exactly 0.0 across every delta in this run.

---
*Regenerate: `python tools/delta_report.py --events events/curl.json` — reads only the events file and the history DB; every number above is a pure function of those two artifacts.*
