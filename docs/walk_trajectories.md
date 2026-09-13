# Keyword-trajectory panel analysis — curl, 219-release walk

**EXPLORATORY.** tc#3 + the 2026-09-13 scope-expansion comment ("make keywords temporal"). No p-values anywhere below; every table is descriptive. Suggestive patterns are repo-#3 (openssl) pre-registration candidates, not findings.

Panel: 219 releases, 2000-03-14 -> 2026-09-02. Coverage (files x releases): 1297 distinct C file_paths ever observed, 82467 (file,release) cells, 925 files with a contiguous run >= 16 releases (**that's the real panel** for the trajectory features below) out of 1054 with any run >= 8. Only 3 file_paths persist from the 2000 snapshot to the 2026 snapshot unbroken — path identity is not stable across curl's 26-year layout churn (39 -> 1,144 files), so trajectories are scored per contiguous run only, never stitched across a gap.

**The alloc/cleanup cliff**: between curl-8_17_0 (2025-11-05) and curl-8_18_0 (release idx 214), summed state_memory_alloc across all C files drops ~86% and def_cleanup ~83% in ONE release step while total_loc keeps growing and every other keyword column stays continuous — real curl history shows a wide allocator-wrapping refactor in that window (many "use curlx allocator instead of malloc/free" commits): a real code change that reads as a vocabulary cliff to literal malloc/free-family keyword matching, not an engine bug. All alloc/cleanup-derived features (alloc_slope_8, pairing_ratio_t, pairing_ratio_drift_8, the post-fix alloc column, the survival sketch) are **truncated at release idx 213 (curl-8_17_0)** and NaN beyond it — reported, not papered over.

Runtime: 16.8s. Fix-class events loaded: 1293 (security-fix/bugfix-fixes/bugfix-bug/regression only — wave1 revert/cve-followup excluded by definition); matched to a panel file + release: 1003.

## 1-2. Trajectory features vs. total_loc / churn-proxy baselines (outcome: touched by a fix-class event in (t, t+4])

Row population is identical across every feature in this table (an 8-release contiguous lookback is required to compute ANY of them, applied uniformly) so the AUC comparison is apples-to-apples. Pooled AUC = rank-based (Mann-Whitney), descriptive only.

### Pooled (all eras)

| feature | n | n_pos | AUC |
|---|---|---|---|
| total_loc_t (baseline: total_loc at t) | 71442 | 2449 | 0.913 |
| churn_proxy_8 (baseline: # releases file changed in last 8 (LOC-delta count)) | 71442 | 2449 | 0.865 |
| danger_slope_8 (trajectory: slope of state_danger over last 8 releases) | 71442 | 2449 | 0.499 |
| alloc_slope_8 (trajectory: slope of state_memory_alloc over last 8 releases (gated at the alloc/cleanup cliff)) | 70765 | 2407 | 0.520 |
| pairing_ratio_t (trajectory: cum. alloc-growth / cum. cleanup-growth since run start (gated)) | 70765 | 2407 | 0.770 |
| pairing_ratio_drift_8 (trajectory: pairing ratio drift over last 8 releases (gated)) | 69777 | 2381 | 0.498 |
| keyword_volatility_8 (trajectory: std of deltas, pointers+branch+danger+cast composite) | 71442 | 2449 | 0.860 |
| pagerank_t (bonus: pagerank_score at t) | 71442 | 2449 | 0.400 |

### Pre-2015

| feature | n | n_pos | AUC |
|---|---|---|---|
| total_loc_t (baseline: total_loc at t) | 13675 | 355 | 0.931 |
| churn_proxy_8 (baseline: # releases file changed in last 8 (LOC-delta count)) | 13675 | 355 | 0.868 |
| danger_slope_8 (trajectory: slope of state_danger over last 8 releases) | 13675 | 355 | 0.501 |
| alloc_slope_8 (trajectory: slope of state_memory_alloc over last 8 releases (gated at the alloc/cleanup cliff)) | 13675 | 355 | 0.509 |
| pairing_ratio_t (trajectory: cum. alloc-growth / cum. cleanup-growth since run start (gated)) | 13675 | 355 | 0.752 |
| pairing_ratio_drift_8 (trajectory: pairing ratio drift over last 8 releases (gated)) | 13122 | 343 | 0.563 |
| keyword_volatility_8 (trajectory: std of deltas, pointers+branch+danger+cast composite) | 13675 | 355 | 0.864 |
| pagerank_t (bonus: pagerank_score at t) | 13675 | 355 | 0.280 |

### Post-2015

| feature | n | n_pos | AUC |
|---|---|---|---|
| total_loc_t (baseline: total_loc at t) | 57767 | 2094 | 0.910 |
| churn_proxy_8 (baseline: # releases file changed in last 8 (LOC-delta count)) | 57767 | 2094 | 0.867 |
| danger_slope_8 (trajectory: slope of state_danger over last 8 releases) | 57767 | 2094 | 0.499 |
| alloc_slope_8 (trajectory: slope of state_memory_alloc over last 8 releases (gated at the alloc/cleanup cliff)) | 57090 | 2052 | 0.523 |
| pairing_ratio_t (trajectory: cum. alloc-growth / cum. cleanup-growth since run start (gated)) | 57090 | 2052 | 0.771 |
| pairing_ratio_drift_8 (trajectory: pairing ratio drift over last 8 releases (gated)) | 56655 | 2038 | 0.488 |
| keyword_volatility_8 (trajectory: std of deltas, pointers+branch+danger+cast composite) | 57767 | 2094 | 0.861 |
| pagerank_t (bonus: pagerank_score at t) | 57767 | 2094 | 0.414 |

**Headline**: no trajectory feature beats both baselines (best baseline AUC 0.913) in the pooled read — consistent with the program's standing wall (everything structural reduces to size).

## 3. Post-fix trajectory shape: recidivists vs. non-recidivists

Files with >=2 matched fix events; per fix event, delta = value at (fix release + 8) minus value at fix release, within the same contiguous run. Recidivist = another fix on the same file within 12 releases. Descriptive only.

| group | n events | median danger delta | % danger rebound (>0) | n (alloc, gated) | median alloc delta | % alloc rebound |
|---|---|---|---|---|---|---|
| recidivist | 540 | 0.000 | 0.185 | 506 | 0.000 | 27.273 |
| non-recidivist | 226 | 0.000 | 0.442 | 223 | 0.000 | 12.556 |

## 4. Survival sketch: releases-until-next-fix by pairing-ratio tercile

Pairing ratio at the fix release (gated at the alloc/cleanup cliff); terciles cut on the pooled fix-event population; gap = releases to the NEXT matched fix event on the same file (None if the file's last fix in-panel, i.e. right-censored). Descriptive only.

Tercile cuts: low <= 0.667 <= mid <= 1.179 <= high.

| tercile | n | n censored | median releases-until-next-fix (uncensored) |
|---|---|---|---|
| low | 302 | 89 | 6.000 |
| mid | 303 | 32 | 3.000 |
| high | 285 | 27 | 4.000 |

---
*Generated by `tools/walk_trajectories.py`. DB `dbs/curl_out/curl_galaxy_master.db` opened read-only, WAL-aware. Panel + event-touch caches under `/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad/walk_cache` (10-worker fork pools for both the per-release DB fetch and the per-event git-diff touched-file harvest). EXPLORATORY throughout — no confirmatory claim is made in this document.*
