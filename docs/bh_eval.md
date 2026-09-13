# B-H1..B-H3 — bug-label expansion (power for the small-file bands)

Generated 2026-09-13 08:04 · repo `curl` · pool HEAD `04bfe8fbbf55` · DB `curl_galaxy_master.db` (opened read-only, WAL-aware) · pre-registered gitgalaxy#2982 comment 5651082895; implemented verbatim; verdicts publish either way. **Do not commit** per operator instruction; this doc is a local artifact of an unattended run.

## Leakage-free design

Centrality columns and `total_loc` are read from the existing scan DB at each event's **parent** commit (T0) — no rescan. HCM1_LD_30 is computed fresh from the pool clone via `git log <parent> --since=<parent_date-365d> -n 4000 --no-merges`, ancestors of parent ONLY (`hcm_variants.raw_commit_walk`, called directly, not reimplemented) — no information from the fix commit or anything after it can enter any feature. Walk cache (`/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad/hcmwalk_cache`) is the SAME directory `hcm_variants.py` uses, reused verbatim per the pre-registration.

Coverage: **957** events usable (of **1107** class-matching in the event set); skipped — {'no touched file present in parent snapshot': 150}. Pooled candidate files: **767591**, pooled positives: **1900**. Event-file class counts in `curl_bugs.json`: {'regression': 307, 'bugfix-fixes': 500, 'bugfix-bug': 300}. HCM walk wall-time: 496.6s (cached per parent sha, shared with hcm_variants.py's own cache).

Band sizes (absolute NLOC scheme): `<=22` n=29511 n_pos=28 (powered), `23-48` n=110612 n_pos=42 (powered), `49-108` n=228013 n_pos=117 (powered), `>108` n=399455 n_pos=1713 (powered). Powered small bands: 2/2 -> B-H1 Bonferroni alpha = 0.01/(5 x 2) = 0.001000.

**Parallel execution**: fork pool, 10 workers. B-H1's 20 (measure,band) cells each ran their own full serial bootstrap in one worker, seeded `base_seed + feat_idx*4 + band` (distinct per cell). B-H2/B-H3 each split `--iters` into 10 chunks (sizes [500, 500, 500, 500, 500, 500, 500, 500, 500, 500]), seeded `base_seed + 1000*chunk_id`, concatenated in the parent before computing percentiles/the monotonicity fraction.

## B-H1 — powered small-file centrality test

Per measure x band: AUC(measure), AUC(total_loc), lift, one-sided event-bootstrap (5000 iters) lower bound on the lift. Bonferroni family = 5 measures x powered SMALL bands only (<=22, 23-48) — large bands shown for context, not part of the family or the verdict.

### `pagerank_score` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | powered | verdict |
|---|---|---|---|---|---|---|---|---|---|
| <=22 | 29511 | 28 | 0.2588 | 0.3062 | -0.0474 | -0.0853 | [-0.0700, 0.0283] | yes | not supported |
| 23-48 | 110612 | 42 | 0.6044 | 0.5871 | 0.0173 | -0.1506 | [-0.0911, 0.1288] | yes | not supported |
| 49-108 (context) | 228013 | 117 | 0.6407 | 0.4961 | 0.1446 | 0.0195 | [0.0676, 0.2186] | yes | **SUPPORTED** |
| >108 (context) | 399455 | 1713 | 0.5450 | 0.7982 | -0.2532 | -0.2908 | [-0.2781, -0.2281] | yes | not supported |

### `betweenness_score` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | powered | verdict |
|---|---|---|---|---|---|---|---|---|---|
| <=22 | 29511 | 28 | 0.5000 | 0.3062 | 0.1938 | -0.2629 | [-0.2568, 0.2143] | yes | not supported |
| 23-48 | 110612 | 42 | 0.4821 | 0.5871 | -0.1050 | -0.2313 | [-0.1855, -0.0186] | yes | not supported |
| 49-108 (context) | 228013 | 117 | 0.5382 | 0.4961 | 0.0421 | -0.0478 | [-0.0154, 0.1040] | yes | not supported |
| >108 (context) | 399455 | 1713 | 0.5153 | 0.7982 | -0.2829 | -0.3039 | [-0.2962, -0.2701] | yes | not supported |

### `popularity` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | powered | verdict |
|---|---|---|---|---|---|---|---|---|---|
| <=22 | 29511 | 28 | 0.5030 | 0.3062 | 0.1968 | -0.2761 | [-0.2717, 0.2179] | yes | not supported |
| 23-48 | 110612 | 42 | 0.4010 | 0.5871 | -0.1861 | -0.3916 | [-0.3188, -0.0415] | yes | not supported |
| 49-108 (context) | 228013 | 117 | 0.6285 | 0.4961 | 0.1324 | 0.0250 | [0.0655, 0.1974] | yes | **SUPPORTED** |
| >108 (context) | 399455 | 1713 | 0.4955 | 0.7982 | -0.3027 | -0.3265 | [-0.3179, -0.2889] | yes | not supported |

### `import_count` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | powered | verdict |
|---|---|---|---|---|---|---|---|---|---|
| <=22 | 29511 | 28 | 0.4835 | 0.3062 | 0.1773 | -0.2783 | [-0.2732, 0.1978] | yes | not supported |
| 23-48 | 110612 | 42 | 0.4081 | 0.5871 | -0.1790 | -0.3761 | [-0.3097, -0.0566] | yes | not supported |
| 49-108 (context) | 228013 | 117 | 0.4179 | 0.4961 | -0.0783 | -0.1923 | [-0.1517, 0.0011] | yes | not supported |
| >108 (context) | 399455 | 1713 | 0.7250 | 0.7982 | -0.0731 | -0.1010 | [-0.0905, -0.0551] | yes | not supported |

### `internal_dependency_links` vs `total_loc`

| band | n | n pos | AUC(measure) | AUC(total_loc) | lift | boot lower bound | 95% CI (lift) | powered | verdict |
|---|---|---|---|---|---|---|---|---|---|
| <=22 | 29511 | 28 | 0.4998 | 0.3062 | 0.1937 | -0.2624 | [-0.2569, 0.2143] | yes | not supported |
| 23-48 | 110612 | 42 | 0.4433 | 0.5871 | -0.1438 | -0.3239 | [-0.2668, -0.0218] | yes | not supported |
| 49-108 (context) | 228013 | 117 | 0.4328 | 0.4961 | -0.0634 | -0.1781 | [-0.1349, 0.0104] | yes | not supported |
| >108 (context) | 399455 | 1713 | 0.7256 | 0.7982 | -0.0725 | -0.1031 | [-0.0925, -0.0535] | yes | not supported |

**B-H1 per-small-band status:** `<=22`=not supported, `23-48`=not supported

**B-H1: not supported.** SUPPORTED iff >=1 measure clears AUC>0.5 and lift lower bound>0 in EACH powered small band.

## B-H2 — the monotone shape (confirmatory)

PageRank only, all 4 absolute bands, ONE joint bootstrap (5000 iters) — each resample draws one shared set of resampled events and computes all 4 bands' lifts from it, so the ordering claim is evaluated on correlated draws, not 4 independent per-band bounds. SUPPORTED iff lift band0>band1>band2>band3 holds in >=99% of resamples.

| band | observed lift (PageRank − total_loc) |
|---|---|
| `<=22` | -0.0474 |
| `23-48` | 0.0173 |
| `49-108` | 0.1446 |
| `>108` | -0.2532 |

**Fraction of 4314/5000 valid resamples with strict monotone decrease: 0.0000** (threshold >=0.99). **B-H2: not supported.**

## B-H3 — HCM1_LD_30 out-of-selection validation

Pooled over all 767591 candidate files across all 957 parent snapshots (n_pos=1900), no banding. One-sided event-bootstrap (5000 iters, alpha=0.01, single comparison, no Bonferroni).

| n | n pos | AUC(HCM1_LD_30) | AUC(total_loc) | lift | boot lower bound (α) | 95% CI | verdict |
|---|---|---|---|---|---|---|---|
| 767591 | 1900 | 0.8683 | 0.8303 | 0.0379 | 0.0211 | [0.0230, 0.0564] | **SUPPORTED** |

**B-H3: **SUPPORTED**.**

## Design notes / ambiguity resolutions

- **B-H1's Bonferroni family is scoped to the 2 small bands only** (5 measures x n_powered_small_bands), per the pre-registration's literal text — unlike `centrality_bands.py`'s C-H1, which scopes its family to all 4 bands as a stated ambiguity resolution; no such ambiguity exists here.
- **The two large bands are reported at the same small-band alpha**, for at-a-glance comparability and because B-H2 reuses their point estimates — they carry no verdict of their own and are excluded from B-H1's SUPPORTED determination.
- **B-H1's SUPPORTED rule reads as AND-across-bands, OR-across-measures**: each powered small band needs its OWN qualifying measure — both powered bands must clear it independently for the overall claim.
- **B-H2 uses ONE shared resampled-event draw per iteration across all 4 bands** — a joint bootstrap, deliberately NOT four independent per-band streams (B-H1's design): the claim is about simultaneous ordering within one resample.
- **Multiprocessing seeding is fixed but NOT a serial-stream-equivalence claim.** B-H1 cells use `base_seed + feat_idx*4 + band`; B-H2/B-H3 chunk seeds use `base_seed + 1000*chunk_id`. Both are deterministic and rerunnable, but a serial single-process run at the same `--seed` will NOT reproduce bit-identical draws — what the pre-registration's seed=2982 buys here is reproducibility of THIS (parallel) procedure, not cross-procedure identity.
- **The numpy AUC engine (`auc_numpy`) replaces `rw_analyses.pooled_auc`** (pure-Python, does not finish at ~2.5M pooled rows) with an identical-formula, vectorized reimplementation — verified against the original on 20 randomized tie-heavy trials (exact match) before this file was written.
- **HCM1_LD_30 is never reimplemented** — `hcm_variants.raw_commit_walk` and `compute_all_variants` are called directly and the `HCM1_LD_30` key is read out, so this test is byte-for-byte frozen to its CVE-label definition by construction.

---
*Regenerate: `python tools/bh_eval.py --events events/curl_bugs.json` — stdlib+numpy only; HCM walks cached under `/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad/hcmwalk_cache` (shared with hcm_variants.py) keyed by parent sha; bootstrap cells checkpointed to `/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad/bh_eval_cache_curl_bugs_i5000_s2982.json`. Bootstrap compute time this run: 3589.6s wall-clock summed across workers (cells loaded from cache report 0s).*

## Assumption audit (2026-09-13, post-hoc — recorded for honest reading of the above)

- **Label purity:** a 12-commit sample of `bugfix-fixes` found ~half are not code-bug fixes
  (man-page edits, CMake fixes, deprecations, test infra). The pooled positive class is
  "changes maintainers linked to issues," not "bugs."
- **Bystander positives:** ~31% of fix-touched files are under `tests/`/`docs/` (sampled
  194 files across 80 events) — positives are not all product code.
- **HCM vs churn (the churn-proxy trap):** rank-corr(HCM, churn) = **0.853** — heavily
  entangled. But HCM beats churn pooled (0.868 vs 0.848) and adds discrimination within
  churn bands Q2 (0.70 vs LOC 0.46) and Q4 (0.80 vs 0.76), while being dead in Q1 (files
  with no recent history have no periods to accumulate entropy). Honest restatement of
  B-H3: **change entropy is a refinement of churn** — "was the change chaotic?" on top of
  "did it change?" — better than both trivial baselines, not an independent axis.
  (Exploratory checks, no bootstrap bounds.)
