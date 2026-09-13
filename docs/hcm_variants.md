# Hassan HCM variant sweep — does ANY entropy formulation beat file size?

Generated 2026-09-12 21:50 · repo `curl` · pool HEAD `04bfe8fbbf55` · DB `curl_galaxy_master.db` (opened read-only, WAL-aware) · pre-registered gitgalaxy#2982 comment 5649866008; implemented verbatim; verdicts publish either way.

## Leakage-free design

`total_loc` and `structural_exposure` are read from the existing scan DB at each security-fix event's **parent** commit (T0) — no rescan. Every HCM variant is computed fresh from the pool clone via `git log <parent> --since=<parent_date-365d> -n 4000 --no-merges --name-only --pretty=format:"@@|%H|%ct"` — starting AT the parent and walking only its ancestors, so no information from the fix commit or anything after it can enter any variant's score. This reuses the exact leakage-free walk shape verified in `tools/incremental_value.py` (IV-H1/IV-H2, gitgalaxy#2982 comment 5649564429); a parallel raw-commit-stream cache (`hcmwalk_cache/`, keyed by parent sha) sits alongside IV's own `procfeat_cache/` — same git command shape, never mixed, because this sweep needs the un-aggregated per-commit (timestamp, file-list) stream to build periods, not IV's pre-summed churn/cochange counters.

Coverage: 182 security-fix events usable (of 186 in the event set); skipped — {'no touched file present in parent snapshot': 4}. Pooled candidate files: **155477**, pooled positives: **460**. Raw-walk wall-time: **53.7s** (cached per parent sha; near-instant on re-run).

## The 36-variant matrix (+ `repowise_flavour` reference)

Per-period entropy `H = -Σ p_i log2(p_i)` over the change-count distribution across files touched in that period, normalised by `log2(n_files_changed)` (periods with n_files_changed<2 contribute nothing). Periods count backward from the parent commit in fixed-length buckets (k=0 = most recent); a period's representative age for decay weighting is its **midpoint** (an ambiguity resolution — a period is a span, not an instant; see Design notes).
- **Attribution**: `HCM1` = p_i·H (share-weighted) · `HCM2` = (1/n)·H (uniform over files changed) · `HCM3` = H (full period entropy, undiluted).
- **Decay**: `none` (w=1) · `ED` exp(-age/180) · `LD` max(0, 1-age/365) · `LGD` 1/log2(2+age/30).
- **Period length**: 30d · 90d · 180d.
- `repowise_flavour` (reference, NOT one of the 36, NOT in the Bonferroni family): period=90d, attribution=HCM1, decay=ED τ=180d, with commits touching >30 files excluded from its period counts (repowise's stated file cap, generalised from per-commit to this sweep's per-period design — see Design notes).

### Full 36-variant ranking, by lift over `total_loc` (pooled AUC − AUC(total_loc))

Pooled AUC(`total_loc`) baseline: **0.8585** (n_pos=460, n_neg=155017).

| rank | variant | pooled AUC | lift vs total_loc | n_pos | n_neg |
|---|---|---|---|---|---|
| 1 | `HCM1_LD_30` | 0.8823 | 0.0238 | 460 | 155017 |
| 2 | `HCM1_ED_30` | 0.8823 | 0.0238 | 460 | 155017 |
| 3 | `HCM1_LGD_30` | 0.8820 | 0.0235 | 460 | 155017 |
| 4 | `HCM1_LD_90` | 0.8796 | 0.0211 | 460 | 155017 |
| 5 | `HCM1_none_30` | 0.8795 | 0.0210 | 460 | 155017 |
| 6 | `HCM1_ED_90` | 0.8789 | 0.0205 | 460 | 155017 |
| 7 | `HCM1_LD_180` | 0.8777 | 0.0192 | 460 | 155017 |
| 8 | `HCM1_LGD_90` | 0.8773 | 0.0188 | 460 | 155017 |
| 9 | `HCM1_ED_180` | 0.8767 | 0.0183 | 460 | 155017 |
| 10 | `HCM1_none_90` | 0.8749 | 0.0164 | 460 | 155017 |
| 11 | `HCM1_LGD_180` | 0.8737 | 0.0152 | 460 | 155017 |
| 12 | `HCM1_none_180` | 0.8716 | 0.0131 | 460 | 155017 |
| 13 | `HCM2_LGD_30` | 0.8684 | 0.0100 | 460 | 155017 |
| 14 | `HCM2_ED_30` | 0.8669 | 0.0084 | 460 | 155017 |
| 15 | `HCM2_none_30` | 0.8657 | 0.0073 | 460 | 155017 |
| 16 | `HCM2_LD_30` | 0.8648 | 0.0063 | 460 | 155017 |
| 17 | `HCM3_LGD_30` | 0.8618 | 0.0033 | 460 | 155017 |
| 18 | `HCM3_none_30` | 0.8612 | 0.0027 | 460 | 155017 |
| 19 | `HCM3_ED_30` | 0.8588 | 0.0003 | 460 | 155017 |
| 20 | `HCM3_LD_30` | 0.8578 | -0.0007 | 460 | 155017 |
| 21 | `HCM3_LGD_90` | 0.8363 | -0.0222 | 460 | 155017 |
| 22 | `HCM3_none_90` | 0.8342 | -0.0243 | 460 | 155017 |
| 23 | `HCM3_ED_90` | 0.8324 | -0.0261 | 460 | 155017 |
| 24 | `HCM3_LD_90` | 0.8259 | -0.0325 | 460 | 155017 |
| 25 | `HCM2_LGD_90` | 0.8190 | -0.0395 | 460 | 155017 |
| 26 | `HCM2_ED_90` | 0.8168 | -0.0416 | 460 | 155017 |
| 27 | `HCM2_none_90` | 0.8160 | -0.0424 | 460 | 155017 |
| 28 | `HCM2_LD_90` | 0.7985 | -0.0600 | 460 | 155017 |
| 29 | `HCM3_LGD_180` | 0.7558 | -0.1027 | 460 | 155017 |
| 30 | `HCM2_LGD_180` | 0.7546 | -0.1039 | 460 | 155017 |
| 31 | `HCM2_none_180` | 0.7544 | -0.1040 | 460 | 155017 |
| 32 | `HCM3_ED_180` | 0.7537 | -0.1048 | 460 | 155017 |
| 33 | `HCM3_none_180` | 0.7533 | -0.1052 | 460 | 155017 |
| 34 | `HCM2_ED_180` | 0.7522 | -0.1063 | 460 | 155017 |
| 35 | `HCM3_LD_180` | 0.7148 | -0.1437 | 460 | 155017 |
| 36 | `HCM2_LD_180` | 0.7115 | -0.1470 | 460 | 155017 |
| — | `repowise_flavour` (reference) | 0.8777 | 0.0192 | 460 | 155017 |

**19/36 variants have positive pooled lift over `total_loc`.** Best by lift: **`HCM1_LD_30`** (AUC 0.8823, lift 0.0238).

## (c) Within-LOC-quartile bootstrap — the wall test

**Runtime containment (pre-registration authorizes this):** the expensive within-band bootstrap (5000 iters × 4 bands, one `within_band_test` call per variant) was run ONLY for the **top 5 variants by lift** (`HCM1_LD_30`, `HCM1_ED_30`, `HCM1_LGD_30`, `HCM1_LD_90`, `HCM1_none_30`) **plus explicitly `HCM1_none_90`** (the engine's currently shipped definition) — not all 36. De-duplicated subset actually run: `HCM1_LD_30`, `HCM1_ED_30`, `HCM1_LGD_30`, `HCM1_LD_90`, `HCM1_none_30`, `HCM1_none_90`. Band = `total_loc` quartile (rank-based, equal count, same convention as IV); score = the variant. Bootstrap resamples the **event list** 5000 times, seed 2982+band-offset. **Effective alpha: 0.01/(4×36) = 6.944444e-05** — Bonferroni across the 4 bands AND the full 36-variant family (the sweep is a multiple-comparison machine and is corrected as one, per pre-registration, even though only 6 of the 36 were actually tested at this stage — the correction denominator stays 36, not 6, because the claim being protected is about the whole family). Within-band compute time: 1289.5s.

### `HCM1_LD_30`

| band (`total_loc` quartile) | n files | n positives | AUC | boot lower bound (α_eff/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 8 | 0.6070 | 0.1373 | [0.2969, 0.9936] | 4995 | not supported |
| Q2 (lowest=False) | 38869 | 22 | 0.6530 | 0.2308 | [0.5084, 0.7860] | 5000 | not supported |
| Q3 (lowest=False) | 38869 | 62 | 0.7705 | 0.6143 | [0.6928, 0.8491] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 368 | 0.8027 | 0.7498 | [0.7749, 0.8320] | 5000 | **SUPPORTED** |

2/4 bands clear (needs ≥3 of 4 for this variant to carry HV-H1).

### `HCM1_ED_30`

| band (`total_loc` quartile) | n files | n positives | AUC | boot lower bound (α_eff/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 8 | 0.6078 | 0.1363 | [0.2966, 0.9942] | 4995 | not supported |
| Q2 (lowest=False) | 38869 | 22 | 0.6421 | 0.2099 | [0.4965, 0.7753] | 5000 | not supported |
| Q3 (lowest=False) | 38869 | 62 | 0.7703 | 0.6123 | [0.6929, 0.8483] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 368 | 0.8029 | 0.7471 | [0.7743, 0.8329] | 5000 | **SUPPORTED** |

2/4 bands clear (needs ≥3 of 4 for this variant to carry HV-H1).

### `HCM1_LGD_30`

| band (`total_loc` quartile) | n files | n positives | AUC | boot lower bound (α_eff/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 8 | 0.6116 | 0.1363 | [0.3014, 0.9930] | 4995 | not supported |
| Q2 (lowest=False) | 38869 | 22 | 0.6303 | 0.2062 | [0.4850, 0.7645] | 5000 | not supported |
| Q3 (lowest=False) | 38869 | 62 | 0.7654 | 0.6115 | [0.6899, 0.8434] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 368 | 0.8026 | 0.7454 | [0.7730, 0.8329] | 5000 | **SUPPORTED** |

2/4 bands clear (needs ≥3 of 4 for this variant to carry HV-H1).

### `HCM1_LD_90`

| band (`total_loc` quartile) | n files | n positives | AUC | boot lower bound (α_eff/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 8 | 0.6071 | 0.1373 | [0.2958, 0.9943] | 4995 | not supported |
| Q2 (lowest=False) | 38869 | 22 | 0.6419 | 0.2776 | [0.5075, 0.7707] | 5000 | not supported |
| Q3 (lowest=False) | 38869 | 62 | 0.7665 | 0.6085 | [0.6872, 0.8469] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 368 | 0.7973 | 0.7412 | [0.7692, 0.8275] | 5000 | **SUPPORTED** |

2/4 bands clear (needs ≥3 of 4 for this variant to carry HV-H1).

### `HCM1_none_30`

| band (`total_loc` quartile) | n files | n positives | AUC | boot lower bound (α_eff/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 8 | 0.6156 | 0.1363 | [0.3099, 0.9880] | 4995 | not supported |
| Q2 (lowest=False) | 38869 | 22 | 0.6209 | 0.2162 | [0.4754, 0.7567] | 5000 | not supported |
| Q3 (lowest=False) | 38869 | 62 | 0.7553 | 0.6094 | [0.6823, 0.8337] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 368 | 0.7995 | 0.7389 | [0.7688, 0.8307] | 5000 | **SUPPORTED** |

2/4 bands clear (needs ≥3 of 4 for this variant to carry HV-H1).

### `HCM1_none_90`

| band (`total_loc` quartile) | n files | n positives | AUC | boot lower bound (α_eff/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 8 | 0.6333 | 0.1363 | [0.3252, 0.9859] | 4995 | not supported |
| Q2 (lowest=False) | 38869 | 22 | 0.6049 | 0.3002 | [0.4726, 0.7314] | 5000 | not supported |
| Q3 (lowest=False) | 38869 | 62 | 0.7563 | 0.6188 | [0.6837, 0.8337] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 368 | 0.7898 | 0.7325 | [0.7594, 0.8216] | 5000 | **SUPPORTED** |

2/4 bands clear (needs ≥3 of 4 for this variant to carry HV-H1).

## Verdicts

### HV-H1 (the real claim)

SUPPORTED iff at least one variant (among those given the full (c) treatment above) clears within-band AUC>0.5 with the bootstrap lower bound excluding 0.5 in ≥3 of 4 LOC bands, at α_eff=6.944444e-05. **HV-H1: not supported** — none of the 6 tested variants (top 5 by lift + `HCM1_none_90`) cleared ≥3 bands. This does not exhaustively rule out one of the remaining 31 variants clearing it — the within-band bootstrap was not run on them, per the stated runtime containment — but every variant left untested scored a LOWER pooled lift than the ones tested here, which is the evidence available for why they were not expected to fare better.

### HV-H2 (ranking, confirmatory only for the winner)

The best variant by (b), `HCM1_LD_30`, vs `total_loc`, pooled, one-sided bootstrap over events (no Bonferroni — single named comparison), α=0.01. Observed pooled AUC(HCM1_LD_30)=0.8823 vs AUC(total_loc)=0.8585, diff=0.0238, one-sided bootstrap lower bound (α=0.01 percentile)=0.0050, 95% CI=[0.0083, 0.0398], n_boot=5000. **HV-H2: SUPPORTED**. Compute time: 662.9s.

## Plain-language reading

`HCM1_LD_30` beats `total_loc` pooled (HV-H2 supported), but that lift does not survive being checked separately within each LOC quartile at the full Bonferroni-corrected bound (HV-H1 not supported) — consistent with the pooled win being driven by the LOC-size gradient itself rather than a same-size-file discriminator.

## Design notes / ambiguity resolutions

- **Period age for decay = the period's midpoint in days before the parent commit.** The pre-registration specifies decay as a function of "age_days" but a period is a span (e.g. all commits 30-60 days back), not an instant; the midpoint (45 days, in that example) is the representative age used here, applied uniformly across all decay functions and period lengths.
- **`repowise_flavour`'s period length and attribution are not stated** by the pre-registration (only its file cap and decay tau are); resolved as period=90d (matching this program's other documentation of repowise's own 90-day activity window), attribution=HCM1 (the closest period-based analogue to a per-file co-change weight), with the stated 30-file cap applied by excluding oversized commits from that column's period counts entirely.
- **`within_band_test` (tools/incremental_value.py) gained an optional `alpha=` parameter** (default unchanged at the module's own ALPHA=0.01) so this sweep can pass its own family-wide alpha_eff without forking or reimplementing the bootstrap; IV's own two call sites (IV-H1/IV-H2) are unaffected — verified by `py_compile` and by re-reading both call sites after the edit.
- **HV-H1's Bonferroni denominator stays 36** even though only 6 variants received the full (c) treatment — the claim being protected from multiple-comparison inflation is about the 36-variant family as a whole, per the pre-registration text ("across the variant count"), not about however many were actually run.
- **Candidate pool pseudo-replication**: the same file can recur across nearby events' parent snapshots (expected, same convention as every other rung-6 tool in this repo); the bootstrap's resampling unit is nonetheless the EVENT, per the pre-registration.

---
*Regenerate: `python tools/hcm_variants.py --events events/curl.json` — stdlib only; raw commit walks cached under `/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad/hcmwalk_cache` keyed by parent sha. Total measured wall-time this run: 2006.1s (walk 53.7s + within-band 1289.5s + HV-H2 662.9s).*
