# Incremental-value test — does structure add lift over process?

Generated 2026-09-12 20:22 · repo `curl` · pool HEAD `04bfe8fbbf55` · DB `curl_galaxy_master.db` (opened read-only, WAL-aware) · pre-registered gitgalaxy#2982 comment 5649564429; implemented verbatim; verdicts publish either way.

## Leakage-free design

Structural exposure and `total_loc` are read from the existing scan DB at each security-fix event's **parent** commit (T0) — no rescan. Process features (`churn`, `ownership_entropy`, `co_change_scatter`, `change_entropy`) are computed fresh from the pool clone via `git log <parent> --since=<parent_date-365d> -n 4000 --no-merges --name-only --pretty=format:"@@|%H|%ct|%an"` — starting AT the parent and walking only its ancestors, so no information from the fix commit or anything after it can enter the process features. This is necessary because scans in this program run with `GITGALAXY_DISABLE_GIT_HISTORY=1` (tools/_engine.py), which pegs churn/ownership to zero in every DB row — process signal for this test could not come from the DB even if leakage were not a concern.

**Window**: 365 days before the parent's own commit date, capped at 4000 commits, `--no-merges` — matching the chronometer prototype's own `--since=1.year`/`--no-merges` default on engine branch `feat/cochange-entropy` (`gitgalaxy/metrics/chronometer.py`). Measured walk wall-time for all 182 usable events (one `git log` per distinct parent, cached to disk keyed by parent sha): **28.9s** on first run (subsequent runs read the cache and are near-instant). No window reduction was needed.

`co_change_scatter`/`change_entropy` ignore commits touching more than 50 files (mass reformats), identical to the chronometer prototype's `_record_cochange` gate. `churn`/`ownership_entropy` have no such filter (matching the prototype, which increments its churn/author maps unconditionally). `ownership_entropy` and `change_entropy` are reported as raw Shannon entropy in **bits**, not the engine's downstream 0–100 `min(H*32, 100)` scaled ownership score (`signal_processor._calc_ownership_entropy`) — the pre-registration text asks for entropy directly.

Coverage: 182 security-fix events usable (of 186 in the event set); skipped — {'no touched file present in parent snapshot': 4}. Pooled candidate files (sum of parent-snapshot sizes across usable events; a file recurs across nearby events' snapshots by design, same pseudo-replication convention as every other rung-6 tool here): **155477**, pooled positives: **460**.

## 1 · Descriptive — single-feature pooled AUC (no verdict)

Positives (fix-touched files) vs non-positive files, pooled over all usable parent snapshots. Ranks the six features; no significance claimed here.

| rank | feature | AUC | n positives | n negatives |
|---|---|---|---|---|
| 1 | `churn` | 0.8591 | 460 | 155017 |
| 2 | `total_loc` | 0.8585 | 460 | 155017 |
| 3 | `co_change_scatter` | 0.8467 | 460 | 155017 |
| 4 | `ownership_entropy` | 0.8414 | 460 | 155017 |
| 5 | `change_entropy` | 0.8357 | 460 | 155017 |
| 6 | `structural_exposure` | 0.7239 | 460 | 155017 |

**Strongest process feature: `churn`** (highest AUC among `churn`, `ownership_entropy`, `co_change_scatter`, `change_entropy`) — this is the stratifying feature for IV-H1 and the scored feature for IV-H2.

## 2 · IV-H1 — does structure add lift within process bands? (the real question)

Files stratified into quartile bands (equal-COUNT, by RANK — see design note below) of `churn`, pooled over all usable snapshots. Within each band: AUC of `structural_exposure` separating positives from non-positives. SUPPORTED iff AUC>0.5 AND the one-sided bootstrap lower bound at the Bonferroni-adjusted alpha (0.01/4 = 0.0025 percentile) excludes 0.5. Bootstrap resamples the **event list** (not files) 5000 times, seed 2982+band-offset; band membership is fixed from the observed pooled data (not recomputed per resample). Compute time: 207.4s.

| band (`churn` quartile) | n files | n positives | AUC | boot lower bound (α/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 12 | 0.5991 | 0.3344 | [0.4335, 0.8026] | 4999 | not supported |
| Q2 (lowest=False) | 38869 | 23 | 0.6893 | 0.5096 | [0.5822, 0.7914] | 5000 | **SUPPORTED** |
| Q3 (lowest=False) | 38869 | 49 | 0.7140 | 0.5754 | [0.6160, 0.8051] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 376 | 0.6101 | 0.5552 | [0.5740, 0.6447] | 5000 | **SUPPORTED** |

**IV-H1 verdict: SUPPORTED (partial — see per-band verdicts)** (all 4 bands must independently clear the Bonferroni bound for a clean SUPPORTED).

## 3 · IV-H2 — the mirror: does process add lift within structure bands?

Files stratified into quartile bands of `structural_exposure`; within each band, AUC of `churn` (the same strongest process feature from step 1). Same verdict rule, same bootstrap design. Compute time: 125.0s.

| band (`structural_exposure` quartile) | n files | n positives | AUC(`churn`) | boot lower bound (α/4) | 95% CI | n boot | verdict |
|---|---|---|---|---|---|---|---|
| Q1 (lowest=True) | 38869 | 55 | 0.8958 | 0.7836 | [0.8220, 0.9605] | 5000 | **SUPPORTED** |
| Q2 (lowest=False) | 38869 | 55 | 0.8065 | 0.6922 | [0.7293, 0.8768] | 5000 | **SUPPORTED** |
| Q3 (lowest=False) | 38869 | 25 | 0.8150 | 0.6305 | [0.7010, 0.9009] | 5000 | **SUPPORTED** |
| Q4 (lowest=False) | 38870 | 325 | 0.7722 | 0.7344 | [0.7452, 0.7990] | 5000 | **SUPPORTED** |

**IV-H2 verdict: SUPPORTED**.

## Design notes / ambiguity resolutions

- **Quartile bands are rank-based (equal count), not value-quantile cut points.** Process features under a bounded 1-year ancestors-only window are heavily zero-inflated (most files in any snapshot were not touched in the last year); a value-quantile split would collapse edges onto a single tied value. Rank quartiles guarantee ~n/4 files per band at the cost of splitting some tied values across adjacent bands — reported, not hidden.
- **Band membership is fixed from the observed pooled population**, not recomputed inside the bootstrap loop, so a band means the same thing across all 5000 resamples; only which events (and therefore which of that band's files) are present varies per resample, per the pre-registration's stated sampling unit (event, not file).
- **`ownership_entropy`/`change_entropy` reported in raw bits**, not the engine's downstream 0-100 scaled ownership score — the registration text says "Shannon entropy (bits)" explicitly for `ownership_entropy`, and mirroring the chronometer prototype's `get_cochange_metrics` for `change_entropy` (which is already raw bits, unscaled).
- **"Strongest process feature" picked by raw step-1 AUC** (not distance-from-0.5), i.e. the single highest AUC among the four process features, per a literal reading of "pick by the step-1 AUC".

---
*Regenerate: `python tools/incremental_value.py --events events/curl.json` — stdlib only; process-feature git walks cached under `/tmp/claude-1000/-home-joe-Projects/7026d7a1-a379-4dda-a4df-b5859b206664/scratchpad/procfeat_cache` keyed by parent sha.*

## 4 · Orchestrator verification — the size control the registration omitted

IV-H1 stratifies by `churn` but **never controls file size**, and `total_loc` is the
second-strongest feature in the whole table (pooled AUC 0.8585, vs structural_exposure's
0.7239). So "structure discriminates within churn bands" does not establish that structure
carries information — a plain line count might do it better. Re-running each band with
`total_loc` as the score:

| churn band | n pos | AUC(structural_exposure) | AUC(total_loc) | structure − LOC |
|---|---|---|---|---|
| Q1 | 12 | 0.5991 | 0.5672 | +0.0319 |
| Q2 | 23 | 0.6893 | 0.7399 | **−0.0506** |
| Q3 | 49 | 0.7140 | 0.7680 | **−0.0540** |
| Q4 | 376 | 0.6101 | 0.7675 | **−0.1575** |

**Structure loses to a line count in 3 of 4 bands**, including the band holding 82% of the
positives (Q4, −0.158). The only band where it leads has 12 positives. **IV-H1's partial
support is therefore a size artifact, not incremental value** — the pre-registered banding
design was insufficient, and this is recorded as a correction to it, not as a finding.

The mirror check is equally sobering — within `structural_exposure` bands, `churn` also
mostly fails to beat `total_loc`:

| structure band | n pos | AUC(churn) | AUC(total_loc) | churn − LOC |
|---|---|---|---|---|
| Q1 | 55 | 0.8958 | 0.8316 | +0.0641 |
| Q2 | 55 | 0.8065 | 0.8227 | −0.0162 |
| Q3 | 25 | 0.8150 | 0.8366 | −0.0216 |
| Q4 | 325 | 0.7722 | 0.8107 | −0.0385 |

**Corrected verdicts.** IV-H1: **not supported** (structure adds no lift over size within
process bands). IV-H2: **supported only in the weak sense** that process ranks above
structure pooled (churn 0.8591 > structural 0.7239) — but process does not cleanly beat a
line count within structure bands either.

**What this design actually shows.** The task as posed — *which files in this snapshot does
this fix touch* — is **dominated by file size and centrality**: `churn` (0.8591) and
`total_loc` (0.8585) are statistically indistinguishable at the top, and every other feature
trails. This independently reproduces **repowise-bench's size-confound wall** (their pooled
AUC 0.737 collapses to 0.525/0.572 inside small/medium NLOC bands) on a completely different
label set — CVE-fix touches rather than bug-fix commits. Any future benchmark built from this
program must be **size-orthogonal by construction** (partial-Spearman vs NLOC, within-band
AUC, effort-aware Popt) or it will simply re-measure size.

**Labelling note.** The `change_entropy` column above is the *first-cut* definition
(Shannon entropy of a file's co-change partner distribution). Verification on the engine
branch showed that metric correlates with `log2(co_change_scatter)` at **r=0.998** — it is
effectively a monotone transform of scatter, not an independent feature. It has since been
renamed `coupling_entropy`, and a true Hassan HCM (`change_entropy`, r=0.411 with scatter)
implemented alongside it. Re-running this table with real HCM is follow-up work.
