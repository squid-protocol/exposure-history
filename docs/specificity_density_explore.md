# Signal beyond size — count vs density vs length (EXPLORATORY)

**Exploratory, no p-values claimed; computed on data already seen.** Asks whether a family's signal carries anything BEYOND file size, which a raw count cannot show (AUC(count) ≈ AUC(LOC) because a count scales with size). Density divides size out but can manufacture a signal via a moving denominator (the `tech_debt` lesson, gitgalaxy#2979/#2984) — so the **length-matched pairwise** column is the cleaner read. Positives vs the control class, file grain, parent snapshot.

## curl

| family | coverage | n_pos / n_ctrl | AUC(count) | AUC(density) | AUC(LOC) | match win% count | match win% density | n_matched |
|---|---|---|---|---|---|---|---|---|
| memory | 76.2% | 99/415 | 0.560 | 0.503 | 0.546 | 46% | 43% | 99 |
| cert/auth ⚠dead-vocab | 0.1% | 101/415 | 0.505 | 0.505 | 0.619 | 50% | 50% | 101 |
| info-leak | 77.6% | 79/415 | 0.531 | 0.488 | 0.531 | 55% | 53% | 78 |

Reading: AUC(density) or match-win% **materially above** AUC(LOC)/50% ⇒ signal beyond size (→ register for repo #3). At/near LOC ⇒ the signal is just size. `⚠dead-vocab` = family signal nonzero on <2% of file-rows (uninformative).

## ndpi

| family | coverage | n_pos / n_ctrl | AUC(count) | AUC(density) | AUC(LOC) | match win% count | match win% density | n_matched |
|---|---|---|---|---|---|---|---|---|
| memory | 70.1% | 0/162 | — | — | — | — | — | — |
| cert/auth | 0.0% | 0/162 | — | — | — | — | — | — |
| info-leak | 75.1% | 0/162 | — | — | — | — | — | — |

**nDPI is untestable at family grain: 0 CWE-labeled positives** — the OSS-Fuzz feed carries no
CWE, so events can't be assigned to a family (note the signals themselves ARE populated:
memory 70%, info-leak 75% coverage — it's the *labels* that are missing, not the vocabulary).
This is the same gap that bars nDPI from the S-H* specificity battery; a repo #3 for this axis
must carry CWE labels.

## Verdict (exploratory)

On the only repo that can run it (curl): **density and length-matching do NOT reveal signal
beyond size.** Memory's slim raw-count edge (AUC 0.560 vs LOC 0.546) collapses to chance when
size is divided out (density 0.503) and inverts when size is held equal (length-matched
win 46% — CVE files are *less* danger-dense than same-size peers). info-leak is the same
(density 0.488; match 55% is a whisper). cert/auth is dead-vocabulary. **Nothing separated ⇒
no density/length hypothesis is registered for repo #3** — the near-tie AUC(count)≈AUC(LOC)
was the count *being* size, not size masking a signal. Reinforces the program verdict:
structural standing is a size proxy; the durable predictor is recidivism.

Reading: AUC(density) or match-win% **materially above** AUC(LOC)/50% ⇒ signal beyond size (→ register for repo #3). At/near LOC ⇒ the signal is just size. `⚠dead-vocab` = family signal nonzero on <2% of file-rows (uninformative).

