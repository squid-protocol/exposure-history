# Specificity split — curl held-out temporal analysis

Held-out curl temporal-split specificity analysis (gitgalaxy#2982, comment 5648804679). Tests whether the RIGHT raw exposure signal marks the RIGHT CWE failure family, out-of-sample, beyond a plain line-count baseline.

**All verdicts below are TEST-half only.** This is temporal out-of-sample *within one repo* (curl split at its own median fix-commit date) — it is a genuine held-out test, but it is not a substitute for a second repo (that is repo #3's job). The derivation half is shown only for direction, never for a verdict.

- Events file: `curl.json` · DB: `curl_galaxy_master.db` (opened read-only, WAL-aware)
- CWE-labeled security-fix events: 186 · control events: 185
- Skipped (no usable touched-file diff): control: no-touched-files (17), security-fix: no-touched-files (4)
- **Split boundary date: `2022-06-25`** (index-median of the 186 CWE-labeled security-fix dates; earlier = derivation, `>=` boundary = test). Same boundary applied to control events.

## Per-family event counts, both halves

`other`/unlabeled CWEs are dropped from the confirmatory family rows below (shown here as context only).

| family | derivation events | test events |
|---|---|---|
| **memory** | 41 | 15 |
| **cert/auth** | 12 | 23 |
| **info-leak** | 14 | 19 |
| other (context) | 24 | 34 |
| unlabeled (context) | 0 | 0 |
| control (negative pool) | 87 | 81 |

## Defect-lift beyond size (TEST half only)

defect-lift = AUC(matched-F-signal) − AUC(total_loc), file grain, parent-snapshot scores. One-sided bootstrap over EVENTS (an event's files are not independent draws), n=5000 iters (seed 2982, floor 2000). **Verdict bound** is the bootstrap lower percentile at the Bonferroni-corrected one-sided alpha (0.00333 = 0.01 / 3 families); SUPPORTED iff lift > 0 AND that bound excludes 0. A separate, purely descriptive one-sided-95% lower bound (5th percentile) is also shown for context — it is NOT what decides the verdict.

### memory

| negative set | n_pos (events/files) | n_neg (events/files) | AUC(signal) | AUC(LOC) | lift | verdict-bound lo (α=0.00333) | descriptive 95% lo | verdict |
|---|---|---|---|---|---|---|---|---|
| (a) controls | 15/26 | 81/210 | 0.5877 | 0.5896 | -0.0018 | -0.0727 | -0.0473 | **not supported** |
| (b) non-F CVE | 15/26 | 76/222 | 0.5106 | 0.5047 | 0.0059 | -0.0554 | -0.0344 | **not supported** |

### cert/auth

| negative set | n_pos (events/files) | n_neg (events/files) | AUC(signal) | AUC(LOC) | lift | verdict-bound lo (α=0.00333) | descriptive 95% lo | verdict |
|---|---|---|---|---|---|---|---|---|
| (a) controls | 23/57 | 81/210 | 0.5088 | 0.6048 | -0.0960 | -0.2642 | -0.2007 | **not supported** |
| (b) non-F CVE | 23/57 | 68/191 | 0.5088 | 0.5492 | -0.0405 | -0.2262 | -0.1519 | **not supported** |

### info-leak

| negative set | n_pos (events/files) | n_neg (events/files) | AUC(signal) | AUC(LOC) | lift | verdict-bound lo (α=0.00333) | descriptive 95% lo | verdict |
|---|---|---|---|---|---|---|---|---|
| (a) controls | 19/37 | 81/210 | 0.5356 | 0.5726 | -0.0369 | -0.1828 | -0.1181 | **not supported** |
| (b) non-F CVE | 19/37 | 72/211 | 0.5232 | 0.5144 | 0.0088 | -0.1486 | -0.0837 | **not supported** |

## Direction-check, no verdict (derivation half, vs controls)

| family | n_pos (events/files) | n_neg (events/files) | AUC(signal) | AUC(LOC) | lift |
|---|---|---|---|---|---|
| memory | 41/73 | 87/205 | 0.5476 | 0.5148 | 0.0328 |
| cert/auth | 12/44 | 87/205 | 0.5000 | 0.6432 | -0.1432 |
| info-leak | 14/42 | 87/205 | 0.5240 | 0.4909 | 0.0332 |

## S-H0 — the specificity discriminant (TEST half, vs controls)

Confusion matrix: rows = a family's positives, columns = the three matched signal-sets. Cell = AUC of that column's signal-set for that row's positives vs controls. **SUPPORTED iff every row's argmax is its own diagonal cell** (a family's own matched signal ranks its own failures highest, not just *a* signal above chance).

| positives \ signal-set | memory | cert/auth | info-leak |
|---|---|---|---|
| **memory** | **0.5877** | 0.5000 | 0.4415 |
| **cert/auth** | 0.5804 | **0.5088** | 0.5651 |
| **info-leak** | 0.6154 | 0.5000 | **0.5356** |

**S-H0: not supported** — not every row's argmax lands on the diagonal.

## Signal coverage & interpretation (orchestrator verification)

Before reading the verdicts, the matched signals' coverage across all 1,054,217 curl
`file_data` rows — because a "null" means nothing if the signal was never extracted:

| family | matched signals | % of file-rows nonzero |
|---|---|---|
| memory | `state_pointers` / `state_cast_hits` / `state_memory_alloc` / `state_danger` | 70% / 36% / 17% / 6.8% |
| info-leak | `arch_io` / `arch_api` | 21% / 73% |
| cert/auth | `arch_crypto` / `def_auth` | **0.1% / 0.0%** |

This splits the negative into two different findings:

- **S-H1 memory — GENUINE NULL.** The danger cluster is well-populated, yet its AUC ties a
  line count (0.588 vs 0.590) and shows no defect-lift out-of-sample. Pre-event structural
  *standing* does not mark which file gets a memory CVE better than size — consistent with
  H1 / RW-H1 (standing ≈ LOC). The security signal we found earlier lives in the fix
  **delta** (grammar: fixes *add* branches/pointers), not in standing.
- **S-H3 info-leak — GENUINE NULL.** `arch_io`/`arch_api` populated; AUC ties LOC (0.54 vs
  0.57); no lift.
- **S-H2 cert/auth — DEGENERATE, NOT A VERDICT.** `def_auth` is **0 in every row** and
  `arch_crypto` fires on 0.1% — the matched signal is effectively absent, so its AUC pins at
  ~0.509 (no ranking power) by construction. This is the **D-H1 vocabulary gap**, not a
  specificity result: curl delegates crypto to external TLS backends and carries no `def_auth`
  construct the extractor tags. **Untestable on curl** — deferred to a repo whose language/
  code actually exercises crypto/auth vocabulary.
- **S-H0 — not diagonal, but read with the caveat** that one column (cert/auth) is dead
  (0.509 = noise). Among the two *live* signal-sets, the **memory** set ranks highest even for
  info-leak's own positives (0.615 vs info-leak's own 0.536) — i.e. the populated "danger"
  signals behave as a **general code-mass proxy, not a mechanism-specific detector.**

**Plain-language:** "the right keyword marks the right bug" did **not** survive out-of-sample
on curl. Where the keywords are actually present (memory, info-leak) they were no better than
a line count and weren't specific to their failure type; where they'd have been most telling
(cert/auth) curl doesn't carry the vocabulary at all. Predicting *which* file gets *which* bug
from pre-event structural standing doesn't work on curl — reinforcing that the real signal is
in what a fix **does**, and making the case for a repo #3 with live crypto/auth + concurrency
vocabulary (and flagging to the engine that `def_auth`/`arch_crypto` under-fire on C — cf.
gitgalaxy#2984/#2979).

---
*Regenerate: `python tools/specificity_split.py` — stdlib only, reads only the events file and the read-only history DB; deterministic given `--seed` (default 2982). Bootstrap resamples EVENTS, not files.*
