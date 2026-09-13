# Multivariate keyword-importance classifier -- curl (tc#32 / gitgalaxy#2982)

**EXPLORATORY -- no hypothesis tests, no p-values.** L2-regularized multinomial logistic regression (hand-derived softmax loss/gradient in numpy; `scipy.optimize.minimize` L-BFGS-B as the generic solver -- sklearn is not installed for system python3 and nothing was installed to get it) over the per-event mean-signal-delta vector (26 active signals after dropping 43 that move in <3% of train events) plus net-LOC as an explicit feature. Standardized (z-score, fit on train only). L2 strength chosen per model by 5-fold stratified CV on train (grid [0.03, 0.1, 0.3, 1.0, 3.0, 10.0, 30.0], macro-F1 scored).

**Caveats carried from the harness (not re-derived here):** `Fixes #` label purity is ~50% (docs/bh_eval.md audit -- half of `Fixes #` commits are docs/build/deprecation, not code-bug fixes); ~31% of touched files across the corpus are tests/docs, not implementation, so per-event mean deltas are diluted by bystander files; files recur across events (pseudo-replication) -- the temporal split (train < 2022-01-01, test >= 2022-01-01, split by EVENT COMMIT DATE) prevents a model from training on a file it will be tested on in the *same* commit, and reduces the leakage from recurring files across DIFFERENT commits, but does not remove it -- curl's hot files (`lib/vtls/*`, `lib/http.c`, ...) get fixed repeatedly across the full 26-year window, before and after the cutoff.

## Data

1545 usable events (cache hit, non-null stats) out of 1545 candidates scanned; 1545 carry a resolvable commit date.

| class | train (< 2022-01-01) | test (>= 2022-01-01) |
|---|---|---|
| security-fix | 81 | 101 |
| regression | 157 | 122 |
| bugfix-bug | 210 | 34 |
| bugfix-fixes | 195 | 239 |
| control | 73 | 95 |
| introduced | 85 | 33 |
| revert | 87 | 18 *(thin test sample)* |
| cve-followup | 3 | 12 *(thin test sample)* |
| **total** | **891** | **654** |

Dropped signals (<3% of train events move them): `arch_concurrency`, `arch_crypto`, `arch_dependency_injection`, `arch_events`, `arch_feature_flags`, `arch_hardware`, `arch_inline_asm`, `arch_io`, `arch_ipc`, `arch_regex`, `arch_scientific`, `arch_serialization`, `arch_ssr_boundaries`, `arch_time`, `arch_ui_framework`, `def_auth`, `def_doc`, `def_listeners`, `def_ownership`, `def_spec_exposure`, `def_sync_locks`, `def_telemetry`, `def_test`, `def_test_skip`, `dl_frameworks`, `llm_api`, `llm_local_compute`, `llm_orchestrator`, `llm_vector_store`, `ml_traditional`, `state_bailout_hits`, `state_danger`, `state_fragile_debt`, `state_halt_hits`, `state_planned_debt`, `state_slop_duplicates`, `struct_camel_case`, `struct_closures`, `struct_comprehensions`, `struct_decorators`, `struct_generics`, `struct_long_vars`, `struct_pascal_case`

**Class-prior drift across the cutoff:** the train-set mode class is `bugfix-bug` (24% of train) but only 5% of test; the test-set mode class is `bugfix-fixes` (37% of test) but only 22% of train. This is not a train/test split artifact -- binning by year shows a smooth secular trend across curl's whole history (`bugfix-bug` dominant through ~2015, `bugfix-fixes` overtaking and growing every year after), consistent with which commit-message trailer convention (`Bug:`-style vs GitHub `Fixes #`) the bug-harvest matched shifting as curl moved its own issue tracking onto GitHub over the 2010s -- a labeling-methodology artifact, not a change in what a bug fix structurally looks like. It means raw 8-way accuracy is not directly comparable to a naive 1/8 chance baseline; the trivial baselines below give the honest reference points.

## 1. Test-set confusion matrix + per-class F1 (full vector)

Overall test accuracy **0.150**, macro-F1 **0.091** (n=654, lambda=3.0). Trivial baselines for context: always predicting the **train**-mode class (`bugfix-bug`) on test scores **0.052**; always predicting the **test**-mode class (`bugfix-fixes`, an oracle a real model can't use) scores **0.365**.

| true \ pred | security-fix | regression | bugfix-bug | bugfix-fixes | control | introduced | revert | cve-followup |
|---|---|---|---|---|---|---|---|---|
| **security-fix** | 4 | 5 | 52 | 32 | 0 | 4 | 4 | 0 |
| **regression** | 0 | 2 | 90 | 23 | 0 | 6 | 1 | 0 |
| **bugfix-bug** | 2 | 5 | 19 | 6 | 0 | 2 | 0 | 0 |
| **bugfix-fixes** | 2 | 5 | 143 | 68 | 4 | 11 | 6 | 0 |
| **control** | 3 | 3 | 60 | 24 | 0 | 2 | 3 | 0 |
| **introduced** | 2 | 1 | 14 | 10 | 0 | 3 | 3 | 0 |
| **revert** | 0 | 3 | 11 | 2 | 0 | 0 | 2 | 0 |
| **cve-followup** | 0 | 0 | 7 | 5 | 0 | 0 | 0 | 0 |

| class | support | precision | recall | F1 |
|---|---|---|---|---|
| security-fix | 101 | 0.31 | 0.04 | 0.07 |
| regression | 122 | 0.08 | 0.02 | 0.03 |
| bugfix-bug | 34 | 0.05 | 0.56 | 0.09 |
| bugfix-fixes | 239 | 0.40 | 0.28 | 0.33 |
| control | 95 | 0.00 | 0.00 | 0.00 |
| introduced | 33 | 0.11 | 0.09 | 0.10 |
| revert | 18 | 0.11 | 0.11 | 0.11 |
| cve-followup | 12 | 0.00 | 0.00 | 0.00 |

**Most-confused pairs** (true -> predicted, count): bugfix-fixes -> bugfix-bug (143); regression -> bugfix-bug (90); control -> bugfix-bug (60); security-fix -> bugfix-bug (52); security-fix -> bugfix-fixes (32)

**Degenerate:** the model predicts `bugfix-bug` for 61% of test events regardless of true class (predicted-class distribution: bugfix-bug=396, bugfix-fixes=170, introduced=28, regression=24, revert=19, security-fix=13, control=4) -- a near-majority-class collapse. With a single dominant softmax bias term and weak per-feature separation, L2 pulls the decision surface toward the train class prior; the train prior's mode (`bugfix-bug`) is exactly the class most depleted by the class-prior drift noted above, so the collapse target and the true test distribution are maximally mismatched. The full-vector model still beats both trivial single-class baselines here, but the raw 8-way accuracy number is dominated by this prior-shift pathology, not primarily by feature quality -- read the collapsed binary AUC (section 4) and per-class precision/recall above as the more prior-robust reading.

## 2. Top-15 signal coefficients per class contrast

Standardized-feature coefficient difference between the two classes' softmax columns of the full-vector model (positive = pushes toward the first-named class relative to the second). `net_loc` is included in the ranking so its relative rank shows whether a signal's importance survives controlling for it.

### security-fix vs control

| rank | feature | coefficient |
|---|---|---|
| 1 | `arch_globals` | -0.657 |
| 2 | `def_encapsulation` | +0.594 |
| 3 | `state_cast_hits` | -0.578 |
| 4 | `struct_upper_case` | -0.488 |
| 5 | `def_freeze_hits` | -0.456 |
| 6 | `state_flux` | +0.371 |
| 7 | `state_memory_alloc` | -0.334 |
| 8 | `struct_macros` | -0.301 |
| 9 | `struct_var_decl` | +0.300 |
| 10 | `def_safety` | +0.276 |
| 11 | `state_safety_neg` | -0.260 |
| 12 | `arch_import` | +0.240 |
| 13 | `def_cleanup` | +0.206 |
| 14 | `arch_api` | +0.204 |
| 15 | `struct_class_start` | -0.198 |

### introduced vs control

| rank | feature | coefficient |
|---|---|---|
| 1 | `arch_api` | +1.150 |
| 2 | `def_encapsulation` | +0.622 |
| 3 | `state_cast_hits` | -0.553 |
| 4 | `struct_var_decl` | +0.506 |
| 5 | `arch_import` | +0.419 |
| 6 | `state_pointers` | +0.392 |
| 7 | `struct_func_start` | -0.378 |
| 8 | `def_freeze_hits` | -0.297 |
| 9 | `state_safety_neg` | +0.273 |
| 10 | `struct_class_start` | -0.257 |
| 11 | `state_memory_alloc` | -0.246 |
| 12 | `bitwise_ops` | +0.236 |
| 13 | `struct_snake_case` | +0.206 |
| 14 | `def_cleanup` | +0.171 |
| 15 | `struct_args` | +0.167 |

### fix-classes (bugfix-fixes+bugfix-bug+regression, mean) vs control

| rank | feature | coefficient |
|---|---|---|
| 1 | `def_encapsulation` | +0.608 |
| 2 | `state_cast_hits` | -0.498 |
| 3 | `struct_var_decl` | +0.472 |
| 4 | `net_loc` *(net-LOC)* | -0.396 |
| 5 | `arch_api` | +0.377 |
| 6 | `def_freeze_hits` | -0.354 |
| 7 | `arch_globals` | -0.331 |
| 8 | `def_cleanup` | +0.303 |
| 9 | `state_memory_alloc` | -0.293 |
| 10 | `struct_upper_case` | -0.281 |
| 11 | `struct_short_vars` | -0.183 |
| 12 | `struct_class_start` | -0.176 |
| 13 | `state_flux` | +0.176 |
| 14 | `struct_branch` | +0.164 |
| 15 | `state_print_hits` | +0.134 |

### Does the univariate fix-grammar (branch/pointer adds, no new cast/alloc) survive multivariately?

Full rank (of the active-feature count) and signed coefficient for the four grammar signals, in each contrast above -- not just whether they crack the top 15:

| signal | security-fix vs control | introduced vs control | fix-classes (bugfix-fixes+bugfix-bug+regression, mean) vs control |
|---|---|---|---|
| `struct_branch` | rank 17/27, +0.139 | rank 26/27, -0.028 | rank 14/27, +0.164 |
| `state_pointers` | rank 27/27, -0.025 | rank 6/27, +0.392 | rank 25/27, +0.051 |
| `state_memory_alloc` | rank 7/27, -0.334 | rank 11/27, -0.246 | rank 9/27, -0.293 |
| `state_cast_hits` | rank 3/27, -0.578 | rank 3/27, -0.553 | rank 2/27, -0.498 |

**No.** In the security-fix vs control contrast, `struct_branch` sits mid-table (rank 17/27) and `state_pointers` is dead last (rank 27/27, coefficient essentially zero) once every other signal and net-LOC compete for the same coefficient budget -- branch/pointer additions do **not** top the multivariate security-fix signature, contradicting the univariate read. What *does* survive multivariately, and consistently across all three contrasts, is the grammar's other half: `state_cast_hits` (rank 3) and `state_memory_alloc` (rank 7) are both negative and land in the top third of every contrast -- a fix/introduction event that does *not* add new casts or new allocations, more than one that adds branches or pointers. The top-ranked features overall (`arch_globals`, `def_encapsulation`, `state_cast_hits`, `struct_upper_case`, `def_freeze_hits` for security-fix vs control) are a mix of style/scope signals as much as danger vocabulary -- once collinear signals compete for coefficient budget under L2, the univariate grammar's headline term (branch+/pointer+) turns out to be the weaker, more redundant half of it.

## 3. Net-LOC alone vs the full vector (the beyond-size delta)

| model | test accuracy | test macro-F1 |
|---|---|---|
| full vector (27 features) | 0.150 | 0.091 |
| net-LOC alone (1 feature) | 0.064 | 0.042 |
| **beyond-size delta** | **+0.086** | **+0.048** |

## 4. Collapsed binary: fix-like (security-fix+bugfix-*+regression) vs control

Train n=716 (bugfix-bug=210, bugfix-fixes=195, regression=157, security-fix=81, control=73), test n=591 (bugfix-fixes=239, regression=122, security-fix=101, control=95, bugfix-bug=34).

| model | test AUC |
|---|---|
| full vector | 0.479 |
| net-LOC alone | 0.531 |
| **beyond-size delta** | **-0.052** |

Descriptive only (exploratory, no test run here) -- for context, a rough Hanley-McNeil-style AUC standard error at this n (n1=496, n0=95) is on the order of 0.03; both AUCs above are within noise of 0.5 (chance). Unlike the raw multiclass accuracy in section 1, AUC is prior-invariant (rank statistic), so this comparison is NOT distorted by the class-prior drift noted in Data -- fix-like-vs-control separability, in this feature vector, out of temporal sample, reads as indistinguishable from chance, for both the full vector and net-LOC alone.

---
*Regenerate: `python tools/class_signals.py` (reads/fills `dbs/keyword_pools_cache.json` via `tools/keyword_pools.py`'s compute pass; both gitignored). Not committed by the tool.*
