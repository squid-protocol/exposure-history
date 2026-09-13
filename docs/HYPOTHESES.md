# The hypothesis ledger

## The plain-language summary (read this first)

**What we did:** validated GitGalaxy's measurements against real defect ground truth,
pre-registering every prediction before looking: curl's 25-year CVE history (fix +
introducing commits), a second repository (nDPI, OSS-Fuzz-found CVEs), and 1,107 of curl's
own bug-fix / regression commits — ~3,550 repository snapshots scanned, every verdict
published either way.

**What we learned, in plain terms (updated 2026-09-13, after the full program):**

1. **Two predictors survive honest evaluation; both are history, neither is structure.**
   - **Recidivism** — the file that had the last fix gets the next one — beats every static
     ranking, decisively, on both repositories (p<1e-4). The strongest and most replicated
     result of the program.
   - **Change entropy (Hassan HCM, `HCM1_LD_30`)** — was this file changed during periods
     when edits were scattered chaotically across the codebase? Selected on CVE labels,
     then **validated frozen on fresh bug labels**: AUC 0.868 vs a line count's 0.830
     (lift +0.038, bound +0.021). The only *feature* to beat a line count out-of-selection.
2. **Everything structural reduces to file size.** Keyword counts, danger vocabulary,
   complexity, per-file risk totals — pooled, density-normalized, length-matched, or
   banded — none beats a line count (nulls equivalence-confirmed, two repos). The same
   size-confound wall was independently reported by repowise-bench on ordinary bug labels;
   we reproduced it on CVE labels. Nobody's per-file structural score clears it.
3. **The fix "grammar" is real but narrow.** curl's security fixes have a recognizable
   shape (branch/pointer adds without new allocations) — it survives fix-size controls but
   **does not travel**: nDPI's fuzzer-found one-line fixes carry no signature. It is a
   property of *human-reported* CVE fixes in curl, not a law.
4. **Centrality is not the small-file answer.** With proper power (28/42 positives),
   PageRank in ≤22-line files is *inverted* (AUC 0.26), and the once-beautiful monotone
   size story failed in 5,000/5,000 bootstrap resamples. The surviving candidate is an
   **inverted U** — centrality lifts only in mid-size files (49–108 LOC: +0.14, robust) —
   registered for repo #3, not yet claimed.
5. **The guards did the finding.** Pre-registration killed post-hoc stories (the monotone
   shape, the best-of-36 HCM selection); the ≥20-positive power rule stopped an AUC-0.999
   "result" built on one positive; equivalence tests turned "not significant" into
   "confirmed near-zero"; and the instrument audit caught a real engine determinism bug
   (gitgalaxy#2988). More predictions died than lived — that is the record working.

**What this points at:** ship history (recidivism + change entropy) as the predictive
layer; let structure do what it actually does — describe, explain, and localize, across
59 languages. The open questions now live in repo #3 (openssl, fixed-side): does the
grammar return on human-reported fixes elsewhere, is mid-band centrality real, does HCM
replicate, and the CWE-matched specificity battery that curl and nDPI could not power.


This is the temporal crucible's register of record — every confirmatory claim this program
makes lives here, with its registration date, its registered direction and threshold, and
its verdict **whatever that verdict was**. It is the sibling of keyword-rosetta's deviation
ledger: there, no manifest number exists without a validated entry; here, **no finding
exists without a pre-registration**.

## The protocol (the rule this repo runs on)

1. **Hypothesis first.** A confirmatory claim is registered — on gitgalaxy#2982 or here —
   with its direction, its test, and its α **before** the analysis that could confirm it
   runs. The registration text is quoted verbatim in the report that evaluates it.
2. **Verdicts are published either way.** A dead hypothesis stays in this ledger forever
   with its autopsy. Three of our first five died; that is the record working.
3. **Exploratory is labeled exploratory.** Descriptive tables (prevalence shares, gap
   rankings) claim no p-values and are marked in-place. An exploratory observation may
   *become* a hypothesis — registered for **data it has not seen** (the next repo, the next
   label class), never re-tested on the data that suggested it.
4. **Every test carries its guards**: size-matched controls, length-matched pairs where
   grain is the function, temporal ablation (churn/stability frozen so events cannot
   predict themselves), rename tracking, and multiple-comparison correction on any table
   wider than one registered claim.

## Scope of validation to date

**curl** (C, ~39.7k commits, 25 years): 186 CVE-fix + 137 CVE-introducing commits (OSV GIT
ranges, 0 unresolvable) + 185 size-matched controls + 147 wave-1 (reverts/follow-ups) +
1,107 bug-label events (Fixes#/Bug:/regression, seeded sample). **nDPI** (C/C++): 121
fix + 73 introducing (OSS-Fuzz-bisected) + 111 controls. **~3,550 snapshots scanned in
total** across both repos; ~3.4M per-function measurements on curl alone.
**Repo #2 (nDPI) has now run** (see "Repo #2 (nDPI) replication — RESULTS" below): of curl's
positives, **only recidivism (RW-H2) replicated**; every structural signature (H3
`safety_score`, the fix-shaped grammar, R2-H1 danger density) **failed to replicate**, while
every structural null held. So the cross-repo standing is: recidivism is real; structural
exposure is a size proxy whose fix-signatures are repo/discovery-specific. Still two C-family
repos — no cross-*language* or cross-ecosystem claim yet.

## Register

| id | hypothesis (registered direction) | registered | verdict | evidence |
|---|---|---|---|---|
| H1 | Security fixes reduce aggregate structural exposure vs matched controls | 2026-09-12, pre-batch | **✗ not supported (final)** — p=0.77, n=182/168 | exposure_history_report.md |
| H2 | Introducing commits raise it | same | **✗ not supported** — direction right (+0.007 vs +0.000), p=0.023 vs α=0.01 | exposure_history_report.md |
| H3 | Per-vector table names the carriers | same | **✓ `safety_score` p=0.0072** — the one vector moving its assumed direction; `tech_debt` p=0.0011 diagnosed as a density-denominator artifact | exposure_history_report.md, commit anatomy |
| D-H1 | Vulnerable functions are under-guarded relative to danger (guard rate < length-matched siblings) | 2026-09-12, pre-analysis | **✗ not supported** — metric degenerate (median 0.000 both sides: C carries no `def_safety` vocabulary at function grain) | signal_anatomy.md Phase D |
| D-H2 | The fix closes the deficit | same | **✗ not supported** — same degeneracy | signal_anatomy.md Phase D |
| M-H1..M-H3 | Multi-label signatures (classes distinguishable; security-fix vs `Fixes #` differ; follow-up-corrected fixes differ) | 2026-09-12, pre-batch | **pending** — batch not yet run | gitgalaxy#2982 Phase M |
| D-H1′ | Branch-per-danger guard deficit (the C idiom) — implicated < length-matched siblings; the fix raises it | 2026-09-12, for **repo #2 only** (post-hoc on curl) | **✗ not supported** — nDPI: implicated 0.634 vs sibling 0.600 (*wrong* direction, p=0.75); fix doesn't raise it (D-H2′ p=0.999). Non-degenerate → a real no. | ndpi_stage2.md |
| RW-H1 | Structural exposure beats LOC at ordering a 20%-LOC review budget (effort-aware, from repowise's Popt result) | 2026-09-12, pre-analysis | **✗ not supported** — 52W/48L/82T, p=0.38; exposure ≈ LOC even at ordering, on CVE labels | rw_hypotheses.md |
| RW-H2 | Prior CVE-fix count beats any static ranking (recall@budget + AUC) | 2026-09-12, pre-analysis | **✓ SUPPORTED decisively** — median recall .444 vs .000; 77W/27L vs exposure, 71W/10L vs LOC, both p<1e-4. **Recidivism is the rung-7 baseline to beat.** | rw_hypotheses.md |
| R2-H1 | Danger density marks the vulnerable function: at equal length, more pointer/danger/alloc/cast constructs than siblings | 2026-09-12, for **repo #2** (curl read p=0.032, below α — suggestive only) | **✗ not supported** — nDPI: implicated 19.0 vs sibling 20.0, p=0.47. The curl suggestion did not replicate. | ndpi_signal_anatomy.md |
| W1-H1 | Reverts are net-removal: grammar-signal deltas predominantly negative (where other classes are net-positive); median event net-LOC < 0 | 2026-09-12, pre-batch | **✓ SUPPORTED** — net-LOC median −1.0 (60 events <0 / 24 >0, sign p=5.4e-05) vs +2.0..+6.5 for every other class; net-grammar median −1.0 (57/23, p=9.2e-05); revert < control 1-sided MW p<1e-4. A clean instrument sanity check. | wave1_hypotheses.md |
| W1-H2 | Fixes that later needed a follow-up carry the fix-shaped composite at a LOWER rate than fixes that stuck (one-sided) | 2026-09-12, pre-batch | **✗ not supported** — direction wrong: needs-follow-up 0.71 (10/14) vs stuck 0.65 (110/168), Fisher p=0.77. Incomplete fixes are not structurally thinner. | wave1_hypotheses.md |
| W1-H3 | CVE-fix follow-ups carry the fix grammar (branch/pointer adds) at a rate closer to fixes than to controls | 2026-09-12, pre-batch | **✗ not supported** — follow-ups are THIN: loose (branch/ptr+) rate 0.20 (3/15), below controls (0.45) and fixes (0.71). The follow-ups are administrative (build/cmake/test), not added security logic; n=15 small. | wave1_hypotheses.md |

## What one repo taught us (the reflection)

1. **The engine's premise survived contact with ground truth.** Commit classes have
   distinct, robust structural signatures in the engine's own keyword vocabulary — the
   security-fix grammar (pointers p=0.0001, branches p=0.0004), the class-discriminating
   prevalence profiles, and one formula tracking events at p=0.007. *Structural keywords
   carry security semantics* — the correlative validation of the whole instrument, which
   matters more than any single finding's novelty.
2. **Formula shape decides temporal validity.** The one vector that moved its assumed
   direction (`safety_score`) is a credit/debit **net** over unlike-signed inputs; every
   **density** either stayed flat or produced an artifact (`tech_debt`'s denominator).
   Direct, event-grounded evidence for the score-contract program's thesis.
3. **Aggregates hide opposing physics.** Fixes add complexity (guards) while removing
   debt-density; the sum washes out. Per-vector is the layer where meaning lives.
4. **Hot files are where everything happens** — security-changed files are *not* hotter
   than ordinarily-changed files (86.2 vs 86.5 percentile, clean null). File-level
   exposure predicts activity; the discriminating questions are conditional and finer-grained.
5. **The emerging function-level profile of CVE-corrected code** (curl; the repo-#2
   prediction, not yet a claim): the functions that undergo CVE fixes are the **long**
   ones (length dominates; complexity adds nothing at equal length), **danger-dense at
   equal length** (more pointer/danger constructs per function, suggestive), in files
   where change concentrates generally; and the *corrections* arrive as **branch+pointer
   additions without new allocations or casts** — while the commits that *introduce*
   vulnerabilities are large feature additions carrying new allocs, casts, and debt
   markers. Vulnerabilities lurk a median **4.5 years** between those two moments.
6. **The guards did their job.** Two artifacts (tech_debt's denominator, the function
   length bias) were caught by the instrument's own controls before either became a slide.

## Current verdict, one sentence

After two repositories and three label families: **history predicts (recidivism,
replicated; change entropy, validated out-of-selection) and structure describes** —
every structural signal reduces to file size, the fix grammar is curl-/human-report-
specific, small-file centrality is dead and mid-band centrality is the registered
candidate — with repo #3 (openssl, fixed-side) carrying every remaining open question.

## Repo #2 (nDPI) replication battery — pre-registered 2026-09-12

Registered **while the nDPI scan was in flight (~[228]/610 commits) and before any nDPI
delta, grammar, ranking, or function-grain result had been computed** — no nDPI analysis
artifact existed at registration (epic gitgalaxy#2982, comment 5648589175). Dataset:
`events/ndpi.json` — 121 security-fix, 73 introduced (OSS-Fuzz-bisected), 111 size-matched
control; `pool_head 7787711`. nDPI uses the original three classes, so
`delta_report`/`signal_anatomy`/`rw_analyses` run unchanged.

**Correction & reporting.** Each lettered claim is one registered test at α=0.01; within a
multi-cell (per-vector) table, Bonferroni across cells; a battery-wide Bonferroni
(α=0.01/k) is reported alongside as a sensitivity. Verdicts published either way. Directions
are pre-set to curl's observed direction (legitimate — registered for unseen nDPI data).

| id | maps to (curl) | registered nDPI direction | test / α | for nulls: equivalence δ |
|---|---|---|---|---|
| **N-H3** | H3 ✓ | fixes' `risk_safety_score` Δ below controls (curl direction) | 1-sided MW, α=0.01 | — |
| **N-GRAM** | grammar ✓ | fixes net-add `struct_branch` **and** `state_pointers` vs controls | 1-sided MW ×2, Bonferroni | — |
| **N-FIXSHAPE** | fix-shaped 66/38/40 ✓ | security-fix fix-shaped rate > control **and** > introduced | 1-sided Fisher ×2, Bonferroni | — |
| **N-RW2** | RW-H2 ✓ | prior-CVE-fix count beats exposure- and LOC-ranking at recall@20%LOC + AUC | 1-sided, α=0.01 | — |
| **D-H1′** | repo-#2 reg. | implicated functions' branch-guard rate `branch/(ptr+danger+alloc+cast+1)` < loc-matched siblings; fix raises it | 1-sided MW pairs, α=0.01 | — |
| **R2-H1** | repo-#2 reg. (curl p=0.032) | at equal length, implicated functions carry more pointer/danger/alloc/cast than siblings | 1-sided MW, α=0.01 | — |
| **N-FIRST** | repo-#2 reg. | pre-event structural exposure separates first-CVE files from age/size-matched non-CVE files | AUC, α=0.01 | — |
| **N-H1** | H1 ✗ (p=0.77) | fixes' event-median structural Δ < controls | 1-sided MW, α=0.01 + effect-size CI | ±0.10 exposure units |
| **N-H2** | H2 ✗ (p=0.023) | introduced > controls | 1-sided MW, α=0.01 + effect-size CI | ±0.10 exposure units |
| **N-RW1** | RW-H1 ✗ | exposure recall@20%LOC > LOC recall@budget | 1-sided, α=0.01 + effect-size CI | ±0.05 recall |

**Null-replication rule (N-H1/N-H2/N-RW1):** "null replicated" is declared only if BOTH
(a) non-significant at α=0.01 in curl's direction AND (b) the effect's 95% CI lies within δ
(TOST/equivalence) — a repeated p>α on nDPI's smaller n is otherwise just lower power. A
**flip to significant is reported as a new signal**, not hidden.

**Explicitly NOT a clean replication on nDPI** (reported as contrast, not pass/fail):
dwell time (nDPI median lurk ≈ weeks under continuous fuzzing vs curl's 4.5 years — a
different discovery population); **D-H1 verbatim** (degenerate at C function grain — subsumed
by D-H1′); **Phase M / wave-1 classes** (revert, cve-followup — no such labels in the
OSS-Fuzz set).

## Mechanism-matched specificity battery — pre-registered 2026-09-12 (for unseen data)

The engine's exposure vectors are named for what they *should* mark (crypto, IO, concurrency,
memory-danger…). The stronger claim than "exposure ≈ CVEs" is **specificity**: the *right*
vector marks the *right* failure type, and it does so **beyond a line count**. These are
registered from curl's *exploratory* CWE×vector table, so — per protocol rule 3 — they are
**never scored on curl's full table that suggested them**. They evaluate on **unseen data**:
a CWE-labeled repo #3 (below), or a held-out curl temporal split (register on pre-2020 CVEs,
test on post-2020). curl's failure supply (323 CWE-labeled events) gives the families power;
the two named vectors that curl *can't* test are called out.

Each signal set is the engine's raw keyword columns. Metric = **defect-lift beyond size**:
AUC(signal | matched controls) and, one-sided, AUC(signal) > AUC(LOC) — the bar
gitgalaxy#2987 sets for a signal to earn a gated formula slot. α=0.01, Bonferroni across the
family.

| id | failure family (example CWEs) | matched signal set | registered direction |
|---|---|---|---|
| **S-H1** | memory-safety (126/416/122/125/415/121/124/787) | `state_pointers + state_memory_alloc + state_cast_hits + state_danger` | memory-CVE functions carry more, at equal length, than matched non-CVE siblings **and** than non-memory CVE functions; AUC > LOC |
| **S-H2** | cert/auth (295/297/305/294/299) | `arch_crypto + def_auth` | cert/auth-CVE files carry more than matched controls **and** than non-auth CVE files; AUC > LOC |
| **S-H3** | info-leak (200/201/319/488/522) | `arch_io + api_exposure` | leak-CVE files carry more egress surface than matched controls **and** than non-leak CVE files; AUC > LOC |
| **S-H4** | concurrency (362/367) — *repo-#3 dependent* | `arch_concurrency + def_sync_locks` | race/TOCTOU-CVE functions carry more than matched controls; AUC > LOC. **Untestable on curl** (single-threaded, ~0 such CVEs) — requires a concurrency-bearing repo |
| **S-H0** | *the discriminant* | all four sets | the family→best-matched-signal **confusion matrix is diagonal** — each family's own set ranks its own failures above other families'. This is the real specificity claim: the vectors are specific, not one undifferentiated "danger" blob |

Failure verdicts published either way. A vector that lifts *generally* but is **not** specific
(S-H0 off-diagonal) is itself a finding — it would mean "danger" is one blob, not a set of
mechanism-specific signals, and it caps what the score-contract program can gate.

### Repo-#3 selection criteria (this battery drives them)
Beyond the repo-#2 hard criteria (OSV GIT ranges with introduced+fixed, ≥50 events,
GitGalaxy-supported language, full history), repo #3 must add what curl and nDPI each lack:
- **CWE labels on the vulnerability data** — *required* for any mechanism-matched test.
  nDPI's OSS-Fuzz feed has none, so nDPI runs the general battery only, never S-H*.
- **Concurrency-bearing with real race/TOCTOU CVEs** — for S-H4 (curl has ~none).
- **Mixed network / non-network CVEs** — so S-H3's IO test has a contrast (curl is
  all-network: no non-IO group to separate against).
Candidates to weigh against these: redis, postgres, nginx (concurrency + mixed surface),
a managed-language service; openssl only if its `CHANGES.md` CVE→PR trail is parsed to real
fix commits (its OSV SHAs are version-tag proxies — see docs/repo2_survey.md).

### Held-out curl result — 2026-09-12 (split at median fix-date 2022-06-25; test half only)

Full detail: `docs/specificity_curl_heldout.md` (tool: `tools/specificity_split.py`).

| id | verdict | evidence |
|---|---|---|
| **S-H1** memory ↔ danger cluster | **✗ not supported (genuine null)** — signal well-populated (state_pointers 70% nonzero) yet AUC ties LOC (0.588 vs 0.590); no defect-lift out-of-sample | specificity_curl_heldout.md |
| **S-H3** info-leak ↔ arch_io/arch_api | **✗ not supported (genuine null)** — populated; AUC 0.54 vs LOC 0.57; no lift | specificity_curl_heldout.md |
| **S-H2** cert/auth ↔ arch_crypto/def_auth | **⚠ degenerate — no verdict** — `def_auth` is 0 across all 1.05M rows, `arch_crypto` 0.1%; the matched signal is absent (D-H1-class vocabulary gap), AUC pins at 0.509. Untestable on curl; deferred to a repo with live crypto/auth vocabulary | specificity_curl_heldout.md |
| **S-H0** the discriminant (diagonal?) | **✗ not supported** (caveat: cert/auth column dead) — among the *live* signal-sets the **memory** set ranks highest even for info-leak's positives; the populated "danger" signals read as a general code-mass proxy, not mechanism-specific | specificity_curl_heldout.md |

**Reading.** Predicting *which* file gets *which* CVE from pre-event structural *standing*
does not work on curl (coheres with H1/RW-H1: standing ≈ LOC) — the real security signal is
in the fix **delta/grammar**, not standing. cert/auth couldn't be tested (dead vocabulary),
which is itself an engine signal: `def_auth`/`arch_crypto` under-fire on C (cf.
gitgalaxy#2984/#2979). This is a *within-curl temporal* result; the independent cross-repo
test remains repo #3 — and it must carry live crypto/auth + concurrency vocabulary.

## Repo #2 (nDPI) replication — RESULTS (2026-09-12)

Ran the pre-registered nDPI battery (epic gitgalaxy#2982, comment 5648589175) on the fresh
nDPI scan (112 security-fix / 68 introduced / 96 control usable events; 555 snapshots).
Reports: `docs/ndpi_exposure_report.md`, `docs/ndpi_signal_anatomy.md`, `docs/ndpi_rw.md`.

| id | curl | nDPI | cross-repo verdict |
|---|---|---|---|
| N-H1 aggregate exposure | null (0.77) | null (**0.70**) | ✅ null replicates |
| N-H2 introduced raises | null (0.023) | null (**0.37**) | ✅ null replicates |
| N-RW1 exposure > LOC @budget | null | null (**0.60**, W/L/T 8/8/96) | ✅ null replicates |
| N-H3 `safety_score` tracks | ✓ (0.0072) | **✗ (0.71)**, all vectors flat | ❌ **fails to replicate** |
| N-GRAM fix grammar (branch/ptr adds) | ✓ (0.0004/0.0001) | **✗** (struct_branch 0.28, state_pointers 0.079) | ❌ **fails** |
| N-FIXSHAPE fix-shaped signature | ✓ 66/38/40 differential | **✗ 58/59/59** (no differential) | ❌ **fails** |
| R2-H1 danger density (equal length) | suggestive (0.032) | **✗ (0.47)**, implicated 19 vs sibling 20 | ❌ **fails** |
| D-H1/D-H2 guard deficit | degenerate | degenerate (**0.70**) | ➖ degeneracy replicates |
| N-RW2 recidivism beats static | ✓✓ | **✓✓ (p<1e-4 vs exposure and vs LOC)** | ✅ **replicates** |

**The verdict after two repositories:** the only *positive* that replicates is **recidivism**
(N-RW2) — a file's prior-CVE-fix count beats every structural ranking, decisively, on both
repos. Every **structural** signature curl showed — the `safety_score` vector (H3), the
fix-shaped branch/pointer grammar (N-GRAM/N-FIXSHAPE), and the danger-density function
profile (R2-H1) — **fails to replicate on nDPI.** And every structural **null** (aggregate
exposure, exposure-vs-LOC) holds on both.

**Why the structural signatures collapsed:** nDPI's CVEs are OSS-Fuzz-discovered, and its
fixes are *tiny* — median event net-LOC **+1** vs curl's +6 — minimal bounds-checks that
barely move any signal (function-grain values are non-degenerate: implicated functions
n=243, complexity 22 vs 3, so the DB is populated; the fixes simply don't add branch/pointer
*grammar* the way curl's user-reported-CVE fixes did). This is the pre-registered
discovery-population contrast made real: **curl's fix-shaped grammar was a property of
user-reported CVE fixes, not a cross-repo law.** The emerging function profile (register
reflection #5) is therefore **withdrawn as a cross-repo claim** — length dominates on nDPI
too (length-bias gate: complexity 17 vs 15, p=0.39), but danger-density does not separate.

Stage-2 items still owed (need new code, verdicts pending): D-H1′ (branch-guard variant),
N-FIRST (first-CVE AUC), and the equivalence/TOST CIs formalizing the three replicated
nulls. Given the grammar collapsed, D-H1′ and N-FIRST are expected null; they will be
evaluated and published regardless.

**What this sharpens:** structural exposure is a general size/activity proxy whose
event-signatures are repo- and discovery-specific; the durable, cross-repo predictive law is
**recidivism** (history beats structure). That is the rung-7 baseline, now confirmed twice.

### Stage-2 (D-H1′, N-FIRST, equivalence CIs) — 2026-09-12

Detail: `docs/ndpi_stage2.md` (tool: `tools/ndpi_stage2.py`).

- **D-H1′ / D-H2′ (branch-per-danger guard deficit, nDPI): ✗ not supported.** Guard rate
  `struct_branch/(ptr+danger+alloc+cast+1)` — implicated functions 0.634 vs siblings 0.600
  (p=0.75, *wrong* direction); the fix doesn't raise it (D-H2′ null). Non-degenerate this time
  (branch-guards exist where `def_safety` didn't), so a real "no", not a vocabulary artifact.
- **Equivalence (TOST) on the three replicated nulls (nDPI): all ✓ EQUIVALENT-NULL.** N-H1
  effect 0.000, 95% CI [0, 0.0008] ⊂ ±0.10; N-H2 0.000, CI [−0.011, 0.039] ⊂ ±0.10; N-RW1
  0.000, CI [0, 0] ⊂ ±0.05. The nulls are **confirmed near-zero**, not merely underpowered —
  the structural nulls genuinely replicate.
- **N-FIRST (first-CVE profile, nDPI): ✓ SUPPORTED — but the mechanism is CENTRALITY, not
  fine structure.** Structural exposure separates first-CVE files from size-matched clean files
  (AUC 0.755). Orchestrator verification: that raw AUC is inflated — the [0.66,1.5]× LOC match
  is loose (positives +25 LOC larger within the band) and AUC(LOC)≈0.50 is forced by matching,
  so the "+0.25 over LOC" is circular. Dividing size out, a real component survives
  (**AUC(density) 0.624, density-win 78%**) — carried by *total* exposure (`api_exposure`/
  **centrality**) against *peripheral* never-CVE files: the hot-files effect (reflection #4)
  that also drives recidivism, **not** the fine danger-structure the density/specificity tests
  killed (memory density-win 43%). curl context far weaker (density-win 62%). So the file that
  gets its *first* bug is a **central/hot** one — a genuine but coarse signal, to be cleanly
  separated from residual size + activity by tighter matching + a per-vector decomposition,
  **registered for repo #3.**

**Net after Stage 2:** the two-repo picture is unchanged and now airtight — recidivism is the
lone replicated positive; aggregate/fine-structural exposure is size (the three nulls are
*equivalence-confirmed*); and the only "structure predicts the first bug" signal that survives
is **centrality**, which is the same hot-files axis, not a new structural predictor.

### G-H1 / G-H2 — the LOC-floor grammar re-test (2026-09-12)

Registered on gitgalaxy#2982 (comment 5649412476) **before any floor-restricted statistic was
computed**; only the fix-size distributions were inspected to set the floors. The question:
the cross-repo grammar failure was confounded with fix size (nDPI fixes median net-LOC +1 vs
curl +6) — a one-line bounds-check cannot express a structural signature. Restricting BOTH
repos to fixes above a churn floor de-confounds them. Detail: `docs/grammar_floor.md`
(tool: `tools/grammar_floor.py`).

| id | verdict | evidence |
|---|---|---|
| **G-H2** curl's grammar survives the floor | **✓ SUPPORTED** | persists at ≥5 (branch p=0.0001) and ≥10 (p=0.0008, n=115/108); fix-shaped composite 72%/39% and 69%/37%; thins only at ≥20 where n=72 halves power. **Not** an artifact of tiny commits. |
| **G-H1** the grammar returns on nDPI under a size floor | **✗ not supported** | no floor revives it — at ≥10 (n=50/46) branch p=0.44, `state_pointers` p=0.93 (*wrong* direction), fix-shaped composite **68% fix vs 67% control** (no differential). |

**This is pre-registered outcome (b): fix size is NOT the explanation.** The grammar is
**genuinely curl-specific** — a property of *human-reported CVE fixes*, not a consequence of
nDPI's small commits. Conservative detail: nDPI's controls are *larger* than its fixes at
every floor (median net-LOC 3.0 vs 4.8 at ≥10), so the fixes were not size-handicapped.

**What remains open.** With size eliminated, the surviving explanation for the curl↔nDPI
divergence is **discovery process** (human-reported vs fuzzer-found). That cannot be tested by
comparing repos — repo is confounded with language, era, and team — it requires **both
provenance classes inside one repository** (e.g. curl commits fixing OSS-Fuzz/ASAN findings vs
curl commits fixing human-reported CVEs, labeled from commit-message provenance). Registered
as the next experiment; until it runs, the fix-grammar stands as **single-repo, single-
discovery-process, and explicitly not general**.

## HCM variant sweep + centrality bands — results (2026-09-12/13)

**HV-H1/HV-H2 — the Hassan HCM family** (registered epic comment 5649866008; detail
`docs/hcm_variants.md`). 36 variants (attribution × decay × period) + repowise's flavour,
evaluated size-orthogonally on curl CVE labels:

| id | verdict | evidence |
|---|---|---|
| **HV-H1** a variant clears the size wall (≥3/4 LOC bands) | **✗ not supported** — best variant `HCM1_LD_30` clears 2/4 (Q3 0.771, Q4 0.803); same monotone wall shape as repowise's | hcm_variants.md |
| **HV-H2** best variant beats LOC pooled | **⚠ supported-as-computed (lift +0.0238, lo +0.0050) but DISCOUNTED — selected best-of-36 and tested on the same data**; out-of-selection validation registered as B-H3 | hcm_variants.md |

Robust family pattern regardless of the winner: all top-8 are HCM1 (share-weighted), 30-day
periods beat 90/180d, and HCM2/HCM3 at 180d are *worse than a line count* (−0.10..−0.15).
repowise's shipped shape was near-optimal (rank ~6, lift +0.0192) — their choice was sound.

**C-H1/C-H2 — centrality in the small-file regime** (registered 5650157545; per-cell
checkpoint cache, full doc regenerating):

| id | verdict | evidence |
|---|---|---|
| **C-H1** centrality beats LOC in small bands | **⚠ NOT EVALUABLE on curl** — the small bands are unpowered by the data itself: ≤22-LOC has **1** CVE positive, 23–48 has **4**; the ≥20-positive rule refuses verdicts (without it we'd quote AUC 0.999 off one positive) | centrality cache / centrality_bands.md |
| **C-H2** lift monotone-decreasing with size | **suggestive, no verdict** — PageRank lift +0.458 → +0.320 → +0.154 → **−0.271**, perfectly monotone (repowise's shape), but the small end is unpowered | same |

Solid negative within this: **in >108-LOC files (433 positives) PageRank is far worse than a
line count** (0.525 vs 0.796) — centrality is not a large-file ranking signal.

## Overnight bug-label expansion (B-H1..B-H3) — registered 2026-09-13, batch in flight

Mirror of epic comment 5651082895 (registered **before the sample was drawn**). Purpose:
power the small-file bands with labels that actually land in small files (CVE fixes don't),
and provide selection-free validation data. Sample (seed 2982): ALL `regression` commits +
500 uniform from `Fixes #` + 300 from `Bug:`; SHAs already scanned excluded; multi-label
kept. Drawn: **1,107 unique events** (307 regression / 500 fixes / 300 bug; census after
exclusions 1,915 / 1,195 / 307 — the registration's parenthetical "(census 154)" for
regression was a case-sensitive undercount; the registered case-insensitive rule stands).
Batch: `dbs/bugs_batch.log`, ≤2,214 scans ≈ 6.4 h, resumable by construction.

| id | claim (α=0.01; ≥20-positives power rule) | status |
|---|---|---|
| **B-H1** | on bug-label positives, ≥1 centrality measure beats LOC (AUC>0.5, lift lo>0) within each powered small band (≤22, 23–48); Bonferroni 5×bands | **pending scans** |
| **B-H2** | PageRank lift decreases across all four bands in ≥99% of 5,000 event-bootstraps | **pending** |
| **B-H3** | `HCM1_LD_30` (frozen from the CVE-label selection) has pooled lift>0 over LOC on bug labels — fresh labels, no selection problem | **pending** |

Priors registered in advance: B-H1 uncertain (the live lead), B-H2 expected supported,
B-H3 expected shrunken-but-positive. Exploratory alongside (no verdicts): per-class grammar
profiles (CVE vs Fixes# vs Bug: vs regression — the Phase-M question).

## B-H1..B-H3 — results (2026-09-13; registration epic comment 5651082895)

957 usable bug-label events, 767,591 pooled files, 1,900 positives; **both small bands
powered** (28 / 42 positives). Detail: `docs/bh_eval.md` (tool `tools/bh_eval.py`,
numpy-parallel, per-cell checkpointed).

| id | verdict | evidence |
|---|---|---|
| **B-H1** small-file centrality | **✗ not supported** — with real power the small-file story dies: PageRank ≤22 *inverted* (AUC 0.259); 23–48 n.s. | bh_eval.md |
| **B-H2** monotone lift shape | **✗ not supported, decisively** — frac_monotone 0.0000/5000; the true shape is an **inverted U** (lifts −0.047 / +0.017 / +0.145 / −0.253). The CVE-label "perfect monotone" was an unpowered-band artifact | bh_eval.md |
| **B-H3** HCM selection-free validation | **✓ SUPPORTED** — `HCM1_LD_30` frozen from the CVE selection, fresh bug labels: AUC 0.868 vs LOC 0.830, lift **+0.0379** (lo +0.0211). **The second genuine positive after recidivism**, and the first *feature* to beat a line count out-of-selection | bh_eval.md |

**Exploratory (context cells, outside the registered family — registered for repo #3, not
claimed):** the 49–108 mid-band carries two robust centrality cells (PageRank lift +0.145
lo +0.020; popularity +0.132 lo +0.025). Mid-band, not small-file, is the surviving
centrality candidate.

**Program standing after the bug-label expansion:** surviving predictors = **recidivism**
(replicated, 2 repos) + **change entropy (HCM1_LD_30)** (selection-free, single-repo until
repo #3). Centrality small-file: dead. Structure/keywords as predictors: size, everywhere.

## Repo-#3 survey — 2026-09-13 (docs/repo3_survey.md)

No candidate clears all five criteria. **Primary: openssl, fixed-side-only** — CWE joinable
via NVD (5/5), human-reported fixes (median ≈+13 net LOC), confirmed race CVEs (S-H4
testable at last), mixed network/non-network surface (S-H3 contrast); introduced-side 0%.
Its CHANGES/commit trail is parseable (9/10 sampled resolve to diff-verified fix commits) —
reversing repo-2's future-work flag. **Version-proxy diff-check failed** nginx, sqlite,
systemd, imagemagick, netty, tensorflow-partially, and **vim** (worst mode found yet:
real-looking SHAs pointing at *unrelated* commits). Sleeper lead: **kernel subsystem-scoped
harvest** (net/ ≈43s/scan, fs/ ≈32s) — the only gold-standard introduced-side at tractable
cost; unexplored.

## X-H1 / X-H2 — registered 2026-09-13 from the keyword-pools exploration (unseen data only)

Mirror of epic comment 5653744144. Both derive from `docs/keyword_pools_explore.md`
(post-hoc) and are therefore never scored on curl.

| id | claim (α=0.01) | evaluates on |
|---|---|---|
| **X-H1** | "Unpaired allocation" (net-add `state_memory_alloc` with `def_cleanup` delta ≤ 0) is enriched among vulnerability-**introducing** commits vs paired-allocation commits; one-sided Fisher | a genuine introduced-side corpus (kernel-subsystem harvest, tc#27) |
| **X-H2** | The fix-grammar **gradient** replicates: fix-shaped rate orders security-fix > ordinary bug-fix > control (two one-sided Fishers, Bonferroni ×2) | openssl (repo #3, tc#26) |

Motivation on record: the `state_memory_alloc`+`def_cleanup` pair co-moves at ρ=0.85 while
nearly size-independent (ρ=0.25 vs net-LOC) — breaking the pairing is the anomaly; and the
8-class table orders 66/53/48/46/38/20/13, replacing the retired binary "grammar is
CVE-specific" claim with a gradient.

## What precisely was falsified — the scoping statement (2026-09-13)

The program's negative results share four assumptions, and the falsification applies to
their **conjunction**, not to "structure relates to risk" in general:

> risk as a property of a **file**, in **isolation**, as a standing **level**, scored by
> marker **abundance**.

Every dead test instantiated all four (pooled, density-normalized, length-matched, banded,
multivariate, and trajectory variants alike). What was **validated** at the same time: the
markers annotate *activity* (the x-ray — what a function is involved in), and marker
*changes* characterize *events* (fix-vs-nonfix at patch grain; allocation-at-introduction
51% vs 5–10%). Analogy on record: protein domains annotate function, not pathology;
pathology is dosage, context, and interaction partners — we scored domain counts per gene
and called the count a disease score.

**What remains untested — hypothesis 3 restated one level up (tc#37):** risk as a *system*
property — module-level dosage/thresholds (SYS-1), marker *dispersion* across files
(SYS-2), system-level discipline trajectories (SYS-3), cross-file responsibility splits
(INT-1), marker×process conjunctions (INT-3), and neighborhood/graph interactions (INT-2,
blocked on edge persistence, gitgalaxy#2992). Mandatory guard carried forward: module-LOC
controls in every SYS design, since aggregation can re-manufacture the size confound one
level up. Engine-side consequence tracked as gitgalaxy#2991 (descriptive-layer reform +
separate gated predictive layer).
