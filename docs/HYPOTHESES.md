# The hypothesis ledger

## The plain-language summary (read this first)

**What we did:** took 25 years of curl's security history (every CVE's fix commit and the
commit that introduced it), scanned the repository at each of those moments, and asked
whether GitGalaxy's measurements know anything about where security bugs live and what
fixing them looks like. Every question was written down as a prediction *before* looking.

**What we learned, in plain terms:**

1. **The best predictor of the next security bug is where the last one was.** A reviewer
   inspecting 20% of the codebase catches ~44% of future CVE files by revisiting past-CVE
   files — and ~0% by following our risk score or file size. History wins, decisively.
2. **Our per-file risk totals don't beat a line count** at finding or ranking CVE files.
   Neither does anyone else's — the leading commercial tools tie a line count too.
3. **But the raw ingredients carry real signal.** Security fixes have a recognizable shape
   (added pointer-handling and branching, without the new allocations that mark feature
   code); one formula built the contract-recommended way (`safety_score`) genuinely tracks
   fixes; and the functions that get CVE fixes are the long, danger-dense ones. The pieces
   know things the sum washes out.
4. **Vulnerabilities lurk ~4.5 years** between being written and being fixed — a huge
   window for any early warning to matter.
5. **The negative controls behave.** Reverts measurably *remove* structure (the instrument's
   sanity check — passed); and CVE-fix *follow-ups* turn out to be administrative (build /
   cmake / test fixes), not more security logic — so neither "incomplete fixes look thinner"
   nor "follow-ups finish the job" held. Two more registered predictions died on contact; the
   record keeps working.

**What this points at:** the question worth owning is not "rank everything by risk"
(history wins that) but **"which file gets its *first* security bug?"** — where history is
blind and only structure can answer. That prediction is registered below, awaiting a
second repository.


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

**One repository: curl** (C-dominant, ~39.7k commits, 25 years). Events: 186 CVE-fix +
137 CVE-introducing commits from curl's OSV feed (GIT ranges, 0 unresolvable SHAs) +
185 size-matched controls; 1,014 full snapshots scanned; ~3.4M per-function measurements.
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
| D-H1′ | Branch-per-danger guard deficit (the C idiom) — implicated < length-matched siblings; the fix raises it | 2026-09-12, for **repo #2 only** (post-hoc on curl) | **pending repo #2** | gitgalaxy#2982 Phase D result |
| RW-H1 | Structural exposure beats LOC at ordering a 20%-LOC review budget (effort-aware, from repowise's Popt result) | 2026-09-12, pre-analysis | **✗ not supported** — 52W/48L/82T, p=0.38; exposure ≈ LOC even at ordering, on CVE labels | rw_hypotheses.md |
| RW-H2 | Prior CVE-fix count beats any static ranking (recall@budget + AUC) | 2026-09-12, pre-analysis | **✓ SUPPORTED decisively** — median recall .444 vs .000; 77W/27L vs exposure, 71W/10L vs LOC, both p<1e-4. **Recidivism is the rung-7 baseline to beat.** | rw_hypotheses.md |
| R2-H1 | Danger density marks the vulnerable function: at equal length, more pointer/danger/alloc/cast constructs than siblings | 2026-09-12, for **repo #2** (curl read p=0.032, below α — suggestive only) | **pending repo #2** | signal_anatomy.md Phase D control row |
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

After one repository: the signal layer and contract-shaped formulas correlate with real
security events; aggregate exposure does not; the specific function-level profile of
CVE-prone code is registered as a prediction awaiting repo #2 — which is the program's
single highest-value next step.

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
