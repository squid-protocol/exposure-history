# The hypothesis ledger

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
Every "supported" below is therefore a **single-project result** until repo #2 replicates
it. Nothing here is yet a cross-language or cross-ecosystem claim.

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
| R2-H1 | Danger density marks the vulnerable function: at equal length, more pointer/danger/alloc/cast constructs than siblings | 2026-09-12, for **repo #2** (curl read p=0.032, below α — suggestive only) | **pending repo #2** | signal_anatomy.md Phase D control row |

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
