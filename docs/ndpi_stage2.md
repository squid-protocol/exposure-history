# nDPI Stage-2 — N-FIRST, D-H1', equivalence CIs

Stage-2 of the nDPI replication battery (gitgalaxy#2982, comment 5648589175; flagged as owed in `docs/HYPOTHESES.md` "Repo #2 (nDPI) replication — RESULTS"). Pre-registered; implemented verbatim; verdicts publish either way. DB opened read-only, WAL-aware (`file:{db}?mode=ro`). Bootstraps: seed 2982, 5000 iterations.

## N-FIRST — the first-CVE file profile

Registered: among files at their FIRST CVE (security-fix) event, pre-event structural exposure separates them from size-matched never-CVE files better than chance (AUC). Positive = that file's parent-snapshot structural exposure (sum of `risk_<STRUCTURAL_COLUMNS>`) and `total_loc`; negative = a never-CVE file (never touched by any security-fix or introduced event, at any snapshot) from the same parent snapshot, size-matched within [0.66, 1.5]x total_loc (falling back to the date-nearest fix-event snapshot when the same snapshot has no candidate in range). **Age-matching is omitted** — no file-birth-time data is captured by this harness — a limitation of this test, not a design choice; report accordingly.

Verdict rule: SUPPORTED iff AUC(exposure) > 0.5 AND the one-sided bootstrap lower bound at alpha=0.01 (1st percentile) excludes 0.5. A descriptive (two-sided) 95% CI is also shown.

| repo | role | first-CVE files | positives scanned | matched pairs (same/nearby/unmatched) | AUC(exposure) | AUC(LOC) | lift (expo−LOC) | verdict-bound lo (α=0.01) | 95% CI | verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| nDPI (verdict) | VERDICT | 602 | 158 | 152/4/2 | 0.7551 | 0.5005 | 0.2546 | 0.6890 | [0.6983, 0.8094] | **SUPPORTED** |
| curl (EXPLORATORY) | context | 248 | 185 | 179/6/0 | 0.6121 | 0.5021 | 0.1100 | 0.5495 | [0.5589, 0.6638] | **SUPPORTED** |

nDPI: 444 first-CVE files had no scanned parent-row (excluded); skip reasons {}. curl: 63 missing-scan; skip reasons {'introduced: root-commit': 1}. Bootstrap lift 95% CI — nDPI [0.1976, 0.3085], curl [0.0565, 0.1611].

**N-FIRST (nDPI, the verdict): SUPPORTED — but the mechanism is centrality, not fine structure (orchestrator verification).** The raw AUC(exposure)=0.755 is inflated: the [0.66,1.5]× LOC match is loose (positives are **+25.4 LOC larger within the band**) and AUC(LOC)≈0.50 is forced by the matching, so the "+0.25 lift over LOC" is circular. Dividing size out, a **real beyond-size component survives** — AUC(density)=**0.624**, paired density-win **78%** — but it is carried by *total* structural exposure, which is dominated by `api_exposure`/**centrality**, tested against *peripheral* never-CVE files. This is the known **hot-files effect** (reflection #4) that also underlies recidivism — **not** the fine danger-structure signal, which the density/specificity tests independently killed (memory density-win 43%). curl context is much weaker (density-win 62%, AUC-density 0.549). So the "which file gets its first bug?" answer is **the central/hot files** — a genuine but coarse (centrality) signal, on-thesis with the program, and to be cleanly separated from residual size and from activity by tighter matching + a per-vector decomposition, registered for repo #3. curl reading is **EXPLORATORY context only** — never a confirmatory test.

## D-H1' / D-H2' — branch-per-danger guard deficit (function grain, nDPI)

Registered: guard rate = `struct_branch / (state_pointers + state_danger + state_memory_alloc + state_cast_hits + 1)`. D-H1': implicated functions (overlap the fix's changed parent-side lines) carry a LOWER rate than length-matched same-file siblings ([0.66, 1.5]x loc, same pairing gate as `signal_anatomy.py` Phase D). D-H2': the fix RAISES the implicated function's rate more than the sibling's (surviving, same-named functions only). One-sided MW, α=0.01.

| metric | implicated median | sibling median | n pairs | p (one-sided) | verdict |
|---|---|---|---|---|---|
| guard rate (D-H1') | 0.634 | 0.600 | 149 | 0.7452 | **not supported** |
| danger load (control) | 19.0 | 20.0 | 149 | 0.4729 | (context only) |
| guard-rate change after fix (D-H2') | 0.0000 (n=149) | 0.0000 (n=149) | 149 | 0.0000 | **not supported** |

Events contributing an implicated function: 109; touched files with a hit: 304.

**D-H1': not supported · D-H2': not supported** (α=0.01, nDPI is the verdict repo for this test).

## Equivalence (TOST) read on the three replicated nulls (nDPI)

For each: effect size + bootstrap 95% CI (percentile, seed 2982, n=5000). "Null replicated (equivalent)" iff BOTH (a) non-significant at α=0.01 in curl's registered direction, AND (b) the 95% CI lies entirely within the pre-set δ. A flip to significant would be reported as a new signal, not hidden.

| id | effect | n's | p (registered direction) | 95% CI | δ | equivalent? |
|---|---|---|---|---|---|---|
| **N-H1** median(fix Δ) − median(ctrl Δ) | 0.0000 | fix=112, ctrl=96 | 0.6978 | [0.0000, 0.0008] | ±0.10 | **equivalent-null** |
| **N-H2** median(intro Δ) − median(ctrl Δ) | 0.0000 | intro=68, ctrl=96 | 0.3670 | [-0.0110, 0.0388] | ±0.10 | **equivalent-null** |
| **N-RW1** median(recall_expo − recall_LOC) | 0.0000 | events=112 (W/L/T 8/8/96) | 0.5982 | [0.0000, 0.0000] | ±0.05 | **equivalent-null** |

Skipped events (no usable touched-file diff): {'introduced': 5, 'security-fix': 9, 'control': 15}.

---
*Regenerate: `python tools/ndpi_stage2.py` — stdlib only, reads only the events files and the read-only history DBs; deterministic given `--seed` (default 2982) and `--iters` (default 5000, floor 5000).*
