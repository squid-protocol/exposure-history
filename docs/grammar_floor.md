# G-H1 / G-H2 — does the fix grammar return when fix SIZE is controlled?

Pre-registered on gitgalaxy#2982 (comment 5649412476) **before any floor-restricted statistic was computed**. Churn = added+deleted lines excluding docs/tests. Grammar recomputed exactly as `signal_anatomy.py` §1 (per-event mean signal delta over touched files; one-sided MW in the registered direction: fixes ADD). α=0.01, Bonferroni ×2 over the two signals. Floor 0 = unrestricted baseline.

## curl

| floor | n fix | n ctrl | median net-LOC fix / ctrl | struct_branch fix Δ / ctrl Δ | p | state_pointers fix Δ / ctrl Δ | p | fix-shaped % fix / ctrl |
|---|---|---|---|---|---|---|---|---|
| ≥0 | 182 | 168 | +3.0 / +2.0 | +0.73 / +0.00 | 0.0004 | +0.33 / +0.00 | 0.0001 | 66% / 38% |
| ≥5 | 149 | 140 | +4.0 / +3.0 | +1.00 / +0.00 | 0.0001 | +0.75 / +0.00 | 0.0004 | 72% / 39% |
| ≥10 | 115 | 108 | +5.0 / +2.1 | +1.00 / +0.00 | 0.0008 | +1.00 / +0.00 | 0.0065 | 69% / 37% |
| ≥20 | 72 | 70 | +4.5 / +4.0 | +0.63 / +0.00 | 0.0315 | +0.73 / +0.00 | 0.1609 | 65% / 37% |

## ndpi

| floor | n fix | n ctrl | median net-LOC fix / ctrl | struct_branch fix Δ / ctrl Δ | p | state_pointers fix Δ / ctrl Δ | p | fix-shaped % fix / ctrl |
|---|---|---|---|---|---|---|---|---|
| ≥0 | 112 | 96 | +1.0 / +2.0 | +0.54 / +0.00 | 0.2843 | +0.00 / +0.00 | 0.9214 | 58% / 59% |
| ≥5 | 69 | 61 | +1.5 / +4.7 | +1.00 / +0.50 | 0.2826 | +0.00 / +0.50 | 0.9239 | 68% / 64% |
| ≥10 | 50 | 46 | +3.0 / +4.8 | +1.00 / +1.00 | 0.4352 | +0.00 / +1.00 | 0.9342 | 68% / 67% |
| ≥20 | 30 | 27 | +5.7 / +8.0 | +1.00 / +2.00 | 0.7745 | +0.00 / +3.00 | 0.9846 | 63% / 81% |

## Verdicts (floor ≥10, the registered decision point)

- curl (n=115 fix / 108 ctrl): **G-H2: SUPPORTED (curl's grammar survives)** — struct_branch p=0.0008, state_pointers p=0.0065 (Bonferroni-corrected bar p<0.005). curl's effect persists with small fixes removed, so it is not an artifact of tiny commits.
- ndpi (n=50 fix / 46 ctrl): **G-H1: not supported** — struct_branch p=0.4352, state_pointers p=0.9342 (Bonferroni-corrected bar p<0.005). the grammar does NOT return once fix size is controlled — the nDPI failure is not a fix-size artifact.

**Reading (interpretation set in advance, outcome (b)):** the grammar does not return on nDPI at any floor — at ≥10 the fix-shaped composite is 68% fix vs 67% control, and `state_pointers` runs the *wrong* way (p=0.93). Meanwhile curl's grammar persists at ≥5 and ≥10 (branch p=0.0001/0.0008; composite 72%/69% vs 39%/37%), thinning only at ≥20 where n=72 halves the power. **Fix size is therefore NOT the explanation for the cross-repo failure** — the grammar is genuinely curl-specific (a property of human-reported CVE fixes), not an artifact of nDPI's small commits. Note nDPI's controls are *larger* than its fixes at every floor (median net-LOC 3.0 vs 4.8 at ≥10), so if anything the comparison is conservative against the fixes.

---
*Regenerate: `python tools/grammar_floor.py`. Stdlib only; DB read-only, WAL-aware.*
