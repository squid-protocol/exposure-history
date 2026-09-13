# RW-H1 / RW-H2 — ndpi

Registered on gitgalaxy#2982 before this tool ran; evaluated on existing snapshots only. Fix events analyzed: 112 (median implicated files/event: 1).

## RW-H1 — does exposure beat LOC at ordering a 20%-LOC review budget?

| ranking | median recall@20%LOC | pooled AUC (descriptive) |
|---|---|---|
| structural exposure | 0.000 | 0.734 |
| LOC | 0.000 | 0.781 |

Paired per event: exposure wins 8, LOC wins 8, ties 96 (ties = both rankings catch/miss the same files). One-sided sign test p = 0.5982. **RW-H1: not supported** (α=0.01, direction exposure > LOC).

## RW-H2 — is prior CVE-fix history the baseline to beat? (events with ≥5 prior fixes: n=107)

| ranking | median recall@20%LOC | pooled AUC |
|---|---|---|
| prior CVE-fix count | 0.500 | 0.678 |
| structural exposure | 0.000 | 0.738 |
| LOC | 0.000 | 0.779 |

Paired: prior vs exposure — wins 42, losses 8, p = 0.0000; prior vs LOC — wins 40, losses 2, p = 0.0000. **RW-H2: SUPPORTED** (α=0.01, both comparisons, direction prior > static).

Limits: recalls are coarse (few implicated files/event); prior counts follow paths (renames break lineage, handicapping the baseline); prior ties break neutrally by path. Pooled AUCs are descriptive (repeated files across snapshots), the paired tests are the registered readings.

