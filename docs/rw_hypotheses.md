# RW-H1 / RW-H2 — curl

Registered on gitgalaxy#2982 before this tool ran; evaluated on existing snapshots only. Fix events analyzed: 182 (median implicated files/event: 1).

## RW-H1 — does exposure beat LOC at ordering a 20%-LOC review budget?

| ranking | median recall@20%LOC | pooled AUC (descriptive) |
|---|---|---|
| structural exposure | 0.000 | 0.724 |
| LOC | 0.000 | 0.858 |

Paired per event: exposure wins 52, LOC wins 48, ties 82 (ties = both rankings catch/miss the same files). One-sided sign test p = 0.3822. **RW-H1: not supported** (α=0.01, direction exposure > LOC).

## RW-H2 — is prior CVE-fix history the baseline to beat? (events with ≥5 prior fixes: n=179)

| ranking | median recall@20%LOC | pooled AUC |
|---|---|---|
| prior CVE-fix count | 0.444 | 0.762 |
| structural exposure | 0.000 | 0.734 |
| LOC | 0.000 | 0.862 |

Paired: prior vs exposure — wins 77, losses 27, p = 0.0000; prior vs LOC — wins 71, losses 10, p = 0.0000. **RW-H2: SUPPORTED** (α=0.01, both comparisons, direction prior > static).

Limits: recalls are coarse (few implicated files/event); prior counts follow paths (renames break lineage, handicapping the baseline); prior ties break neutrally by path. Pooled AUCs are descriptive (repeated files across snapshots), the paired tests are the registered readings.

