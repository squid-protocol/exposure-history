# Wave-1 hypothesis evaluation — curl

Pre-registered on gitgalaxy#2982 (comment 5647715438, α=0.01), evaluated verbatim. Operational definitions reuse `signal_anatomy.py` pass-1 (same signal set, per-event mean delta, fix-shaped composite). Counts are the engine's own extraction.

Events analyzed: control 168, cve-followup 15, introduced 118, revert 105, security-fix 182.

## W1-H1 — reverts as net-removal

Registered: revert grammar-signal deltas predominantly negative (others net-positive); median event net-LOC < 0.

| quantity | revert median | n<0 / n>0 (of 105) | sign-test p (median<0) | vs control (1-sided MW) |
|---|---|---|---|---|
| event net-LOC | -1.0 | 60 / 24 | 5.36e-05 | 0.0000 |
| net grammar Δ | -1.000 | 57 / 23 | 9.16e-05 | 0.0000 |

Contrast (median event net-LOC): security-fix +3.0, control +2.0, introduced +6.5, revert -1.0, cve-followup -1.0.

**W1-H1: SUPPORTED** — net-LOC<0 ✓, net-grammar<0 ✓ (α=0.01).

## W1-H2 — fixes that needed a follow-up look thinner

Registered: fixes later needing a follow-up carry the fix-shaped composite at a LOWER rate than fixes that stuck (one-sided).

| group | n | fix-shaped | rate |
|---|---|---|---|
| needs-follow-up | 14 | 10 | 0.71 |
| stuck | 168 | 110 | 0.65 |

One-sided Fisher (needs < stuck): p = 0.7673.

**W1-H2: not supported** (α=0.01; matched SHAs: 14 needs-follow-up / 17 follow-up links).

## W1-H3 — follow-ups carry the fix grammar

Registered: follow-up commits show branch/pointer adds (loose signature) at a rate closer to fixes than to controls.

| class | n | loose (branch/ptr+) | rate |
|---|---|---|---|
| cve-followup | 15 | 3 | 0.20 |
| security-fix | 182 | 129 | 0.71 |
| control | 168 | 75 | 0.45 |

Follow-up vs control (one-sided Fisher, follow-up > control): p = 0.9865. |rate(fu)−rate(fix)| = 0.51 vs |rate(fu)−rate(ctrl)| = 0.25.

**W1-H3: not supported** — closer to fixes than controls ✗; follow-up>control at α=0.01 ✗ (n=15 is small).

## Exploratory — area-prefix re-slice of existing fixes (LABELED; no p-values)

| area | n fixes | fix-shaped rate | loose rate | median net-LOC |
|---|---|---|---|---|
| url: | 13 | 0.62 | 0.62 | +4 |
| cookie: | 11 | 0.82 | 0.82 | +8 |
| http: | 8 | 0.62 | 0.75 | +3 |
| openssl: | 7 | 1.00 | 1.00 | +8 |
| ftp: | 5 | 0.60 | 0.80 | +2 |
| http2: | 4 | 0.00 | 0.25 | -2 |
| setopt: | 4 | 0.50 | 0.50 | +0 |
| tls: | 4 | 1.00 | 1.00 | +4 |
| netrc: | 4 | 1.00 | 1.00 | +3 |
| cookies: | 4 | 1.00 | 1.00 | +7 |

Descriptive only — an exploratory observation here may be *registered* for repo #2, never re-tested on this data.

