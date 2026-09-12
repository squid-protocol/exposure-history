# Instrument-control forensics — the +47.1 outlier and the spillover tail (issue #5)

*Provenance: investigation run 2026-09-12 against the live master DB; both headline
verdicts independently re-derived by the orchestrator before this record was committed
(Q1: `lib/ws.c` +0.78 vs test-file `risk_concurrency` 0→87.264; Q2: `base64.c`
`state_unreferenced` 3→0 vs `raw_state_unreferenced` 3→3 at byte-identical inputs). The
Q2 determinism defect is engine-level and is escalated to the GitGalaxy engine separately.*

## Instrument controls — forensic notes on two outlier readings

Both readings were re-derived read-only against `dbs/curl_out/curl_galaxy_master.db` and
`dbs/curl_out/worktrees/curl` / the pool checkout at
`/srv/storage_16tb/projects/temporal-crucible-pool/curl`, replicating the exact
`structural_delta` definition in `tools/_engine.py` / `tools/exposure_delta.py` /
`tools/delta_report.py`: sum of `Δrisk_*` over the 10 STRUCTURAL_COLUMNS
(`cognitive_load, safety_score, tech_debt, verification, api_exposure, concurrency,
state_flux, dead_code, spec_match, secrets_risk`; `stability`/`churn` excluded as temporal
and confirmed 0 by the delta_report assertion). Note this is the 10-column `risk_*` vector,
not the raw `struct_*/arch_*/state_*/threat_*` per-hit counters — those are the *inputs* to
the risk_* formulas and are used below to diagnose mechanism.

**Operational note surfaced mid-investigation:** a live `galaxyscope --db-only` rescan of
this exact repo (10-12 worker processes) was running against
`dbs/curl_out/curl_galaxy_master.db` throughout this analysis. Opening the DB with
`?mode=ro&immutable=1` produced `PRAGMA integrity_check` corruption errors (torn pages) —
`immutable=1` is unsafe against a live WAL writer. Plain `?mode=ro` (WAL-aware) reads clean
(`integrity_check` → `ok`) and was used for everything below; spot-checked rows were
byte-identical under both connection strings once corrected. Flagging this because the same
mistake in a future run would silently read garbage.

---

## Q1 — the +47.112 outlier (CURL-CVE-2026-11586)

**Event:** fix SHA `849317ff5c5a5e13f50ec3d001e46ddffa77d8a4` ("ws: make pong sending lazy",
Closes #21911), parent `fb9a520873133e369fa86ef63b4e4f0fd2fc1f68`. Introduced-by SHA also on
file: `0b091328773c64e23f5c4739da74527093c6a5ab` (not needed for this delta — the report's
+47.112 row is the **fix** event).

**The 2 touched files** (`git diff --name-status -M parent..fix`): both `M` (modified),
no renames, no additions/deletions:
- `lib/ws.c`
- `tests/http/test_20_websockets.py`

**Per-file structural delta** (risk_* vector, fix − parent):

| file | cognitive_load | safety_score | tech_debt | verification | api_exposure | concurrency | state_flux | dead_code | spec_match | secrets_risk | **structural Δ** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `lib/ws.c` | +0.2817 | +0.5182 | −0.0178 | 0 | −0.0017 | 0 | 0 | 0 | 0 | 0 | **+0.780** |
| `tests/http/test_20_websockets.py` | +7.4506 | −1.3518 | 0 | 0 | +0.0632 | **+87.2643** | 0 | 0 | 0 | 0 | **+93.427** |

Event mean = (0.780 + 93.427) / 2 = **+47.10** ≈ reported +47.112 (small residual is
rounding in the reported figure vs. these 4-dp DB reads).

**Raw signals, before → after** (state fed to the risk formulas):

| file | struct_branch | arch_io | arch_api | state_flux(raw) | arch_concurrency | threat_network_hooks | total_loc | function_count |
|---|---|---|---|---|---|---|---|---|
| `lib/ws.c` | 332→335 | 0→0 | 21→21 | 240→245 | 0→0 | 0→0 | 1983→1992 | 45→45 |
| test file | 13→19 | 9→15 | 14→16 | 56→75 | **0→3** | 1→3 | 223→301 | 15→17 |

**git show --stat:** `lib/ws.c` 33 lines changed (+21/−12); test file +78/−0 (net-new test
function added, not a rewrite). `git show <fix> -- tests/http/test_20_websockets.py` shows a
brand-new test `test_20_11_crazy_pings` that adds a real `threading` import and **two
`threading.Thread(target=srv, ...)` calls** spinning up a raw-socket WS server thread to
blast PING frames while the main thread drives curl — genuine new concurrency-bearing code,
not boilerplate.

**Rename-tracking check:** N/A — both files are plain `M` in `--name-status -M`, matched by
identical path on both sides. `exposure_delta.py`'s rename logic was never invoked for this
event; no mispairing is possible here.

**Mechanism:** the entire +47.1 rise is **not** the CVE-relevant source fix. `lib/ws.c`
itself — the file that actually fixes the WS Auto-PONG memory-exhaustion bug — moves only
+0.78. 99.2% of the event's mean delta (93.43 of 94.21 raw-summed points across both files)
comes from `risk_concurrency` jumping 0.0 → 87.2643 in the *accompanying test file*, driven
deterministically by `arch_concurrency` (raw hit count) going 0 → 3 as `import threading` +
2×`threading.Thread(...)` were added. Checked against the corpus: `risk_concurrency` is
exactly 0.0 whenever `arch_concurrency = 0` for all 965,436 curl file-snapshot rows in the
DB (a hard floor, no exceptions), and for `arch_concurrency = 3` observed scores range
0–95.6 (mean 39.6) depending on file size — 87.26 in a 240-coding-line file is high but
inside the observed range for a short file with 3 hits (density-based formula, small
denominator amplifies). This is the same "small-file density" sensitivity the report already
flags for `tech_debt` in the commit-anatomy section, just on `concurrency` here, and it is a
correct behavior of that formula given genuinely new code, not a bug.

**VERDICT: GENUINE — but not where the report row implies.** The +47.1 read is a real
structural jump produced by real code (no rename/add/delete mishandling, no pairing bug),
but it is driven almost entirely by the *test file's* newly added threading harness, not by
the vulnerability fix in `lib/ws.c`. Interpreting this row as "the CVE-2026-11586 fix
raised structural exposure by 47" is misleading for the report's "top movers" table —
the source-code fix itself moved +0.78. Recommend a footnote on that table distinguishing
source-file delta from test-file delta when a security fix ships tests, since the current
per-event mean silently blends the two and a short test file can dominate.

---

## Q2 — the untouched-file spillover tail (max 29.7754)

**Legitimate channel, per the code:** `tools/delta_report.py`'s "Instrument controls"
section states graph ripple via `api_exposure` (i.e. `risk_api_exposure`, fed by the raw
`arch_api` hit count, `def_encapsulation`, `total_loc`, and — critically — `popularity`,
a cross-file inbound-reference count) is the only legitimate nonzero channel on an untouched
file. All 9 other STRUCTURAL_COLUMNS should read exactly 0 Δ on a file the commit didn't
touch, because they're computed purely from the file's own (unchanged) content.

**Reproduction (read-only, `mode=ro`, WAL-aware):** replayed `event_deltas()`'s untouched-file
loop over all 508 events in `events/curl.json` (1 event skipped — root-commit "introduced"
event with no parent). Result:

- **n_cells = 393,433**, **n_nonzero = 2,712** (0.689% — matches the report's "<1% of cells
  move" reading; the live rescan running during this session means my cell count is larger
  than the report's preliminary n=375,265, but the flagged **max record is bit-for-bit the
  same file/event/value**, so the finding is stable across the batch's growth).
- Of the 2,712 nonzero cells: **199 (7.3%) are confined purely to `api_exposure`** (every
  other vector exactly 0) — these are the clean graph-ripple cases.
  **2,513 (92.7%) "leak" into at least one other vector** — but 2,509 of those leaks are
  into `risk_verification` at a **median magnitude of 0.0001** (max non-outlier leak
  magnitude 0.0013) — sub-rounding noise that contributes nothing to the reported
  median/p99 (both correctly read 0.0000 at 4dp). This near-universal micro-leak is present
  on almost every nonzero cell and is far too small to be the "max = 29.8" story; it reads
  as a shared small repo-wide term in the verification formula, not a defect worth gating on.

**Top ~10 |Δ| (all confirmed against `git diff --name-status -M` + blob-hash identity —
every file below is untouched, correctly classified):**

| rank | \|Δ\| | class | event | file | which vector(s) moved | legitimate? |
|---|---|---|---|---|---|---|
| 1 | **29.7754** | security-fix | CURL-CVE-2025-5025 | `lib/curlx/base64.c` | `tech_debt −41.2713`, `api_exposure +11.4959` | **NO — see below** |
| 2 | 5.0203 | introduced | CURL-CVE-2020-8285 | `lib/llist.h` | `api_exposure +5.0203` only | yes (pagerank 0.006015→0.006135, blast-radius 6.015→6.135; commit added 4 new files incl. `curl_fnmatch.c/h`) |
| 3 | 4.4006 | introduced | CURL-CVE-2019-5435 | `lib/curl_ctype.h` | `api_exposure` only | yes (commit = the URL-API feature landing, large graph change) |
| 4 | 3.896 | introduced | CURL-CVE-2026-4873 | `lib/http.h` | `api_exposure` only | not individually re-verified, same pattern as #2/#3/#8 (all `.h` files, all api-only) |
| 5 | 3.201 | introduced | CURL-CVE-2021-22923 | `src/tool_setopt.h` | `api_exposure` only | — |
| 6 | 3.0517 | introduced | CURL-CVE-2026-4873 | `lib/socks.h` | `api_exposure` only | — |
| 7 | 3.0429 | control | control-for-CURL-CVE-2021-22923 | `lib/bufref.h` | `api_exposure` only | — |
| 8 | 2.9525 | security-fix | CURL-CVE-2026-8932 | `lib/peer.h` | `api_exposure` only | — |
| 9 | 2.914 | introduced | CURL-CVE-2026-4873 | `lib/if2ip.h` | `api_exposure` only | — |
| 10 | 2.6223 | security-fix | CURL-CVE-2021-22923 | `src/tool_paramhlp.h` | `api_exposure` only | — |
| 15 | 1.0578 | security-fix | **CURL-CVE-2026-11586** (same fix as Q1!) | `lib/curlx/base64.c` | `tech_debt 0`, `verification +0.0532`, `api_exposure +1.0046` | **NO — same file, same bug, different event** |

Two more sub-1.0 leak records checked (`lib/curl_trc.h` Δ=0.4575, event CURL-CVE-2024-2379;
`lib/easy_lock.h` Δ=0.2881, event CURL-CVE-2023-28320): both are **legitimate** — their
`popularity` and `pagerank_score` columns genuinely moved between parent/child (e.g.
`easy_lock.h` popularity 2→3, pagerank 0.000452→0.000471), consistent with real reference-graph
changes elsewhere in those commits.

**The `lib/curlx/base64.c` case is categorically different — and reproduces twice, on two
unrelated events:**

| commit pair (event) | blob hash (parent=child?) | `popularity` | `arch_api` | `def_encapsulation` | `total_loc` | `internal_dependency_links` | `pagerank_score` | `risk_api_exposure` | `state_unreferenced` | `raw_state_unreferenced` | `risk_tech_debt` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2dfe421a6→e1f65937a9 (CVE-2025-5025) | identical (`80624cc2…`) | 0 → 0 | 3 → 3 | 3 → 3 | 286 → 286 | 6 → 6 | 0.000346 → 0.000346 | **2.4495 → 13.9454** | **3 → 0** | 3 → 3 | **41.2713 → 0.0** |
| fb9a5208→849317ff (CVE-2026-11586) | identical (`7f51576f…`) | 0 → 0 | 3 → 3 | 3 → 3 | 268 → 268 | 2 → 2 | 0.000452 → 0.000452 | **14.1069 → 15.1115** | n/a | n/a | 0.0 → 0.0 |

Traced `_calc_api_exposure` and `_calc_tech_debt` in
`/srv/storage_16tb/projects/gitgalaxy/v6/gitgalaxy/metrics/signal_processor.py`:
`_calc_api_exposure(raw_signals, total_loc, popularity)` is a **pure function** of
`arch_api` ("api" hits), `def_encapsulation`, `total_loc`, and `popularity` only — no other
inputs. Every one of those four is byte-identical across both scans in both pairs above, so
the persisted `risk_api_exposure` **must** be identical too — it is not (2.45 vs 13.95; 14.11
vs 15.11). This is a direct proof of non-determinism in the scan pipeline, not a graph-ripple
effect: none of the graph proxies that *would* legitimately move it (`popularity`,
`pagerank_score`, `internal_dependency_links`) moved at all.

`_calc_tech_debt`'s `orphans` term reads `raw_signals["unreferenced_by_name"]`, which is
persisted to `file_data.state_unreferenced`. That column reads **3 in the parent, 0 in the
child** for the identical blob — while a separate tracking column, `raw_state_unreferenced`,
correctly holds **3 in both**. Line 1509 of `_calc_tech_debt` is:
```python
if good_debt == 0 and bad_debt == 0 and orphans == 0 and duplicates == 0:
    return 0.0
```
`good_debt`/`bad_debt` are 0/0 in both snapshots (confirmed), so the only thing that can flip
the score from 41.27 to a hard-floored 0.0 is `orphans` (`state_unreferenced`) going from 3
to 0 — which the parallel `raw_state_unreferenced` column shows should not have happened.
`state_unreferenced` (the "is this symbol referenced anywhere in the repo" check) is by
nature a cross-file/whole-repo computation — exactly the kind of shared/global state that a
multi-worker scan race would corrupt. A live `galaxyscope --db-only` scan of this same repo
(10-12 worker processes) was observed running throughout this investigation, which is
circumstantial support for a multiprocessing race in the symbol-reference index rather than
a one-off fluke.

**Characterizing the <1%:** of the 2,712 nonzero untouched-file cells, 2,509 are negligible
verification-only noise (≤0.0013), 199 are clean single-vector `api_exposure` graph-ripple
backed by real `popularity`/`pagerank_score` movement (spot-checked 4/4), and exactly **2**
(both `lib/curlx/base64.c`, on two unrelated CVE events) show the impossible
identical-inputs/different-outputs pattern — but one of those two is the record that sets
the reported max (29.7754), so the single most extreme number in the entire spillover tail
is the artifact, not the norm.

**VERDICT: MOSTLY LEGITIMATE, BUT THE MAX (29.7754) IS AN ARTIFACT — a scan-pipeline
non-determinism bug, not graph ripple.** The bulk of the nonzero tail is exactly what the
report's hypothesis predicts (api_exposure-only, backed by real popularity/pagerank shifts,
plus universally-negligible verification noise). But the single largest cell — the number
that sets `max = 29.7754` in the report — is produced by `risk_api_exposure` and
`risk_tech_debt` (specifically its `state_unreferenced` input) failing to be pure functions
of their documented, byte-identical inputs on `lib/curlx/base64.c` across two independent
scan pairs. This is a scanner determinism defect (most likely in whole-repo symbol-reference
resolution under concurrent workers), not evidence that structural deltas leak outside
`api_exposure` by design.

**What would settle it read-only-adjacent (not run here per instructions):** re-run
`galaxyscope --db-only` single-threaded (`--workers 1` or equivalent) over just
`2dfe421a6`/`e1f65937a9` and diff the resulting `state_unreferenced`/`risk_api_exposure` for
`lib/curlx/base64.c` against the numbers above; if they come back identical (3/3,
matching `risk_tech_debt`≈41.27 for both), that confirms a multi-worker race as the root
cause rather than something in the commit-specific scan context. Also worth checking whether
`lib/curlx/base64.c` is scanned under `#ifdef`-gated backend variance (curl builds base64
support conditionally per TLS backend) — if the engine's static pass resolves a different
conditional branch depending on worker/thread scheduling, that would independently explain a
`state_unreferenced`/`arch_api` race without invoking a shared-cache bug.
