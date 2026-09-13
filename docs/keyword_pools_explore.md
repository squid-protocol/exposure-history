# Keyword-first exploratory analysis -- curl (gitgalaxy#2982)

**EXPLORATORY -- computed post-hoc on data already analyzed; no hypothesis tests, no p-values.** Patterns here are candidates for *registration* on unseen data (repo #3), never claims.

Known label caveats carried forward: roughly half of `Fixes #` commits are not code-bug fixes (docs/build/deprecation commits get the same trailer); ~31% of touched files across this corpus are tests/docs, not implementation; class pooling is heterogeneous (bugfix-fixes/bugfix-bug/regression were drawn by commit-message label, not by hand-verified bug content -- see docs/HYPOTHESES.md's overnight bug-label expansion section).

Events: 1762 in the three source files (events/curl.json, events/curl_wave1.json, events/curl_bugs.json); 1545 yielded usable touched-file stats (217 skipped -- root commits, unscanned parents, or no touched files after rename resolution). Compute pass this run: 164s (most/all events already cached from a prior run if this is small).

## Part A -- the owed per-class grammar table

Median per-event signal delta (mean over a commit's touched files, then median across events of that class), median net-LOC, and the composite rates, one table, classes as columns. `loose` = struct_branch net-added OR state_pointers net-added; `strict` = both; `fix-shaped` = loose AND NOT (state_cast_hits or state_memory_alloc net-added) -- the same composite defined in signal_anatomy.py / wave1_analysis.py, applied here to all 8 classes.

| quantity | security-fix | regression | bugfix-bug | bugfix-fixes | control | introduced | revert | cve-followup |
|---|---|---|---|---|---|---|---|---|
| n | 182 | 279 | 244 | 434 | 168 | 118 | 105 | 15 |
| struct_branch | +0.733 | +0.000 | +0.000 | +0.333 | +0.000 | +0.633 | +0.000 | +0.000 |
| state_pointers | +0.333 | +0.000 | +0.000 | +0.000 | +0.000 | +1.583 | +0.000 | +0.000 |
| state_memory_alloc | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| state_cast_hits | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| def_safety | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| state_bailout_hits | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| arch_io | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| arch_time | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| def_test | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| def_doc | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| state_planned_debt | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 | +0.000 |
| median net-LOC | +3.0 | +1.0 | +2.0 | +2.0 | +2.0 | +6.5 | -1.0 | -1.0 |
| loose rate (branch+ or ptr+) | 71% | 50% | 52% | 62% | 45% | 71% | 18% | 20% |
| strict rate (branch+ and ptr+) | 45% | 22% | 24% | 33% | 21% | 55% | 8% | 13% |
| fix-shaped rate | 66% | 46% | 48% | 53% | 38% | 40% | 13% | 20% |

**Headline (security-fix vs regression vs bugfix-bug vs bugfix-fixes):** fix-shaped rate = security-fix 66%, regression 46%, bugfix-bug 48%, bugfix-fixes 53%; loose rate = security-fix 71%, regression 50%, bugfix-bug 52%, bugfix-fixes 62%. The classes separate on this composite rather than converging -- security-fix does not sit inside the same band as the ordinary bug-fix classes.

## Part B -- keyword-first pools (the inversion)

Baseline: all 1545 analyzed events, 4236 touched-file instances. Baseline class composition: security-fix 12%, regression 18%, bugfix-bug 16%, bugfix-fixes 28%, control 11%, introduced 8%, revert 7%, cve-followup 1%. Baseline test-file share (touched files under `tests/`): 13%. Co-added signals reported at >= 25% pool prevalence.

### `struct_branch` net-add pool (n=712, 46% of all events)

**Class composition** (pool% vs baseline%): security-fix 16% (base 12%), regression 15% (base 18%), bugfix-bug 15% (base 16%), bugfix-fixes 32% (base 28%), control 9% (base 11%), introduced 10% (base 8%), revert 2% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 12% (base 9%), `lib/url.c` 5% (base 4%), `lib/urldata.h` 4% (base 3%), `tests/http/` 4% (base 2%), `tests/data/` 3% (base 2%), `tests/libtest/` 2% (base 5%)

**Median net-LOC:** +5.0 (baseline over all events: +2.0). **Test-file share:** 12% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): state_pointers 64% (base 38%), state_flux 56% (base 32%), struct_var_decl 45% (base 26%), struct_snake_case 43% (base 24%), struct_args 35% (base 19%), struct_macros 27% (base 17%)

**Exemplars** (shortest net-LOC, purest cases): `aeb1a281ca` (security-fix, +0 LOC) "gtls: fix OCSP stapling management"; `914aaab915` (security-fix, +0 LOC) "urlapi: reject percent-decoding host name into separator bytes"; `9889db0433` (security-fix, +0 LOC) "openldap: check ldap_get_attribute_ber() results for NULL before using"

### `state_pointers` net-add pool (n=593, 38% of all events)

**Class composition** (pool% vs baseline%): security-fix 17% (base 12%), regression 16% (base 18%), bugfix-bug 13% (base 16%), bugfix-fixes 32% (base 28%), control 8% (base 11%), introduced 13% (base 8%), revert 2% (base 7%), cve-followup 1% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 12% (base 9%), `lib/url.c` 6% (base 4%), `lib/urldata.h` 5% (base 3%), `tests/http/` 3% (base 2%), `lib/http.c` 3% (base 2%), `tests/libtest/` 2% (base 5%)

**Median net-LOC:** +5.0 (baseline over all events: +2.0). **Test-file share:** 10% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_branch 77% (base 46%), state_flux 65% (base 32%), struct_var_decl 48% (base 26%), struct_snake_case 47% (base 24%), struct_args 34% (base 19%)

**Exemplars** (shortest net-LOC, purest cases): `aeb1a281ca` (security-fix, +0 LOC) "gtls: fix OCSP stapling management"; `119fb18719` (security-fix, +0 LOC) "content_encoding: do not reset stage counter for each header"; `9889db0433` (security-fix, +0 LOC) "openldap: check ldap_get_attribute_ber() results for NULL before using"

### `state_memory_alloc` net-add pool (n=57, 4% of all events)

**Class composition** (pool% vs baseline%): security-fix 9% (base 12%), regression 12% (base 18%), bugfix-bug 12% (base 16%), bugfix-fixes 16% (base 28%), control 7% (base 11%), introduced 39% (base 8%), revert 5% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 16% (base 9%), `lib/urldata.h` 5% (base 3%), `lib/url.c` 5% (base 4%), `lib/vquic/` 3% (base 2%), `tests/libtest/` 3% (base 5%), `tests/http/` 3% (base 2%)

**Median net-LOC:** +8.0 (baseline over all events: +2.0). **Test-file share:** 9% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): def_cleanup 86% (base 4%), state_pointers 81% (base 38%), struct_branch 77% (base 46%), state_flux 70% (base 32%), struct_var_decl 63% (base 26%), struct_snake_case 63% (base 24%)

**Exemplars** (shortest net-LOC, purest cases): `4fc7737742` (revert, +1 LOC) "Revert "x509asn1: avoid freeing unallocated pointers""; `6e241bbf1d` (regression, +1 LOC) "digest: fix memory leak, fix not quoted 'opaque'"; `8123560d44` (bugfix-fixes, +2 LOC) "HTTP: allow "header;" to replace an internal header with a blank one"

### `state_cast_hits` net-add pool (n=99, 6% of all events)

**Class composition** (pool% vs baseline%): security-fix 5% (base 12%), regression 9% (base 18%), bugfix-bug 7% (base 16%), bugfix-fixes 33% (base 28%), control 11% (base 11%), introduced 28% (base 8%), revert 6% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 12% (base 9%), `lib/urldata.h` 4% (base 3%), `tests/http/` 4% (base 2%), `lib/url.c` 4% (base 4%), `lib/vquic/` 3% (base 2%), `lib/multi.c` 3% (base 2%)

**Median net-LOC:** +9.0 (baseline over all events: +2.0). **Test-file share:** 9% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_branch 79% (base 46%), state_pointers 72% (base 38%), state_flux 67% (base 32%), struct_var_decl 65% (base 26%), struct_snake_case 63% (base 24%), struct_args 61% (base 19%)

**Exemplars** (shortest net-LOC, purest cases): `c2e427cc93` (control, +0 LOC) "hostip: skip error check for infallible function call"; `1cfa4cd427` (bugfix-bug, +0 LOC) "curl_rtmp: fix a compiler warning"; `2e48139fbf` (bugfix-bug, +0 LOC) "lib554.c: use curl_formadd() properly"

### `def_safety` net-add pool (n=126, 8% of all events)

**Class composition** (pool% vs baseline%): security-fix 18% (base 12%), regression 10% (base 18%), bugfix-bug 7% (base 16%), bugfix-fixes 28% (base 28%), control 12% (base 11%), introduced 25% (base 8%), revert 0% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 13% (base 9%), `tests/http/` 8% (base 2%), `lib/urldata.h` 4% (base 3%), `lib/url.c` 3% (base 4%), `lib/vquic/` 3% (base 2%), `lib/vauth/` 2% (base 2%)

**Median net-LOC:** +9.2 (baseline over all events: +2.0). **Test-file share:** 14% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_branch 83% (base 46%), state_pointers 82% (base 38%), struct_var_decl 77% (base 26%), struct_snake_case 77% (base 24%), state_flux 74% (base 32%), struct_args 59% (base 19%)

**Exemplars** (shortest net-LOC, purest cases): `76c21ed3fd` (bugfix-bug, +0 LOC) "telnet: (win32) fix read callback return variable"; `e40e9d7f0d` (introduced, -0 LOC) "buffer: use data->set.buffer_size instead of BUFSIZE"; `9b5e12a549` (security-fix, -0 LOC) "url: fix alignment of ssl_backend_data struct"

### `state_bailout_hits` net-add pool (n=30, 2% of all events)

**Class composition** (pool% vs baseline%): security-fix 3% (base 12%), regression 17% (base 18%), bugfix-bug 7% (base 16%), bugfix-fixes 27% (base 28%), control 17% (base 11%), introduced 20% (base 8%), revert 10% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 8% (base 9%), `tests/unit/` 5% (base 1%), `configure.ac` 5% (base 2%), `tests/http/` 3% (base 2%), `include/curl/` 3% (base 2%), `lib/url.c` 3% (base 4%)

**Median net-LOC:** +10.9 (baseline over all events: +2.0). **Test-file share:** 16% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_branch 63% (base 46%), state_flux 60% (base 32%), struct_var_decl 53% (base 26%), state_pointers 53% (base 38%), struct_snake_case 47% (base 24%), struct_macros 40% (base 17%)

**Exemplars** (shortest net-LOC, purest cases): `8fe8fd2b17` (revert, +0 LOC) "Revert "configure: don't error out on variable confusions, just warn""; `7fd35f4c34` (control, +1 LOC) "unittests: cleanups"; `c92d2e14cf` (introduced, -3 LOC) "Added support for libssh SSH SCP back-end"

### `arch_io` net-add pool (n=36, 2% of all events)

**Class composition** (pool% vs baseline%): security-fix 3% (base 12%), regression 8% (base 18%), bugfix-bug 8% (base 16%), bugfix-fixes 39% (base 28%), control 8% (base 11%), introduced 28% (base 8%), revert 6% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `tests/http/` 17% (base 2%), `lib/vtls/` 13% (base 9%), `lib/urldata.h` 3% (base 3%), `lib/url.c` 3% (base 4%), `src/tool_operate.c` 3% (base 2%), `lib/transfer.c` 2% (base 1%)

**Median net-LOC:** +11.1 (baseline over all events: +2.0). **Test-file share:** 26% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_branch 89% (base 46%), state_flux 81% (base 32%), struct_args 75% (base 19%), struct_func_start 72% (base 11%), struct_var_decl 69% (base 26%), struct_snake_case 67% (base 24%)

**Exemplars** (shortest net-LOC, purest cases): `d5c01d779f` (bugfix-fixes, +0 LOC) "smbserver: fix Python version specific ConfigParser import"; `d52316e460` (bugfix-fixes, +1 LOC) "tests/smbserver.py: fix compatibility with impacket 0.9.23+"; `0a79a599a9` (bugfix-fixes, +4 LOC) "transfer: fix retry for empty downloads on reuse"

### `arch_api` net-add pool (n=141, 9% of all events)

**Class composition** (pool% vs baseline%): security-fix 12% (base 12%), regression 9% (base 18%), bugfix-bug 9% (base 16%), bugfix-fixes 29% (base 28%), control 8% (base 11%), introduced 33% (base 8%), revert 1% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 10% (base 9%), `tests/libtest/` 8% (base 5%), `tests/http/` 6% (base 2%), `lib/urldata.h` 3% (base 3%), `lib/vquic/` 3% (base 2%), `lib/url.c` 2% (base 4%)

**Median net-LOC:** +8.2 (baseline over all events: +2.0). **Test-file share:** 18% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_args 79% (base 19%), struct_branch 76% (base 46%), state_pointers 70% (base 38%), state_flux 68% (base 32%), struct_func_start 67% (base 11%), struct_var_decl 62% (base 26%)

**Exemplars** (shortest net-LOC, purest cases): `26da21c84a` (bugfix-bug, +0 LOC) "system_win32: fix clang warning"; `d78e129d50` (introduced, +0 LOC) "WebSockets: make support official (non-experimental)"; `ef8d98bbba` (bugfix-fixes, -0 LOC) "os400: make vsetopt() non-static as Curl_vsetopt() for os400 support."

### `arch_crypto` net-add pool (n=1, 0% of all events)

**Class composition** (pool% vs baseline%): security-fix 100% (base 12%), regression 0% (base 18%), bugfix-bug 0% (base 16%), bugfix-fixes 0% (base 28%), control 0% (base 11%), introduced 0% (base 8%), revert 0% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/ws.c` 50% (base 0%), `tests/http/` 50% (base 2%)

**Median net-LOC:** +43.5 (baseline over all events: +2.0). **Test-file share:** 50% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_var_decl 100% (base 26%), struct_snake_case 100% (base 24%), struct_short_vars 100% (base 7%), struct_func_start 100% (base 11%), struct_branch 100% (base 46%), struct_args 100% (base 19%)

**Exemplars** (shortest net-LOC, purest cases): `849317ff5c` (security-fix, +44 LOC) "ws: make pong sending lazy"

### `arch_time` net-add pool (n=10, 1% of all events)

**Class composition** (pool% vs baseline%): security-fix 20% (base 12%), regression 10% (base 18%), bugfix-bug 10% (base 16%), bugfix-fixes 30% (base 28%), control 10% (base 11%), introduced 10% (base 8%), revert 10% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `tests/http/` 23% (base 2%), `tests/libtest/` 7% (base 5%), `lib/ftp.c` 5% (base 1%), `lib/transfer.c` 5% (base 1%), `lib/urldata.h` 5% (base 3%), `lib/ws.c` 2% (base 0%)

**Median net-LOC:** +6.8 (baseline over all events: +2.0). **Test-file share:** 34% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_branch 90% (base 46%), state_flux 80% (base 32%), struct_func_start 70% (base 11%), struct_args 70% (base 19%), state_pointers 70% (base 38%), arch_api 70% (base 9%)

**Exemplars** (shortest net-LOC, purest cases): `adef394ac5` (bugfix-fixes, +2 LOC) "timers: store internal time stamps as time_t instead of doubles"; `0a79a599a9` (bugfix-fixes, +4 LOC) "transfer: fix retry for empty downloads on reuse"; `0044443a02` (bugfix-fixes, +4 LOC) "parsedate: offer a getdate_capped() alternative"

### `def_test` net-add pool (n=28, 2% of all events)

**Class composition** (pool% vs baseline%): security-fix 14% (base 12%), regression 14% (base 18%), bugfix-bug 4% (base 16%), bugfix-fixes 46% (base 28%), control 7% (base 11%), introduced 14% (base 8%), revert 0% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `tests/http/` 36% (base 2%), `lib/vtls/` 22% (base 9%), `lib/vquic/` 6% (base 2%), `lib/urldata.h` 2% (base 3%), `lib/http2.c` 2% (base 1%), `lib/transfer.c` 2% (base 1%)

**Median net-LOC:** +10.5 (baseline over all events: +2.0). **Test-file share:** 40% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_branch 93% (base 46%), arch_api 93% (base 9%), struct_args 89% (base 19%), state_flux 89% (base 32%), struct_var_decl 86% (base 26%), struct_snake_case 86% (base 24%)

**Exemplars** (shortest net-LOC, purest cases): `3210101088` (introduced, -2 LOC) "tls: use shared init code for TCP+QUIC"; `29b3b1ae6d` (regression, +4 LOC) "wolfssl: fix cipher list, skip 5.8.4 regression"; `ed09a99af5` (bugfix-fixes, +4 LOC) "vtls: revert "receive max buffer" + add test case"

### `state_planned_debt` net-add pool (n=8, 1% of all events)

**Class composition** (pool% vs baseline%): security-fix 0% (base 12%), regression 0% (base 18%), bugfix-bug 12% (base 16%), bugfix-fixes 12% (base 28%), control 0% (base 11%), introduced 62% (base 8%), revert 12% (base 7%), cve-followup 0% (base 1%)

**Area profile** (top 6 path prefixes, pool% vs baseline%): `lib/vtls/` 16% (base 9%), `lib/urldata.h` 4% (base 3%), `lib/url.c` 4% (base 4%), `lib/vquic/` 3% (base 2%), `lib/http.c` 3% (base 2%), `lib/ftp.c` 2% (base 1%)

**Median net-LOC:** +3.8 (baseline over all events: +2.0). **Test-file share:** 4% (baseline 13%)

**Co-added signals** (pool rate vs baseline rate): struct_macros 62% (base 17%), struct_branch 62% (base 46%), state_pointers 62% (base 38%), arch_import 62% (base 8%), arch_api 62% (base 9%), struct_args 50% (base 19%)

**Exemplars** (shortest net-LOC, purest cases): `3210101088` (introduced, -2 LOC) "tls: use shared init code for TCP+QUIC"; `c341311a0e` (revert, +4 LOC) "Revert "cleanup: general removal of TODO (and similar) comments""; `172b2beba6` (bugfix-bug, +4 LOC) "SSL: Add an option to disable certificate revocation checks"

## Part C -- signal co-movement structure

Spearman rank correlation of per-event mean signal deltas, over all 1545 analyzed events, restricted to the 25 most-active signals among those moving in >= 3% of events. 43 signals dropped for moving in < 3% of events: arch_concurrency, arch_crypto, arch_dependency_injection, arch_events, arch_feature_flags, arch_hardware, arch_inline_asm, arch_ipc, arch_regex, arch_scientific, arch_serialization, arch_ssr_boundaries, arch_time, arch_ui_framework, def_auth, def_doc, def_listeners, def_ownership, def_spec_exposure, def_sync_locks, def_telemetry, def_test, def_test_skip, dl_frameworks, llm_api, llm_local_compute, llm_orchestrator, llm_vector_store, ml_traditional, state_bailout_hits, state_danger, state_fragile_debt, state_halt_hits, state_planned_debt, state_print_hits, state_slop_duplicates, struct_camel_case, struct_closures, struct_comprehensions, struct_decorators, struct_generics, struct_long_vars, struct_pascal_case.

**Top 12 correlated pairs** (|rho| descending):

| signal a | signal b | rho |
|---|---|---|
| struct_var_decl | struct_snake_case | +0.94 |
| def_cleanup | state_memory_alloc | +0.85 |
| struct_func_start | def_encapsulation | +0.70 |
| state_flux | struct_snake_case | +0.70 |
| state_flux | struct_var_decl | +0.68 |
| struct_args | struct_func_start | +0.64 |
| struct_branch | state_pointers | +0.58 |
| state_pointers | state_flux | +0.57 |
| struct_branch | state_flux | +0.56 |
| struct_func_start | arch_api | +0.51 |
| arch_api | state_unreferenced | +0.49 |
| struct_branch | struct_snake_case | +0.49 |

**Single-linkage clusters at |rho| >= 0.6:** 3 multi-member cluster(s); 17 signals have no partner at this threshold.

- **cluster 1** {state_flux, struct_snake_case, struct_var_decl} -- correlation of the summed cluster delta with net-LOC: rho=+0.66 (SIZE PROXY, threshold |rho|>=0.5)
- **cluster 2** {def_encapsulation, struct_args, struct_func_start} -- correlation of the summed cluster delta with net-LOC: rho=+0.44 (co-moves beyond size, threshold |rho|>=0.5)
- **cluster 3** {def_cleanup, state_memory_alloc} -- correlation of the summed cluster delta with net-LOC: rho=+0.25 (co-moves beyond size, threshold |rho|>=0.5)

---
*Regenerate: `python tools/keyword_pools.py` (cache at `dbs/keyword_pools_cache.json`, gitignored). Not committed.*
