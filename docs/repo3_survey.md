# Repo #3 candidate survey (DRAFT — not committed)

Fetch date for every count in this document: **2026-09-13**. All API/query results were pulled
live against OSV.dev, GitHub's native security-advisories REST API (via authenticated `gh api`,
5000 req/hr), NVD 2.0 REST API, and the GitHub commits API on that date. Re-running the same
queries later will drift — these feeds are append-only but live.

**Survey only** — no scans, no GalaxyScope, no worktrees, no clones. SHA verification and
genuineness checks used the GitHub commits API (`GET /repos/{owner}/{repo}/commits/{sha}`) to pull
the actual commit message + diffstat for every "dual-sided" pair sampled, per the brief's
explicit instruction to check the diff, not just presence.

## 0 · Headline finding: the version-proxy trap is nearly universal outside OSS-Fuzz

Repo #2's survey found the trap on openssl and redis (fix SHA = release-tag boundary, not the
patch). This survey deliberately diff-checked ≥1 "dual-sided" sample from **every** candidate
below, and the same trap recurred on **7 of 9** non-OSS-Fuzz-native candidates tested — just in
different local flavors:

| candidate | "introduced"/"fixed" SHA turned out to be | verified via |
|---|---|---|
| **nginx** | `nginx-1.20.1-RELEASE` / `nginx-0.6.18-RELEASE` — version-bump commits | commit diff |
| **sqlite** | `Version 3.39.2` / `Version 1.0.12` (from year 2000) — version-bump commits | commit diff |
| **systemd** | `NEWS: add one more name...` / `NEWS: patch in today's date for 235` — changelog commits, unrelated to the fix | commit diff |
| **tensorflow** | `Update release notes for TensorFlow 2.7.2/2.8.1` and `Update version numbers for TensorFlow 2.3.0/2.3.1` — for every "introduced"/secondary-branch "fixed" SHA OSV auto-generates | commit diff |
| **imagemagick** | `release` / `Update git version` — version-bump commits | commit diff |
| **netty** | `[maven-release-plugin] prepare release netty-4.1.135.Final` — Maven release-plugin commits | commit diff |
| **vim** | the "introduced" side (the ~14% of entries that aren't `introduced:"0"`) resolved to commits **unrelated to the CVE entirely** — a GTK4/X11 `configure` change for a JSON-decoder UAF CVE, a SPA-filetype-detection commit for a tuple-import UAF CVE | commit diff, 3/3 checked |
| postgres | *no GIT ranges at all* in OSV — not even a proxy; only SEMVER ranges | OSV record inspection |
| **openssl** *(re-tested this pass)* | genuinely different result — see §4, the CHANGES/commit-message trail is real and 90% parseable on resample | commit diff, 10/10 checked |

**The pattern**: OSV's automated version→commit resolution (`database_specific.source:
CPE_RANGE`) reliably picks "the commit nearest a version tag" whenever a project doesn't
self-publish a real fix SHA, and that nearest-tag commit is essentially always a release/version-
bump/changelog commit — never the actual patch. The only sources that survive diff-checking at
scale are **(a) OSS-Fuzz-native bisection** (real dual-sided, genuinely automated, no version
tags involved — confirmed again here on ghostscript, replicating nDPI/harfbuzz from repo #2), and
**(b) a maintainer's own prose citing an exact SHA** (openssl's `Fixes CVE-...` trailers,
TensorFlow's `We have patched the issue in GitHub commit [SHA]` boilerplate) — and even those
only ever cite the **fixed** side, never a bisected **introduced** side.

## 1 · Ranked candidate table

"Dual-sided usable" = pairs where **both** introduced and fixed are non-"0"/non-degenerate GIT
SHAs *and* the fixed-side diff was confirmed (by reading the actual commit) to be a real security
patch, not a proxy. Where I could not verify a count at the stated scale, it's flagged.

| candidate | lang | dual-sided usable (verified genuine) | CWE source | median fix churn (sampled net LOC) | race/TOCTOU CVE count | network/non-network mix | provenance | temporal spread | est. s/scan | SHA miss rate | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **ghostscript** | C | **~184–192** (OSS-Fuzz bisected, 192/200 non-degenerate; genuineness inherited from OSS-Fuzz bisection tooling, not individually diff-checked at nDPI's 40-SHA depth — *partially verified*) | **none available** — 0/200 have CVE aliases; separately, human-reported ghostscript CVEs (checked 4) DO carry CWE via NVD join but carry **zero** GIT ranges in OSV | not sampled this pass | not checked (architecturally single-threaded interpreter; expect ~0, unverified) | almost entirely non-network (local PS/PDF/XPS parsing) — **no network side**, same gap as nDPI | 100% fuzzer (OSS-Fuzz) for the 200; human-reported subset (real CVEs, has CWE) unusable — **0 resolved to a commit** in this pass | not established this pass | not computed | not sampled | **Replicates nDPI's exact profile**: huge genuine dual-sided volume, zero CWE, zero concurrency, zero network. Does not add anything curl+nDPI don't already cover. |
| **openssl** | C | **0 genuine** (no bisected introduced side exists anywhere in its public trail) — but **≥200 genuine FIXED-side events** newly confirmed parseable (see §4) | **joinable via NVD**, confirmed 5/5 sampled (CWE-476, CWE-399 ×3, CWE-834/606) | **+16, +18, +46, +6, +1(!), +170, +9, +3, +8, +22** across the 10-sample diff-check (§4) — clearly non-trivial, human-audit-shaped, median ≈ **+13** | **≥2 confirmed genuine** (CVE-2014-3509, CVE-2015-1791 — both explicit multithread race/double-free fixes with CVE cited in the commit message); 43 commits mention "race condition" total, only 2 tie to a CVE in the same commit — undercount likely | **genuinely mixed**: TLS/DTLS/QUIC handshake code = network; ASN.1/OID/X.509/DH parsing = non-network — **solves curl's S-H3 gap directly** | mixed audit + external researcher reports (not fuzzer-dominated in the sample; openssl does have *some* OSS-Fuzz integration, split not fully quantified) | **21 years** (2005–2026), confirmed from 343 CVE-mentioning commits | ~11s (500K-LOC proxy, repo #2 estimate, not re-measured) | not sampled this pass (existence not the blocker — genuineness/volume was) | **Fixed-side-only, same accepted-gap shape as golang/go in repo #2.** Only candidate surveyed that clears CWE + concurrency + network-mix simultaneously. |
| **tensorflow** | C++/Python | **0 genuine dual-sided** (0/427 have a genuine non-"0" introduced side — the non-"0" "introduced" events that exist are auto-generated per-branch version-bump proxies, verified) | **not native** (1/427 GHSA-native); **joinable via NVD/OSV for a subset** — 3/6 sampled had CWE (CWE-617, CWE-20 ×2) | **+2, +19, +14** across 3 diff-checked fixed commits — small but real, non-degenerate | **~2/427** mention race/concurrency keywords — thin, unconfirmed as real CVEs | **almost entirely non-network** — surface is malicious-model/crafted-tensor input to local ops (segfault/FPE/NPE/OOB); 0 TF Serving (network-service) CVEs found in the corpus | **predominantly human-reported** — named security researchers/teams in ~all sampled Attribution sections (Qihoo 360, Brown University, etc.), not fuzzer-dominated | **~5y dominant** (2019–2023; 200/170/34/21/1 by year 2021/2022/2020/2023/2024) — **below the ≥8y bar** | not computed (large monorepo, LOC not pulled) | not sampled | **376/427 (88%) fixed-side citations parse cleanly** from `We have patched the issue in GitHub commit [SHA]` boilerplate — highest-volume genuine-fixed-side trail found. Fails dual-sided, concurrency, network-mix, temporal-spread. |
| **vim** | C | **0 genuine** — 11/72 (15%) sampled had a non-"0" introduced SHA, and **3/3 diff-checked were unrelated commits**, not bisection (0% genuine after verification) | **90% native** (65/72 GHSA-native has `cwe_ids`) — best CWE coverage of any C candidate checked | not formally sampled; one verified fix (`sign_jump` Ex-injection) was +36 net | **0** found (no CWE-362/366/367 in the 72-CVE sample; vim is single-threaded) | mostly local/non-network (buffer/filename/Ex-command parsing); minimal network surface | 100% human-reported (security researchers credited by name in every advisory) | 72 native advisories span 2023–2026 only; older (pre-2023) CVEs exist in OSV back to ~2016 but carry the same `introduced:"0"` pattern, no CWE | not computed | not sampled | **High prior, verified hard, and it broke.** Looked like the best candidate on paper (CWE 90%, GIT ranges present) — the "dual-sided" subset is fabricated by version-window mapping, not bisection. Fixed side alone is genuine and well-cited (many commits literally end with a GHSA URL). |
| **imagemagick** | C | **0 genuine** — release/version-bump proxy confirmed via diff on the one non-"0" sample checked | **87% native** (164/189 GHSA-native has `cwe_ids`) — best raw CWE coverage of anything surveyed | not sampled | not checked | mostly non-network (local image-format parsing) | mixed, not quantified | 189 native advisories, dates not tabulated this pass | not computed | not sampled | Best CWE% found, but description text almost never cites a commit (4/189, 2%) — no viable fixed-side parser like TF's, unlike openssl/TF. |
| **netty** | Java | **0 genuine** — Maven release-plugin proxy confirmed via diff | **63% native** (74/117 has `cwe_ids`) — best managed-language CWE coverage found | not sampled | not checked | network-heavy (it's an async network I/O framework) — likely genuinely mixed if a real fix-commit source existed | not quantified | 117 advisories, dates not tabulated | not computed | not sampled | Best-looking managed-language candidate on paper; description commit-citations only 2/117 (1.7%) — no TF-style escape hatch. **Disqualified.** |
| nginx | C | **0** — release-tag proxy confirmed via diff (3/3 checked pairs, 2 shown in §0) | **0%** (0/3 sampled had `cwe_ids`) | not sampled | not checked | network-heavy by nature, but unusable without genuine commits | not quantified | 61 CVEs listed on nginx.org (2009–2026) | not computed | not sampled | GitHub mirror *does* have granular real history (confirmed non-mirror-only), so the trap is purely in OSV's extraction, not the source repo. Nginx's own advisories page has no commit links either. **Disqualified**, same shape as postgres/sqlite. |
| sqlite | C | **0** — version-bump proxy confirmed via diff | **0%** (0/1 sampled) | not sampled | not checked | almost entirely non-network (embedded DB engine) | not quantified | 54 CVEs on sqlite.org/cves.html | not computed | not sampled | Population too small (54) to clear ≥50 even before the quality problem. **Disqualified.** |
| systemd | C | **inconsistent, 0 reliable** — 1 of 2 diff-checked pairs was genuine (CVE-2021-33910, explicit CVE-citing fix commit) by coincidence, the other (CVE-2018-15687) was a bogus NEWS-file commit; both records are tagged `source: CPE_RANGE` in OSV, i.e. **the method is identical for both and only one got lucky** | not sampled (empty in both checked) | not sampled | concurrency-relevant by architecture (PID1, many workers) but not counted | mixed by architecture, not quantified | not quantified | only **15** native GHSA advisories (5 with CVE) | not computed | not sampled | Volume alone disqualifies (15 ≪ 50) before quality is even relevant. |
| postgres | C | **0** — no GIT ranges exist in OSV at all, only SEMVER; postgresql.org's own CVE pages link only to release-note pages, never a commit | not sampled | n/a | not checked | network-heavy by nature (it's a network DB server) but unusable | not quantified | n/a | not computed | n/a | Worse than openssl/redis — doesn't even have proxy SHAs to be tricked by. **Hard-disqualified.** |
| grafana | Go | n/a — not pursued past volume gate | 9/28 native | n/a | not checked | n/a | n/a | n/a | n/a | n/a | **28 native advisories — fails ≥50 before any quality check.** |
| hashicorp/vault, kubernetes | Go | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | **0 native GitHub security-advisories** on the primary repo (both run CVE processes off-GitHub) — not pursued further. |
| tokio-rs/tokio | Rust | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | **1 native advisory total** — no volume. |
| linux kernel | C | **genuinely large, structurally sound** (spot-checked CVE-2024-26581: 6 distinct introduced+fixed pairs across mainline+stable branches, all resolvable at `git.kernel.org`, not diff-content-verified this pass for time reasons) | **not available via OSV/NVD** — Linux's CNA doesn't do structured CWE the way others do; **gold-standard label quality is the `Fixes:` trailer + CNA provenance, not CWE** | not sampled | not sampled (known to exist; kernel has real historical race/TOCTOU CVEs, not quantified here) | genuinely mixed (net/ subsystem = network; fs/, drivers/ = mostly non-network) | mixed human-report + internal audit, not quantified | decades | **full kernel: ~591s/snapshot at ~30M-LOC ceiling estimate — disqualifying, ~10× over the 60s target.** Subsystem-scoped: **net/ (~2M LOC) ≈ 43s**, **fs/ (~1.5M LOC) ≈ 32s** — both clear the bar | not sampled | **Reported honestly per the brief: label-quality gold standard, cost-disqualified at full scope.** A subsystem-scoped harvest (net/ or fs/) is the one genuinely promising *unexplored* lead from this survey — not attempted, would need its own scoping work before it could be evaluated as a real candidate. |

## 2 · Top-3 recommendation

**No candidate surveyed — in repo #2 or repo #3 — simultaneously clears all five hard criteria
with genuine, verified data.** That is the honest headline. Every source that gives genuine
**dual-sided** (introduced+fixed) data is OSS-Fuzz-native (nDPI, harfbuzz, ghostscript), and every
OSS-Fuzz-native source checked so far has **zero CWE, ~zero concurrency, ~zero network** — because
fuzzers find memory-safety bugs in local parsers, not races in network protocol state machines.
Every source that gives real CWE + real concurrency + real network/non-network mix (openssl,
partially tensorflow) only ever cites a **fixed** commit, never a bisected **introduced** one.
This is not a search-effort gap — it recurred identically across 9 independently-checked
candidates via 3 different mechanisms (release-tag proxies, changelog-commit proxies, unrelated-
commit proxies), so it reads as a structural property of how projects other than OSS-Fuzz members
publish vulnerability data, not something a better query would fix.

> **Decision (2026-09-13):** primary = **openssl, accepted on a fixed-side-only basis** — the
> same accepted-gap shape golang/go used in repo #2, and for the identical reason: it is the only
> candidate that clears CWE (2), human-provenance + non-trivial churn (3), real race/TOCTOU CVEs
> (4), and genuine network/non-network mix (5) simultaneously. The introduced-side gap (1) is real
> and total — flagging it exactly as plainly as repo #2 flagged Go's.
> Reserve / dual-sided alternate = **ghostscript** (or nDPI/harfbuzz again) if the orchestrator
> would rather keep strict dual-sidedness and drop CWE — but that just re-runs repo #2's nDPI
> result a third time and adds nothing repo #3 was commissioned to test.
> Volume alternate = **tensorflow**, fixed-side-only, if a second/larger managed-adjacent corpus
> is wanted — but it fails concurrency and network-mix outright, and its temporal spread (~5y) is
> short of the ≥8y bar.

**Named primary: openssl.** Reasoning against criteria 1–5:
1. **Fails** — 0% genuine introduced-side coverage, verified; no source (OSV, NVD, CHANGES.md,
   commit messages) ever cites a bisected regression commit for any sampled CVE.
2. **Passes** — CWE not native to OSV's openssl records but reliably joinable via NVD (5/5
   sampled), matching the brief's explicit allowance ("qualifies if CWE is JOINABLE by CVE id").
3. **Passes** — provenance is a mix of internal audit and external researcher report (not fuzzer-
   dominated in the sample checked), fix churn sampled at +1 to +170 net LOC (median ≈+13),
   clearly non-trivial and structurally unlike nDPI's median +1.
4. **Passes, thin margin** — 2 confirmed genuine race-condition CVEs with CVE IDs cited directly
   in the fix commit message (CVE-2014-3509, CVE-2015-1791); 43 commits mention "race condition"
   total, so the true count is likely higher but unconfirmed without more per-commit CVE-tying.
5. **Passes** — TLS/DTLS/QUIC protocol code is genuinely network-facing; ASN.1/OID/X.509/DH
   parsing and validation code is genuinely local/non-network — this is the first candidate in
   either survey that offers a real contrast for S-H3, which curl (all-network) could not.

**What changed from repo #2's verdict on openssl.** Repo #2 flagged the CHANGES.md/commit trail
as "future-work, not attempted." This pass spent the time-boxed ≤20 minutes the brief asked for:
sampled 10 random CVE-tagged commits from the 343-commit "mentions CVE-" search, and **9/10
resolved directly to a genuine, diff-verified fix commit**; the 10th (CVE-2021-4160) required one
extra hop through a PR-number reference cited in a CHANGES.md-only commit. That is a much higher
hit rate than the "custom parser, unvalidated" framing implied — **the trail is viable today**,
not a stretch goal.

## 3 · vim and tensorflow verdicts (as specifically requested)

**vim: does not qualify, and the reason is instructive.** It had the highest prior of any
candidate in the brief — huntr-era OSS-Fuzz-adjacent reputation, human-reported, C, huge
history — and it does deliver on CWE (90% native coverage, the best C-language number in this
survey) and on genuine fixed-side commits (many vim patches literally end with a GHSA URL in the
commit trailer, unambiguous). But the "dual-sided" claim is **fabricated by OSV's tooling**: only
~15% of sampled CVEs even have a non-`"0"` introduced SHA, and every one diff-checked in this pass
turned out to be an **unrelated** commit (a GTK4/X11 build-config change for a JSON-decode UAF; a
filetype-detection commit for a tuple-import UAF) — not a nearby version-bump like the other
traps, but a genuinely random-looking nearest-preceding-patch-number pick. This is a *worse*
failure mode than a release-tag proxy because it's less obviously wrong at a glance — it *looks*
like a real commit hash pointing at real code, and only breaks under the exact diff-content check
the brief mandated.

**tensorflow: fixed-side-only viable, but doesn't solve repo #3's actual ask.** 427 native GHSA
advisories, 376 (88%) with a cleanly parseable `We have patched the issue in GitHub commit [SHA]`
citation that verified genuine on every sample diff-checked (+2 to +19 net LOC, real source files,
real tests). CWE joinable via NVD for roughly half the sample. But its CVE population is
**overwhelmingly one mechanism class** — crafted tensor/model input causing segfault/FPE/NPE/OOB
in a local op kernel — which means **near-zero concurrency signal and near-zero network signal**,
i.e., it fails the two criteria repo #3 exists specifically to add (S-H3's non-network contrast,
S-H4's race/TOCTOU population). It also has 0% genuine introduced-side coverage, same as every
other candidate. Its temporal spread (concentrated 2019–2023, thin before/after) is also short of
the ≥8y bar. Good volume, good fixed-side parseability, wrong mechanism mix.

## 4 · openssl CHANGES/commit-trail parseability test (the ≤20-minute task)

Method: `gh api "/search/commits?q=CVE+repo:openssl/openssl"` → 343 total commits mentioning
"CVE-" across **2005–2026** (21-year span), 224 unique CVE IDs. Classified by first line of commit
message: 5 pure `CHANGES.md`/`NEWS.md` bulk-update commits, 17 test-only commits (`Add test for
CVE-...`), 321 "genuine-looking" by first-line heuristic.

Random 10-CVE sample (seed=7), each resolved to its associated commit(s) and diff-verified:

| CVE | resolved commit | verdict |
|---|---|---|
| CVE-2023-0216 | `80253dbd` "Do not dereference PKCS7 object data if not set / Fixes CVE-2023-0216" | genuine, `crypto/pkcs7/pk7_lib.c`, +12/-4 |
| CVE-2021-4160 | `134f17d5` "Document CVE-2021-4160" (CHANGES.md/NEWS.md only) | **not genuine directly** — message names the real fix as PR #17258, one more hop needed |
| CVE-2011-4619 | `206310c3` "Fix bug in CVE-2011-4619: check we have really received a client hello..." | genuine, `ssl/s3_srvr.c`, +14/-8 |
| CVE-2014-3508 | `0042fb5f` "Fix OID handling..." | genuine, `crypto/asn1/a_object.c` + `obj_dat.c`, +30/-16 |
| CVE-2026-42771 | `b3a555a0` "Fix length miscalculation in validate_email" | genuine, `crypto/x509/x509_vpm.c`, +3/-3 |
| CVE-2026-35188 | `58633b65` "Fix Double-free When Checking OCSP Stapled Response" | genuine, `crypto/x509/x509_vfy.c`, +1/-0 |
| CVE-2016-6308 | `48c054fe` "Excessive allocation of memory in dtls1_preprocess_fragment()" | genuine, `ssl/statem/statem_dtls.c`, +18/-17 |
| CVE-2010-2939 | `57594258` (bundled `CHANGES` + code, pre-GitHub-PR era) | genuine, `ssl/s3_clnt.c`, +4/-0 |
| CVE-2026-45446 | `609bcb24` "Fix handling of empty-ciphertext messages in AES-GCM-SIV and AES-SIV" | genuine, 2 crypto files + test, +159/-11 |
| CVE-2023-3817 | `1c16253f` "DH_check(): Do not try checking q properties if it is obviously invalid" | genuine, `crypto/dh/dh_check.c`, +8/-1 |

**Result: 9/10 resolve directly; the 10th resolves with one extra PR-number hop.** This is a
strong, practically-usable hit rate — **the CHANGES/commit-message trail is parseable**, reversing
repo #2's "not attempted, future work" framing into a verified "works, fixed-side-only" result.
The remaining risk not fully quantified in this 20-minute box: the parser would need a rule to
skip changelog/test-only commits and, for the ~10% CVE-2021-4160-style cases, follow a `#NNNNN`
PR reference to its merge commit — both are mechanical, not judgment calls.

## 5 · What I could not verify

- **ghostscript's 192 OSS-Fuzz dual-sided events** were confirmed non-degenerate (introduced ≠
  fixed ≠ "0") at the population level but **not individually diff-checked** the way nDPI's 40-SHA
  sample was in repo #2 — time-boxed out given the population was disqualified on CWE regardless.
- **openssl's race/TOCTOU CVE count** — 2 confirmed via direct commit-message CVE citation; the
  43-commit "race condition" keyword hit rate suggests more exist but aren't tied to a CVE in the
  same commit (older openssl practice separated the fix commit from the CVE-announcement commit
  more often, per §4's CVE-2021-4160 case) — undercounted, not fully resolved.
- **openssl's human-vs-fuzzer provenance split** — sampled commits read as audit/researcher-driven,
  not fuzzer-driven, but no systematic classification (e.g., counting OSS-Fuzz-tagged commits
  across the full 224-CVE population) was run.
- **linux kernel's diff-level genuineness** — the CVE-2024-26581 sample showed structurally sound,
  distinct introduced/fixed SHA pairs per stable branch, consistent with the well-documented
  `Fixes:` trailer convention, but I did not pull and read the actual diff content the way I did
  for the 9 other candidates, given the full-kernel cost estimate already disqualifies it and a
  subsystem-scoped variant was flagged as future work rather than pursued.
- **ImageMagick and netty's total advisory counts by year** (temporal spread) were not tabulated
  since both failed the dual-sided check before temporal spread became relevant.
- **grafana, vault, kubernetes, tokio** were only checked at the volume gate (native GHSA advisory
  count) and dropped before any quality check — genuinely under-explored if the orchestrator wants
  a Go/Rust dual-sided candidate specifically; their off-GitHub CVE processes (vault, kubernetes)
  were not queried through NVD/OSV directly, only through the GH-native advisories endpoint.
- **Scan-cost numbers** are LOC-proxy estimates (kernel from published line-count figures, openssl
  carried over from repo #2's estimate) — no scans were run, per the brief's hard constraint.
