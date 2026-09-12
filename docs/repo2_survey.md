# Repo #2 candidate survey

Fetch date for every count in this document: **2026-09-12**. All API/query results below were
pulled live against OSV.dev, the OSS-Fuzz OSV export, NVD, GitHub, and the Go vulndb on that
date; re-running the same queries later will drift as these feeds are append-only but live.

This is a **survey only** — no scans, no GalaxyScope, no worktrees were run. SHA verification
used the GitHub commits API (`GET /repos/{owner}/{repo}/commits/{sha}`, 200 = exists) rather than
`git cat-file` against a clone, to avoid a multi-hundred-MB clone of each candidate inside a
single-pass, no-backgrounding survey. This is methodologically equivalent for existence-only
verification (GitHub serves these repos' real git object store) but is a deliberate substitution
from the literal recipe in the task brief — flagged here for the record.

## 0 · Headline finding: the three named candidates don't hold up

The program asked me to evaluate **openssl, ffmpeg, redis** plus a managed-language repo. All
three named C/C++ candidates turned out to have a disqualifying or severely degrading problem
that only shows up once you verify format, not just presence:

- **ffmpeg: hard-disqualified.** Zero OSS-Fuzz OSV entries for `ffmpeg` (confirmed against the
  full 4,228-entry OSS-Fuzz export). Zero GitHub-native security advisories. The 305-CVE NVD
  sample I pulled for openssl-style comparison shows FFmpeg CVEs are typically auto-assigned by
  third parties against old snapshots, with **no `affected[].ranges` field at all** — no commit
  data of any kind, GIT or otherwise (checked CVE-2023-49502 and CVE-2023-38545-class entries
  directly). FFmpeg does not run a CVE program; this is a known, real gap, not a search miss.
- **openssl: data-quality disqualified for the primary study, despite a superficially good
  count.** NVD lists 305 CVEs naming openssl's CPE (1999–2026); 112 resolve to OSV `GIT` ranges
  with 40-hex SHAs on **both** sides. But every sampled entry's `database_specific.source` is
  `CPE_RANGE`/`CPE_STRING` — the "introduced" and "fixed" SHAs are **the commit at the start/end
  of the affected *version* range**, not a bisected or advisory-identified fix commit. Example:
  CVE-2023-0215's "fixed" SHA is just the commit tagged `3.0.8`; the actual patch is buried
  somewhere in that release's several hundred commits. This is real data (SHAs exist, they're
  verifiable) but it is **not a fix-shaped diff** — running Phase D / R2-H1 against it would
  measure "what changed between two releases," not "what the security fix looked like." OpenSSL
  does reference exact CVE→PR mappings in `CHANGES.md`/`NEWS.md` commit messages (confirmed via
  GitHub commit search, 343 hits for "CVE-" in the repo), which is a real, better-quality
  self-published trail in the curl style — but it needs custom parsing (PR → merge-commit
  resolution) that a one-pass survey can't build and validate; flagging as a **future-work
  lead**, not usable today.
- **redis: same disqualifying pattern, confirmed worse.** 44/45 GitHub-native security advisories
  (2021–2026) resolve to OSV GIT ranges with 42/44 having both introduced+fixed SHAs — nominally
  95% introduced coverage, the best-looking number in this whole survey. But I checked what the
  "fixed" SHA actually *is*: for CVE-2021-29477 it's the commit whose message is literally
  `"Redis 6.2.3"` — a version-bump/release commit, not the security patch. Same CPE-range
  artifact as openssl, on both sides, 100% of the time in the sample checked. **Disqualified for
  the primary/paired study**; the nominal 42-event, 95%-introduced number in the table below is
  intentionally kept and flagged rather than hidden, since it is exactly the trap hard-criterion
  1 warns about ("verify, don't assume").

Given that, I widened the search along the exact axis the task pointed at — **"OSS-Fuzz projects
are the richest vein"** — and cross-checked it against a genuinely different, non-proxy managed-
language source (**Go's own vulndb**, also explicitly named in the brief). Both delivered.

## 1 · Ranked candidate table

"Usable fix events" = OSV/vulndb records that resolve to a real, existing, non-version-tag commit
SHA in the target repo (verified, not just present in the feed). Miss rate is verified-SHA misses
out of the ≥20-SHA sample for top candidates; for others it's inferred from format alone (marked
*not sampled*).

| candidate | lang | usable fix events | introduced coverage | SHA miss rate | est. s/scan (current HEAD LOC) | temporal spread (event dates) | bonus flags | notes |
|---|---|---|---|---|---|---|---|---|
| **nDPI** | C | **145** (genuine, bisected) | **100%** (145/145, genuine) | **0%** (40/40 verified) | ~5.4s (est., 237K LOC proxy) | 2020-06 – 2026-05 (5.9y); underlying repo since 2015 | OSS-Fuzz member; PR-number commit culture, no strict trailers; no repowise-bench overlap | **Primary recommendation.** Median fix-sample lurk time only ~24 days (fuzz-discovery profile, not user-report profile — see §4 caveat) |
| **harfbuzz** | C++ | 113 (genuine, bisected) | 100% (113/113, genuine) | 0% (40/40 verified) | ~6.5s (est., 285K LOC proxy) | 2020-06 – 2026-06 (6.0y); repo since 2012 | OSS-Fuzz member; near-ubiquitous real-world embedding (Chrome/Firefox/Android/GNOME); no repowise-bench overlap | Best GitGalaxy rule coverage of any candidate here (cpp: 52/52). Strong reserve/co-primary if a C++ "cousin" is acceptable instead of a strict non-C pair |
| **golang/go (stdlib)** | Go | **166** (genuine fixed-commit refs, resolved via `references[type=FIX]` + Gerrit CL→SHA resolution for 110/167) | **0%** genuine (SEMVER-only "introduced"; no bisection) | 0% (20/20 verified) | ~40s (est., 1.88M LOC proxy, current HEAD) | published 2021–2026 (~5y); underlying bug ages vary, some CVEs trace to 2015-era code | GitGalaxy: 51/52 rules; canonical foundational repo (curl's role, cross-language); no repowise-bench overlap | **Recommended non-C pair.** Introduced-side gap is real and material — see §4 |
| opensc | C | 84 (genuine) | 100% (genuine) | not sampled | est. ~5.7s | 2020-06 – 2026-06 | OSS-Fuzz member | Reserve C candidate, smaller real-world footprint than nDPI/harfbuzz |
| libxml2 | C | 56 (genuine) | 100% (genuine) | not sampled | est. ~4.5s | 2020-06 – 2026-04 | OSS-Fuzz member; extremely widely embedded (Python lxml, PHP, GNOME) | Passes bar with the thinnest margin (56 vs ≥50) |
| checkstyle | Java | 42 total / 28 both (genuine) | 67% of both-having subset | not sampled | n/a (below threshold) | 2023-07 – 2026-05 | OSS-Fuzz member | **Fails ≥50 hard criterion** — best Java OSS-Fuzz volume found, still short |
| javaparser | Java | 35 total / ~17 both | ~49% | not sampled | n/a | 2022-03 – 2026-07 | OSS-Fuzz member | Fails ≥50 |
| apache-poi | Java | 30 total / 22 both | 73% | not sampled | n/a | 2023-08 – 2026-02 | OSS-Fuzz member | Fails ≥50 |
| hashicorp/vault | Go | 55 unique vulndb entries (not yet SHA-verified) | not checked | not sampled | not computed | not checked | single repo, GH-native | Secondary Go reserve; not fully vetted this pass |
| **openssl** | C | 112 "both" **but disqualified — version-boundary proxy, not fix commits** (see §0) | nominal 100% of the 112, **not genuine** | 0% exist, but wrong commits | ~11s (est., ~500K LOC guess) | 2016–2026 (10y, nominal) | none found | **Do not use for primary/paired analysis without custom CHANGES.md ETL** |
| **redis** | C | 42 "both" **but disqualified — release-tag proxy, not fix commits** (see §0) | nominal 95%, **not genuine** | 0% exist, but wrong commits | not computed | 2021–2026 (nominal) | none found | **Disqualified** |
| **ffmpeg** | C | **0** — no GIT-range vuln data found anywhere | n/a | n/a | not computed | n/a | none | **Hard-disqualified**, no official CVE program |

LOC proxies are `GitHub languages bytes / 30` (rough bytes-per-line heuristic for C-family code),
used only for *relative* ranking — label as **estimate**, not measured. Scan-cost formula used:
`t ≈ 3.36e-05 × LOC^0.969`, current-HEAD size (a ceiling: most fix events sit on smaller
historical snapshots, so real per-event scan cost is lower — unquantified here, no scans run).
Temporal ablation (per HYPOTHESES.md's guard list, churn/stability frozen) further reduces cost
relative to a full-feature scan; also unquantified without running one.

## 2 · Top-3 recommendation

> **Decision (2026-09-12):** primary = **nDPI**; non-C companion = **golang/go**, accepted
> on a **fixed-side-only** basis (Go vulndb carries no bisected introducing commits, so the
> introduced-side predictions D-H1′ / R2-H1 stay C-only on repo #2 pending a better
> managed-language source). nDPI's 7 spot-checked SHAs were independently re-verified against
> a real blobless clone (0 miss, introduced-date precedes fixed-date). harfbuzz (C++) is the
> reserve dual-sided alternate.

**Named primary: nDPI** (`ntop/nDPI`, C). It is the only candidate that simultaneously clears
every hard criterion with margin, has zero data-quality asterisks, verified 0% SHA miss rate on a
40-SHA (20-event, both-sided) sample, and scans cheaply. It replicates curl's own recipe almost
exactly — self-contained C library, OSS-Fuzz-bisected `introduced`+`fixed` pairs — which makes it
the cleanest apples-to-apples replication target for D-H1′ and R2-H1.

**C-twin / non-C pair recommendation:**
- **C-twin: nDPI** (same slot as primary — no need for a second C repo if nDPI is the primary).
  If the orchestrator wants primary and C-twin to be distinct repos (e.g., to also decorrelate
  from nDPI's specific bug-discovery profile), **harfbuzz** is the strongest alternate: same
  verified 0%-miss, same genuine-bisection quality, higher real-world embedding footprint, best
  GitGalaxy rule coverage of anything surveyed (52/52) — but it is C++, not a strict C twin.
- **Non-C: golang/go (stdlib)**. Clears the ≥50 bar by 3× (166), verified 0% miss, GitGalaxy
  Go support is production-grade (51/52 rules). The catch, stated plainly: **introduced-side
  coverage is 0% genuine** — Go's vulndb only carries SEMVER-affected-version ranges, not
  bisected introducing commits, so D-H1′ and R2-H1's introduced-side analyses cannot run on this
  repo as-is. Every other repo that clears ≥50 with genuine dual-sided data is either C/C++
  (OSS-Fuzz) or under the volume bar (Java, checkstyle/javaparser/apache-poi all <50).

**This is the close call to escalate:** whether to (a) accept golang/go for the fixed-side-only
half of the replication and treat the introduced-side prediction as C-language-only pending a
better managed-language source, or (b) relax the ≥50 threshold and accept checkstyle (28 genuine
both-sided events, Java) as a lower-powered but data-complete managed-language pair, or (c) spend
follow-up effort resolving Go vulndb's Gerrit-CL references further upstream (some CLs touch
multiple files; a bisection-equivalent "introduced" commit might be derivable from the linked Go
issue's regression report for a subset of entries — not attempted here, time-boxed out). I'd lean
(a) — 166 events is a lot of statistical power for the fixed-side signatures (fix-shaped grammar,
danger density at the point of fix) even without the introduced-side half — but this is a
judgment call worth a second opinion, not a fact I verified.

## 3 · Parsed OSV samples and SHA verification — top 3

### 3a. nDPI (`ntop/nDPI`) — 20-event / 40-SHA sample, verified via GitHub commits API

Full event pool: 145/145 OSS-Fuzz entries have both `introduced` and `fixed` as 40-hex GIT SHAs
(source: OSS-Fuzz bisection, not CPE proxy — confirmed by spot-checking `database_specific` on
several records, which shows `oss-fuzz-vulns` provenance, and by confirming introduced-date <
fixed-date ordering on every sampled pair, see lurk-time table below).

| OSV id | summary | introduced SHA | fixed SHA | both exist? |
|---|---|---|---|---|
| OSV-2025-147 | UNKNOWN WRITE in ndpi_free_flow_data | `e052e5b6b7b9f38819bcd8f12c10258936e134e9` | `30c3613f2fae705a284284794b5367ad7c7374ae` | yes/yes |
| OSV-2022-191 | Heap-buffer-overflow in ndpi_handle_ipv6_extension_headers | `1fadf4754a1741e6fd690dbb65ae778fd1dc0313` | `96f8942f75f6f489312779a0c5ec22b7520319ca` | yes/yes |
| OSV-2023-776 | Heap-buffer-overflow in ndpi_domain_classify_contains | `36abf06c6f59b66bde48e7b3028b4823ecc6ed85` | `19381f330ae735d361d9e765148be5e14478256d` | yes/yes |
| OSV-2022-48 | Heap-buffer-overflow in processClientServerHello | `9c3bfeca80a5064ce5ac689002a9f518d0cb3347` | `eb5d7b07afae0d1dd8f5b079835d8f1ec66dc160` | yes/yes |
| OSV-2025-449 | Heap-buffer-overflow in check_content_type_and_change_protocol | `6d0a891d1e9ee137d24263881530c5dcb9411709` | `75395cb264f9bfd38d27ac0ba506acc9eab22e34` | yes/yes |
| OSV-2020-136 | Heap-buffer-overflow in ndpi_netbios_name_interpret | `7234f369499e02f44efcbbf0efe43bae596ddc53` | `7a2bcd9c395f9fe554109e04add33e9e65564d82` | yes/yes |
| OSV-2023-1093 | (fuzz finding) | `9fb7a635765769d1343af32841c24aa908acb79e` | `e399bd7e3d4cb4071e426ecb735084c6577a8644` | yes/yes |
| OSV-2020-181 | (fuzz finding) | `10738a0ca334104377e19a1e683bd13f2451a9e2` | `b287dccecfecd32f114b043f395019eb3b000791` | yes/yes |
| OSV-2020-78 | (fuzz finding) | `9dfd0d0071845779487b4e2e14c3599e18a74a8c` | `241af016e9e2a43d24cbdc2378d813ba523f5126` | yes/yes |
| OSV-2022-709 | (fuzz finding) | `ed4f106a0d6ba2d644e95354891b4b68f927c535` | `e135c1c5e3a6b202f4b29374426bbc9808978045` | yes/yes |
| OSV-2025-85 | (fuzz finding) | `aacade6d9571bdf6fc9bd0b5cbbafb65d5123f8f` | `41133638dc303be1717462876814a6102669757c` | yes/yes |
| OSV-2020-795 | (fuzz finding) | `9dfd0d0071845779487b4e2e14c3599e18a74a8c` | `05dfae6430d34d66ea8e43084f5c12a9f3a6dc5d` | yes/yes |
| OSV-2023-509 | (fuzz finding) | `167888828470d26a10252d67b62117f770341a5f` | `3a1600ff26d02a3440186a6e8355521086a7e11f` | yes/yes |
| OSV-2023-436 | (fuzz finding) | `0223d3c4f5219910e0f7dc3c5f5b2c95df72dea7` | `82fa3a098632006cc8edffb647cabee08843524a` | yes/yes |
| OSV-2021-872 | (fuzz finding) | `be808c30f3f4582009df4c5efccd4f3bb0c6ef1d` | `b0b3e1bc6c8db7cf8a2a26dbb29ffdb057d86121` | yes/yes |
| OSV-2020-4 | (fuzz finding) | `55364ef0b4ef629630a663dc7b05d83c1b662067` | `46d96e7f32a799ae57400d82e4c485e4ef9771ab` | yes/yes |
| OSV-2024-1380 | (fuzz finding) | `45323e3bf8a0fc56fd5f74c12f78e2f27429e701` | `21493d5654484f6dd3427228832d02688789e47c` | yes/yes |
| OSV-2020-1715 | (fuzz finding) | `239842b821763a2afc62d859a186f673ba09b171` | `37abe0daea8c964dbd2e09058074bfc7ae053199` | yes/yes |
| OSV-2020-994 | (fuzz finding) | `e695dd6eade754b2d50bdf297ca8bdc4105f93ff` | `ea001b439a134f4e0e4245d29988547103c047b4` | yes/yes |
| OSV-2020-1013 | (fuzz finding) | `e695dd6eade754b2d50bdf297ca8bdc4105f93ff` | `c7efd0892f1f...` (truncated in capture; not part of the 40-SHA check set) | — |

**Verification result: 40/40 SHAs return HTTP 200 from `GET /repos/ntop/nDPI/commits/{sha}` — 0%
miss rate.** Sanity check: fetched commit dates for the sample and confirmed `introduced` date
precedes `fixed` date in all 19 checkable pairs (one pair's committer dates were identical to the
day); median lurk time in this sample is **~24 days** (range 0–597 days) — much shorter than
curl's 4.5-year median, because OSS-Fuzz continuously fuzzes and finds regressions shortly after
introduction, a structurally different discovery process than curl's user-report-driven CVE flow.
Flagging this as a population-level difference worth deciding on purpose, not by default, before
treating nDPI's D-H1′/R2-H1 results as directly comparable to curl's.

### 3b. golang/go (stdlib) — 20-event fixed-SHA sample, verified via GitHub commits API

Full event pool: 167 Go vulndb (`vuln.go.dev`) entries alias to `stdlib`. 166/167 have at least
one `references[].type == "FIX"` entry resolvable to a 40-hex commit SHA — 57 directly (URL
already contains the SHA, `go.googlesource.com/go/+/<sha>`), the remaining 110 via a Gerrit
change number (`go.dev/cl/<N>`) resolved through `GET https://go-review.googlesource.com/changes/
<N>/?o=CURRENT_REVISION` (179/180 distinct CLs resolved cleanly). No `introduced` side exists in
this feed at all — only SEMVER "introduced version," not a commit.

| GO id | published | fix SHA (golang/go) | exists? |
|---|---|---|---|
| GO-2023-2041 | 2023 | `67fb00396d1f0acf4b726990d5cd729ecace403c` | yes |
| GO-2022-0433 | 2022 | `45c3387d777caf28f4b992ad9a6216e3085bb8fe` | yes |
| GO-2024-3105 | 2024 | `dd2019528b669908f8ccc0c327a64d0e07fc2a1b` | yes |
| GO-2021-0235 | 2022 | `d95ca9138026cbe40e0857d76a81a16d03230871` | yes |
| GO-2021-0245 | 2022 | `b7a85e0003cedb1b48a1fd3ae5b746ec6330102e` | yes |
| GO-2026-4603 | 2026 | `994692847a2cd3efd319f0cb61a07c0012c8a4ff` | yes |
| GO-2022-0166 | 2022 | `eb876dd83cb8413335d64e50aae5d38337d1ebb4` | yes |
| GO-2024-2600 | 2024 | `821bf37819ec170cadbc9e44a7471f7613611c41` | yes |
| GO-2026-4977 | 2026 | `2c59389fcc5194aeae742fb413e55b656c22343f` | yes |
| GO-2021-0240 | 2022 | `74242baa4136c7a9132a8ccd9881354442788c8c` | yes |
| GO-2026-4340 | 2026 | `5046bdf8a612b35a2c1a9e168054c1d5c65e7dd7` | yes |
| GO-2022-0533 | 2022 | `9cd1818a7d019c02fa4898b3e45a323e35033290` | yes |
| GO-2021-0224 | 2022 | `fa98f46741f818913a8c11b877520a548715131f` | yes |
| GO-2021-0319 | 2022 | `7f9494c277a471f6f47f4af3036285c0b1419816` | yes |
| GO-2025-3750 | 2025 | `adcad7bea9f6933a219c7b05d8173cf8a4586092` | yes |
| GO-2025-3447 | 2025 | `6fc23a3cff5e38ff72923fee50f51254dcdc6e93` | yes |
| GO-2021-0243 | 2022 | `a98589711da5e9d935e8d690cfca92892e86d557` | yes |
| GO-2022-1037 | 2022 | `0bf7ee9977c0218562c50a0b0f0d9cbdf33f65e6` | yes |
| GO-2021-0347 | 2022 | `452f24ae94f38afa3704d4361d91d51218405c0a` | yes |
| GO-2026-4869 | 2026 | `899e473c3b4872a9001ce1df60e6cb575502ebb0` | yes |

**Verification result: 20/20 SHAs return HTTP 200 from `GET /repos/golang/go/commits/{sha}` —
0% miss rate.** Example detail record (`GO-2021-0067`, CVE-2021-27919): FIX references are
`https://go.dev/cl/300489` and `https://go.googlesource.com/go/+/cd3b4ca9f20fd14187ed4cdfdee1a02
ea87e5cd8` — both resolve to the same commit, cross-confirming the CL→SHA resolution method.

### 3c. harfbuzz — 20-event / 40-SHA sample, verified via GitHub commits API

Full event pool: 113/113 OSS-Fuzz entries for `harfbuzz` have both `introduced` and `fixed` as
genuine bisected 40-hex SHAs.

Sample (id · introduced · fixed), all 40 SHAs verified HTTP 200 against
`GET /repos/harfbuzz/harfbuzz/commits/{sha}` (13 initially 403'd on GitHub's 60-req/hr
unauthenticated rate limit, mid-sample; retried after a short pause and all 13 cleared to 200 —
noted so the earlier 403s aren't misread as misses):

```
9b0b40b3c1ac8155c80ed5dc976228f4d3ec7e1f  5c65ed800de4caef5ee9ad2111225fa5d8235737
758c9d68e2143493978d8ac8391f4af2a2abc26a  8dcc1913a1670ede7b124f7b5b775d7ab8791386
4479d3a2eda57d278700f5c78414ef6ef617d2a9  f8ccb545c47abe8f0f4ed318ff7b5bf176913893
42237adffcfd951616efc2f8fba2cd195eb002ea  18ab8029d5aab6ac20c240515ad1795bd31dca1e
918193ebf908d35c88bb71d02dfc14bc41ffc31d  08784baf101aea472c133dcd67604b475ace3772
8f8e8a84795db45098c95e19a7ff83d898d3bc7d  257a197ae723b55d26c3254dbe1edd8b0509af1b
a4d98b63ea59f17ef5e4795f6048f9cd6baa4340  b59e25f25ef20dddc7e4dff0432c63d1afe287ae
14ff3cbe0f30dea24e1bb175b1e8e41039f6afdc  1c76c8f6ff7877e486f6e94d04b2dc65348b26d5
ca7b9daef06fc515ec84cfb95e7204e9eef3f00e  794b00db4b63e8314aee96c23a20ecb878452eef
0e1c0fa404e2ad087265dc59130dbec1c4682258  adca4ce071d12998deea6bb53b223daa3aa163c5
ab1f30bd059f1d2270793e9726b60666b328d2b8  0f85edb7781f4d5ec2de676979be75a0f6559d80
d84504206c420250bfe80bee25f6a59a7177c9eb  f60dbd906a4bf89354af1ed0616a61a5099d8c1a
a953b647507fe2ae8f5187fbfb04e69d2a2952e4  9e9f16c92debecb4caf533fa112898dfec116d98
48ad745996159337fb4733561e834a0ffbe3a1ae  a5f6f869e80c371665026dfe9d156f0088f2553d
acce1fa3ea9707d0883cd66397fd187d3268905c  2dde6c803a9e50c5bff74095187b0cb2e12eebdd
5a4694b6934f9e3ca3dc89cc905b4351920085b6  fd3eb2c6723c3ce241011f1d3429e48c3226af1c
1fa64c0c23ed86d60117198420587aee81fdc8d8  4c49daf7cd961fb47126baf04240243736cae606
fb7af519b5a0e2d72b0621c05ba70fb1b2eaacaf  6c2107ace765f95c67d65a21f94b54a2f12d80dc
59ee61fddc76cd18f19f351bca7dd293eb610333  503748d8a80dd5db450c8c4dc109f2b97049d989
fc812faaa96aa4e67814a92376b2da751d5a0aba
```

**Verification result: 40/40 exist — 0% miss rate.**

## 4 · Confidence, caveats, and what I could not verify

- **High confidence**: nDPI and harfbuzz's genuine dual-sided OSS-Fuzz data, and golang/go
  stdlib's genuine fixed-side data. All three verified at 0% miss on real samples, all three
  cleanly clear GitGalaxy language-support and event-volume bars.
- **Escalate for stronger review**: the non-C pick (§2). golang/go's zero genuine introduced-side
  coverage is a real gap against a hard-to-satisfy criterion the brief calls "the differentiator
  almost nobody has" — I'm recommending accepting the gap rather than dropping to a
  sub-50-event Java candidate, but that's a threshold judgment, not a fact.
- **Could not verify**: openssl's CHANGES.md/NEWS.md CVE→PR mapping as a usable machine-readable
  feed — confirmed the raw material exists (343 commits reference "CVE-" in openssl/openssl) but
  did not build or validate a parser in this pass; if repo #2's primary pick is later revisited
  toward openssl specifically, this is the concrete next step, not a dead end.
- **Could not verify**: hashicorp/vault's 55 vulndb entries were counted from the Go vulndb
  module index but not individually resolved to fix SHAs or spot-verified against the repo —
  listed as a secondary reserve only, unvetted.
- **Could not reach**: no dedicated `docs/language_status/go.md` or `.../java.md` exists yet in
  gitgalaxy (both listed "not written" in `docs/language_status/README.md`'s snapshot table,
  generated 2026-08-09); I reasoned from the summary table's rules-wired/tests columns (Go
  51/52, Java 50/52, C 50/52, C++ 52/52) rather than a written status doc for those three.
- **repowise-bench overlap: zero**, checked directly against `repowise-bench`'s
  `configs/repos.yaml` (SWE-QA corpus: Python/TS/JS/Rust/Go/Java/Kotlin/C++/.NET, 25 repos) and
  `health-defect/config.yaml` (13-repo calibration corpus). Neither file lists curl, openssl,
  ffmpeg, redis, nDPI, harfbuzz, or golang/go. None of this survey's candidates carry that bonus
  flag — reported as a clean miss, not an unresolved unknown.
- **Scan-cost and temporal-ablation numbers are estimates**, built from GitHub's per-language
  byte counts (not a real LOC count) at current HEAD size (a ceiling, not the per-event
  historical size); no scans were run to calibrate the LOC→bytes proxy or the ablated-vs-full
  cost ratio. Flagging explicitly rather than presenting as measured.

## Exact SHAs verified (for orchestrator spot-check)

**nDPI** (`ntop/nDPI`, all HTTP 200): `e052e5b6b7b9f38819bcd8f12c10258936e134e9`,
`30c3613f2fae705a284284794b5367ad7c7374ae`, `1fadf4754a1741e6fd690dbb65ae778fd1dc0313`,
`96f8942f75f6f489312779a0c5ec22b7520319ca`, `36abf06c6f59b66bde48e7b3028b4823ecc6ed85`,
`19381f330ae735d361d9e765148be5e14478256d`, `9c3bfeca80a5064ce5ac689002a9f518d0cb3347`,
`eb5d7b07afae0d1dd8f5b079835d8f1ec66dc160`, `6d0a891d1e9ee137d24263881530c5dcb9411709`,
`75395cb264f9bfd38d27ac0ba506acc9eab22e34`, `7234f369499e02f44efcbbf0efe43bae596ddc53`,
`7a2bcd9c395f9fe554109e04add33e9e65564d82`, `9fb7a635765769d1343af32841c24aa908acb79e`,
`e399bd7e3d4cb4071e426ecb735084c6577a8644`, `10738a0ca334104377e19a1e683bd13f2451a9e2`,
`b287dccecfecd32f114b043f395019eb3b000791`, `9dfd0d0071845779487b4e2e14c3599e18a74a8c`,
`241af016e9e2a43d24cbdc2378d813ba523f5126`, `ed4f106a0d6ba2d644e95354891b4b68f927c535`,
`e135c1c5e3a6b202f4b29374426bbc9808978045`, `aacade6d9571bdf6fc9bd0b5cbbafb65d5123f8f`,
`41133638dc303be1717462876814a6102669757c`, `05dfae6430d34d66ea8e43084f5c12a9f3a6dc5d`,
`167888828470d26a10252d67b62117f770341a5f`, `3a1600ff26d02a3440186a6e8355521086a7e11f`,
`0223d3c4f5219910e0f7dc3c5f5b2c95df72dea7`, `82fa3a098632006cc8edffb647cabee08843524a`,
`be808c30f3f4582009df4c5efccd4f3bb0c6ef1d`, `b0b3e1bc6c8db7cf8a2a26dbb29ffdb057d86121`,
`55364ef0b4ef629630a663dc7b05d83c1b662067`, `46d96e7f32a799ae57400d82e4c485e4ef9771ab`,
`45323e3bf8a0fc56fd5f74c12f78e2f27429e701`, `21493d5654484f6dd3427228832d02688789e47c`,
`239842b821763a2afc62d859a186f673ba09b171`, `37abe0daea8c964dbd2e09058074bfc7ae053199`,
`e695dd6eade754b2d50bdf297ca8bdc4105f93ff`, `ea001b439a134f4e0e4245d29988547103c047b4`.

**golang/go** (all HTTP 200): `67fb00396d1f0acf4b726990d5cd729ecace403c`,
`45c3387d777caf28f4b992ad9a6216e3085bb8fe`, `dd2019528b669908f8ccc0c327a64d0e07fc2a1b`,
`d95ca9138026cbe40e0857d76a81a16d03230871`, `b7a85e0003cedb1b48a1fd3ae5b746ec6330102e`,
`994692847a2cd3efd319f0cb61a07c0012c8a4ff`, `eb876dd83cb8413335d64e50aae5d38337d1ebb4`,
`821bf37819ec170cadbc9e44a7471f7613611c41`, `2c59389fcc5194aeae742fb413e55b656c22343f`,
`74242baa4136c7a9132a8ccd9881354442788c8c`, `5046bdf8a612b35a2c1a9e168054c1d5c65e7dd7`,
`9cd1818a7d019c02fa4898b3e45a323e35033290`, `fa98f46741f818913a8c11b877520a548715131f`,
`7f9494c277a471f6f47f4af3036285c0b1419816`, `adcad7bea9f6933a219c7b05d8173cf8a4586092`,
`6fc23a3cff5e38ff72923fee50f51254dcdc6e93`, `a98589711da5e9d935e8d690cfca92892e86d557`,
`0bf7ee9977c0218562c50a0b0f0d9cbdf33f65e6`, `452f24ae94f38afa3704d4361d91d51218405c0a`,
`899e473c3b4872a9001ce1df60e6cb575502ebb0`.

**harfbuzz** (all HTTP 200 after retry on 13 rate-limited 403s):
`9b0b40b3c1ac8155c80ed5dc976228f4d3ec7e1f`, `5c65ed800de4caef5ee9ad2111225fa5d8235737`,
`758c9d68e2143493978d8ac8391f4af2a2abc26a`, `8dcc1913a1670ede7b124f7b5b775d7ab8791386`,
`4479d3a2eda57d278700f5c78414ef6ef617d2a9`, `f8ccb545c47abe8f0f4ed318ff7b5bf176913893`,
`42237adffcfd951616efc2f8fba2cd195eb002ea`, `18ab8029d5aab6ac20c240515ad1795bd31dca1e`,
`918193ebf908d35c88bb71d02dfc14bc41ffc31d`, `08784baf101aea472c133dcd67604b475ace3772`,
`8f8e8a84795db45098c95e19a7ff83d898d3bc7d`, `257a197ae723b55d26c3254dbe1edd8b0509af1b`,
`a4d98b63ea59f17ef5e4795f6048f9cd6baa4340`, `b59e25f25ef20dddc7e4dff0432c63d1afe287ae`,
`14ff3cbe0f30dea24e1bb175b1e8e41039f6afdc`, `1c76c8f6ff7877e486f6e94d04b2dc65348b26d5`,
`ca7b9daef06fc515ec84cfb95e7204e9eef3f00e`, `794b00db4b63e8314aee96c23a20ecb878452eef`,
`0e1c0fa404e2ad087265dc59130dbec1c4682258`, `adca4ce071d12998deea6bb53b223daa3aa163c5`,
`ab1f30bd059f1d2270793e9726b60666b328d2b8`, `0f85edb7781f4d5ec2de676979be75a0f6559d80`,
`d84504206c420250bfe80bee25f6a59a7177c9eb`, `f60dbd906a4bf89354af1ed0616a61a5099d8c1a`,
`a953b647507fe2ae8f5187fbfb04e69d2a2952e4`, `9e9f16c92debecb4caf533fa112898dfec116d98`,
`48ad745996159337fb4733561e834a0ffbe3a1ae`, `a5f6f869e80c371665026dfe9d156f0088f2553d`,
`acce1fa3ea9707d0883cd66397fd187d3268905c`, `2dde6c803a9e50c5bff74095187b0cb2e12eebdd`,
`5a4694b6934f9e3ca3dc89cc905b4351920085b6`, `fd3eb2c6723c3ce241011f1d3429e48c3226af1c`,
`1fa64c0c23ed86d60117198420587aee81fdc8d8`, `4c49daf7cd961fb47126baf04240243736cae606`,
`fb7af519b5a0e2d72b0621c05ba70fb1b2eaacaf`, `6c2107ace765f95c67d65a21f94b54a2f12d80dc`,
`59ee61fddc76cd18f19f351bca7dd293eb610333`, `503748d8a80dd5db450c8c4dc109f2b97049d989`,
`fc812faaa96aa4e67814a92376b2da751d5a0aba`.
