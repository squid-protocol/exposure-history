# Exposure History

The **rung-6 validation program** for [GitGalaxy](https://github.com/squid-protocol/gitgalaxy)
(gitgalaxy [#2982](https://github.com/squid-protocol/gitgalaxy/issues/2982); the design lives
in the engine's [`docs/validation.md`](https://github.com/squid-protocol/gitgalaxy/blob/main/docs/validation.md)
§ "The next validation: risk over Git history"):

> **Do commits independently identified as security fixes typically reduce the corresponding
> GitGalaxy exposure — and do the commits that introduced those vulnerabilities increase it —
> relative to ordinary commits?**

The method is **event-pair scanning**: for each labeled event commit, scan its first parent
and the commit itself with the real `galaxyscope` CLI, join per-file exposure across the two
snapshots, and record the delta. No per-commit sweeps, no tag panels — two scans per label.

## The four guards (pre-registered in the epic before any batch ran)

1. **Temporal ablation** — scans run with `GITGALAXY_DISABLE_GIT_HISTORY=1`, so churn and
   stability are neutral constants in every snapshot and provably contribute **zero** to any
   delta. A fix commit mechanically raises churn on the files it touches; letting temporal
   columns into a before/after delta would let the event predict itself.
2. **Size matching** — within-file before/after deltas self-control identity and size;
   control commits are matched to fix commits on touched-file count and diff size.
3. **Rename tracking** — `git diff --name-status -M`; renamed files join old-path → new-path.
4. **Pre-registered criteria** — H1/H2/H3 in the epic, evaluated verbatim in the report
   whatever they say. A null result is a finding about the formulas, and routes into the
   engine's score-contract program.

## Layout

    tools/_engine.py        engine wiring (GITGALAXY_PATH / GALAXYSCOPE_BIN) + column sets
    tools/scan_pair.py      worktree → scan ×2 → one accumulating history DB per repo
    tools/run_batch.py      resumable batch over an events file (skip-if-scanned)
    tools/event_harvest.py  OSV vuln data + matched controls → events/<repo>.json
    tools/exposure_delta.py rename-tracked per-file delta join between two commits
    tools/delta_report.py   the statistics + docs/exposure_history_report.md
    events/curl.json        the labeled events (pinned to the pool clone's HEAD)
    dbs/                    history DBs + logs (gitignored; regenerable from events/)
    docs/                   the regenerated report

Clones under study live in an uncommitted pool (`EXPOSURE_POOL`, default
`/srv/storage_16tb/projects/exposure-history-pool/`).

The engine's own SQLite schema does the heavy lifting: `file_data` rows are keyed
`(repo_name, commit_hash)` with a uniqueness guarantee, so one DB holds every scanned
revision of a repo and joins across commits by `file_path`. Scanning an already-scanned
commit is a no-op — batches are interruptible and resumable by construction.

## Pilot: curl

curl publishes OSV vulnerability data (<https://curl.se/docs/vuln.json>) whose GIT ranges
carry **both the fix commit and the introduced-by commit** — 186 fix + 137 introduced events
with 0 unresolvable SHAs at harvest time, plus 185 size-matched control commits.

## Reproduce

    # harvest events (pins the pool HEAD it ran against)
    python tools/event_harvest.py

    # scan pairs (resumable; interrupt freely)
    python tools/run_batch.py --events events/curl.json --classes security-fix,control,introduced

    # one pair's deltas, by hand
    python tools/scan_pair.py --repo curl --sha <fix-sha>
    python tools/exposure_delta.py --repo <pool>/curl --db dbs/curl_out/*.db \
        --parent <sha^> --child <sha>

    # the report
    python tools/delta_report.py --events events/curl.json

Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
