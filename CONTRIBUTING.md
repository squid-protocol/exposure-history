# Contributing

This repo just came off direct pushes to `main` onto a PR-based flow with CI
(`.github/workflows/verify.yml`). A few things that make this repo specific:

## The PR flow

1. **Branch, don't push to `main` directly** — `main` is (or is about to be)
   protected: the `verify` check must pass and at least one review is
   required before merge.
2. **Open the PR as a draft.** Org norm (learned the hard way on `gitgalaxy`):
   non-draft PRs on `squid-protocol` repos can auto-merge within ~10 seconds
   of opening, before pull-request-only checks like `verify` have even
   started. Open as draft, wait for `verify` to go green, then mark it ready
   for review.
3. Keep the PR focused. If a change touches both a tool's behavior and a
   registered hypothesis's evaluation, say so explicitly in the PR
   description — reviewers need to know whether they're reviewing code or a
   confirmatory result.
4. `gh issue view` and `gh pr edit` are known to fail on this org's repos;
   use `gh api` directly if you need to script against issues/PRs.

## Hypothesis-first (the rule this repo runs on)

[`docs/HYPOTHESES.md`](docs/HYPOTHESES.md) is the **register of record**. If
your change produces or touches a confirmatory claim (a hypothesis test with
a p-value and a verdict, not a descriptive/exploratory table):

1. **Register first.** The hypothesis — its direction, its test, its α — goes
   into `docs/HYPOTHESES.md` (or the tracking issue, gitgalaxy#2982) *before*
   the analysis that could confirm it runs. A PR that adds both a new
   registration AND that same hypothesis's verdict in one shot is, by
   definition, not pre-registered — split it, or say plainly in the PR that
   it's post-hoc/exploratory and label it as such in the output.
2. **Verdicts get published either way.** A null or contradicted result is
   not a reason to drop the table from the doc — it's the finding. Update
   the register's `verdict` column regardless of which way it went.
3. **Exploratory stays labeled exploratory**, in the doc and in any generated
   report (`docs/exposure_history_report.md`, `docs/signal_anatomy.md`,
   `docs/rw_hypotheses.md`, ...). An exploratory observation can graduate
   into a registered hypothesis, but only for data it hasn't seen yet — never
   re-tested on the sample that suggested it.
4. Every test keeps its guards: size-matched controls, length-matched pairs
   at function grain, temporal ablation (`GITGALAXY_DISABLE_GIT_HISTORY=1`
   — see below), rename tracking, and multiple-comparison awareness on any
   table wider than one registered claim. Don't quietly drop a guard to make
   a table simpler.

## Long batches: run detached, never through a 600-second-capped shell

`run_batch.py` and `walk_history.py` scan real commits with a real
`galaxyscope` — two full scans per event, and a full curl batch is well past
what any interactive/agent shell session's timeout budget allows (this repo
is routinely driven from tool shells with a 600-second cap). Both scripts
are **resumable by construction** — `scan_pair.py` skips any `(repo_name,
commit_hash)` already in the accumulating history DB — so the only wrong way
to run a big batch is inside a shell that will get killed before it finishes
and calling that a failure. Launch it detached:

    setsid nohup python tools/run_batch.py --events events/curl.json \
        --classes security-fix,control,introduced \
        > dbs/full_batch.log 2>&1 < /dev/null &
    disown

then tail the log and re-run the identical command if it gets interrupted —
it picks up exactly where it left off. The same applies to `walk_history.py`
for release/tag panels.

## The temporal ablation is not optional

Every scan in this repo runs with `GITGALAXY_DISABLE_GIT_HISTORY=1`
(`tools/_engine.py`'s `SCAN_ENV`) so the churn/stability columns are neutral
constants and can't let an event predict itself (guard 1 of gitgalaxy#2982).
If you're adding a new scan path, wire it through `SCAN_ENV`, don't
reinvent it — and if you ever need to compare against an *unablated* scan for
a specific investigation, say so loudly in the PR and don't let it near a
confirmatory hypothesis.

## CI (`.github/workflows/verify.yml`)

Runs on every PR and on pushes to non-`main` branches, fast (a few minutes),
and needs none of: the 2.6GB master DB, the pool clone, or `galaxyscope`.
It byte-compiles every tool, runs `delta_report.py` and `signal_anatomy.py`
end-to-end against the small fixture under `tests/fixtures/` (see
`tools/make_fixture_db.py`'s docstring for what's in there and how to
regenerate it), and schema-checks the committed `dataset/` export
(`tools/schema_check.py`) against `tools/export_dataset.py`'s current
schema version. If you change a tool's CLI shape, a DB column name a
downstream tool reads, or the dataset export schema, run these locally
before pushing:

    python -m py_compile tools/*.py
    python tools/schema_check.py --dataset-dir dataset --repo curl

and regenerate `tests/fixtures/` (`tools/make_fixture_db.py`) if the schema
of `file_data`/`function_data`/etc. itself changed.

## License

Contributions are accepted under the PolyForm Noncommercial License 1.0.0
(see [`LICENSE`](LICENSE)) — same as the rest of the repo.
