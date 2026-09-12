#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Build the CI fixture trio from the real master DB + pool clone.

The real DB (dbs/curl_out/curl_galaxy_master.db, ~2.6GB, gitignored) can't be
a CI dependency. This writes three small, committable artifacts to
tests/fixtures/ that together let delta_report.py / signal_anatomy.py /
export_dataset.py run end-to-end in CI with NO real DB and NO galaxyscope:

  fixture.db           schema-identical subset of the master DB (repo_data,
                       folder_data, file_data, class_data, function_data) for
                       a handful of commit_hashes -- an event's parent + child
                       across security-fix/control/introduced, so every class
                       is represented. excluded_artifacts is intentionally
                       NOT copied: no tool in this repo reads it, and it was
                       the single largest table relative to what it's worth.
  fixture_repo.tar.gz  a tar of a BARE git repo holding ONLY those same
                       commits (`git fetch --depth=2` per commit from the
                       real pool clone) -- NOT curl's 25-year history. This
                       exists because delta_report.py/signal_anatomy.py run
                       real `git rev-parse` / `git diff` / `git show` against
                       the pool clone (their own docstrings undersell this --
                       they are not pure functions of the events file + DB).
                       NOTE: this is shipped as a tar, not a `git bundle`.
                       `git bundle create` does not reliably preserve shallow
                       history across a fresh `git clone` in this git version
                       (see the regen log below) -- connectivity-checking on
                       clone walks raw parent pointers and doesn't know about
                       the shallow boundary, so it tries to fetch the (absent)
                       grandparent and fails. A verbatim tar of the bare repo
                       sidesteps that: CI restores it with `tar xzf`, no git
                       transport/connectivity check involved.
  fixture_events.json  an events file (same shape as events/curl.json) that
                       references exactly the commits above.

Read-only against the real DB (opened `mode=ro`) and against the pool clone
(only `git fetch` into a NEW scratch dir; the pool clone itself is never
written to).

Regenerate:

    python3 tools/make_fixture_db.py \\
        --db dbs/curl_out/curl_galaxy_master.db \\
        --events events/curl.json \\
        --pool-repo /srv/storage_16tb/projects/temporal-crucible-pool/curl \\
        --repo-name curl --per-class 1 \\
        --out-dir tests/fixtures

--per-class controls how many events per class (security-fix/control/
introduced) are pulled in; the smallest-diff (fewest touched files) event per
class is picked by default, to keep the fixture tiny. Bump it if a test needs
more variety.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tarfile

TABLES = ["repo_data", "folder_data", "file_data", "class_data", "function_data"]
CLASSES = ("security-fix", "control", "introduced")


def _git(repo, *args, check=True):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=check)


def touched_paths(repo, parent, child) -> list[tuple[str, str]]:
    """[(old_path, new_path)] for M/R entries only (what delta_report.py calls
    'touched'; added/deleted files never carry a before/after delta)."""
    out = _git(repo, "diff", "--name-status", "-M", f"{parent}..{child}").stdout
    pairs = []
    for line in out.splitlines():
        parts = line.split("\t")
        code = parts[0]
        if code.startswith("R") and len(parts) == 3:
            pairs.append((parts[1], parts[2]))
        elif code not in ("A", "D") and len(parts) == 2:
            pairs.append((parts[1], parts[1]))
    return pairs


def scanned_touched_count(db_con, repo_name, parent, child, pairs) -> int:
    """How many of `pairs` actually have a row in file_data at BOTH ends --
    the engine excludes some files (machine-generated-source heuristics,
    unsupported extensions, ...), and an event whose only touched file got
    excluded produces zero delta rows: a degenerate, useless fixture pick."""
    n = 0
    for old, new in pairs:
        pr = db_con.execute(
            "SELECT 1 FROM file_data WHERE repo_name=? AND commit_hash=? AND file_path=? LIMIT 1",
            (repo_name, parent, old)).fetchone()
        cr = db_con.execute(
            "SELECT 1 FROM file_data WHERE repo_name=? AND commit_hash=? AND file_path=? LIMIT 1",
            (repo_name, child, new)).fetchone()
        if pr and cr:
            n += 1
    return n


def pick_events(events, repo, repo_name, db_con, per_class):
    """Smallest-diff event(s) per class that actually have >=1 file_data-backed
    delta, paired with their resolved parent sha. Candidates are ranked by
    (has_any_scanned_delta desc via filter, touched_file_count asc) so the
    fixture stays tiny AND exercises real touched-file logic, not a no-op."""
    picked = []
    for cls in CLASSES:
        cands = []
        for e in events:
            if e["class"] != cls:
                continue
            r = _git(repo, "rev-parse", f"{e['sha']}^", check=False)
            if r.returncode != 0:
                continue  # root commit, no parent -- unusable for a delta fixture
            parent = r.stdout.strip()
            pairs = touched_paths(repo, parent, e["sha"])
            if not pairs:
                continue
            n_scanned = scanned_touched_count(db_con, repo_name, parent, e["sha"], pairs)
            if n_scanned == 0:
                continue  # every touched file was scanner-excluded -- degenerate pick
            cands.append((len(pairs), e, parent))
        cands.sort(key=lambda t: t[0])
        for _n, e, parent in cands[:per_class]:
            picked.append((e, parent))
    return picked


def build_fixture_db(db_path, out_path, repo_name, shas):
    if out_path.exists():
        out_path.unlink()
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    dst = sqlite3.connect(out_path)
    for t in TABLES:
        sql = src.execute("SELECT sql FROM sqlite_master WHERE name=?", (t,)).fetchone()
        if not sql or not sql[0]:
            sys.exit(f"table {t!r} not found in {db_path} -- schema drift?")
        dst.execute(sql[0])
    dst.commit()

    def copy(table, where, params):
        rows = src.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()
        if rows:
            cols = rows[0].keys()
            dst.executemany(
                f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                [tuple(r) for r in rows],
            )
        return rows

    ph = ",".join("?" * len(shas))
    for t in ("repo_data", "folder_data", "file_data"):
        copy(t, f"repo_name = ? AND commit_hash IN ({ph})", [repo_name, *shas])
    dst.commit()
    file_ids = [r[0] for r in dst.execute("SELECT id FROM file_data")]
    if file_ids:
        fph = ",".join("?" * len(file_ids))
        for t in ("class_data", "function_data"):
            copy(t, f"file_id IN ({fph})", file_ids)
    dst.commit()
    counts = {t: dst.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}
    dst.close()
    src.close()
    return counts


def build_fixture_repo(pool_repo, picked, out_tar):
    scratch = out_tar.parent / "_fixture_repo_scratch"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    _git(scratch, "init", "-q", "--bare")
    for i, (e, parent) in enumerate(picked):
        # depth=2 pulls the event commit + its parent as full commit objects
        # (tree+blobs included); nothing deeper is ever needed by the tools.
        _git(scratch, "fetch", "-q", "--depth=2", str(pool_repo),
             f"{e['sha']}:refs/heads/fx{i}")
    if out_tar.exists():
        out_tar.unlink()
    with tarfile.open(out_tar, "w:gz") as tf:
        for p in sorted(scratch.rglob("*")):
            if p.is_file():
                tf.add(p, arcname=str(p.relative_to(scratch)))
    shutil.rmtree(scratch)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True, help="real master DB (opened read-only)")
    ap.add_argument("--events", required=True)
    ap.add_argument("--pool-repo", required=True, help="path to the pool clone (read-only)")
    ap.add_argument("--repo-name", default="curl")
    ap.add_argument("--per-class", type=int, default=1)
    ap.add_argument("--out-dir", default="tests/fixtures")
    args = ap.parse_args()

    events_data = json.loads(pathlib.Path(args.events).read_text())
    pool_repo = pathlib.Path(args.pool_repo)
    probe = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    picked = pick_events(events_data["events"], pool_repo, args.repo_name, probe, args.per_class)
    probe.close()
    if not picked:
        sys.exit("no candidate events had a scanner-visible delta; nothing to extract")

    shas = sorted({s for e, p in picked for s in (e["sha"], p)})
    print(f"picked {len(picked)} event(s) across {len({e['class'] for e, _ in picked})} "
          f"class(es) -> {len(shas)} commits: {[s[:12] for s in shas]}")

    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    db_path = out_dir / "fixture.db"
    counts = build_fixture_db(args.db, db_path, args.repo_name, shas)
    print(f"fixture.db row counts: {counts}")
    print(f"fixture.db size: {db_path.stat().st_size / 1024:.0f} KiB")

    tar_path = out_dir / "fixture_repo.tar.gz"
    build_fixture_repo(pool_repo, picked, tar_path)
    print(f"fixture_repo.tar.gz size: {tar_path.stat().st_size / 1024:.0f} KiB")

    ev_out = {
        "repo": args.repo_name,
        "source": f"tools/make_fixture_db.py (subset of {events_data.get('source', '?')})",
        "pool_head": events_data.get("pool_head", "unknown"),
        "counts": {},
        "events": [],
    }
    for e, _parent in picked:
        ev_out["events"].append(dict(e))
        ev_out["counts"][e["class"]] = ev_out["counts"].get(e["class"], 0) + 1
    events_path = out_dir / "fixture_events.json"
    events_path.write_text(json.dumps(ev_out, indent=1) + "\n")
    print(f"wrote {events_path}: {ev_out['counts']}")

    print("\nRegenerate with:\n"
          f"  python3 tools/make_fixture_db.py --db {args.db} --events {args.events} "
          f"--pool-repo {args.pool_repo} --repo-name {args.repo_name} "
          f"--per-class {args.per_class} --out-dir {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
