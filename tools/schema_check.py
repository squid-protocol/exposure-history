#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""CI schema check for the committed ML-dataset export (gitgalaxy#2982).

`tools/export_dataset.py` writes `dataset/<repo>.manifest.json` plus three
gzipped JSONL files (events/files/functions grain). This script re-validates
the COMMITTED export against the exporter's current schema, catching the case
where the exporter changed (SCHEMA_VERSION bumped, a field renamed) but
`dataset/` wasn't regenerated, or vice versa -- without needing the DB, the
pool clone, or galaxyscope. Pure read of already-committed files.

Checks, per repo:
  1. dataset/<repo>.manifest.json exists; its "schema_version" equals
     tools/export_dataset.py's SCHEMA_VERSION constant (imported, not
     hard-coded here, so a legitimate version bump doesn't require editing
     this script).
  2. the manifest carries the required top-level keys.
  3. every file the manifest lists under "files" exists, is valid gzip, and
     every line parses as JSON with at least {schema_version, repo, kind},
     repo matching, and kind matching the grain (events -> "event", etc).
  4. per-grain record counts match manifest["counts"] -- a stale partial
     regenerate (crashed halfway, only some lines written) is caught, not
     just malformed JSON.

Exit 1 with every problem printed (not just the first) on any mismatch.

    python3 tools/schema_check.py --dataset-dir dataset --repo curl
"""
from __future__ import annotations

import argparse
import gzip
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from export_dataset import SCHEMA_VERSION as EXPORTER_SCHEMA_VERSION  # noqa: E402

REQUIRED_MANIFEST_KEYS = ("schema_version", "repo", "pool_head", "feature_groups",
                          "counts", "files")
REQUIRED_RECORD_KEYS = ("schema_version", "repo", "kind")
# manifest["files"] grain -> the "kind" value export_dataset.py stamps on each line
KIND_MAP = {"events": "event", "files": "file_sample", "functions": "function_sample"}


def check(dataset_dir: pathlib.Path, repo: str) -> list[str]:
    errors: list[str] = []
    manifest_path = dataset_dir / f"{repo}.manifest.json"
    if not manifest_path.exists():
        return [f"missing manifest: {manifest_path}"]
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        return [f"manifest is not valid JSON: {e}"]

    for key in REQUIRED_MANIFEST_KEYS:
        if key not in manifest:
            errors.append(f"manifest missing required key: {key!r}")

    mv = manifest.get("schema_version")
    if mv != EXPORTER_SCHEMA_VERSION:
        errors.append(
            f"manifest schema_version={mv!r} does not match tools/export_dataset.py "
            f"SCHEMA_VERSION={EXPORTER_SCHEMA_VERSION!r} -- dataset/ is stale; "
            f"regenerate with `python tools/export_dataset.py --events events/{repo}.json`"
        )

    files = manifest.get("files", {})
    counts = manifest.get("counts", {})
    for grain, fname in files.items():
        path = dataset_dir / fname
        if not path.exists():
            errors.append(f"manifest references missing file: {fname}")
            continue
        want_kind = KIND_MAP.get(grain)
        n = 0
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError as e:
                        errors.append(f"{fname}:{lineno}: invalid JSON ({e})")
                        continue
                    missing = [k for k in REQUIRED_RECORD_KEYS if k not in rec]
                    if missing:
                        errors.append(f"{fname}:{lineno}: missing keys {missing}")
                    if rec.get("repo") != repo:
                        errors.append(
                            f"{fname}:{lineno}: repo={rec.get('repo')!r}, expected {repo!r}")
                    if want_kind and rec.get("kind") != want_kind:
                        errors.append(
                            f"{fname}:{lineno}: kind={rec.get('kind')!r}, expected {want_kind!r}")
                    n += 1
        except OSError as e:
            errors.append(f"{fname}: not valid gzip ({e})")
            continue
        want_n = counts.get(grain)
        if want_n is not None and n != want_n:
            errors.append(f"{fname}: {n} records, manifest counts.{grain}={want_n}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset-dir", default="dataset")
    ap.add_argument("--repo", default="curl")
    args = ap.parse_args()

    errors = check(pathlib.Path(args.dataset_dir), args.repo)
    if errors:
        print(f"schema_check: {len(errors)} problem(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"schema_check: OK ({args.dataset_dir}/{args.repo}.* matches "
          f"schema_version {EXPORTER_SCHEMA_VERSION!r})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
