#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Export the harness's ground-truth dataset as versioned, well-labeled JSONL
for a future multi-repo aggregator / ML pipeline (gitgalaxy#2982).

Three grains, one file each (gzipped JSONL, one record per line), plus a
manifest that makes the export self-describing:

  dataset/<repo>.events.jsonl.gz     one record per labeled event
  dataset/<repo>.files.jsonl.gz      one record per (event x touched file):
                                     full before/after/delta feature vectors
  dataset/<repo>.functions.jsonl.gz  one record per (event x touched file x
                                     function) in the PARENT snapshot, with
                                     the engine's per-function signal counts
                                     and an `implicated` flag (overlaps the
                                     event's changed lines)
  dataset/<repo>.manifest.json       schema_version, feature groups, counts,
                                     provenance (engine commit, pool head,
                                     ablation flags), label semantics

Design rules for the aggregator's sake:
  - engine column names are kept VERBATIM (traceable to the schema and the
    signal contracts); feature groups are listed in the manifest instead of
    renaming anything;
  - every record carries `repo`, `schema_version`, and its labels inline —
    files are self-sufficient after `zcat | jq`;
  - labels are FACTS (event class, CWE, overlap flags), never judgments; the
    aggregator defines its own tasks;
  - scans are temporally ablated (churn/stability neutral) — recorded in the
    manifest so no model ever trains on the self-fulfilling columns.

    python tools/export_dataset.py --events events/curl.json
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import json
import pathlib
import sqlite3
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import GITGALAXY_PATH, REPO_ROOT, RISK_VECTOR, TEMPORAL_COLUMNS  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import (  # noqa: E402
    SIGNAL_PREFIXES, SKIP_SIGNALS, hunk_lines_parent_side, parent_child, signal_columns,
)

SCHEMA_VERSION = "1.0.0"
DATASET_DIR = REPO_ROOT / "dataset"

FILE_CONTEXT = ["total_loc", "coding_loc", "doc_loc", "structural_mass", "cog_raw",
                "function_count", "class_count", "avg_func_complexity", "max_func_complexity",
                "avg_func_args", "func_complexity_gini", "control_flow_ratio",
                "encapsulation_ratio", "import_count", "pagerank_score",
                "normalized_blast_radius", "popularity", "has_credentials"]
FUNC_META = ["func_name", "start_line", "loc", "complexity", "func_z_score", "args",
             "is_public", "is_documented", "keyword_density", "usage_status"]


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def rowdicts(con, sql, params):
    cur = con.execute(sql, params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True)
    args = ap.parse_args()

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(db)
    fsig = signal_columns(con, "file_data")
    fnsig = [c for c in ([r[1] for r in con.execute("PRAGMA table_info(function_data)")])
             if c.startswith(SIGNAL_PREFIXES) and c not in SKIP_SIGNALS]
    risk_cols = [f"risk_{c}" for c in RISK_VECTOR]
    file_feats = ["file_path", "language"] + FILE_CONTEXT + risk_cols + fsig

    DATASET_DIR.mkdir(exist_ok=True)
    stem = DATASET_DIR / data["repo"]
    ev_f = gzip.open(f"{stem}.events.jsonl.gz", "wt")
    fi_f = gzip.open(f"{stem}.files.jsonl.gz", "wt")
    fn_f = gzip.open(f"{stem}.functions.jsonl.gz", "wt")
    counts = {"events": 0, "files": 0, "functions": 0, "skipped": 0}

    intro_by_id = {e["id"]: e["sha"] for e in data["events"] if e["class"] == "introduced"}
    fix_by_id = {e["id"]: e["sha"] for e in data["events"] if e["class"] == "security-fix"}

    for e in data["events"]:
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            counts["skipped"] += 1
            continue
        before = {r["file_path"]: r for r in rowdicts(
            con, f"SELECT id, {', '.join(file_feats)} FROM file_data WHERE commit_hash = ?",
            (parent,))}
        after = {r["file_path"]: r for r in rowdicts(
            con, f"SELECT {', '.join(file_feats)} FROM file_data WHERE commit_hash = ?",
            (child,))}
        if not before or not after:
            counts["skipped"] += 1
            continue
        statuses = diff_statuses(repo, parent, child)
        touched = [(p, st) for p, st in statuses.items()
                   if st["status"] == "touched" and p in after and st["old_path"] in before]
        dwell_days = None
        if e["class"] in ("security-fix", "introduced"):
            other = intro_by_id.get(e["id"]) if e["class"] == "security-fix" else fix_by_id.get(e["id"])
            if other:
                try:
                    t0 = int(_git(repo, "show", "-s", "--format=%ct", other))
                    t1 = int(_git(repo, "show", "-s", "--format=%ct", child))
                    dwell_days = abs(t1 - t0) / 86400
                except subprocess.CalledProcessError:
                    pass
        base = {
            "schema_version": SCHEMA_VERSION, "repo": data["repo"],
            "event_id": e["id"], "event_class": e["class"],
            "cwe": e.get("cwe"), "severity": e.get("severity"),
            "sha": child, "parent_sha": parent,
            "date": _git(repo, "show", "-s", "--format=%cI", child),
        }
        ev_f.write(json.dumps(base | {
            "kind": "event", "summary": e.get("summary"),
            "matched_to": e.get("matched_to"), "dwell_days": dwell_days,
            "n_touched_code_files": len(touched),
        }) + "\n")
        counts["events"] += 1

        for path, st in touched:
            b, a = before[st["old_path"]], after[path]
            feat_b = {k: b[k] for k in file_feats if k != "file_path"}
            feat_a = {k: a[k] for k in file_feats if k != "file_path"}
            delta = {k: ((a[k] or 0) - (b[k] or 0))
                     for k in FILE_CONTEXT + risk_cols + fsig if k != "has_credentials"}
            fi_f.write(json.dumps(base | {
                "kind": "file_sample", "file_path": path,
                "renamed_from": st["old_path"] if st.get("renamed") else None,
                "before": feat_b, "after": feat_a, "delta": delta,
            }) + "\n")
            counts["files"] += 1

            changed = hunk_lines_parent_side(repo, parent, child, st["old_path"])
            for fr in rowdicts(
                con,
                f"SELECT {', '.join(FUNC_META + fnsig)} FROM function_data "
                "WHERE file_id = ?", (b["id"],)):
                start, loc = fr.get("start_line"), fr.get("loc")
                implicated = bool(changed and start is not None and loc is not None and any(
                    ln in changed for ln in range(start, start + max(loc, 1))))
                fn_f.write(json.dumps(base | {
                    "kind": "function_sample", "file_path": st["old_path"],
                    "snapshot": "parent", "implicated": implicated, **fr,
                }) + "\n")
                counts["functions"] += 1

    for f in (ev_f, fi_f, fn_f):
        f.close()

    engine_commit = subprocess.run(
        ["git", "-C", str(GITGALAXY_PATH), "rev-parse", "HEAD"],
        capture_output=True, text=True).stdout.strip()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "repo": data["repo"], "pool_head": data["pool_head"],
        "events_source": data["source"], "engine_commit": engine_commit,
        "scan_flags": {"GITGALAXY_DISABLE_GIT_HISTORY": "1",
                       "note": "temporal columns (stability, churn) are neutral constants; "
                               "never train on them"},
        "temporal_columns": sorted(TEMPORAL_COLUMNS),
        "label_semantics": {
            "event_class": "security-fix = commit named as a CVE fix by the OSV source; "
                           "introduced = commit named as introducing that CVE; control = "
                           "ordinary commit matched to a fix on touched-file count and "
                           "diff size (merges and docs-only excluded)",
            "implicated": "function's [start_line, start_line+loc) at the PARENT snapshot "
                          "overlaps the event's changed lines (git diff -U0, parent side). "
                          "KNOWN BIAS: longer functions overlap more often by area; "
                          "length-controlled analyses required (see signal_anatomy.md)",
            "cwe": "verbatim from the OSV source; may be null",
        },
        "feature_groups": {
            "file_context": FILE_CONTEXT,
            "risk_vector": risk_cols,
            "file_signals": fsig,
            "function_meta": FUNC_META,
            "function_signals": fnsig,
        },
        "counts": counts,
        "files": {k: f"{data['repo']}.{k}.jsonl.gz" for k in ("events", "files", "functions")},
    }
    (DATASET_DIR / f"{data['repo']}.manifest.json").write_text(
        json.dumps(manifest, indent=1) + "\n")
    print(json.dumps(counts), "| manifest:", f"{stem}.manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
