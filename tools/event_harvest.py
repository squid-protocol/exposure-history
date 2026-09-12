#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Harvest labeled event commits for the rung-6 pilot (gitgalaxy#2982).

curl publishes OSV-format vulnerability data (https://curl.se/docs/vuln.json)
whose GIT ranges carry BOTH the fix commit and the introduced-by commit for
most CVEs -- the two delta directions of the experiment from one authoritative,
independently maintained source (189 of 215 entries at harvest time).

repo #2 (nDPI) has no curl-style self-published feed; instead its vuln data
lives in OSS-Fuzz's OSV export (ids like OSV-2025-147), fetched live from
OSV.dev's query API (`--source oss-fuzz`). Same GIT-range shape (introduced +
fixed 40-hex SHAs), same event classes, same control-matching -- just a
different fetch step, selected with `--source {curl-vuln-json,oss-fuzz}`.

Event classes emitted:
  security-fix  -- the commit that fixed a CVE (H1: deltas below controls)
  introduced    -- the commit that introduced it (H2: deltas above controls)
  control       -- ordinary commits, one matched per security-fix event on
                   touched-file count and diff size, drawn from the +-400
                   commits around the event (guard 2: size matching); merges,
                   docs/tests-only commits, and any event commit are excluded.

Every SHA is verified to exist in the pool clone; the clone's HEAD is pinned
into the output so the harvest is reproducible.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import urllib.request

from _engine import EVENTS_DIR, POOL_DIR

VULN_URL = "https://curl.se/docs/vuln.json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DOC_PREFIXES = ("docs/", "tests/", ".github/", "scripts/", "packages/", "plan/")


def _git(repo, *args, check=True):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=check)


def sha_exists(repo, sha) -> bool:
    return _git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def commit_stat(repo, sha):
    """(n_code_files_touched, total_churn_lines, is_merge) for one commit."""
    parents = _git(repo, "rev-list", "--parents", "-n", "1", sha).stdout.split()
    if len(parents) > 2:
        return None  # merge
    out = _git(repo, "diff", "--numstat", f"{sha}^..{sha}", check=False).stdout
    files, churn = 0, 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        add, rm, path = parts
        if path.startswith(DOC_PREFIXES):
            continue
        files += 1
        if add.isdigit():
            churn += int(add)
        if rm.isdigit():
            churn += int(rm)
    return (files, churn)


def pick_control(repo, event_sha, taken, event_shas):
    """Nearest non-event commit around event_sha with similar code-diff shape."""
    target = commit_stat(repo, event_sha)
    if target is None or target[0] == 0:
        return None
    window = _git(repo, "rev-list", "--no-merges", "-n", "400",
                  f"{event_sha}").stdout.split()[1:]  # commits older than event
    best, best_cost = None, None
    for cand in window:
        if cand in taken or cand in event_shas:
            continue
        st = commit_stat(repo, cand)
        if st is None or st[0] == 0:
            continue
        cost = abs(st[0] - target[0]) * 50 + abs(st[1] - target[1])
        if best_cost is None or cost < best_cost:
            best, best_cost = cand, cost
        if best_cost == 0:
            break
    return best


def fetch_curl_osv():
    """curl's self-published OSV feed -- a plain JSON array of entries."""
    with urllib.request.urlopen(VULN_URL) as r:  # noqa: S310 -- fixed https URL
        return json.load(r)


def fetch_ossfuzz_osv(project: str):
    """All OSV entries for an OSS-Fuzz project, paginated via page_token.

    OSV.dev's query API takes {"package": {"name", "ecosystem": "OSS-Fuzz"}}
    and returns full entries inline (ranges included) -- no per-id GET needed,
    unlike the /v1/vulns/<id> lookup path. `name` is the OSS-Fuzz project
    slug, which is lowercase even when the upstream repo/display name isn't
    (e.g. "ndpi" for ntop/nDPI).
    """
    entries, page_token = [], None
    while True:
        body = {"package": {"name": project, "ecosystem": "OSS-Fuzz"}}
        if page_token:
            body["page_token"] = page_token
        req = urllib.request.Request(
            OSV_QUERY_URL, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req) as r:  # noqa: S310 -- fixed https URL
            page = json.load(r)
        entries.extend(page.get("vulns", []))
        page_token = page.get("next_page_token")
        if not page_token:
            break
    return entries


def extract_events(osv_entries, repo, repo_filter=None):
    """Walk OSV-shaped entries -> (events, missing), verifying every SHA.

    Shared by both sources: the GIT-range {introduced, fixed} event shape is
    OSV-standard, not curl-specific. `repo_filter`, if given, is a substring
    that a GIT range's `repo` field must contain -- OSS-Fuzz projects can in
    principle span more than one upstream repo under one project name, so
    this is a guard, not a formatting assumption. Severity/CWE live under
    `database_specific` in curl's feed and under the per-`affected` entry
    (`ecosystem_specific` or `database_specific`) in OSS-Fuzz's -- both are
    checked so one extractor covers both shapes.
    """
    events, missing = [], []
    for entry in osv_entries:
        vid = entry["id"]
        entry_ds = entry.get("database_specific", {})
        for aff in entry.get("affected", []):
            aff_specific = {**aff.get("database_specific", {}),
                             **aff.get("ecosystem_specific", {})}
            for rng in aff.get("ranges", []):
                if rng.get("type") != "GIT":
                    continue
                if repo_filter and repo_filter.lower() not in (rng.get("repo") or "").lower():
                    continue
                intro = fixed = None
                for ev in rng.get("events", []):
                    intro = ev.get("introduced", intro)
                    fixed = ev.get("fixed", fixed)
                for sha, cls in ((fixed, "security-fix"), (intro, "introduced")):
                    if not sha or len(sha) < 40:
                        continue
                    if not sha_exists(repo, sha):
                        missing.append((vid, cls, sha))
                        continue
                    cwe = entry_ds.get("CWE", {})
                    events.append({
                        "id": vid, "class": cls, "sha": sha,
                        "severity": entry_ds.get("severity") or aff_specific.get("severity"),
                        "cwe": cwe.get("id"), "cwe_desc": cwe.get("desc"),
                        "summary": entry.get("summary"),
                    })
    return events, missing


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default="curl")
    ap.add_argument("--out", default=str(EVENTS_DIR / "curl.json"))
    ap.add_argument("--limit", type=int, default=0, help="cap events (0 = all)")
    ap.add_argument("--source", choices=["curl-vuln-json", "oss-fuzz"],
                    default="curl-vuln-json",
                    help="curl-vuln-json: curl's own vuln.json feed (default). "
                         "oss-fuzz: query OSV.dev for an OSS-Fuzz project's "
                         "entries (needs --osv-project).")
    ap.add_argument("--osv-project", default=None,
                    help="OSS-Fuzz project slug for --source oss-fuzz, e.g. "
                         "'ndpi' for ntop/nDPI. Defaults to --repo, lowercased.")
    ap.add_argument("--repo-filter", default=None,
                    help="Substring the GIT range's repo URL must contain "
                         "(oss-fuzz source only, guards against a project "
                         "name spanning multiple upstream repos). Defaults "
                         "to --repo (case-insensitive) when unset.")
    args = ap.parse_args()

    repo = POOL_DIR / args.repo
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()

    if args.source == "oss-fuzz":
        project = args.osv_project or args.repo.lower()
        source_label = f"{OSV_QUERY_URL} (ecosystem=OSS-Fuzz, package={project})"
        osv = fetch_ossfuzz_osv(project)
        repo_filter = args.repo_filter or args.repo
        events, missing = extract_events(osv, repo, repo_filter=repo_filter)
    else:
        source_label = VULN_URL
        osv = fetch_curl_osv()
        events, missing = extract_events(osv, repo)

    # de-dup (same sha can fix/introduce several CVEs) -- keep first label
    seen, unique = set(), []
    for e in events:
        if (e["sha"], e["class"]) in seen:
            continue
        seen.add((e["sha"], e["class"]))
        unique.append(e)
    if args.limit:
        unique = unique[: args.limit]

    fix_events = [e for e in unique if e["class"] == "security-fix"]
    event_shas = {e["sha"] for e in unique}
    taken: set[str] = set()
    controls = []
    for e in fix_events:
        c = pick_control(repo, e["sha"], taken, event_shas)
        if c:
            taken.add(c)
            controls.append({"id": f"control-for-{e['id']}", "class": "control",
                             "sha": c, "matched_to": e["sha"]})

    out = {
        "repo": args.repo, "source": source_label, "pool_head": head,
        "counts": {"security-fix": len(fix_events),
                   "introduced": sum(1 for e in unique if e["class"] == "introduced"),
                   "control": len(controls), "missing_shas": len(missing)},
        "events": unique + controls,
        "missing": [{"id": c, "class": k, "sha": s} for c, k, s in missing],
    }
    pathlib.Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out["counts"], indent=1))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
