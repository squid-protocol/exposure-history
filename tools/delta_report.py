#!/usr/bin/env python3
# ==============================================================================
# exposure-history
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""The rung-6 report: exposure deltas by event class (gitgalaxy#2982).

Pre-registered (H1-H3, from the epic, written before any batch ran):
  H1  security-fix commits' structural-exposure deltas on touched files lie
      BELOW matched controls' (one-sided Mann-Whitney U, alpha = 0.01).
  H2  introduced-by commits' deltas lie ABOVE controls (same test).
  H3  the per-vector table names which exposure vectors carry any signal.

Statistical unit: the EVENT (mean structural delta over its touched files) --
a ten-file commit is one sample, not ten. Per-file pooling is reported as a
labeled secondary. Temporal columns are neutral by construction (scans run
under GITGALAXY_DISABLE_GIT_HISTORY=1) and are asserted zero here.

Also reported, beyond the pre-registered set:
  - sign split per class (what fraction of fixes RAISE exposure -- the
    guard-code-reads-as-complexity effect the first sample showed)
  - severity gradient (do higher-severity fixes move more?)
  - top movers with CVE ids, both directions
  - CVE hotspot files (which files keep appearing in security events)
  - untouched-file spillover: on files a commit did NOT touch, deltas measure
    scan noise + graph ripple -- a built-in negative control for the whole
    instrument (expected ~0; api_exposure may legitimately ripple via the
    dependency graph)
  - LOC coupling: rank correlation of structural delta vs LOC delta on
    touched files (is the metric just measuring size change?)

Usage:
    python tools/delta_report.py --events events/curl.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import pathlib
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, STRUCTURAL_COLUMNS, TEMPORAL_COLUMNS  # noqa: E402
from exposure_delta import diff_statuses, rows_for  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402


# ------------------------------------------------------------------ statistics
def mann_whitney_u(a: list[float], b: list[float]) -> tuple[float, float]:
    """One-sided MW U (H: a < b). Normal approximation with tie correction.
    Returns (U_a, p_one_sided). Dependency-free on purpose."""
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return float("nan"), float("nan")
    pooled = sorted((v, 0) for v in a) + sorted((v, 1) for v in b)
    pooled.sort(key=lambda t: t[0])
    ranks, i = {}, 0
    vals = [v for v, _ in pooled]
    rank_of = [0.0] * len(pooled)
    while i < len(pooled):
        j = i
        while j + 1 < len(pooled) and vals[j + 1] == vals[i]:
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            rank_of[k] = r
        i = j + 1
    r1 = sum(r for r, (_, g) in zip(rank_of, pooled) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    mu = n1 * n2 / 2
    tie_counts = Counter(vals).values()
    n = n1 + n2
    tie_term = sum(t**3 - t for t in tie_counts)
    sigma = math.sqrt(n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1)))) if n > 1 else 0.0
    if sigma == 0:
        return u1, float("nan")
    z = (u1 - mu + 0.5) / sigma  # continuity-corrected; a<b => small U => z<0
    p = 0.5 * math.erfc(-z / math.sqrt(2))  # P(Z <= z)
    return u1, p


def spearman(a: list[float], b: list[float]) -> float:
    def ranks(x):
        order = sorted(range(len(x)), key=lambda i: x[i])
        r = [0.0] * len(x)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and x[order[j + 1]] == x[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return r
    if len(a) < 3:
        return float("nan")
    ra, rb = ranks(a), ranks(b)
    ma, mb = sum(ra) / len(ra), sum(rb) / len(rb)
    num = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    da = math.sqrt(sum((x - ma) ** 2 for x in ra))
    db = math.sqrt(sum((y - mb) ** 2 for y in rb))
    return num / (da * db) if da and db else float("nan")


def median(xs):
    if not xs:
        return float("nan")
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def q(xs, frac):
    if not xs:
        return float("nan")
    s = sorted(xs)
    i = max(0, min(len(s) - 1, int(round(frac * (len(s) - 1)))))
    return s[i]


# ------------------------------------------------------------------ extraction
def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def event_deltas(con, repo, sha):
    """Per-file structural/vector deltas for one event; None if not fully scanned."""
    child = _git(repo, "rev-parse", sha)
    try:
        parent = _git(repo, "rev-parse", f"{child}^")
    except subprocess.CalledProcessError:
        return None  # root commit (curl's 1999 initial commit can "introduce" a CVE)
    before, after = rows_for(con, parent), rows_for(con, child)
    if not before or not after:
        return None
    statuses = diff_statuses(repo, parent, child)
    when = _git(repo, "show", "-s", "--format=%ci", child)[:10]
    # Pre-event context: every file's structural exposure in the PARENT snapshot,
    # so an implicated file's standing can be ranked among all files before
    # anyone knew ("are the outliers where events happen?").
    parent_scores = {
        p: sum((r[f"risk_{c}"] or 0) for c in STRUCTURAL_COLUMNS) for p, r in before.items()
    }
    ranked = sorted(parent_scores.values())
    import bisect
    def pct(v):
        return 100.0 * bisect.bisect_left(ranked, v) / max(len(ranked) - 1, 1)
    # Per-vector rankings too: "which vector flags which weakness type" needs
    # each implicated file's standing per vector, not just the aggregate.
    vec_ranked = {
        c: sorted((r[f"risk_{c}"] or 0) for r in before.values()) for c in STRUCTURAL_COLUMNS
    }
    def vec_pct(c, v):
        lst = vec_ranked[c]
        return 100.0 * bisect.bisect_left(lst, v) / max(len(lst) - 1, 1)
    touched, untouched = [], []
    for path, arow in after.items():
        st = statuses.get(path)
        old = st["old_path"] if st else path
        brow = before.get(old)
        if brow is None:
            continue  # added files have no delta
        d = {c: (arow[f"risk_{c}"] or 0) - (brow[f"risk_{c}"] or 0) for c in STRUCTURAL_COLUMNS}
        t = {c: (arow[f"risk_{c}"] or 0) - (brow[f"risk_{c}"] or 0) for c in TEMPORAL_COLUMNS}
        rec = {
            "path": path,
            "structural": sum(d.values()),
            "temporal": sum(t.values()),
            "vectors": d,
            "loc_delta": (arow["total_loc"] or 0) - (brow["total_loc"] or 0),
            "pre_percentile": pct(parent_scores.get(st["old_path"] if st else path, 0)),
            "pre_vector_percentiles": {
                c: vec_pct(c, (brow[f"risk_{c}"] or 0)) for c in STRUCTURAL_COLUMNS
            },
        }
        (touched if st and st["status"] == "touched" else untouched).append(rec)
    repo_mean = sum(parent_scores.values()) / len(parent_scores) if parent_scores else 0.0
    return {"parent": parent, "child": child, "date": when, "repo_mean": repo_mean,
            "n_files": len(parent_scores), "touched": touched, "untouched": untouched}


# ------------------------------------------------------------------ report
def fmt(x, nd=3):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:+.{nd}f}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True)
    ap.add_argument("--out", default=str(DOCS_DIR / "exposure_history_report.md"))
    args = ap.parse_args()

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row

    by_class = defaultdict(list)  # class -> [(event, deltas)]
    skipped = Counter()
    for e in data["events"]:
        d = event_deltas(con, repo, e["sha"])
        if d is None:
            skipped[e["class"]] += 1
            continue
        if not d["touched"]:
            skipped[f"{e['class']} (no touched code files)"] += 1
            continue
        by_class[e["class"]].append((e, d))

    # temporal-ablation assertion: guard 1, mechanically re-checked every run
    max_temporal = max(
        (abs(f["temporal"]) for evs in by_class.values() for _, d in evs for f in d["touched"]),
        default=0.0,
    )
    assert max_temporal == 0.0, f"temporal ablation violated: {max_temporal}"

    # event-level primary unit: mean structural delta over touched files
    unit = {
        cls: [sum(f["structural"] for f in d["touched"]) / len(d["touched"]) for _, d in evs]
        for cls, evs in by_class.items()
    }
    filepool = {
        cls: [f["structural"] for _, d in evs for f in d["touched"]]
        for cls, evs in by_class.items()
    }

    fixes, ctrls, intros = unit.get("security-fix", []), unit.get("control", []), unit.get("introduced", [])
    _, p1 = mann_whitney_u(fixes, ctrls)          # H1: fixes < controls
    _, p2 = mann_whitney_u(ctrls, intros)         # H2: controls < introduced
    _, p1f = mann_whitney_u(filepool.get("security-fix", []), filepool.get("control", []))
    _, p2f = mann_whitney_u(filepool.get("control", []), filepool.get("introduced", []))

    # H3 per-vector table (event-level means per vector)
    vec_rows = []
    for c in STRUCTURAL_COLUMNS:
        per = {
            cls: [sum(f["vectors"][c] for f in d["touched"]) / len(d["touched"]) for _, d in evs]
            for cls, evs in by_class.items()
        }
        _, pv = mann_whitney_u(per.get("security-fix", []), per.get("control", []))
        vec_rows.append((c, median(per.get("security-fix", [])), median(per.get("control", [])),
                         median(per.get("introduced", [])), pv))

    # extras
    sign = {cls: (sum(1 for v in vs if v < 0), sum(1 for v in vs if v > 0), sum(1 for v in vs if v == 0))
            for cls, vs in unit.items()}
    sev_rows = defaultdict(list)
    for e, d in by_class.get("security-fix", []):
        m = sum(f["structural"] for f in d["touched"]) / len(d["touched"])
        sev_rows[e.get("severity") or "?"].append(m)
    movers = sorted(
        ((sum(f["structural"] for f in d["touched"]) / len(d["touched"]), e, d)
         for e, d in by_class.get("security-fix", [])), key=lambda t: t[0])
    hot = Counter()
    for e, d in by_class.get("security-fix", []) + by_class.get("introduced", []):
        for f in d["touched"]:
            hot[f["path"]] += 1
    spill = [abs(f["structural"]) for evs in by_class.values() for _, d in evs for f in d["untouched"]]
    loc_pairs = [(f["loc_delta"], f["structural"])
                 for _, d in by_class.get("security-fix", []) + by_class.get("control", [])
                 for f in d["touched"]]
    rho_loc = spearman([a for a, _ in loc_pairs], [b for _, b in loc_pairs])

    total_wanted = Counter(e["class"] for e in data["events"])
    partial = any(skipped[c] for c in ("security-fix", "control", "introduced"))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    def verdict(p, direction_ok):
        if math.isnan(p):
            return "n/a"
        return ("**SUPPORTED**" if p < 0.01 else "not supported") if direction_ok else "not supported"

    md = []
    md.append(f"# Exposure history report — {data['repo']}\n")
    md.append(f"Generated {now} · engine scans temporally ablated (asserted: max |temporal Δ| = 0.0) · "
              f"DB `{pathlib.Path(db).name}` · events pinned to pool HEAD `{data['pool_head'][:12]}`"
              + (" · **PRELIMINARY — batch incomplete**" if partial else "") + "\n")
    md.append("## Coverage\n")
    md.append("| class | analyzed | pending/skipped | of harvested |\n|---|---|---|---|")
    for cls in ("security-fix", "control", "introduced"):
        md.append(f"| {cls} | {len(unit.get(cls, []))} | {skipped[cls]} | {total_wanted[cls]} |")
    md.append("")
    md.append("## Pre-registered hypotheses (gitgalaxy#2982; unit = event, "
              "mean structural Δ over its touched files)\n")
    md.append("| test | n | median Δ | vs | n | median Δ | p (one-sided MW) | verdict at α=0.01 |")
    md.append("|---|---|---|---|---|---|---|---|")
    md.append(f"| **H1** fixes < controls | {len(fixes)} | {fmt(median(fixes))} | controls | "
              f"{len(ctrls)} | {fmt(median(ctrls))} | {p1:.4f} | {verdict(p1, median(fixes) < median(ctrls))} |")
    md.append(f"| **H2** introduced > controls | {len(intros)} | {fmt(median(intros))} | controls | "
              f"{len(ctrls)} | {fmt(median(ctrls))} | {p2:.4f} | {verdict(p2, median(intros) > median(ctrls))} |")
    md.append(f"\nPer-file pooled secondary (pseudo-replicated, labeled as such): "
              f"H1 p = {p1f:.4f} over {len(filepool.get('security-fix', []))} fix-file vs "
              f"{len(filepool.get('control', []))} control-file deltas; H2 p = {p2f:.4f}.\n")
    md.append("## H3 — which vectors carry it (event-level medians)\n")
    md.append("| vector | fixes | controls | introduced | H1 p |\n|---|---|---|---|---|")
    for c, mf, mc, mi, pv in sorted(vec_rows, key=lambda r: (r[4] if not math.isnan(r[4]) else 1)):
        md.append(f"| {c} | {fmt(mf)} | {fmt(mc)} | {fmt(mi)} | {pv:.4f} |")
    md.append("")
    md.append("## Sign split — does a fix *reduce* exposure?\n")
    md.append("| class | Δ<0 (reduced) | Δ>0 (raised) | Δ=0 |\n|---|---|---|---|")
    for cls in ("security-fix", "control", "introduced"):
        if cls in sign:
            lo, hi, z = sign[cls]
            n = lo + hi + z
            md.append(f"| {cls} | {lo} ({lo / n:.0%}) | {hi} ({hi / n:.0%}) | {z} |")
    md.append("\nThe first pilot sample predicted this split: guard code added by a fix reads "
              "as complexity (dead_code, cognitive_load), so a security fix RAISING structural "
              "exposure is not a scan error — whether the *distribution* differs from controls "
              "is what H1 asks.\n")
    md.append("## Severity gradient (security fixes)\n")
    md.append("| severity | n | median Δ | p25 | p75 |\n|---|---|---|---|---|")
    for sev in ("Critical", "High", "Medium", "Low", "?"):
        if sev_rows.get(sev):
            v = sev_rows[sev]
            md.append(f"| {sev} | {len(v)} | {fmt(median(v))} | {fmt(q(v, .25))} | {fmt(q(v, .75))} |")
    md.append("")
    md.append("## Top movers (security fixes, event mean Δ)\n")
    md.append("| direction | CVE | Δ | files touched |\n|---|---|---|---|")
    for v, e, d in movers[:5]:
        md.append(f"| ↓ largest drop | {e['id']} | {fmt(v)} | {len(d['touched'])} |")
    for v, e, d in movers[-5:][::-1]:
        md.append(f"| ↑ largest rise | {e['id']} | {fmt(v)} | {len(d['touched'])} |")
    md.append("")
    md.append("## CVE hotspot files (appearances across fix+introduced events)\n")
    md.append("| file | events |\n|---|---|")
    for path, n in hot.most_common(10):
        md.append(f"| `{path}` | {n} |")
    md.append("")
    # --- outlier targeting: pre-event percentile of implicated files ---------
    pctile = {
        cls: [f["pre_percentile"] for _, d in evs for f in d["touched"]]
        for cls, evs in by_class.items()
    }
    _, p_tgt = mann_whitney_u(pctile.get("control", []), pctile.get("security-fix", []))
    md.append("## Are the outliers where security events happen?\n")
    md.append("Each implicated file's **structural-exposure percentile within its parent "
              "snapshot** (all files ranked, before the event was known). Random targeting "
              "reads ~50; if GitGalaxy's high-exposure files are where CVEs live, "
              "security classes read high — a rung-7 preview from rung-6 data.\n")
    md.append("| class | files | median pre-event percentile | p25 | p75 |")
    md.append("|---|---|---|---|---|")
    for cls in ("security-fix", "introduced", "control"):
        v = pctile.get(cls, [])
        if v:
            md.append(f"| {cls} | {len(v)} | {median(v):.1f} | {q(v, .25):.1f} | {q(v, .75):.1f} |")
    md.append(f"\nfix-files sit above control-files with one-sided MW p = {p_tgt:.4f} "
              f"(controls < fixes).\n")

    # --- CWE x vector: which vector flags which weakness type ----------------
    CWE_FAMILY = {
        "CWE-119": "memory", "CWE-122": "memory", "CWE-125": "memory", "CWE-126": "memory",
        "CWE-131": "memory", "CWE-415": "memory", "CWE-416": "memory", "CWE-787": "memory",
        "CWE-476": "memory", "CWE-590": "memory", "CWE-121": "memory", "CWE-124": "memory",
        "CWE-295": "cert/auth", "CWE-297": "cert/auth", "CWE-305": "cert/auth",
        "CWE-287": "cert/auth", "CWE-290": "cert/auth", "CWE-620": "cert/auth",
        "CWE-200": "info-leak", "CWE-201": "info-leak", "CWE-522": "info-leak",
        "CWE-311": "info-leak", "CWE-319": "info-leak",
    }
    cwe_events = defaultdict(list)  # family -> [(event, deltas)]
    for e, d in by_class.get("security-fix", []) + by_class.get("introduced", []):
        fam = CWE_FAMILY.get(e.get("cwe"), "other") if e.get("cwe") else "unlabeled"
        cwe_events[fam].append((e, d))
    md.append("## CWE × vector — which exposure vector flags which weakness type?\n")
    md.append("Median **pre-event per-vector percentile** of implicated files (each file "
              "ranked per vector among all files in its parent snapshot). Reading guide: a "
              "high cell means files that later carried this weakness class already stood "
              "out on that vector before the event. Control-file rows give the baseline "
              "'changed files look like this anyway' profile.\n")
    show_vecs = ["cognitive_load", "safety_score", "state_flux", "api_exposure",
                 "verification", "tech_debt", "documentation", "concurrency"]
    md.append("| class (events) | " + " | ".join(show_vecs) + " |")
    md.append("|---|" + "---|" * len(show_vecs))
    def vec_profile_row(label, recs):
        cells = []
        for c in show_vecs:
            vals = [f["pre_vector_percentiles"][c] for _, d in recs for f in d["touched"]]
            cells.append(f"{median(vals):.0f}" if vals else "–")
        md.append(f"| {label} | " + " | ".join(cells) + " |")
    for fam in sorted(cwe_events, key=lambda k: -len(cwe_events[k])):
        vec_profile_row(f"{fam} ({len(cwe_events[fam])})", cwe_events[fam])
    vec_profile_row(f"control baseline ({len(by_class.get('control', []))})",
                    by_class.get("control", []))
    md.append("")
    # per-family structural delta of the FIX (does fixing a memory bug read
    # differently than fixing a cert check?)
    md.append("**Fix-delta by weakness family** (median event Δ, security fixes only): ")
    fix_by_fam = defaultdict(list)
    for e, d in by_class.get("security-fix", []):
        fam = CWE_FAMILY.get(e.get("cwe"), "other") if e.get("cwe") else "unlabeled"
        fix_by_fam[fam].append(sum(f["structural"] for f in d["touched"]) / len(d["touched"]))
    md.append(" · ".join(f"{fam} {fmt(median(v))} (n={len(v)})"
                         for fam, v in sorted(fix_by_fam.items(), key=lambda t: -len(t[1]))))
    md.append("")

    # --- first look over time (event-sampled; caveats named) -----------------
    md.append("## First look over time (event-sampled snapshots, 5-year eras)\n")
    md.append("Repo-mean structural exposure and implicated-file percentiles per era. "
              "**Caveats before believing a trend**: sampling is event-biased (snapshots "
              "exist where CVEs were fixed/introduced), the codebase grows (absolute "
              "scores drift with file size — percentiles are the robust reading), and "
              "deleted files leave the panel (survivorship). The phase-W walk replaces "
              "this with a uniform panel.\n")
    era_rows = defaultdict(lambda: {"repo": [], "pct": [], "n": []})
    for cls, evs in by_class.items():
        for e, d in evs:
            era = f"{(int(d['date'][:4]) // 5) * 5}–{(int(d['date'][:4]) // 5) * 5 + 4}"
            era_rows[era]["repo"].append(d["repo_mean"])
            era_rows[era]["n"].append(d["n_files"])
            if cls in ("security-fix", "introduced"):
                era_rows[era]["pct"] += [f["pre_percentile"] for f in d["touched"]]
    md.append("| era | snapshots | repo files (median) | repo-mean structural exposure "
              "(median) | implicated-file percentile (median) |")
    md.append("|---|---|---|---|---|")
    for era in sorted(era_rows):
        r = era_rows[era]
        md.append(f"| {era} | {len(r['repo'])} | {median(r['n']):.0f} | "
                  f"{median(r['repo']):.2f} | "
                  f"{median(r['pct']):.1f} |" if r["pct"] else
                  f"| {era} | {len(r['repo'])} | {median(r['n']):.0f} | "
                  f"{median(r['repo']):.2f} | n/a |")
    md.append("")
    md.append("## Instrument controls\n")
    md.append(f"- **Untouched-file spillover** (files the commit did not touch; expected ~0, "
              f"graph ripple via api_exposure is the legitimate exception): "
              f"n = {len(spill)}, median |Δ| = {median(spill):.6f}, p99 = {q(spill, .99):.4f}, "
              f"max = {max(spill) if spill else 0:.4f}.")
    md.append(f"- **LOC coupling** on touched files (is Δ just size change?): Spearman ρ = "
              f"{rho_loc:.3f} over {len(loc_pairs)} files. The length-leak lesson says watch this; "
              f"a high ρ routes to the score-contract program, not to a corpus tweak.")
    md.append(f"- **Temporal ablation**: asserted exactly 0.0 across every delta in this run.\n")
    md.append("---\n*Regenerate: `python tools/delta_report.py --events events/curl.json` — "
              "reads only the events file and the history DB; every number above is a pure "
              "function of those two artifacts.*")

    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")
    print(f"H1 p={p1:.4f} (fix n={len(fixes)}, ctrl n={len(ctrls)}) | H2 p={p2:.4f} "
          f"(intro n={len(intros)}) | spillover median {median(spill):.6f} | wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
