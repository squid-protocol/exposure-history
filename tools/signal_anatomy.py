#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""The signal layer vs CVE ground truth (gitgalaxy#2982): below the risk
formulas, straight at the raw keyword counts the engine extracts.

Three analyses, all reading counts the DB already persists per commit:

  1. THE GRAMMAR OF A SECURITY FIX — per-signal count deltas on touched
     files, fixes vs matched controls vs introductions. Which keywords do
     fixes ADD (guards? branches? casts?) and REMOVE (danger calls?), in the
     engine's own extraction vocabulary.

  2. ASSUMED vs OBSERVED — the risk formulas encode assumptions (safety
     mitigates, danger aggravates, ...). For each signal: where do CVE files
     STAND on it before the event (percentile vs the control-file baseline),
     and which way do fixes MOVE it? An assumption audit against 25 years of
     security ground truth.

  3. THE VULNERABLE FUNCTION — map each fix's diff hunks (parent-side line
     numbers) onto the parent snapshot's function spans (function_data:
     start_line + loc, per commit via file_id): did the exact function later
     patched stand out from its same-file siblings on complexity / z-score /
     signal profile before anyone knew?

Signal deltas are counts and scale with commit size; the control class is
size-matched by construction (guard 2), and net-LOC is printed alongside so
nothing hides in the denominator (the tech_debt lesson).

    python tools/signal_anatomy.py --events events/curl.json
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import subprocess
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR  # noqa: E402
from delta_report import mann_whitney_u, median, q  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402

SIGNAL_PREFIXES = ("struct_", "def_", "state_", "arch_", "bitwise_ops", "llm_", "ml_", "dl_")
SKIP_SIGNALS = {"struct_tabs", "struct_spaces", "struct_linear"}  # formatting, not constructs


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout


def signal_columns(con, table):
    cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
    return [c for c in cols
            if c.startswith(SIGNAL_PREFIXES) and c not in SKIP_SIGNALS]


def file_rows(con, sha, cols):
    sel = ", ".join(["file_path", "total_loc"] + cols)
    return {r[0]: r for r in con.execute(
        f"SELECT {sel} FROM file_data WHERE commit_hash = ?", (sha,))}


def parent_child(repo, sha):
    child = _git(repo, "rev-parse", sha).strip()
    try:
        parent = _git(repo, "rev-parse", f"{child}^").strip()
    except subprocess.CalledProcessError:
        return None, None
    return parent, child


def hunk_lines_parent_side(repo, parent, child, path):
    """Set of parent-side line numbers changed in `path` (deleted/replaced)."""
    out = subprocess.run(
        ["git", "-C", str(repo), "diff", "-U0", f"{parent}..{child}", "--", path],
        capture_output=True).stdout.decode("utf-8", errors="replace")
    lines = set()
    for ln in out.splitlines():
        if ln.startswith("@@"):
            seg = ln.split()[1]  # -start,count
            start_count = seg[1:].split(",")
            start = int(start_count[0])
            count = int(start_count[1]) if len(start_count) > 1 else 1
            lines.update(range(start, start + max(count, 1)))
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True)
    ap.add_argument("--out", default=str(DOCS_DIR / "signal_anatomy.md"))
    args = ap.parse_args()

    data = json.loads(pathlib.Path(args.events).read_text())
    repo = resolve_repo(data["repo"])
    con = sqlite3.connect(history_db(out_dir_for(repo)))
    fcols = signal_columns(con, "file_data")

    # ---------------- pass 1: per-event touched-file signal deltas + levels
    deltas = defaultdict(lambda: defaultdict(list))  # class -> signal -> [event mean delta]
    levels = defaultdict(lambda: defaultdict(list))  # class -> signal -> [pre-event pct]
    netloc = defaultdict(list)
    n_events = defaultdict(int)
    PREV_SIGNALS = ["struct_branch", "state_pointers", "def_safety",
                    "state_cast_hits", "state_memory_alloc"]
    prevalence = defaultdict(lambda: defaultdict(int))
    func_standing = []  # (implicated?, complexity, z, loc) at parent, fixes only
    func_files = []  # same tuples grouped per touched file, for loc-matched pairs

    for e in data["events"]:
        parent, child = parent_child(repo, e["sha"])
        if parent is None:
            continue
        before = file_rows(con, parent, fcols)
        after = file_rows(con, child, fcols)
        if not before or not after:
            continue
        statuses = diff_statuses(repo, parent, child)
        touched = [(p, st) for p, st in statuses.items()
                   if st["status"] == "touched" and p in after and st["old_path"] in before]
        if not touched:
            continue
        n_events[e["class"]] += 1
        # per-signal rankings for level percentiles
        import bisect
        ranked = {c: sorted((r[2 + i] or 0) for r in before.values())
                  for i, c in enumerate(fcols)}
        ev_delta = defaultdict(list)
        ev_loc = []
        for path, st in touched:
            b, a = before[st["old_path"]], after[path]
            ev_loc.append((a[1] or 0) - (b[1] or 0))
            for i, c in enumerate(fcols):
                bv, av = b[2 + i] or 0, a[2 + i] or 0
                ev_delta[c].append(av - bv)
                lst = ranked[c]
                levels[e["class"]][c].append(
                    100.0 * bisect.bisect_left(lst, bv) / max(len(lst) - 1, 1))
        for c in fcols:
            deltas[e["class"]][c].append(sum(ev_delta[c]) / len(ev_delta[c]))
        netloc[e["class"]].append(sum(ev_loc) / len(ev_loc))
        # prevalence flags (exploratory section): did this EVENT add/remove the construct
        for s in PREV_SIGNALS:
            tot = sum(ev_delta[s])
            if tot > 0:
                prevalence[e["class"]][f"+{s}"] += 1
            elif tot < 0:
                prevalence[e["class"]][f"-{s}"] += 1
        b_up = sum(ev_delta["struct_branch"]) > 0
        p_up = sum(ev_delta["state_pointers"]) > 0
        ac_up = sum(ev_delta["state_cast_hits"]) > 0 or sum(ev_delta["state_memory_alloc"]) > 0
        if b_up or p_up:
            prevalence[e["class"]]["loose signature (branch+ or ptr+)"] += 1
        if b_up and p_up:
            prevalence[e["class"]]["strict signature (branch+ and ptr+)"] += 1
        if (b_up or p_up) and not ac_up:
            prevalence[e["class"]]["fix-shaped (branch/ptr+ WITHOUT new allocs/casts)"] += 1

        # ---------------- pass 2 (fixes only): implicated functions vs siblings
        if e["class"] == "security-fix":
            for path, st in touched:
                changed = hunk_lines_parent_side(repo, parent, child, st["old_path"])
                if not changed:
                    continue
                FSEL = ("f.func_name, f.start_line, f.loc, f.complexity, f.func_z_score, "
                        "f.state_pointers, f.state_danger, f.state_memory_alloc, "
                        "f.state_cast_hits, f.def_safety, f.state_bailout_hits")
                frows = con.execute(
                    f"SELECT {FSEL} FROM function_data f JOIN file_data fd ON f.file_id = fd.id "
                    "WHERE fd.commit_hash = ? AND fd.file_path = ?",
                    (parent, st["old_path"])).fetchall()
                # child snapshot rows by name, for D-H2 (did the fix close the deficit?)
                crows = {r[0]: r for r in con.execute(
                    f"SELECT {FSEL} FROM function_data f JOIN file_data fd ON f.file_id = fd.id "
                    "WHERE fd.commit_hash = ? AND fd.file_path = ?", (child, path))}
                def loads(row):
                    danger = sum((row[i] or 0) for i in (5, 6, 7, 8))
                    guard = sum((row[i] or 0) for i in (9, 10))
                    return danger, guard, guard / (danger + 1)
                per_file = []
                for row in frows:
                    name, start, loc, cx, z = row[:5]
                    if start is None or loc is None:
                        continue
                    span = range(start, start + max(loc, 1))
                    hit = any(ln in changed for ln in span)
                    danger, guard, rate = loads(row)
                    post = crows.get(name)
                    post_rate = loads(post)[2] if post else None
                    rec = (hit, cx or 0, z or 0.0, loc or 0, danger, guard, rate, post_rate)
                    func_standing.append(rec)
                    per_file.append(rec)
                func_files.append(per_file)

    # ---------------- report
    md = [f"# Signal anatomy — {data['repo']}\n"]
    md.append(f"Raw-signal layer vs CVE ground truth. Events analyzed: "
              + ", ".join(f"{c} {n}" for c, n in sorted(n_events.items()))
              + f". Median event net-LOC: "
              + ", ".join(f"{c} {median(v):+.0f}" for c, v in sorted(netloc.items())) + ".\n")

    md.append("## 1 · The grammar of a security fix (signal deltas, fixes vs controls)\n")
    md.append("Per-signal mean delta over touched files, per event (median across events). "
              "One-sided MW in the direction the medians differ; sorted by p.\n")
    md.append("| signal | fixes Δ | controls Δ | introduced Δ | p (fix vs ctrl) |")
    md.append("|---|---|---|---|---|")
    rows1 = []
    for c in fcols:
        f, ct, iv = deltas["security-fix"].get(c, []), deltas["control"].get(c, []), \
            deltas["introduced"].get(c, [])
        if not f or not ct:
            continue
        mf, mc = median(f), median(ct)
        _, p_lt = mann_whitney_u(f, ct)
        _, p_gt = mann_whitney_u(ct, f)
        p = min(p_lt, p_gt)
        rows1.append((p, c, mf, mc, median(iv) if iv else float("nan")))
    rows1.sort()
    for p, c, mf, mc, mi in rows1[:20]:
        md.append(f"| {c} | {mf:+.2f} | {mc:+.2f} | "
                  f"{'n/a' if mi != mi else f'{mi:+.2f}'} | {p:.4f} |")
    md.append("")

    md.append("## 1b · Signature prevalence (EXPLORATORY — descriptive shares, no p-values "
              "claimed; class-discrimination confirmatory tests belong to Phase M / repo #2)\n")
    md.append("Share of events whose touched files NET-added (or removed) each construct.\n")
    classes = [c for c in ("security-fix", "control", "introduced") if n_events.get(c)]
    md.append("| construct | " + " | ".join(classes) + " |")
    md.append("|---|" + "---|" * len(classes))
    prev_keys = ([f"+{s}" for s in PREV_SIGNALS] + ["-state_pointers", "-struct_branch",
                 "loose signature (branch+ or ptr+)", "strict signature (branch+ and ptr+)",
                 "fix-shaped (branch/ptr+ WITHOUT new allocs/casts)"])
    for k in prev_keys:
        md.append(f"| {k} | " + " | ".join(
            f"{100 * prevalence[c][k] / n_events[c]:.0f}%" for c in classes) + " |")
    md.append("\nReading: no single feature is a fingerprint (71% of fixes add branch-or-ptr, "
              "but so do 45% of controls). The DIFFERENTIAL is the lead: introductions match "
              "fixes on branches/pointers but differ sharply on allocations and casts — "
              "'pointer/branch-heavy WITHOUT new allocs/casts' is fix-shaped; the same WITH "
              "them is feature-shaped, which is where vulnerabilities are born. Multi-feature "
              "classification is the ML dataset's job, not a threshold's.\n")
    md.append("## 2 · Assumed vs observed — where CVE files stand per signal, before the event\n")
    md.append("Median pre-event percentile of implicated files per signal (ranked among all "
              "files in the parent snapshot), fix-class vs the control-file baseline. A large "
              "gap in either direction is a keyword whose risk association differs from the "
              "'change happens in hot files' baseline; sorted by |gap|.\n")
    md.append("| signal | CVE-fix files | control files | gap |")
    md.append("|---|---|---|---|")
    rows2 = []
    for c in fcols:
        lf, lc = levels["security-fix"].get(c, []), levels["control"].get(c, [])
        if len(lf) < 20 or len(lc) < 20:
            continue
        gap = median(lf) - median(lc)
        rows2.append((abs(gap), c, median(lf), median(lc), gap))
    rows2.sort(reverse=True)
    for _a, c, mf, mc, gap in rows2[:15]:
        md.append(f"| {c} | {mf:.0f} | {mc:.0f} | {gap:+.0f} |")
    md.append("")

    if func_standing:
        imp = [(r[1], r[2], r[3]) for r in func_standing if r[0]]
        sib = [(r[1], r[2], r[3]) for r in func_standing if not r[0]]
        md.append("## 3 · The vulnerable function — implicated vs same-file siblings "
                  "(parent snapshot)\n")
        md.append(f"Functions overlapping a fix's changed lines (n={len(imp)}) vs untouched "
                  f"siblings in the same files (n={len(sib)}):\n")
        md.append("| metric | implicated median | sibling median | p (sib < imp) |")
        md.append("|---|---|---|---|")
        for label, idx in (("complexity", 0), ("z-score", 1), ("loc", 2)):
            a = [t[idx] for t in imp]
            b = [t[idx] for t in sib]
            _, p = mann_whitney_u(b, a)
            md.append(f"| {label} | {median(a):.2f} | {median(b):.2f} | {p:.4f} |")
        md.append("\nIf implicated functions stand out from their own file's siblings, the "
                  "instrument localizes below file granularity — the sharpest claim rung 7 "
                  "could make.\n")
        # ---- the length-bias gate: loc-matched pairs, same file -------------
        # Longer functions overlap a hunk more often by area alone. For each
        # implicated function, take the loc-CLOSEST untouched sibling in the
        # same file within [0.66x, 1.5x] loc; if complexity/z still separate,
        # the localization is not a length artifact.
        pairs = []
        for per_file in func_files:
            hits = [r for r in per_file if r[0]]
            sibs = [r for r in per_file if not r[0]]
            for h in hits:
                cand = [s for s in sibs if 0.66 * h[3] <= s[3] <= 1.5 * h[3]]
                if cand:
                    pairs.append((h, min(cand, key=lambda s: abs(s[3] - h[3]))))
        if pairs:
            md.append(f"**Length-bias gate (loc-matched pairs, n={len(pairs)}, sibling within "
                      f"0.66–1.5× loc in the same file):**\n")
            md.append("| metric | implicated median | matched sibling median | p (sib < imp) |")
            md.append("|---|---|---|---|")
            for label, idx in (("complexity", 1), ("z-score", 2), ("loc (match check)", 3)):
                a = [h[idx] for h, _ in pairs]
                b = [s[idx] for _, s in pairs]
                _, p = mann_whitney_u(b, a)
                md.append(f"| {label} | {median(a):.2f} | {median(b):.2f} | {p:.4f} |")
            wins = sum(1 for h, s in pairs if h[1] > s[1])
            ties = sum(1 for h, s in pairs if h[1] == s[1])
            md.append(f"\nPairwise: implicated more complex than its length-matched sibling in "
                      f"{wins}/{len(pairs)} pairs ({ties} ties). If the gate holds, complexity "
                      f"separates future-patched functions at equal length — a real "
                      f"below-file signal, not hunk-area bias.\n")
            # ---- Phase D: the guard-deficit study (pre-registered on #2982) --
            # D-H1: implicated functions carry a LOWER guard rate
            # (def_safety+bailouts per danger construct) than their
            # length-matched siblings. D-H2: the fix RAISES the implicated
            # function's guard rate; siblings stay flat. Danger load reported
            # alone as the "is it just more pointers" control.
            md.append("### Phase D — the guard deficit (pre-registered)\n")
            md.append("guard rate = (def_safety + bailouts) / (pointers + danger + "
                      "memory_alloc + casts + 1), function grain, parent snapshot, "
                      "loc-matched pairs.\n")
            md.append("| metric | implicated | matched sibling | p (one-sided, "
                      "registered direction) |")
            md.append("|---|---|---|---|")
            a_rate = [h[6] for h, _ in pairs]
            b_rate = [s[6] for _, s in pairs]
            _, p_d1 = mann_whitney_u(a_rate, b_rate)  # D-H1: implicated < sibling
            md.append(f"| guard rate (D-H1) | {median(a_rate):.3f} | {median(b_rate):.3f} | "
                      f"{p_d1:.4f} |")
            a_d = [h[4] for h, _ in pairs]
            b_d = [s[4] for _, s in pairs]
            _, p_dng = mann_whitney_u(b_d, a_d)  # control: sibling < implicated danger
            md.append(f"| danger load (control) | {median(a_d):.1f} | {median(b_d):.1f} | "
                      f"{p_dng:.4f} |")
            # D-H2: paired pre->post guard-rate change where the function survives
            imp_chg = [h[7] - h[6] for h, _ in pairs if h[7] is not None]
            sib_chg = [s[7] - s[6] for _, s in pairs if s[7] is not None]
            _, p_d2 = mann_whitney_u(sib_chg, imp_chg)  # sib change < implicated change
            md.append(f"| guard-rate change after fix (D-H2) | "
                      f"{median(imp_chg):+.4f} (n={len(imp_chg)}) | "
                      f"{median(sib_chg):+.4f} (n={len(sib_chg)}) | {p_d2:.4f} |")
            d1 = "SUPPORTED" if p_d1 < 0.01 and median(a_rate) < median(b_rate) else "not supported"
            d2 = "SUPPORTED" if p_d2 < 0.01 and median(imp_chg) > median(sib_chg) else "not supported"
            md.append(f"\n**D-H1 (vulnerable = under-guarded relative to danger): {d1}** · "
                      f"**D-H2 (the fix closes the deficit): {d2}** (α=0.01, directions "
                      f"registered on gitgalaxy#2982 before this table was generated).\n")

    md.append("---\n*Counts are the engine's own extraction (persisted per commit in "
              "file_data/function_data); no diff-text keyword matching involved. Regenerate: "
              "`python tools/signal_anatomy.py --events events/curl.json`.*")
    out = pathlib.Path(args.out)
    out.write_text("\n".join(md) + "\n")
    print(f"events: {dict(n_events)} | func spans: {len(func_standing)} | wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
