#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Wave-1 hypothesis evaluation: reverts + CVE-follow-ups (gitgalaxy#2982).

Pre-registered on epic comment 5647715438 (α=0.01, BEFORE this batch ran),
evaluated verbatim here. delta_report.py/signal_anatomy.py only *report* the
three original classes, but their pass-1 machinery is class-agnostic — this
tool reuses the SAME helpers (identical signal set, per-event mean delta, the
fix-shaped composite `(branch/ptr+) and not (alloc/cast+)`) so the operational
definitions match the registration exactly.

  W1-H1 reverts = net-removal: a revert's grammar-signal deltas are
        predominantly negative (where other classes are net-positive) and
        median event net-LOC < 0.
  W1-H2 incomplete fixes look thin: CVE fixes that later needed a follow-up
        carry the fix-shaped composite at a LOWER rate than fixes that stuck
        (one-sided).
  W1-H3 follow-ups carry the grammar: cve-followup commits show branch/pointer
        adds (loose signature) at a rate closer to fixes than to controls.

Exploratory (labeled, no p-values): area-prefix re-slice of existing fixes.

    python tools/wave1_analysis.py            # reads events/curl{,_wave1}.json
"""
from __future__ import annotations

import json
import math
import pathlib
import sqlite3
from collections import defaultdict

import sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DOCS_DIR, EVENTS_DIR  # noqa: E402
from delta_report import mann_whitney_u, median  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import _git, file_rows, parent_child, signal_columns  # noqa: E402


def event_stats(con, repo, fcols, sha):
    """Replicates signal_anatomy pass-1 for ONE event. Returns per-event mean
    signal deltas, net grammar delta, net-LOC, and the composite flags."""
    parent, child = parent_child(repo, sha)
    if parent is None:
        return None
    before = file_rows(con, parent, fcols)
    after = file_rows(con, child, fcols)
    if not before or not after:
        return None
    statuses = diff_statuses(repo, parent, child)
    touched = [(p, st) for p, st in statuses.items()
               if st["status"] == "touched" and p in after and st["old_path"] in before]
    if not touched:
        return None
    ev_delta = defaultdict(list)
    ev_loc = []
    for path, st in touched:
        b, a = before[st["old_path"]], after[path]
        ev_loc.append((a[1] or 0) - (b[1] or 0))
        for i, c in enumerate(fcols):
            ev_delta[c].append((a[2 + i] or 0) - (b[2 + i] or 0))
    mean_delta = {c: sum(ev_delta[c]) / len(ev_delta[c]) for c in fcols}
    # net grammar movement = sum over all grammar signals of the event-mean delta
    net_grammar = sum(mean_delta[c] for c in fcols)
    netloc = sum(ev_loc) / len(ev_loc)
    b_up = sum(ev_delta["struct_branch"]) > 0
    p_up = sum(ev_delta["state_pointers"]) > 0
    ac_up = sum(ev_delta["state_cast_hits"]) > 0 or sum(ev_delta["state_memory_alloc"]) > 0
    return {
        "sha": sha, "n_touched": len(touched),
        "mean_delta": mean_delta, "net_grammar": net_grammar, "netloc": netloc,
        "loose": (b_up or p_up),               # "branch/pointer adds" = fix grammar
        "fixshaped": (b_up or p_up) and not ac_up,
    }


def sign_test_lt0(values):
    """One-sided sign test, H1: median < 0. Returns (n_neg, n_pos, p)."""
    neg = sum(1 for v in values if v < 0)
    pos = sum(1 for v in values if v > 0)
    n = neg + pos
    if n == 0:
        return neg, pos, float("nan")
    # P(X >= neg) under Binom(n, 0.5)
    p = sum(math.comb(n, k) for k in range(neg, n + 1)) / (2 ** n)
    return neg, pos, p


def fisher_lower(a, b, c, d):
    """One-sided Fisher exact: P(row-1 rate <= observed). Table [[a,b],[c,d]].
    Returns p for the hypothesis that group-1's 'yes' rate is LOWER."""
    r1, r2 = a + b, c + d
    c1 = a + c
    n = a + b + c + d

    def pmf(k):
        return (math.comb(r1, k) * math.comb(r2, c1 - k)) / math.comb(n, c1)
    kmin = max(0, c1 - r2)
    p = sum(pmf(k) for k in range(kmin, a + 1))
    return min(p, 1.0)


def area_prefix(summary: str) -> str | None:
    s = (summary or "").strip()
    if ":" in s[:24]:
        pre = s.split(":", 1)[0].strip().lower()
        if pre and " " not in pre and 1 < len(pre) <= 16:
            return pre
    return None


def main() -> int:
    base = json.loads((EVENTS_DIR / "curl.json").read_text())
    wave1 = json.loads((EVENTS_DIR / "curl_wave1.json").read_text())
    repo = resolve_repo(base["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # WAL-aware, never immutable
    con.row_factory = None
    fcols = signal_columns(con, "file_data")

    # ---- gather per-event stats for every class we need -------------------
    by_class = defaultdict(list)          # class -> [event_stats]
    fix_by_sha = {}                       # sha -> event_stats (security-fix)
    fix_subjects = {}                     # sha -> git commit subject (for area re-slice)
    for e in base["events"]:
        st = event_stats(con, repo, fcols, e["sha"])
        if st is None:
            continue
        by_class[e["class"]].append(st)
        if e["class"] == "security-fix":
            fix_by_sha[e["sha"]] = st
            try:
                fix_subjects[e["sha"]] = _git(repo, "log", "-1", "--format=%s", e["sha"]).strip()
            except Exception:
                fix_subjects[e["sha"]] = ""
    followups = []
    follows_fix_shas = []
    for e in wave1["events"]:
        st = event_stats(con, repo, fcols, e["sha"])
        if st is not None:
            by_class[e["class"]].append(st)
        if e.get("follows_fix"):
            follows_fix_shas.append(e["follows_fix"])

    md = ["# Wave-1 hypothesis evaluation — curl\n",
          "Pre-registered on gitgalaxy#2982 (comment 5647715438, α=0.01), evaluated verbatim. "
          "Operational definitions reuse `signal_anatomy.py` pass-1 (same signal set, per-event "
          "mean delta, fix-shaped composite). Counts are the engine's own extraction.\n"]
    n_by = {c: len(v) for c, v in by_class.items()}
    md.append("Events analyzed: " + ", ".join(f"{c} {n}" for c, n in sorted(n_by.items())) + ".\n")

    # ===================== W1-H1 =====================
    rev = by_class.get("revert", [])
    rev_netloc = [s["netloc"] for s in rev]
    rev_grammar = [s["net_grammar"] for s in rev]
    ctrl = by_class.get("control", [])
    md.append("## W1-H1 — reverts as net-removal\n")
    md.append("Registered: revert grammar-signal deltas predominantly negative (others net-positive); "
              "median event net-LOC < 0.\n")
    neg_loc, pos_loc, p_loc = sign_test_lt0(rev_netloc)
    neg_gr, pos_gr, p_gr = sign_test_lt0(rev_grammar)
    # between-class contrast: revert < control (one-sided MW)
    _, p_loc_mw = mann_whitney_u(rev_netloc, [s["netloc"] for s in ctrl]) if ctrl else (0, float("nan"))
    _, p_gr_mw = mann_whitney_u(rev_grammar, [s["net_grammar"] for s in ctrl]) if ctrl else (0, float("nan"))
    md.append(f"| quantity | revert median | n<0 / n>0 (of {len(rev)}) | sign-test p (median<0) | vs control (1-sided MW) |")
    md.append("|---|---|---|---|---|")
    md.append(f"| event net-LOC | {median(rev_netloc):+.1f} | {neg_loc} / {pos_loc} | {p_loc:.2e} | {p_loc_mw:.4f} |")
    md.append(f"| net grammar Δ | {median(rev_grammar):+.3f} | {neg_gr} / {pos_gr} | {p_gr:.2e} | {p_gr_mw:.4f} |")
    # other classes' net-LOC for the "others are net-positive" contrast
    md.append("\nContrast (median event net-LOC): " + ", ".join(
        f"{c} {median([s['netloc'] for s in by_class[c]]):+.1f}"
        for c in ("security-fix", "control", "introduced", "revert", "cve-followup")
        if by_class.get(c)) + ".\n")
    h1_loc = (median(rev_netloc) < 0 and p_loc < 0.01)
    h1_gr = (median(rev_grammar) < 0 and p_gr < 0.01)
    h1 = "SUPPORTED" if (h1_loc and h1_gr) else ("PARTIAL" if (h1_loc or h1_gr) else "not supported")
    md.append(f"**W1-H1: {h1}** — net-LOC<0 {'✓' if h1_loc else '✗'}, net-grammar<0 {'✓' if h1_gr else '✗'} (α=0.01).\n")

    # ===================== W1-H2 =====================
    # split security-fix by whether a cve-followup follows it (prefix match both ways)
    def is_followed(sha):
        return any(sha.startswith(f) or f.startswith(sha) for f in follows_fix_shas)
    needs = [st for sha, st in fix_by_sha.items() if is_followed(sha)]
    stuck = [st for sha, st in fix_by_sha.items() if not is_followed(sha)]
    md.append("## W1-H2 — fixes that needed a follow-up look thinner\n")
    md.append("Registered: fixes later needing a follow-up carry the fix-shaped composite at a "
              "LOWER rate than fixes that stuck (one-sided).\n")
    a = sum(1 for s in needs if s["fixshaped"]); b = len(needs) - a
    c = sum(1 for s in stuck if s["fixshaped"]); d = len(stuck) - c
    rate_n = a / len(needs) if needs else float("nan")
    rate_s = c / len(stuck) if stuck else float("nan")
    p_h2 = fisher_lower(a, b, c, d) if needs and stuck else float("nan")
    md.append("| group | n | fix-shaped | rate |")
    md.append("|---|---|---|---|")
    md.append(f"| needs-follow-up | {len(needs)} | {a} | {rate_n:.2f} |")
    md.append(f"| stuck | {len(stuck)} | {c} | {rate_s:.2f} |")
    md.append(f"\nOne-sided Fisher (needs < stuck): p = {p_h2:.4f}.\n")
    h2 = "SUPPORTED" if (rate_n < rate_s and p_h2 < 0.01) else "not supported"
    md.append(f"**W1-H2: {h2}** (α=0.01; matched SHAs: {len(needs)} needs-follow-up / "
              f"{len(follows_fix_shas)} follow-up links).\n")

    # ===================== W1-H3 =====================
    fu = by_class.get("cve-followup", [])
    fix = by_class.get("security-fix", [])
    def loose_rate(lst):
        return (sum(1 for s in lst if s["loose"]) / len(lst)) if lst else float("nan")
    r_fu, r_fix, r_ctrl = loose_rate(fu), loose_rate(fix), loose_rate(ctrl)
    md.append("## W1-H3 — follow-ups carry the fix grammar\n")
    md.append("Registered: follow-up commits show branch/pointer adds (loose signature) at a rate "
              "closer to fixes than to controls.\n")
    # follow-up vs control (matching the fix>control direction)
    af = sum(1 for s in fu if s["loose"]); bf = len(fu) - af
    cc = sum(1 for s in ctrl if s["loose"]); dc = len(ctrl) - cc
    # one-sided Fisher: follow-up rate HIGHER than control => lower(control, followup) framing
    p_fu_ctrl = fisher_lower(cc, dc, af, bf) if fu and ctrl else float("nan")
    md.append("| class | n | loose (branch/ptr+) | rate |")
    md.append("|---|---|---|---|")
    for name, lst, r in (("cve-followup", fu, r_fu), ("security-fix", fix, r_fix), ("control", ctrl, r_ctrl)):
        md.append(f"| {name} | {len(lst)} | {sum(1 for s in lst if s['loose'])} | {r:.2f} |")
    md.append(f"\nFollow-up vs control (one-sided Fisher, follow-up > control): p = {p_fu_ctrl:.4f}. "
              f"|rate(fu)−rate(fix)| = {abs(r_fu-r_fix):.2f} vs |rate(fu)−rate(ctrl)| = {abs(r_fu-r_ctrl):.2f}.\n")
    closer_to_fix = abs(r_fu - r_fix) < abs(r_fu - r_ctrl)
    h3 = "SUPPORTED" if (closer_to_fix and p_fu_ctrl < 0.01) else (
        "DIRECTIONAL" if closer_to_fix else "not supported")
    md.append(f"**W1-H3: {h3}** — closer to fixes than controls {'✓' if closer_to_fix else '✗'}; "
              f"follow-up>control at α=0.01 {'✓' if p_fu_ctrl < 0.01 else '✗'} (n={len(fu)} is small).\n")

    # ===================== exploratory: area re-slice =====================
    md.append("## Exploratory — area-prefix re-slice of existing fixes (LABELED; no p-values)\n")
    area = defaultdict(list)
    for sha, st in fix_by_sha.items():
        pre = area_prefix(fix_subjects.get(sha, ""))
        if pre:
            area[pre].append(st)
    md.append("| area | n fixes | fix-shaped rate | loose rate | median net-LOC |")
    md.append("|---|---|---|---|---|")
    for pre in sorted(area, key=lambda k: -len(area[k])):
        lst = area[pre]
        if len(lst) < 4:
            continue
        fsr = sum(1 for s in lst if s["fixshaped"]) / len(lst)
        lr = sum(1 for s in lst if s["loose"]) / len(lst)
        md.append(f"| {pre}: | {len(lst)} | {fsr:.2f} | {lr:.2f} | {median([s['netloc'] for s in lst]):+.0f} |")
    md.append("\nDescriptive only — an exploratory observation here may be *registered* for repo #2, "
              "never re-tested on this data.\n")

    out = DOCS_DIR / "wave1_hypotheses.md"
    out.write_text("\n".join(md) + "\n")
    print(f"W1-H1 {h1} | W1-H2 {h2} | W1-H3 {h3} | wrote {out}")
    print(f"classes: {n_by} | needs-followup={len(needs)} stuck={len(stuck)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
