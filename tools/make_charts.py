#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Committed charts for the temporal-crucible reports (gitgalaxy-adjacent #4).

Four static, self-contained SVGs under docs/charts/, each COMPUTED from the
same sources delta_report.py / signal_anatomy.py read -- the history DB and
the events file -- never from numbers copied out of a markdown table. Reuses
the report tools' own machinery so definitions match exactly:

  1. delta distributions by class   -- delta_report.event_deltas() per-event
     structural delta (mean over touched files), one box/whisker per class.
  2. era trajectory                 -- delta_report's own era bucketing
     (event child-commit year // 5), implicated-file pre-event percentile,
     security-fix + introduced classes (same restriction the committed
     report's "First look over time" table uses).
  3. CWE x vector heatmap           -- delta_report.CWE_FAMILY reused verbatim
     for family assignment; cell = median pre-event per-vector percentile
     (event_deltas' pre_vector_percentiles), control class as the baseline row.
  4. signature prevalence bars      -- signal_anatomy.py's loose/strict/
     fix-shaped construct, recomputed here with the same primitives
     (signal_columns/file_rows/diff_statuses) grouped by class.

The DB is opened read-only, WAL-aware: `sqlite3.connect("file:...?mode=ro",
uri=True)` -- never immutable=1, the DB may have a live WAL.

Colors and marks follow the dataviz skill's reference palette verbatim
(pre-validated -- no validator re-run needed): categorical slots 1/2/3
(blue/green/magenta) for the three event classes, the sequential blue ramp
for the heatmap, light chart chrome throughout.

Usage:
    python tools/make_charts.py                       # curl, default paths
    python tools/make_charts.py --repo curl --events events/curl.json
"""
from __future__ import annotations

import argparse
import bisect
import pathlib
import sqlite3
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import json  # noqa: E402

from _engine import DOCS_DIR, RISK_VECTOR, STRUCTURAL_COLUMNS  # noqa: E402
from delta_report import CWE_FAMILY, event_deltas, median, q  # noqa: E402
from exposure_delta import diff_statuses  # noqa: E402
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import file_rows, signal_columns  # noqa: E402

CHARTS_DIR = DOCS_DIR / "charts"

# ---------------------------------------------------------------- the palette
# references/palette.md, verbatim -- light mode only (static SVGs, no toggle).
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"
BORDER = "rgba(11,11,11,0.10)"

SLOT_BLUE = "#2a78d6"     # categorical slot 1
SLOT_GREEN = "#008300"    # categorical slot 2
SLOT_MAGENTA = "#e87ba4"  # categorical slot 3

CLASS_COLOR = {
    "security-fix": SLOT_BLUE,
    "control": SLOT_GREEN,
    "introduced": SLOT_MAGENTA,
}
CLASS_LABEL = {
    "security-fix": "security-fix",
    "control": "control",
    "introduced": "introduced",
}

# Sequential blue ramp, 100 -> 700 (references/palette.md).
SEQ_RAMP = [
    (100, "#cde2fb"), (150, "#b7d3f6"), (200, "#9ec5f4"), (250, "#86b6ef"),
    (300, "#6da7ec"), (350, "#5598e7"), (400, "#3987e5"), (450, "#2a78d6"),
    (500, "#256abf"), (550, "#1c5cab"), (600, "#184f95"), (650, "#104281"),
    (700, "#0d366b"),
]

FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _rgb_to_hex(rgb: tuple[float, float, float]) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c))):02x}" for c in rgb)


def seq_color(v: float) -> str:
    """Sequential blue ramp for v in [0,100], light (0) -> dark (100). The ramp's
    13 colors are treated as equally spaced across the domain; the step NUMBERS
    (100..700) are names, not domain positions."""
    v = max(0.0, min(100.0, v))
    ramp = [hx for _, hx in SEQ_RAMP]  # light -> dark
    pos = v / 100.0 * (len(ramp) - 1)
    i = int(pos)
    if i >= len(ramp) - 1:
        return ramp[-1]
    t = pos - i
    r0, g0, b0 = _hex_to_rgb(ramp[i])
    r1, g1, b1 = _hex_to_rgb(ramp[i + 1])
    return _rgb_to_hex((r0 + (r1 - r0) * t, g0 + (g1 - g0) * t, b0 + (b1 - b0) * t))


def cell_text_color(v: float) -> str:
    """Ink on light cells, white on dark cells -- readable, never the fill hue."""
    return "#ffffff" if v >= 56 else INK


# --------------------------------------------------------------- SVG plumbing
def esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def svg_doc(width: int, height: int, title: str, desc: str, body: str) -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" \
width="{width}" height="{height}" role="img" aria-labelledby="title desc">
<title id="title">{esc(title)}</title>
<desc id="desc">{esc(desc)}</desc>
<style>
  text {{ font-family: {FONT}; }}
  .tick {{ font-variant-numeric: tabular-nums; }}
</style>
<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="10" \
fill="{SURFACE}" stroke="{BORDER}" stroke-width="1"/>
{body}
</svg>
'''


def text(x, y, s, *, size=12, fill=INK, anchor="start", weight="normal", tabular=False,
          transform=None) -> str:
    cls = ' class="tick"' if tabular else ""
    tr = f' transform="{transform}"' if transform else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}"{cls}{tr}>{esc(s)}</text>')


def line(x1, y1, x2, y2, *, stroke, width=1, cap="butt", dash=None) -> str:
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{stroke}" stroke-width="{width}" stroke-linecap="{cap}"{d}/>')


def rect(x, y, w, h, *, fill, rx=0, opacity=None, stroke=None, stroke_width=1) -> str:
    o = f' fill-opacity="{opacity}"' if opacity is not None else ""
    s = f' stroke="{stroke}" stroke-width="{stroke_width}"' if stroke else ""
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'rx="{rx}" fill="{fill}"{o}{s}/>')


def circle(cx, cy, r, *, fill, ring=SURFACE, ring_w=2) -> str:
    return (f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r + ring_w}" fill="{ring}"/>'
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{fill}"/>')


# =============================================================== data layer
def load_events(events_path: pathlib.Path) -> dict:
    return json.loads(events_path.read_text())


def open_db(repo: pathlib.Path) -> sqlite3.Connection:
    db = history_db(out_dir_for(repo))
    if db is None:
        sys.exit(f"no history DB under {out_dir_for(repo)} -- scan first")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # WAL-aware, never immutable
    con.row_factory = sqlite3.Row
    return con, db


def gather_deltas(con, repo, events: list[dict]) -> dict[str, dict | None]:
    """sha -> delta_report.event_deltas() result, one DB+diff pass per event.
    This is the SAME function delta_report.py calls for exposure_history_report.md,
    so every number downstream matches that report's definitions exactly."""
    cache = {}
    for e in events:
        cache[e["sha"]] = event_deltas(con, repo, e["sha"])
    return cache


# ---- chart 1: delta distributions by class --------------------------------
def data_class_deltas(events, cache) -> dict[str, list[float]]:
    by_class = defaultdict(list)
    for e in events:
        d = cache.get(e["sha"])
        if not d or not d["touched"]:
            continue
        by_class[e["class"]].append(sum(f["structural"] for f in d["touched"]) / len(d["touched"]))
    return by_class


# ---- chart 2: era trajectory -----------------------------------------------
def data_era_trajectory(events, cache) -> dict[str, list[float]]:
    """Median implicated-file pre-event percentile per 5-year era. Mirrors
    delta_report.py's era_rows['pct'] exactly: security-fix + introduced
    classes only (control excluded -- same restriction the committed
    'First look over time' table uses)."""
    era_pct = defaultdict(list)
    for e in events:
        if e["class"] not in ("security-fix", "introduced"):
            continue
        d = cache.get(e["sha"])
        if not d:
            continue
        year = int(d["date"][:4])
        start = (year // 5) * 5
        era = f"{start}–{(start + 4) % 100:02d}"
        era_pct[era] += [f["pre_percentile"] for f in d["touched"]]
    return era_pct


# ---- chart 3: CWE x vector heatmap -----------------------------------------
SHOW_VECS = ["cognitive_load", "safety_score", "state_flux", "api_exposure",
             "verification", "tech_debt", "documentation", "concurrency"]
assert set(SHOW_VECS) <= set(RISK_VECTOR), "heatmap vectors must be real risk vectors"

FAMILY_DISPLAY = {"memory": "memory", "other": "other", "cert/auth": "cert-auth",
                   "info-leak": "info-leak"}
FAMILY_ORDER = ["memory", "other", "cert-auth", "info-leak", "control-baseline"]


def data_cwe_heatmap(events, cache) -> tuple[dict[str, dict[str, list[float]]], dict[str, int]]:
    """family -> vector -> [pre-event per-vector percentiles]; uses
    delta_report.CWE_FAMILY verbatim for family assignment (security-fix +
    introduced events), and the control class as the baseline row."""
    fam_vecs = defaultdict(lambda: defaultdict(list))
    n_events = defaultdict(int)
    for e in events:
        d = cache.get(e["sha"])
        if not d or not d["touched"]:
            continue
        if e["class"] in ("security-fix", "introduced"):
            raw_fam = CWE_FAMILY.get(e.get("cwe"), "other") if e.get("cwe") else "unlabeled"
            fam = FAMILY_DISPLAY.get(raw_fam)
            if fam is None:
                continue  # unlabeled — excluded from the 5-row chart, as in the doc table
        elif e["class"] == "control":
            fam = "control-baseline"
        else:
            continue
        n_events[fam] += 1
        for c in SHOW_VECS:
            for f in d["touched"]:
                fam_vecs[fam][c].append(f["pre_vector_percentiles"][c])
    return fam_vecs, n_events


# ---- chart 4: signature prevalence -----------------------------------------
PREV_KEYS = ["loose", "strict", "fixshaped"]
PREV_LABEL = {
    "loose": "loose (branch+ or ptr+)",
    "strict": "strict (branch+ and ptr+)",
    "fixshaped": "fix-shaped (branch/ptr+, no new alloc/cast)",
}


def data_signature_prevalence(con, repo, events) -> dict[str, dict[str, float]]:
    """Share of events per class whose touched files NET-add the loose/strict/
    fix-shaped construct. Same definition as signal_anatomy.py's section 1b,
    recomputed here with its own primitives (signal_columns/file_rows/
    diff_statuses) rather than re-parsing its markdown output."""
    fcols = signal_columns(con, "file_data")
    want = ("struct_branch", "state_pointers", "state_cast_hits", "state_memory_alloc")
    idx = {c: fcols.index(c) for c in want}
    counts = defaultdict(lambda: defaultdict(int))
    n_events = defaultdict(int)
    for e in events:
        cls = e["class"]
        if cls not in CLASS_COLOR:
            continue
        child = e["sha"]
        before_sha, after_sha = None, None
        # reuse delta_report's own parent resolution isn't available here without
        # its event_deltas record; resolve directly (matches signal_anatomy.py).
        import subprocess
        try:
            after_sha = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", child],
                capture_output=True, text=True, check=True).stdout.strip()
            before_sha = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", f"{after_sha}^"],
                capture_output=True, text=True, check=True).stdout.strip()
        except subprocess.CalledProcessError:
            continue
        before = file_rows(con, before_sha, fcols)
        after = file_rows(con, after_sha, fcols)
        if not before or not after:
            continue
        statuses = diff_statuses(repo, before_sha, after_sha)
        touched = [(p, st) for p, st in statuses.items()
                   if st["status"] == "touched" and p in after and st["old_path"] in before]
        if not touched:
            continue
        n_events[cls] += 1
        delta = defaultdict(float)
        for path, st in touched:
            b, a = before[st["old_path"]], after[path]
            for c in want:
                bv = b[2 + idx[c]] or 0
                av = a[2 + idx[c]] or 0
                delta[c] += (av - bv)
        b_up = delta["struct_branch"] > 0
        p_up = delta["state_pointers"] > 0
        ac_up = delta["state_cast_hits"] > 0 or delta["state_memory_alloc"] > 0
        loose = b_up or p_up
        strict = b_up and p_up
        fixshaped = loose and not ac_up
        if loose:
            counts[cls]["loose"] += 1
        if strict:
            counts[cls]["strict"] += 1
        if fixshaped:
            counts[cls]["fixshaped"] += 1
    rates = {
        cls: {k: (100.0 * counts[cls][k] / n_events[cls]) if n_events[cls] else 0.0
              for k in PREV_KEYS}
        for cls in n_events
    }
    return rates, dict(n_events)


# =============================================================== chart 1 — box
def chart_boxplot(by_class: dict[str, list[float]]) -> str:
    classes = [c for c in ("security-fix", "control", "introduced") if by_class.get(c)]
    W, H = 720, 440
    ML, MR, MT, MB = 64, 40, 82, 60
    plot_w, plot_h = W - ML - MR, H - MT - MB

    stats = {}
    fences = []
    outliers = {}
    for c in classes:
        xs = by_class[c]
        q1, med, q3 = q(xs, .25), median(xs), q(xs, .75)
        iqr = q3 - q1
        lo_fence, hi_fence = q1 - 1.5 * iqr, q3 + 1.5 * iqr
        inliers = [v for v in xs if lo_fence <= v <= hi_fence]
        w_lo = min(inliers) if inliers else q1
        w_hi = max(inliers) if inliers else q3
        stats[c] = (q1, med, q3, w_lo, w_hi)
        fences.append((w_lo, w_hi))
        outliers[c] = sorted(v for v in xs if v < lo_fence or v > hi_fence)

    # Domain: a touch beyond the whisker fences, padded — NOT stretched to the
    # extreme outliers (an event mean of -87.5 would crush the rest of the
    # distribution to a hairline). Outliers are clamped to the domain edge and
    # labeled with their real value instead — the honest way to show "clusters
    # near 0, with rare violent exceptions."
    lo = min(f[0] for f in fences)
    hi = max(f[1] for f in fences)
    span = max(hi - lo, 0.2)
    lo -= span * 0.35
    hi += span * 0.35

    def y_of(v):
        v = max(lo, min(hi, v))
        return MT + plot_h - (v - lo) / (hi - lo) * plot_h

    body = []
    # y gridlines at 0 and nice steps
    import math
    step = 10 ** math.floor(math.log10(max(span / 4, 1e-6)))
    for mult in (1, 2, 5):
        if span / (step * mult) <= 6:
            step *= mult
            break
    gy = math.floor(lo / step) * step
    while gy <= hi:
        yy = y_of(gy)
        body.append(line(ML, yy, ML + plot_w, yy, stroke=GRID, width=1))
        body.append(text(ML - 10, yy + 4, f"{gy:+.2f}".rstrip("0").rstrip("."),
                          size=11, fill=MUTED, anchor="end", tabular=True))
        gy += step
    # zero baseline, heavier
    y0 = y_of(0)
    body.append(line(ML, y0, ML + plot_w, y0, stroke=BASELINE, width=1.5))
    body.append(text(ML + plot_w, y0 - 6, "0 baseline", size=10.5, fill=MUTED, anchor="end"))

    box_w = 64
    n = len(classes)
    slot_w = plot_w / n
    for i, c in enumerate(classes):
        cx = ML + slot_w * (i + 0.5)
        color = CLASS_COLOR[c]
        q1, med, q3, w_lo, w_hi = stats[c]
        y_q1, y_med, y_q3 = y_of(q1), y_of(med), y_of(q3)
        y_wlo, y_whi = y_of(w_lo), y_of(w_hi)
        # whiskers
        body.append(line(cx, y_whi, cx, y_q3, stroke=color, width=2))
        body.append(line(cx, y_q1, cx, y_wlo, stroke=color, width=2))
        body.append(line(cx - 12, y_whi, cx + 12, y_whi, stroke=color, width=2))
        body.append(line(cx - 12, y_wlo, cx + 12, y_wlo, stroke=color, width=2))
        # box
        body.append(rect(cx - box_w / 2, min(y_q1, y_q3), box_w, abs(y_q1 - y_q3),
                          fill=color, opacity=0.16, stroke=color, stroke_width=2, rx=3))
        # median line
        body.append(line(cx - box_w / 2, y_med, cx + box_w / 2, y_med, stroke=color, width=3))
        # median direct label
        body.append(text(cx + box_w / 2 + 8, y_med + 4, f"median {med:+.3f}",
                          size=11, fill=INK_SECONDARY, tabular=True))
        # outliers clamp to the domain edge; label them INSIDE the plot (high
        # outliers label below their top-edge dot, low outliers above their
        # bottom-edge dot) so nothing collides with the title/subtitle or axis.
        pts = outliers[c]
        hi_out = [v for v in pts if v > q3]
        lo_out = [v for v in pts if v < q1]
        if hi_out:
            v = max(hi_out); yy = y_of(v)
            body.append(circle(cx, yy, 3.5, fill=color))
            body.append(text(cx, yy + 15, f"{v:+.1f}", size=10.5, fill=INK,
                              anchor="middle", tabular=True))
            if len(hi_out) > 1:
                body.append(text(cx, yy + 28, f"+{len(hi_out) - 1} more ↑", size=9,
                                  fill=MUTED, anchor="middle"))
        if lo_out:
            v = min(lo_out); yy = y_of(v)
            body.append(circle(cx, yy, 3.5, fill=color))
            body.append(text(cx, yy - 9, f"{v:+.1f}", size=10.5, fill=INK,
                              anchor="middle", tabular=True))
            if len(lo_out) > 1:
                body.append(text(cx, yy - 22, f"+{len(lo_out) - 1} more ↓", size=9,
                                  fill=MUTED, anchor="middle"))
        # x-axis category label (no dot — the box fill already carries identity)
        body.append(text(cx, MT + plot_h + 28, CLASS_LABEL[c], size=13, fill=INK,
                          anchor="middle", weight="600"))

    body.append(text(ML, 28, "Per-event structural delta by class (mean Δ over "
                      "touched files)", size=15, fill=INK, weight="600"))
    body.append(text(ML, 44, "Box = IQR, whisker = 1.5×IQR (Tukey fence), clipped to "
                      "keep the near-zero cluster readable; outliers labeled at true value.",
                      size=11, fill=MUTED))
    return svg_doc(W, H,
                    "Structural delta by event class",
                    "Box-and-whisker of per-event mean structural delta for security-fix, "
                    "control, and introduced commits; distributions cluster near zero.",
                    "\n".join(body))


# =============================================================== chart 2 — line
def chart_era_line(era_pct: dict[str, list[float]]) -> str:
    eras = sorted(era_pct, key=lambda s: int(s.split("–")[0]))
    vals = [median(era_pct[e]) for e in eras]
    W, H = 720, 380
    ML, MR, MT, MB = 56, 32, 56, 56
    plot_w, plot_h = W - ML - MR, H - MT - MB

    def y_of(v):
        return MT + plot_h - (v / 100.0) * plot_h

    n = len(eras)
    def x_of(i):
        return ML + (plot_w * (i / max(n - 1, 1)))

    body = []
    for gv in (0, 25, 50, 75, 100):
        yy = y_of(gv)
        body.append(line(ML, yy, ML + plot_w, yy, stroke=GRID, width=1))
        body.append(text(ML - 10, yy + 4, str(gv), size=11, fill=MUTED, anchor="end",
                          tabular=True))
    body.append(line(ML, MT + plot_h, ML + plot_w, MT + plot_h, stroke=BASELINE, width=1.5))

    pts = [(x_of(i), y_of(v)) for i, v in enumerate(vals)]
    # 10%-opacity area wash under the line
    area = f"M {pts[0][0]:.1f} {MT + plot_h:.1f} " + " ".join(
        f"L {x:.1f} {y:.1f}" for x, y in pts) + f" L {pts[-1][0]:.1f} {MT + plot_h:.1f} Z"
    body.append(f'<path d="{area}" fill="{SLOT_BLUE}" fill-opacity="0.10"/>')
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    body.append(f'<polyline points="{poly}" fill="none" stroke="{SLOT_BLUE}" '
                f'stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>')
    for i, (x, y) in enumerate(pts):
        body.append(circle(x, y, 4, fill=SLOT_BLUE))
        body.append(text(x, MT + plot_h + 24, eras[i], size=11.5, fill=INK, anchor="middle"))
    # direct labels: first and last point (the trajectory's story)
    body.append(text(pts[0][0], pts[0][1] - 14, f"{vals[0]:.0f}", size=12, fill=INK,
                      anchor="middle", weight="600", tabular=True))
    body.append(text(pts[-1][0], pts[-1][1] - 14, f"{vals[-1]:.0f}", size=12, fill=INK,
                      anchor="middle", weight="600", tabular=True))

    body.append(text(ML, 28, "Implicated-file exposure percentile by era", size=15,
                      fill=INK, weight="600"))
    body.append(text(ML, 44, "Median pre-event structural-exposure percentile of "
                      "security-fix + introduced touched files, per 5-year era.",
                      size=11, fill=MUTED))
    return svg_doc(W, H,
                    "Era trajectory — implicated-file exposure percentile",
                    "Single line, one series (blue): median pre-event exposure percentile "
                    "of CVE-implicated files across six five-year eras, 2000-2029.",
                    "\n".join(body))


# =============================================================== chart 3 — heatmap
VEC_SHORT = {
    "cognitive_load": "cognitive_load", "safety_score": "safety_score",
    "state_flux": "state_flux", "api_exposure": "api_exposure",
    "verification": "verification", "tech_debt": "tech_debt",
    "documentation": "documentation", "concurrency": "concurrency",
}


def chart_heatmap(fam_vecs, n_events) -> str:
    fams = [f for f in FAMILY_ORDER if fam_vecs.get(f)]
    W = 760
    ML, MR, MT, MB = 150, 28, 110, 70
    cell_w = 68
    cell_h = 46
    plot_w = cell_w * len(SHOW_VECS)
    plot_h = cell_h * len(fams)
    H = MT + plot_h + MB

    body = []
    body.append(text(ML, 28, "CWE family × exposure vector", size=15, fill=INK,
                      weight="600"))
    body.append(text(ML, 44, "Median pre-event percentile per vector, implicated files "
                      "ranked within their parent snapshot.", size=11, fill=MUTED))

    # column headers, rotated
    for j, vec in enumerate(SHOW_VECS):
        cx = ML + cell_w * (j + 0.5)
        body.append(text(cx, MT - 10, VEC_SHORT[vec], size=10.5, fill=INK_SECONDARY,
                          anchor="start", transform=f"rotate(-38 {cx:.1f} {MT - 10:.1f})"))
    # rows + cells
    for i, fam in enumerate(fams):
        ry = MT + cell_h * i
        body.append(text(ML - 12, ry + cell_h / 2 + 4, f"{fam} ({n_events.get(fam, 0)})",
                          size=12.5, fill=INK, anchor="end"))
        for j, vec in enumerate(SHOW_VECS):
            cx0 = ML + cell_w * j
            vals = fam_vecs[fam].get(vec, [])
            v = median(vals) if vals else float("nan")
            fill = seq_color(v) if v == v else GRID
            # 2px surface gap between cells
            body.append(rect(cx0 + 1, ry + 1, cell_w - 2, cell_h - 2, fill=fill, rx=2))
            label = f"{v:.0f}" if v == v else "–"
            body.append(text(cx0 + cell_w / 2, ry + cell_h / 2 + 4, label, size=12,
                              fill=cell_text_color(v if v == v else 0), anchor="middle",
                              tabular=True))

    # sequential legend
    leg_y = MT + plot_h + 34
    leg_x0, leg_w = ML, 200
    steps = 40
    for k in range(steps):
        v0 = 100 * k / steps
        v1 = 100 * (k + 1) / steps
        x0 = leg_x0 + leg_w * k / steps
        x1 = leg_x0 + leg_w * (k + 1) / steps
        body.append(rect(x0, leg_y, x1 - x0 + 0.5, 10, fill=seq_color((v0 + v1) / 2)))
    body.append(text(leg_x0, leg_y + 24, "0", size=10.5, fill=MUTED, tabular=True))
    body.append(text(leg_x0 + leg_w, leg_y + 24, "100", size=10.5, fill=MUTED,
                      anchor="end", tabular=True))
    body.append(text(leg_x0 + leg_w / 2, leg_y + 24, "median pre-event percentile",
                      size=10.5, fill=MUTED, anchor="middle"))

    return svg_doc(W, H,
                    "CWE family by exposure vector heatmap",
                    "Sequential blue heatmap: median pre-event percentile of implicated "
                    "files, memory/other/cert-auth/info-leak CWE families vs the control "
                    "baseline, across eight exposure vectors.",
                    "\n".join(body))


# =============================================================== chart 4 — grouped bars
def chart_prevalence_bars(rates: dict[str, dict[str, float]], n_events: dict[str, int]) -> str:
    classes = [c for c in ("security-fix", "control", "introduced") if c in rates]
    W, H = 720, 420
    ML, MR, MT, MB = 56, 24, 70, 70
    plot_w, plot_h = W - ML - MR, H - MT - MB

    def y_of(v):
        return MT + plot_h - (v / 100.0) * plot_h

    body = []
    body.append(text(ML, 28, "Signature prevalence by class", size=15, fill=INK,
                      weight="600"))
    body.append(text(ML, 44, "Share of events whose touched files NET-add each construct "
                      "(same definition as signal_anatomy.py §1b).", size=11, fill=MUTED))

    for gv in (0, 25, 50, 75, 100):
        yy = y_of(gv)
        body.append(line(ML, yy, ML + plot_w, yy, stroke=GRID, width=1))
        body.append(text(ML - 10, yy + 4, f"{gv}%", size=11, fill=MUTED, anchor="end",
                          tabular=True))
    body.append(line(ML, MT + plot_h, ML + plot_w, MT + plot_h, stroke=BASELINE, width=1.5))

    n_groups = len(PREV_KEYS)
    group_w = plot_w / n_groups
    bar_w = 22
    gap = 2  # 2px surface gap between adjacent bars

    for gi, key in enumerate(PREV_KEYS):
        gx0 = ML + group_w * gi
        n_bars = len(classes)
        total_w = n_bars * bar_w + (n_bars - 1) * gap
        start_x = gx0 + (group_w - total_w) / 2
        for bi, c in enumerate(classes):
            v = rates[c][key]
            x = start_x + bi * (bar_w + gap)
            y = y_of(v)
            h = MT + plot_h - y
            color = CLASS_COLOR[c]
            body.append(rect(x, y, bar_w, h, fill=color, rx=4))
            body.append(text(x + bar_w / 2, y - 6, f"{v:.0f}%", size=10.5, fill=INK,
                              anchor="middle", tabular=True))
        body.append(text(gx0 + group_w / 2, MT + plot_h + 22, PREV_LABEL[key], size=10.5,
                          fill=INK_SECONDARY, anchor="middle"))

    # inline color key (not a boxed legend — 3 series, direct-labeled per bar already)
    key_y = MT + plot_h + 48
    kx = ML
    for c in classes:
        body.append(circle(kx, key_y, 4, fill=CLASS_COLOR[c]))
        label = f"{CLASS_LABEL[c]} (n={n_events.get(c, 0)})"
        body.append(text(kx + 10, key_y + 4, label, size=11, fill=INK_SECONDARY))
        kx += 16 + 7.2 * len(label)

    return svg_doc(W, H,
                    "Signature prevalence by class",
                    "Grouped bars: share of security-fix, control, and introduced events "
                    "that net-add the loose, strict, and fix-shaped pointer/branch "
                    "signature.",
                    "\n".join(body))


# =============================================================== main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default="curl")
    ap.add_argument("--events", default=None, help="defaults to events/<repo>.json")
    ap.add_argument("--out-dir", default=str(CHARTS_DIR))
    args = ap.parse_args()

    from _engine import EVENTS_DIR
    events_path = pathlib.Path(args.events) if args.events else EVENTS_DIR / f"{args.repo}.json"
    data = load_events(events_path)
    repo = resolve_repo(data["repo"])
    con, db = open_db(repo)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    events = data["events"]
    print(f"db: {db}")
    print(f"events: {len(events)} ({events_path})")

    print("computing event deltas (delta_report.event_deltas, one pass per event)...")
    cache = gather_deltas(con, repo, events)
    n_ok = sum(1 for v in cache.values() if v and v["touched"])
    print(f"  {n_ok}/{len(events)} events fully scanned with touched files")

    # ---- chart 1 ----
    by_class = data_class_deltas(events, cache)
    svg1 = chart_boxplot(by_class)
    p1 = out_dir / "delta_distributions_by_class.svg"
    p1.write_text(svg1)
    print(f"wrote {p1}  n=" + ", ".join(f"{c}:{len(v)}" for c, v in by_class.items()))

    # ---- chart 2 ----
    era_pct = data_era_trajectory(events, cache)
    svg2 = chart_era_line(era_pct)
    p2 = out_dir / "era_trajectory.svg"
    p2.write_text(svg2)
    print(f"wrote {p2}  eras=" + ", ".join(
        f"{e}:{median(v):.1f}(n{len(v)})" for e, v in sorted(era_pct.items())))

    # ---- chart 3 ----
    fam_vecs, n_fam = data_cwe_heatmap(events, cache)
    svg3 = chart_heatmap(fam_vecs, n_fam)
    p3 = out_dir / "cwe_vector_heatmap.svg"
    p3.write_text(svg3)
    print(f"wrote {p3}  families=" + ", ".join(f"{f}:{n}" for f, n in n_fam.items()))

    # ---- chart 4 ----
    rates, n_prev = data_signature_prevalence(con, repo, events)
    svg4 = chart_prevalence_bars(rates, n_prev)
    p4 = out_dir / "signature_prevalence.svg"
    p4.write_text(svg4)
    print(f"wrote {p4}  n=" + ", ".join(f"{c}:{n}" for c, n in n_prev.items()))
    for c in rates:
        print(f"    {c}: " + ", ".join(f"{k}={rates[c][k]:.0f}%" for k in PREV_KEYS))

    return 0


if __name__ == "__main__":
    sys.exit(main())
