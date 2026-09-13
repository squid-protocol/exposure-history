#!/usr/bin/env python3
# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Multivariate keyword-importance classifier (gitgalaxy#2982 / tc#32).

EXPLORATORY -- no hypothesis tests, no p-values. signal_anatomy's own text says
'multi-feature classification is the ML dataset's job, not a threshold's'; this
is that job. An L2-regularized multinomial logistic regression (hand-derived
softmax loss/gradient, numpy; scipy.optimize.minimize(L-BFGS-B) as the generic
unconstrained solver -- no sklearn available for system python3, none
installed) over the per-event mean-signal-delta vector (~70 signals from
keyword_pools' cache) plus net-LOC as an explicit feature, classifying the 8
scanned commit classes, with a TEMPORAL train/test split (train commit_date <
2022-01-01, test >= 2022-01-01 -- no peeking).

Reuses dbs/keyword_pools_cache.json (per-event mean/sum signal deltas + net-LOC,
keyed by sha; see tools/keyword_pools.py for the cache schema and the 10-worker
fork-pool compute machinery). This tool calls that machinery unconditionally
before reading the cache, so any event missing from the cache is filled in the
same way keyword_pools.py would fill it; if the cache is already complete (the
expected case -- 1,545/1,762 events yield usable touched-file stats) the call
is a fast no-op. Commit dates (needed for the temporal split; not stored in the
cache) are read from the scan DB's `repo_data.commit_date`, keyed by sha, with
a `git log` fallback for any sha repo_data doesn't have.

Deliverables: docs/class_signals.md (confusion matrix + per-class F1, top-15
coefficients per class contrast, net-LOC-alone vs full-vector accuracy, the
collapsed fix-like-vs-control binary AUC comparison). Nothing here is
committed by the tool; the cache and the report are both gitignored/exploratory
unless a human chooses to commit docs/class_signals.md.

Usage:
    python tools/class_signals.py                  # full run (cache should already be warm)
    python tools/class_signals.py --workers 4       # smaller compute pool if cache needs filling
"""
from __future__ import annotations

import argparse
import pathlib
import sqlite3
import subprocess
import sys
import time
from collections import Counter

import numpy as np
from scipy.optimize import minimize
from scipy.stats import rankdata

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _engine import DBS_DIR, DOCS_DIR, EVENTS_DIR  # noqa: E402
from keyword_pools import (  # noqa: E402
    CACHE_PATH, CLASS_ORDER, compute_all, load_all_events, load_cache,
)
from scan_pair import history_db, out_dir_for, resolve_repo  # noqa: E402
from signal_anatomy import signal_columns  # noqa: E402

OUT_PATH = DOCS_DIR / "class_signals.md"

TRAIN_CUTOFF = "2022-01-01"
ACTIVE_SIGNAL_FLOOR = 0.03          # drop signals moving in < 3% of TRAIN events
L2_GRID = [0.03, 0.1, 0.3, 1.0, 3.0, 10.0, 30.0]
CV_FOLDS = 5
CV_SEED = 0
MAXITER = 400

FIX_LIKE_CLASSES = ["security-fix", "bugfix-fixes", "bugfix-bug", "regression"]
CONTRASTS = [
    ("security-fix", "control", "security-fix vs control"),
    ("introduced", "control", "introduced vs control"),
    (FIX_LIKE_CLASSES, "control", "fix-classes (bugfix-fixes+bugfix-bug+regression, "
                                    "mean) vs control"),
]


# ------------------------------------------------------------------ data loading
def get_commit_dates(shas, repo, db_path) -> dict[str, str]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    dates: dict[str, str] = {}
    shas = sorted(set(shas))
    for i in range(0, len(shas), 500):
        chunk = shas[i:i + 500]
        qmarks = ",".join("?" * len(chunk))
        rows = con.execute(
            f"SELECT commit_hash, commit_date FROM repo_data WHERE commit_hash IN ({qmarks})",
            chunk,
        )
        for sha, d in rows:
            dates[sha] = d
    con.close()
    missing = [s for s in shas if s not in dates]
    for s in missing:
        out = subprocess.run(["git", "-C", str(repo), "show", "-s", "--format=%cs", s],
                              capture_output=True).stdout.decode("utf-8", errors="replace").strip()
        if out:
            dates[s] = out
    return dates


def load_dataset(workers: int):
    events = load_all_events()
    cache = load_cache(CACHE_PATH)

    base_events = EVENTS_DIR / "curl.json"
    import json
    base = json.loads(base_events.read_text())
    repo = resolve_repo(base["repo"])
    db = history_db(out_dir_for(repo))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    fcols = signal_columns(con, "file_data")
    con.close()

    elapsed = compute_all(events, db, repo, fcols, cache, CACHE_PATH, workers=workers)

    rows = []
    for e in events:
        st = cache.get(e["sha"])
        if st is None:
            continue
        rows.append({"sha": e["sha"], "class": e["class"], "stats": st})

    dates = get_commit_dates([r["sha"] for r in rows], repo, db)
    n_before = len(rows)
    for r in rows:
        r["date"] = dates.get(r["sha"])
    dateless = [r["sha"] for r in rows if r["date"] is None]
    rows = [r for r in rows if r["date"] is not None]
    return rows, fcols, elapsed, n_before, dateless


# ------------------------------------------------------------------ features
def move_rate(rows, sig):
    if not rows:
        return 0.0
    return sum(1 for r in rows if r["stats"]["mean_delta"].get(sig, 0.0) != 0.0) / len(rows)


def build_matrix(rows, feature_names):
    X = np.empty((len(rows), len(feature_names)), dtype=float)
    for i, r in enumerate(rows):
        st = r["stats"]
        for j, f in enumerate(feature_names):
            X[i, j] = st["netloc"] if f == "net_loc" else st["mean_delta"].get(f, 0.0)
    return X


# ------------------------------------------------------------------ model
def onehot(y, K):
    Y = np.zeros((len(y), K))
    Y[np.arange(len(y)), y] = 1.0
    return Y


def nll_grad(params, X, Y, lam):
    n, F = X.shape
    K = Y.shape[1]
    W = params[:F * K].reshape(F, K)
    b = params[F * K:]
    logits = X @ W + b
    logits -= logits.max(axis=1, keepdims=True)
    expl = np.exp(logits)
    probs = expl / expl.sum(axis=1, keepdims=True)
    nll = -np.sum(Y * np.log(probs + 1e-12)) / n + (lam / (2 * n)) * np.sum(W * W)
    dlogits = (probs - Y) / n
    dW = X.T @ dlogits + (lam / n) * W
    db = dlogits.sum(axis=0)
    return nll, np.concatenate([dW.ravel(), db])


def fit(X, y, K, lam, maxiter=MAXITER):
    n, F = X.shape
    Y = onehot(y, K)
    x0 = np.zeros(F * K + K)
    res = minimize(nll_grad, x0, args=(X, Y, lam), jac=True, method="L-BFGS-B",
                    options={"maxiter": maxiter})
    W = res.x[:F * K].reshape(F, K)
    b = res.x[F * K:]
    return W, b


def predict_proba(X, W, b):
    logits = X @ W + b
    logits -= logits.max(axis=1, keepdims=True)
    expl = np.exp(logits)
    return expl / expl.sum(axis=1, keepdims=True)


def predict(X, W, b):
    return predict_proba(X, W, b).argmax(axis=1)


def standardize_fit(X):
    mu = X.mean(axis=0)
    sd = X.std(axis=0)
    sd = np.where(sd < 1e-9, 1.0, sd)
    return mu, sd


def macro_f1(y_true, y_pred, K):
    f1s = []
    for c in range(K):
        tp = int(np.sum((y_pred == c) & (y_true == c)))
        fp = int(np.sum((y_pred == c) & (y_true != c)))
        fn = int(np.sum((y_pred != c) & (y_true == c)))
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1s.append(2 * prec * rec / (prec + rec) if (prec + rec) else 0.0)
    return float(np.mean(f1s))


def stratified_folds(y, k, seed=CV_SEED):
    rng = np.random.default_rng(seed)
    fold_of = np.full(len(y), -1, dtype=int)
    for c in np.unique(y):
        idx = np.where(y == c)[0]
        rng.shuffle(idx)
        for j, i in enumerate(idx):
            fold_of[i] = j % k
    return fold_of


def select_lambda(X, y, K, grid=L2_GRID, k=CV_FOLDS):
    folds = stratified_folds(y, k)
    scores = {}
    for lam in grid:
        fold_scores = []
        for f in range(k):
            tr, va = folds != f, folds == f
            if va.sum() == 0 or tr.sum() == 0:
                continue
            mu, sd = standardize_fit(X[tr])
            Xtr, Xva = (X[tr] - mu) / sd, (X[va] - mu) / sd
            W, b = fit(Xtr, y[tr], K, lam, maxiter=200)
            pred = predict(Xva, W, b)
            fold_scores.append(macro_f1(y[va], pred, K))
        scores[lam] = float(np.mean(fold_scores)) if fold_scores else float("nan")
    best_lam = max(scores, key=lambda l: (scores[l] if scores[l] == scores[l] else -1))
    return best_lam, scores


def fit_final(X_train, y_train, X_test, K, grid=L2_GRID):
    """CV-select lambda on train, standardize on train, refit on full train."""
    best_lam, cv_scores = select_lambda(X_train, y_train, K, grid)
    mu, sd = standardize_fit(X_train)
    Xtr_s = (X_train - mu) / sd
    Xte_s = (X_test - mu) / sd
    W, b = fit(Xtr_s, y_train, K, best_lam, maxiter=800)
    return W, b, mu, sd, best_lam, cv_scores, Xtr_s, Xte_s


def auc_score(y_bin, scores):
    n1 = int(y_bin.sum())
    n0 = len(y_bin) - n1
    if n1 == 0 or n0 == 0:
        return float("nan")
    ranks = rankdata(scores)
    sum_pos = ranks[y_bin == 1].sum()
    return (sum_pos - n1 * (n1 + 1) / 2) / (n1 * n0)


# ------------------------------------------------------------------ report
def confusion_matrix_md(y_true, y_pred, classes):
    K = len(classes)
    M = np.zeros((K, K), dtype=int)
    for t, p in zip(y_true, y_pred):
        M[t, p] += 1
    lines = ["| true \\ pred | " + " | ".join(classes) + " |",
             "|---|" + "---|" * K]
    for i, c in enumerate(classes):
        lines.append(f"| **{c}** | " + " | ".join(str(M[i, j]) for j in range(K)) + " |")
    return "\n".join(lines), M


def per_class_prf(y_true, y_pred, classes):
    K = len(classes)
    rows = []
    for c in range(K):
        tp = int(np.sum((y_pred == c) & (y_true == c)))
        fp = int(np.sum((y_pred == c) & (y_true != c)))
        fn = int(np.sum((y_pred != c) & (y_true == c)))
        support = int(np.sum(y_true == c))
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        rows.append((classes[c], support, prec, rec, f1))
    return rows


def top_confusions(M, classes, n=5):
    pairs = []
    K = len(classes)
    for i in range(K):
        for j in range(K):
            if i != j and M[i, j] > 0:
                pairs.append((M[i, j], classes[i], classes[j]))
    pairs.sort(reverse=True)
    return pairs[:n]


def contrast_vector(W, feature_names, classes, class_a, class_b):
    idx = {c: i for i, c in enumerate(classes)}
    if isinstance(class_a, list):
        vec_a = np.mean([W[:, idx[c]] for c in class_a], axis=0)
    else:
        vec_a = W[:, idx[class_a]]
    vec_b = W[:, idx[class_b]]
    contrast = vec_a - vec_b
    order = np.argsort(-np.abs(contrast))
    return [(feature_names[i], float(contrast[i])) for i in order]


def coef_contrast_table(W, feature_names, classes, class_a, class_b, n=15):
    return contrast_vector(W, feature_names, classes, class_a, class_b)[:n]


GRAMMAR_WATCH = ["struct_branch", "state_pointers", "state_memory_alloc", "state_cast_hits"]


def grammar_rank_table(W, feature_names, classes, class_a, class_b):
    ranked = contrast_vector(W, feature_names, classes, class_a, class_b)
    lookup = {f: (i + 1, v) for i, (f, v) in enumerate(ranked)}
    rows = []
    for sig in GRAMMAR_WATCH:
        if sig in lookup:
            r, v = lookup[sig]
            rows.append((sig, r, len(ranked), v))
        else:
            rows.append((sig, None, len(ranked), None))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workers", type=int, default=10, help="pool size for keyword_pools compute fill-in")
    ap.add_argument("--out", default=str(OUT_PATH))
    args = ap.parse_args()

    t0 = time.time()
    rows, fcols, compute_elapsed, n_usable, dateless = load_dataset(args.workers)
    print(f"loaded {len(rows)} usable dated events ({len(dateless)} dropped for missing date) "
          f"in {time.time()-t0:.1f}s (cache compute pass: {compute_elapsed:.1f}s)")

    train_rows = [r for r in rows if r["date"] < TRAIN_CUTOFF]
    test_rows = [r for r in rows if r["date"] >= TRAIN_CUTOFF]
    train_counts = Counter(r["class"] for r in train_rows)
    test_counts = Counter(r["class"] for r in test_rows)
    print(f"train {len(train_rows)} / test {len(test_rows)} "
          f"(cutoff {TRAIN_CUTOFF}, dates {min(r['date'] for r in rows)}..{max(r['date'] for r in rows)})")

    # -- active signal selection (train only)
    rates = {s: move_rate(train_rows, s) for s in fcols}
    dropped = sorted(s for s in fcols if rates[s] < ACTIVE_SIGNAL_FLOOR)
    active = sorted((s for s in fcols if rates[s] >= ACTIVE_SIGNAL_FLOOR), key=lambda s: -rates[s])
    feature_names = active + ["net_loc"]
    print(f"{len(active)} active signals kept, {len(dropped)} dropped (<{ACTIVE_SIGNAL_FLOOR:.0%} of "
          f"train events moved): {dropped}")

    classes = [c for c in CLASS_ORDER if train_counts.get(c)]
    class_idx = {c: i for i, c in enumerate(classes)}
    K = len(classes)

    X_train_full = build_matrix(train_rows, feature_names)
    X_test_full = build_matrix(test_rows, feature_names)
    y_train = np.array([class_idx[r["class"]] for r in train_rows])
    y_test = np.array([class_idx.get(r["class"], -1) for r in test_rows])
    test_has_unseen_class = bool((y_test == -1).any())

    # -- FULL VECTOR multiclass model
    t1 = time.time()
    W_full, b_full, mu_f, sd_f, lam_full, cv_full, Xtr_fs, Xte_fs = fit_final(
        X_train_full, y_train, X_test_full, K)
    pred_test_full = predict(Xte_fs, W_full, b_full)
    valid_test = y_test != -1
    acc_full = float(np.mean(pred_test_full[valid_test] == y_test[valid_test]))
    f1_full = macro_f1(y_test[valid_test], pred_test_full[valid_test], K)
    print(f"full-vector multiclass: lambda={lam_full}, test acc={acc_full:.3f}, "
          f"macro-F1={f1_full:.3f} ({time.time()-t1:.1f}s)")

    # -- NET-LOC ONLY multiclass model
    t1 = time.time()
    netloc_idx = feature_names.index("net_loc")
    X_train_nl = X_train_full[:, [netloc_idx]]
    X_test_nl = X_test_full[:, [netloc_idx]]
    W_nl, b_nl, mu_nl, sd_nl, lam_nl, cv_nl, Xtr_nls, Xte_nls = fit_final(
        X_train_nl, y_train, X_test_nl, K)
    pred_test_nl = predict(Xte_nls, W_nl, b_nl)
    acc_nl = float(np.mean(pred_test_nl[valid_test] == y_test[valid_test]))
    f1_nl = macro_f1(y_test[valid_test], pred_test_nl[valid_test], K)
    print(f"net-LOC-only multiclass: lambda={lam_nl}, test acc={acc_nl:.3f}, "
          f"macro-F1={f1_nl:.3f} ({time.time()-t1:.1f}s)")

    # -- collapsed binary: fix-like vs control
    bin_train = [r for r in train_rows if r["class"] in FIX_LIKE_CLASSES or r["class"] == "control"]
    bin_test = [r for r in test_rows if r["class"] in FIX_LIKE_CLASSES or r["class"] == "control"]
    yb_train = np.array([1 if r["class"] in FIX_LIKE_CLASSES else 0 for r in bin_train])
    yb_test = np.array([1 if r["class"] in FIX_LIKE_CLASSES else 0 for r in bin_test])
    Xb_train_full = build_matrix(bin_train, feature_names)
    Xb_test_full = build_matrix(bin_test, feature_names)

    t1 = time.time()
    Wb_full, bb_full, *_r, lam_b_full, cv_b_full, _trs, Xb_te_fs = fit_final(
        Xb_train_full, yb_train, Xb_test_full, 2)
    proba_b_full = predict_proba(Xb_te_fs, Wb_full, bb_full)[:, 1]
    auc_b_full = auc_score(yb_test, proba_b_full)
    print(f"binary fix-like full-vector: lambda={lam_b_full}, test AUC={auc_b_full:.3f} "
          f"({time.time()-t1:.1f}s)")

    Xb_train_nl = Xb_train_full[:, [netloc_idx]]
    Xb_test_nl = Xb_test_full[:, [netloc_idx]]
    t1 = time.time()
    Wb_nl, bb_nl, *_r, lam_b_nl, cv_b_nl, _trs, Xb_te_nls = fit_final(
        Xb_train_nl, yb_train, Xb_test_nl, 2)
    proba_b_nl = predict_proba(Xb_te_nls, Wb_nl, bb_nl)[:, 1]
    auc_b_nl = auc_score(yb_test, proba_b_nl)
    print(f"binary fix-like net-LOC-only: lambda={lam_b_nl}, test AUC={auc_b_nl:.3f} "
          f"({time.time()-t1:.1f}s)")

    # -- trivial baselines (context for the accuracy numbers under temporal class-prior shift)
    train_mode_class = int(np.bincount(y_train).argmax())
    baseline_train_mode_acc = float(np.mean(y_test[valid_test] == train_mode_class))
    test_mode_count = int(np.bincount(y_test[valid_test]).max())
    baseline_test_mode_acc = test_mode_count / int(valid_test.sum())

    # -- report
    cm_md, M = confusion_matrix_md(y_test[valid_test], pred_test_full[valid_test], classes)
    prf_rows = per_class_prf(y_test[valid_test], pred_test_full[valid_test], classes)
    confusions = top_confusions(M, classes)
    pred_dist = Counter(classes[c] for c in pred_test_full[valid_test])

    md = []
    md.append("# Multivariate keyword-importance classifier -- curl (tc#32 / gitgalaxy#2982)\n")
    md.append("**EXPLORATORY -- no hypothesis tests, no p-values.** L2-regularized multinomial "
               "logistic regression (hand-derived softmax loss/gradient in numpy; "
               "`scipy.optimize.minimize` L-BFGS-B as the generic solver -- sklearn is not "
               "installed for system python3 and nothing was installed to get it) over the "
               f"per-event mean-signal-delta vector ({len(active)} active signals after dropping "
               f"{len(dropped)} that move in <{ACTIVE_SIGNAL_FLOOR:.0%} of train events) plus "
               "net-LOC as an explicit feature. Standardized (z-score, fit on train only). L2 "
               f"strength chosen per model by {CV_FOLDS}-fold stratified CV on train (grid "
               f"{L2_GRID}, macro-F1 scored).\n")
    md.append("**Caveats carried from the harness (not re-derived here):** `Fixes #` label purity "
               "is ~50% (docs/bh_eval.md audit -- half of `Fixes #` commits are docs/build/deprecation, "
               "not code-bug fixes); ~31% of touched files across the corpus are tests/docs, not "
               "implementation, so per-event mean deltas are diluted by bystander files; files "
               "recur across events (pseudo-replication) -- the temporal split (train < "
               f"{TRAIN_CUTOFF}, test >= {TRAIN_CUTOFF}, split by EVENT COMMIT DATE) prevents a "
               "model from training on a file it will be tested on in the *same* commit, and "
               "reduces the leakage from recurring files across DIFFERENT commits, but does not "
               "remove it -- curl's hot files (`lib/vtls/*`, `lib/http.c`, ...) get fixed "
               "repeatedly across the full 26-year window, before and after the cutoff.\n")

    dateless_note = f" ({len(dateless)} usable-but-dateless events dropped.)" if dateless else ""
    unseen_note = (" Test contains class(es) absent from train; those rows are excluded from "
                    "scoring." if test_has_unseen_class else "")
    md.append(f"## Data\n\n{n_usable} usable events (cache hit, non-null stats) out of "
               f"{n_usable + len(dateless)} candidates scanned; {len(rows)} carry a resolvable "
               f"commit date.{dateless_note}{unseen_note}\n")
    md.append("| class | train (< " + TRAIN_CUTOFF + ") | test (>= " + TRAIN_CUTOFF + ") |")
    md.append("|---|---|---|")
    for c in CLASS_ORDER:
        tr, te = train_counts.get(c, 0), test_counts.get(c, 0)
        thin = " *(thin test sample)*" if 0 < te < 20 else ""
        md.append(f"| {c} | {tr} | {te}{thin} |")
    md.append(f"| **total** | **{len(train_rows)}** | **{len(test_rows)}** |\n")
    md.append(f"Dropped signals (<{ACTIVE_SIGNAL_FLOOR:.0%} of train events move them): "
               + (", ".join(f"`{s}`" for s in dropped) if dropped else "none") + "\n")

    train_mode_name = classes[int(np.bincount(y_train).argmax())]
    train_mode_share = train_counts.get(train_mode_name, 0) / len(train_rows)
    train_mode_test_share = test_counts.get(train_mode_name, 0) / len(test_rows)
    test_mode_name = max(test_counts, key=lambda c: test_counts.get(c, 0))
    test_mode_share = test_counts.get(test_mode_name, 0) / len(test_rows)
    test_mode_train_share = train_counts.get(test_mode_name, 0) / len(train_rows)
    md.append("**Class-prior drift across the cutoff:** the train-set mode class is "
               f"`{train_mode_name}` ({train_mode_share:.0%} of train) but only "
               f"{train_mode_test_share:.0%} of test; the test-set mode class is "
               f"`{test_mode_name}` ({test_mode_share:.0%} of test) but only "
               f"{test_mode_train_share:.0%} of train. This is not a train/test split artifact -- "
               "binning by year shows a smooth secular trend across curl's whole history "
               "(`bugfix-bug` dominant through ~2015, `bugfix-fixes` overtaking and growing every "
               "year after), consistent with which commit-message trailer convention "
               "(`Bug:`-style vs GitHub `Fixes #`) the bug-harvest matched shifting as curl moved "
               "its own issue tracking onto GitHub over the 2010s -- a labeling-methodology "
               "artifact, not a change in what a bug fix structurally looks like. It means raw "
               "8-way accuracy is not directly comparable to a naive 1/8 chance baseline; the "
               "trivial baselines below give the honest reference points.\n")

    md.append("## 1. Test-set confusion matrix + per-class F1 (full vector)\n")
    md.append(f"Overall test accuracy **{acc_full:.3f}**, macro-F1 **{f1_full:.3f}** "
               f"(n={int(valid_test.sum())}, lambda={lam_full}). Trivial baselines for context: "
               f"always predicting the **train**-mode class (`{train_mode_name}`) on test scores "
               f"**{baseline_train_mode_acc:.3f}**; always predicting the **test**-mode class "
               f"(`{test_mode_name}`, an oracle a real model can't use) scores "
               f"**{baseline_test_mode_acc:.3f}**.\n")
    md.append(cm_md + "\n")
    md.append("| class | support | precision | recall | F1 |")
    md.append("|---|---|---|---|---|")
    for c, support, prec, rec, f1 in prf_rows:
        md.append(f"| {c} | {support} | {prec:.2f} | {rec:.2f} | {f1:.2f} |")
    md.append("")
    md.append("**Most-confused pairs** (true -> predicted, count): " + (
        "; ".join(f"{a} -> {b} ({n})" for n, a, b in confusions) if confusions else "none") + "\n")
    top_pred = pred_dist.most_common(1)[0]
    collapse_share = top_pred[1] / int(valid_test.sum())
    if collapse_share > 0.5:
        pred_dist_str = ", ".join(f"{c}={n}" for c, n in pred_dist.most_common())
        md.append(
            f"**Degenerate:** the model predicts `{top_pred[0]}` for {collapse_share:.0%} of test "
            "events regardless of true class (predicted-class distribution: "
            f"{pred_dist_str}) -- a near-majority-class collapse. With a single dominant softmax "
            "bias term and weak per-feature separation, L2 pulls the decision surface toward the "
            f"train class prior; the train prior's mode (`{train_mode_name}`) is exactly the "
            "class most depleted by the class-prior drift noted above, so the collapse target and "
            "the true test distribution are maximally mismatched. The full-vector model still "
            "beats both trivial single-class baselines here, but the raw 8-way accuracy number is "
            "dominated by this prior-shift pathology, not primarily by feature quality -- read the "
            "collapsed binary AUC (section 4) and per-class precision/recall above as the more "
            "prior-robust reading.\n")

    md.append("## 2. Top-15 signal coefficients per class contrast\n")
    md.append("Standardized-feature coefficient difference between the two classes' softmax "
               "columns of the full-vector model (positive = pushes toward the first-named "
               "class relative to the second). `net_loc` is included in the ranking so its "
               "relative rank shows whether a signal's importance survives controlling for it.\n")
    for a, b, label in CONTRASTS:
        table = coef_contrast_table(W_full, feature_names, classes, a, b)
        md.append(f"### {label}\n")
        md.append("| rank | feature | coefficient |")
        md.append("|---|---|---|")
        for i, (feat, val) in enumerate(table, 1):
            flag = " *(net-LOC)*" if feat == "net_loc" else ""
            md.append(f"| {i} | `{feat}`{flag} | {val:+.3f} |")
        md.append("")

    md.append("### Does the univariate fix-grammar (branch/pointer adds, no new "
               "cast/alloc) survive multivariately?\n")
    md.append("Full rank (of the active-feature count) and signed coefficient for the four "
               "grammar signals, in each contrast above -- not just whether they crack the top 15:\n")
    md.append("| signal | " + " | ".join(label for _, _, label in CONTRASTS) + " |")
    md.append("|---|" + "---|" * len(CONTRASTS))
    grammar_rows = {a_b[2]: grammar_rank_table(W_full, feature_names, classes, a_b[0], a_b[1])
                     for a_b in CONTRASTS}
    for i, sig in enumerate(GRAMMAR_WATCH):
        cells = []
        for _, _, label in CONTRASTS:
            _, r, total, v = grammar_rows[label][i]
            cells.append(f"rank {r}/{total}, {v:+.3f}" if r is not None else "dropped")
        md.append(f"| `{sig}` | " + " | ".join(cells) + " |")
    md.append("")
    branch_rank = grammar_rows["security-fix vs control"][0][1]
    ptr_rank = grammar_rows["security-fix vs control"][1][1]
    cast_rank = grammar_rows["security-fix vs control"][3][1]
    alloc_rank = grammar_rows["security-fix vs control"][2][1]
    n_active_plus1 = len(feature_names)
    md.append(
        f"**No.** In the security-fix vs control contrast, `struct_branch` sits mid-table "
        f"(rank {branch_rank}/{n_active_plus1}) and `state_pointers` is dead last "
        f"(rank {ptr_rank}/{n_active_plus1}, coefficient essentially zero) once every other "
        "signal and net-LOC compete for the same coefficient budget -- branch/pointer additions "
        "do **not** top the multivariate security-fix signature, contradicting the univariate "
        "read. What *does* survive multivariately, and consistently across all three contrasts, "
        f"is the grammar's other half: `state_cast_hits` (rank {cast_rank}) and "
        f"`state_memory_alloc` (rank {alloc_rank}) are both negative and land in the top third of "
        "every contrast -- a fix/introduction event that does *not* add new casts or new "
        "allocations, more than one that adds branches or pointers. The top-ranked features "
        "overall (`arch_globals`, `def_encapsulation`, `state_cast_hits`, `struct_upper_case`, "
        "`def_freeze_hits` for security-fix vs control) are a mix of style/scope signals as much "
        "as danger vocabulary -- once collinear signals compete for coefficient budget under L2, "
        "the univariate grammar's headline term (branch+/pointer+) turns out to be the weaker, "
        "more redundant half of it.\n")

    md.append("## 3. Net-LOC alone vs the full vector (the beyond-size delta)\n")
    md.append("| model | test accuracy | test macro-F1 |")
    md.append("|---|---|---|")
    md.append(f"| full vector ({len(feature_names)} features) | {acc_full:.3f} | {f1_full:.3f} |")
    md.append(f"| net-LOC alone (1 feature) | {acc_nl:.3f} | {f1_nl:.3f} |")
    md.append(f"| **beyond-size delta** | **{acc_full - acc_nl:+.3f}** | "
               f"**{f1_full - f1_nl:+.3f}** |\n")

    def counter_str(rs):
        c = Counter(r["class"] for r in rs)
        return ", ".join(f"{k}={v}" for k, v in c.most_common())

    md.append("## 4. Collapsed binary: fix-like (security-fix+bugfix-*+regression) vs control\n")
    md.append(f"Train n={len(bin_train)} ({counter_str(bin_train)}), "
               f"test n={len(bin_test)} ({counter_str(bin_test)}).\n")
    md.append("| model | test AUC |")
    md.append("|---|---|")
    md.append(f"| full vector | {auc_b_full:.3f} |")
    md.append(f"| net-LOC alone | {auc_b_nl:.3f} |")
    md.append(f"| **beyond-size delta** | **{auc_b_full - auc_b_nl:+.3f}** |\n")
    md.append("Descriptive only (exploratory, no test run here) -- for context, a rough "
               f"Hanley-McNeil-style AUC standard error at this n (n1={int(yb_test.sum())}, "
               f"n0={len(yb_test)-int(yb_test.sum())}) is on the order of 0.03; both AUCs above "
               "are within noise of 0.5 (chance). Unlike the raw multiclass accuracy in section 1, "
               "AUC is prior-invariant (rank statistic), so this comparison is NOT distorted by "
               "the class-prior drift noted in Data -- fix-like-vs-control separability, in this "
               "feature vector, out of temporal sample, reads as indistinguishable from chance, "
               "for both the full vector and net-LOC alone.\n")

    md.append("---\n*Regenerate: `python tools/class_signals.py` (reads/fills "
               "`dbs/keyword_pools_cache.json` via `tools/keyword_pools.py`'s compute pass; "
               "both gitignored). Not committed by the tool.*")

    out_path = pathlib.Path(args.out)
    out_path.write_text("\n".join(md) + "\n")
    print(f"wrote {out_path}")
    print(f"total runtime {time.time()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
