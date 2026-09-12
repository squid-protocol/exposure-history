# ==============================================================================
# temporal-crucible
# Copyright (c) 2026 Joe Esquibel
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE).
# ==============================================================================
"""Engine wiring, the keyword-rosetta `_registry.py` arrangement.

Point GITGALAXY_PATH at the engine checkout and GALAXYSCOPE_BIN at the scanner
binary; the defaults match this box. Every tool in this repo runs the REAL
galaxyscope CLI over a detached worktree -- the harness never imports engine
scan code directly, so the engine under test is exactly the one a user runs.
"""
from __future__ import annotations

import os
import pathlib

GITGALAXY_PATH = pathlib.Path(
    os.environ.get("GITGALAXY_PATH", "/srv/storage_16tb/projects/gitgalaxy/v6")
)
GALAXYSCOPE_BIN = os.environ.get(
    "GALAXYSCOPE_BIN",
    str(GITGALAXY_PATH / ".crucible_venvs" / "full_precision" / "bin" / "galaxyscope"),
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DBS_DIR = REPO_ROOT / "dbs"
EVENTS_DIR = REPO_ROOT / "events"
DOCS_DIR = REPO_ROOT / "docs"
# The uncommitted clone pool (the gitgalaxy/data arrangement): full clones of
# the repos under study live here, never inside this repo.
POOL_DIR = pathlib.Path(
    os.environ.get("EXPOSURE_POOL", "/srv/storage_16tb/projects/exposure-history-pool")
)

# Rung-2 guard #1 (epic gitgalaxy#2982): scans run with git history DISABLED so
# the churn/stability columns are the neutral constants in every snapshot and
# provably contribute zero to any delta. A fix commit mechanically raises churn
# on the files it touches; letting temporal columns into a before/after delta
# would let the event predict itself. Structural exposure is the object of
# study; the temporal ablation is not optional here, it is the design.
SCAN_ENV = {**os.environ, "GITGALAXY_DISABLE_GIT_HISTORY": "1"}

# The 13-slot per-file risk vector (engine RISK_SCHEMA order). Temporal and
# blanket columns called out so report code never hand-lists them.
RISK_VECTOR = [
    "cognitive_load", "safety_score", "tech_debt", "verification", "api_exposure",
    "concurrency", "state_flux", "dead_code", "spec_match", "stability", "churn",
    "documentation", "secrets_risk",
]
TEMPORAL_COLUMNS = {"stability", "churn"}
STRUCTURAL_COLUMNS = [c for c in RISK_VECTOR if c not in TEMPORAL_COLUMNS]
