"""
main.py — Orchestrator for the Adaptive Triage Engine.

1. Loads CIC-IDS2018 data in memory-safe chunks.
2. Trains XGBoost ThreatDetector on ~80% of chunks.
3. Runs online Contextual-Bandit simulation on remaining ~20%.
4. Produces matplotlib plots and exports live state as JSON
   for the React dashboard.
"""

import json
import os
import sys
import time

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
from collections import defaultdict

import matplotlib.pyplot as plt

# Ensure src/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from bandit import ACTION_NAMES, BanditAgent
from data_loader import load_data_in_chunks
from detector import ThreatDetector
from features import preprocess_features

# ── Config ──────────────────────────────────────────────────
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
STATE_FILE = os.path.join(OUTPUT_DIR, "state.json")
PROGRESS_FILE = os.path.join(OUTPUT_DIR, "progress.json")

TRAIN_RATIO = 0.80  # chronological split
LOAD_PHASES = [0.1, 0.3, 0.5, 0.7, 0.9]  # analyst load schedule
MAX_CHUNKS = None  # set to small int for quick testing

SAMPLE_SIZE = 100  # rows saved to state.json for the dashboard


def _binary_labels(df):
    """Return binary labels from a cleaned chunk without scaling features."""
    return (df["Label"].astype(str).str.strip().str.lower() != "benign").astype(np.int8)


def _update_seed_rows(seed_rows, chunk, max_rows=2048):
    """Keep small benign/attack reference samples for single-class chunk augmentation."""
    y = _binary_labels(chunk)
    for cls in (0, 1):
        mask = y == cls
        if not mask.any():
            continue
        sample_n = min(int(mask.sum()), max_rows)
        seed_rows[cls] = chunk.loc[mask].sample(n=sample_n, random_state=42).copy()


def _augment_single_class_chunk(chunk, seed_rows):
    """
    Merge a single-class chunk with a cached opposite-class seed so it can train.
    Returns None when no opposite-class seed has been observed yet.
    """
    y = _binary_labels(chunk)
    unique = np.unique(y)
    if len(unique) != 1:
        return chunk

    opposite_seed = seed_rows.get(int(1 - unique[0]))
    if opposite_seed is None or len(opposite_seed) == 0:
        return None
    return pd.concat([chunk, opposite_seed], ignore_index=True)


def _build_representative_sample(log_steps, n=SAMPLE_SIZE):
    """
    Build a balanced sample of log entries for the dashboard.
    Priority: (1) all threat events, (2) escalate/monitor actions,
    (3) recent benign dismissals to fill remaining slots.
    """
    import random as _rng

    threats = [e for e in log_steps if e.get("true_label") == 1]
    escalated = [
        e
        for e in log_steps
        if e.get("action") == "Escalate" and e.get("true_label") == 0
    ]
    monitored = [
        e
        for e in log_steps
        if e.get("action") == "Monitor" and e.get("true_label") == 0
    ]
    benign = [
        e
        for e in log_steps
        if e.get("action") == "Dismiss" and e.get("true_label") == 0
    ]

    sample = []

    # 1. All threat events (up to n/2)
    if threats:
        _rng.seed(42)
        sample += _rng.sample(threats, min(len(threats), n // 2))

    # 2. Escalated benign (false alarms) — up to 10
    if escalated:
        _rng.seed(43)
        sample += _rng.sample(escalated, min(len(escalated), 10))

    # 3. Monitored benign — up to 15
    if monitored:
        _rng.seed(44)
        sample += _rng.sample(monitored, min(len(monitored), 15))

    # 4. Fill remaining with benign dismissals (evenly spaced)
    remaining = n - len(sample)
    if remaining > 0 and benign:
        step_size = max(1, len(benign) // remaining)
        sample += benign[::step_size][:remaining]

    # Sort by step number for chronological display
    sample.sort(key=lambda e: e.get("step", 0))
    return sample[:n]


def _ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _persist_state(state: dict):
    """Write the latest pipeline state to JSON for the dashboard."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, default=str)


def _persist_progress(progress: dict):
    """Write live training/simulation progress for the frontend."""
    progress["updated_at"] = time.time()
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, default=str)


# ── Main Pipeline ───────────────────────────────────────────


def run():
    _ensure_dirs()
    print("=" * 70)
    print("  Adaptive Triage Engine — Full Pipeline")
    print("=" * 70)

    # Init progress
    progress = {
        "phase": "loading",
        "status": "Loading dataset chunks...",
        "total_chunks": 0,
        "train_chunks": 0,
        "test_chunks": 0,
        "current_chunk": 0,
        "training_acc": 0,
        "sim_step": 0,
        "sim_total": 0,
        "precision": 0,
        "recall": 0,
        "cumulative_reward": 0,
        "epsilon": 1.0,
        "console_log": [],
        "completed": False,
    }
    _persist_progress(progress)

    # ── Collect files for streaming ─────────────────────────
    import glob

    data_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "Dataset", "Data")
    )
    all_files = sorted(
        glob.glob(os.path.join(data_dir, "*.parquet"))
        + glob.glob(os.path.join(data_dir, "*.csv"))
    )
    n_files = len(all_files)
    n_train_files = max(1, int(n_files * TRAIN_RATIO))
    train_files = all_files[:n_train_files]
    test_files = all_files[n_train_files:]

    msg = f"[Pipeline] {n_files} files total → {len(train_files)} train, {len(test_files)} test"
    print(f"\n{msg}")

    progress["phase"] = "training"
    progress["status"] = "Training XGBoost detector..."
    progress["total_chunks"] = n_files
    progress["train_chunks"] = len(train_files)
    progress["test_chunks"] = len(test_files)
    progress["console_log"].append(msg)
    _persist_progress(progress)

    # ── Phase 2: Train detector (with validation) ────────────
    detector = ThreatDetector(n_estimators=250)

    # Create generator for training files
    train_gen = load_data_in_chunks(file_list=train_files, max_chunks=MAX_CHUNKS)

    train_buffer = []  # rolling buffer to hold the last 2 chunks for validation
    cal_reservoir = []  # reservoir: small sample from EVERY chunk for calibration
    seed_rows = {0: None, 1: None}
    pending_train_chunk = None
    chunk_idx = 0

    for chunk in train_gen:
        # Reserve ~5% of each chunk for calibration (max 10K rows per chunk)
        cal_size = min(len(chunk) // 20, 10_000)
        if cal_size > 0:
            cal_sample = chunk.sample(n=cal_size, random_state=42)
            cal_reservoir.append(cal_sample)

        if len(train_buffer) < 2:
            train_buffer.append(chunk)
            _update_seed_rows(seed_rows, chunk)
            continue

        # Pop the oldest chunk from buffer for training
        c_train = train_buffer.pop(0)
        train_buffer.append(chunk)  # Buffer the newest incoming chunk

        if pending_train_chunk is not None:
            c_train = pd.concat([pending_train_chunk, c_train], ignore_index=True)
            pending_train_chunk = None

        _update_seed_rows(seed_rows, c_train)
        train_chunk = _augment_single_class_chunk(c_train, seed_rows)

        if train_chunk is None:
            pending_train_chunk = c_train
            msg = f"  [Train] Chunk {chunk_idx}: deferred (single class)"
            print(msg)
            progress["console_log"].append(msg)
        else:
            X, y = preprocess_features(train_chunk, fit_scaler=True)
            detector.partial_train(X, y)
            acc = (detector.predict(X) == y).mean()
            augmented = " +seed" if len(train_chunk) != len(c_train) else ""
            msg = (
                f"  [Train] Chunk {chunk_idx}{augmented}: "
                f"acc={acc:.4f}  threat_rate={y.mean():.2%}"
            )
            print(msg)
            progress["training_acc"] = round(float(acc), 4)

        progress["current_chunk"] = chunk_idx + 1
        progress["status"] = f"Training chunk {chunk_idx + 1}"
        progress["console_log"].append(msg)
        progress["console_log"] = progress["console_log"][-50:]  # keep last 50
        _persist_progress(progress)
        chunk_idx += 1

    if pending_train_chunk is not None:
        flush_chunk = _augment_single_class_chunk(pending_train_chunk, seed_rows)
        if flush_chunk is not None:
            Xf, yf = preprocess_features(flush_chunk, fit_scaler=True)
            detector.partial_train(Xf, yf)
            acc = (detector.predict(Xf) == yf).mean()
            msg = (
                f"  [Train] Final deferred +seed: "
                f"acc={acc:.4f}  threat_rate={yf.mean():.2%}"
            )
            print(msg)
            progress["console_log"].append(msg)

    # ── Validation on held-out training chunks ────────────────
    if len(train_buffer) > 0:
        val_correct, val_total = 0, 0
        for vc in train_buffer:
            Xv, yv = preprocess_features(vc, fit_scaler=False)
            preds = detector.predict(Xv)
            val_correct += (preds == yv).sum()
            val_total += len(yv)
        val_acc = val_correct / max(1, val_total)
        msg = f"  [Validation] {len(train_buffer)} chunks, acc={val_acc:.4f}"
        print(msg)
        progress["console_log"].append(msg)
        progress["training_acc"] = round(float(val_acc), 4)
        _persist_progress(progress)

    # Log feature importances
    importances = detector.get_feature_importances()
    if importances is not None:
        top_idx = np.argsort(importances)[-5:]
        try:
            from src.features import SELECTED_FEATURES
        except ImportError:
            from features import SELECTED_FEATURES
        avail = [co for co in SELECTED_FEATURES]
        top_features = [avail[i] if i < len(avail) else f"feat_{i}" for i in top_idx]
        msg = f"  [Features] Top-5 importance: {', '.join(reversed(top_features))}"
        print(msg)
        progress["console_log"].append(msg)

    detector.save(os.path.join(OUTPUT_DIR, "detector.json"))
    progress["console_log"].append("[Train] Detector saved.")

    # Save the fitted scaler for inference
    from features import save_scaler
    save_scaler(os.path.join(OUTPUT_DIR, "scaler.joblib"))

    # ── Phase 2b: Train web-specific detector ────────────────
    # A dedicated model trained only on web-port traffic (80, 443, 8080 …)
    # gives much finer decision boundaries for web attacks (XSS, web brute
    # force, SQLi) that look statistically identical to benign HTTP traffic
    # when processed by a general-purpose detector.
    AUTH_PORTS = {21, 22, 23, 3389, 5900, 1433, 3306, 5432, 6379, 27017}
    WEB_PORTS = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888}
    progress["phase"] = "training_web"
    progress["status"] = "Training web-traffic detector..."
    _persist_progress(progress)

    web_detector = ThreatDetector(n_estimators=250)
    web_chunk_count = 0
    web_train_gen = load_data_in_chunks(file_list=train_files, max_chunks=MAX_CHUNKS)
    web_seed_rows = {0: None, 1: None}
    pending_web_chunk = None

    for wchunk in web_train_gen:
        if "Dst Port" not in wchunk.columns:
            continue
        web_chunk = wchunk[wchunk["Dst Port"].isin(WEB_PORTS)].copy()
        if len(web_chunk) < 20:
            continue
        if pending_web_chunk is not None:
            web_chunk = pd.concat([pending_web_chunk, web_chunk], ignore_index=True)
            pending_web_chunk = None
        _update_seed_rows(web_seed_rows, web_chunk)
        web_train_chunk = _augment_single_class_chunk(web_chunk, web_seed_rows)
        if web_train_chunk is None:
            pending_web_chunk = web_chunk
            continue
        Xw, yw = preprocess_features(web_train_chunk, fit_scaler=False)
        web_detector.partial_train(Xw, yw)
        web_chunk_count += 1

    if pending_web_chunk is not None:
        flush_web_chunk = _augment_single_class_chunk(pending_web_chunk, web_seed_rows)
        if flush_web_chunk is not None:
            Xw, yw = preprocess_features(flush_web_chunk, fit_scaler=False)
            web_detector.partial_train(Xw, yw)
            web_chunk_count += 1

    if web_chunk_count > 0:
        web_detector.save(os.path.join(OUTPUT_DIR, "web_detector.json"))
        msg = f"  [WebDet] Trained on {web_chunk_count} web-filtered chunks → web_detector.json"
    else:
        msg = "  [WebDet] No web-port chunks found — web detector not saved"
    print(msg)
    progress["console_log"].append(msg)

    # ── Phase 2b2: Train auth/service detector ─────────────
    progress["phase"] = "training_auth"
    progress["status"] = "Training auth/service detector..."
    _persist_progress(progress)

    auth_detector = ThreatDetector(n_estimators=250)
    auth_chunk_count = 0
    auth_train_gen = load_data_in_chunks(file_list=train_files, max_chunks=MAX_CHUNKS)
    auth_seed_rows = {0: None, 1: None}
    pending_auth_chunk = None

    for achunk in auth_train_gen:
        if "Dst Port" not in achunk.columns:
            continue
        auth_chunk = achunk[achunk["Dst Port"].isin(AUTH_PORTS)].copy()
        if len(auth_chunk) < 20:
            continue
        if pending_auth_chunk is not None:
            auth_chunk = pd.concat([pending_auth_chunk, auth_chunk], ignore_index=True)
            pending_auth_chunk = None
        _update_seed_rows(auth_seed_rows, auth_chunk)
        auth_train_chunk = _augment_single_class_chunk(auth_chunk, auth_seed_rows)
        if auth_train_chunk is None:
            pending_auth_chunk = auth_chunk
            continue
        Xa, ya = preprocess_features(auth_train_chunk, fit_scaler=False)
        auth_detector.partial_train(Xa, ya)
        auth_chunk_count += 1

    if pending_auth_chunk is not None:
        flush_auth_chunk = _augment_single_class_chunk(pending_auth_chunk, auth_seed_rows)
        if flush_auth_chunk is not None:
            Xa, ya = preprocess_features(flush_auth_chunk, fit_scaler=False)
            auth_detector.partial_train(Xa, ya)
            auth_chunk_count += 1

    if auth_chunk_count > 0:
        auth_detector.save(os.path.join(OUTPUT_DIR, "auth_detector.json"))
        msg = f"  [AuthDet] Trained on {auth_chunk_count} auth-filtered chunks → auth_detector.json"
    else:
        msg = "  [AuthDet] No auth-port chunks found — auth detector not saved"
    print(msg)
    progress["console_log"].append(msg)

    # ── Phase 2b3: Train DDoS/DoS detector ─────────────────
    progress["phase"] = "training_ddos"
    progress["status"] = "Training DDoS/DoS detector..."
    _persist_progress(progress)

    ddos_source_names = {
        "DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet",
        "DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet",
        "DoS1-Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet",
        "DoS2-Friday-16-02-2018_TrafficForML_CICFlowMeter.parquet",
        "ddos_loit.csv",
        "dos_golden_eye.csv",
        "dos_hulk.csv",
        "dos_slowhttptest.csv",
        "dos_slowloris.csv",
        "friday_benign.csv",
        "monday_benign.csv",
        "thursday_benign.csv",
        "tuesday_benign.csv",
        "wednesday_benign.csv",
    }
    ddos_train_files = [
        fp for fp in train_files if os.path.basename(fp) in ddos_source_names
    ]
    ddos_detector = ThreatDetector(n_estimators=250)
    ddos_chunk_count = 0
    ddos_train_gen = load_data_in_chunks(file_list=ddos_train_files, max_chunks=MAX_CHUNKS)
    ddos_seed_rows = {0: None, 1: None}
    pending_ddos_chunk = None
    ddos_cal_reservoir = []

    for dchunk in ddos_train_gen:
        cal_size = min(len(dchunk) // 20, 5_000)
        if cal_size > 0:
            ddos_cal_reservoir.append(dchunk.sample(n=cal_size, random_state=42))
        if pending_ddos_chunk is not None:
            dchunk = pd.concat([pending_ddos_chunk, dchunk], ignore_index=True)
            pending_ddos_chunk = None
        _update_seed_rows(ddos_seed_rows, dchunk)
        ddos_train_chunk = _augment_single_class_chunk(dchunk, ddos_seed_rows)
        if ddos_train_chunk is None:
            pending_ddos_chunk = dchunk
            continue
        Xd, yd = preprocess_features(ddos_train_chunk, fit_scaler=False)
        ddos_detector.partial_train(Xd, yd)
        ddos_chunk_count += 1

    if pending_ddos_chunk is not None:
        flush_ddos_chunk = _augment_single_class_chunk(pending_ddos_chunk, ddos_seed_rows)
        if flush_ddos_chunk is not None:
            Xd, yd = preprocess_features(flush_ddos_chunk, fit_scaler=False)
            ddos_detector.partial_train(Xd, yd)
            ddos_chunk_count += 1

    if ddos_chunk_count > 0:
        ddos_detector.save(os.path.join(OUTPUT_DIR, "ddos_detector.json"))
        msg = f"  [DDoSDet] Trained on {ddos_chunk_count} DDoS/DoS chunks → ddos_detector.json"
    else:
        msg = "  [DDoSDet] No DDoS/DoS chunks found — ddos detector not saved"
    print(msg)
    progress["console_log"].append(msg)

    # ── Phase 2c: Calibrate detectors ────────────────────────
    # Isotonic-regression calibration on held-out validation chunks so that
    # threat scores reflect true empirical probabilities rather than raw
    # XGBoost outputs (which are often overconfident or underconfident).
    progress["status"] = "Calibrating detectors..."
    _persist_progress(progress)

    if len(cal_reservoir) > 0:
        # Collect calibration data from reservoir (sampled from ALL chunks)
        import pandas as pd
        cal_df = pd.concat(cal_reservoir, ignore_index=True)
        print(f"  [Calib] Reservoir: {len(cal_df)} rows from {len(cal_reservoir)} chunks")

        cal_X_list, cal_y_list = [], []
        auth_cal_X_list, auth_cal_y_list = [], []
        web_cal_X_list, web_cal_y_list = [], []

        Xc, yc = preprocess_features(cal_df, fit_scaler=False)
        cal_X_list.append(Xc)
        cal_y_list.append(yc)
        if "Dst Port" in cal_df.columns:
            auth_mask = cal_df["Dst Port"].isin(AUTH_PORTS).values
            if auth_mask.sum() >= 10:
                auth_cal_X_list.append(Xc[auth_mask])
                auth_cal_y_list.append(yc[auth_mask])
            web_mask = cal_df["Dst Port"].isin(WEB_PORTS).values
            if web_mask.sum() >= 10:
                web_cal_X_list.append(Xc[web_mask])
                web_cal_y_list.append(yc[web_mask])

        if cal_X_list:
            X_cal = np.vstack(cal_X_list)
            y_cal = np.concatenate(cal_y_list)
            detector.calibrate(X_cal, y_cal)
            detector.save_calibration(os.path.join(OUTPUT_DIR, "calibrator.joblib"))
            progress["console_log"].append("[Calib] Main detector calibrated.")

        if auth_chunk_count > 0:
            if auth_cal_X_list:
                Xac = np.vstack(auth_cal_X_list)
                yac = np.concatenate(auth_cal_y_list)
            elif "Dst Port" in cal_df.columns:
                auth_mask_fb = cal_df["Dst Port"].isin(AUTH_PORTS).values
                if auth_mask_fb.sum() >= 10:
                    Xac = X_cal[auth_mask_fb]
                    yac = y_cal[auth_mask_fb]
                else:
                    Xac, yac = np.array([]), np.array([])
            else:
                Xac, yac = np.array([]), np.array([])

            if len(Xac) >= 10 and len(np.unique(yac)) == 2:
                auth_detector.calibrate(Xac, yac)
                auth_detector.save_calibration(
                    os.path.join(OUTPUT_DIR, "auth_calibrator.joblib")
                )
                progress["console_log"].append("[Calib] Auth detector calibrated.")
            else:
                import shutil
                main_cal = os.path.join(OUTPUT_DIR, "calibrator.joblib")
                auth_cal = os.path.join(OUTPUT_DIR, "auth_calibrator.joblib")
                if os.path.isfile(main_cal):
                    shutil.copy2(main_cal, auth_cal)
                    progress["console_log"].append(
                        "[Calib] Auth calibrator: copied from main (insufficient auth-only data)."
                    )

        if ddos_chunk_count > 0:
            if ddos_cal_reservoir:
                ddos_cal_df = pd.concat(ddos_cal_reservoir, ignore_index=True)
                Xdc, ydc = preprocess_features(ddos_cal_df, fit_scaler=False)
            else:
                Xdc, ydc = np.array([]), np.array([])

            if len(Xdc) >= 10 and len(np.unique(ydc)) == 2:
                ddos_detector.calibrate(Xdc, ydc)
                ddos_detector.save_calibration(
                    os.path.join(OUTPUT_DIR, "ddos_calibrator.joblib")
                )
                progress["console_log"].append("[Calib] DDoS detector calibrated.")
            else:
                import shutil
                main_cal = os.path.join(OUTPUT_DIR, "calibrator.joblib")
                ddos_cal = os.path.join(OUTPUT_DIR, "ddos_calibrator.joblib")
                if os.path.isfile(main_cal):
                    shutil.copy2(main_cal, ddos_cal)
                    progress["console_log"].append(
                        "[Calib] DDoS calibrator: copied from main (insufficient DDoS-only data)."
                    )

        if web_chunk_count > 0:
            # Try web-specific validation data first, fall back to full cal set
            if web_cal_X_list:
                Xwc = np.vstack(web_cal_X_list)
                ywc = np.concatenate(web_cal_y_list)
            elif "Dst Port" in cal_df.columns:
                # Fall back: filter the full calibration set for web ports
                web_mask_fb = cal_df["Dst Port"].isin(WEB_PORTS).values
                if web_mask_fb.sum() >= 10:
                    Xwc = X_cal[web_mask_fb]
                    ywc = y_cal[web_mask_fb]
                else:
                    Xwc, ywc = np.array([]), np.array([])
            else:
                Xwc, ywc = np.array([]), np.array([])

            if len(Xwc) >= 10 and len(np.unique(ywc)) == 2:
                web_detector.calibrate(Xwc, ywc)
                web_detector.save_calibration(
                    os.path.join(OUTPUT_DIR, "web_calibrator.joblib")
                )
                progress["console_log"].append("[Calib] Web detector calibrated.")
            else:
                # Copy main calibrator as a reasonable fallback
                import shutil
                main_cal = os.path.join(OUTPUT_DIR, "calibrator.joblib")
                web_cal = os.path.join(OUTPUT_DIR, "web_calibrator.joblib")
                if os.path.isfile(main_cal):
                    shutil.copy2(main_cal, web_cal)
                    progress["console_log"].append(
                        "[Calib] Web calibrator: copied from main (insufficient web-only data)."
                    )

    # ── Phase 3-4: Online simulation ────────────────────────
    progress["phase"] = "simulation"
    progress["status"] = "Running bandit simulation..."
    _persist_progress(progress)

    agent = BanditAgent()
    # Try to load a previously saved Q-table for continuous learning
    agent.load(OUTPUT_DIR)

    # Initialize generator for simulation files
    test_gen = load_data_in_chunks(file_list=test_files, max_chunks=MAX_CHUNKS)

    # Logging
    log_steps = []
    cumulative_reward = 0.0
    cum_rewards = []
    rolling_tp, rolling_fp, rolling_fn, rolling_tn = 0, 0, 0, 0
    rolling_precisions, rolling_recalls, rolling_f1s = [], [], []
    phase_actions = defaultdict(lambda: defaultdict(int))  # phase → action → cnt

    # Estimate total simulation steps for progress bar
    # Since we stream, we estimate roughly 500k rows per test file
    est_total = len(test_files) * 500_000

    # Live state for dashboard
    live_state = {
        "events_captured": 0,
        "failed_requests": 0,
        "active_threats": 0,
        "flagged_ips": 0,
        "logs": [],
        "reports": [],
        "endpoint_hits": defaultdict(int),
    }

    step = 0
    progress["sim_total"] = est_total
    for tidx, chunk in enumerate(test_gen):
        X, y = preprocess_features(chunk, fit_scaler=False)

        # Route web-port flows to the dedicated web detector
        threat_scores = detector.predict_proba_calibrated(X)
        auth_mask = np.zeros(len(chunk), dtype=bool)
        if auth_chunk_count > 0 and "Dst Port" in chunk.columns:
            auth_mask = chunk["Dst Port"].isin(AUTH_PORTS).values
            if auth_mask.any():
                auth_scores = auth_detector.predict_proba_calibrated(X[auth_mask])
                threat_scores = threat_scores.copy()
                threat_scores[auth_mask] = auth_scores
        if web_chunk_count > 0 and "Dst Port" in chunk.columns:
            web_mask = chunk["Dst Port"].isin(WEB_PORTS).values & ~auth_mask
            if web_mask.any():
                web_scores = web_detector.predict_proba_calibrated(X[web_mask])
                threat_scores = threat_scores.copy()
                threat_scores[web_mask] = web_scores

        # Determine analyst load phase
        phase_idx = min(tidx, len(LOAD_PHASES) - 1)
        analyst_load = LOAD_PHASES[phase_idx]

        for i in range(len(y)):
            ts = float(threat_scores[i])
            true_label = int(y[i])
            dst_port = (
                int(chunk["Dst Port"].iloc[i]) if "Dst Port" in chunk.columns else 80
            )
            action = agent.decide(ts, analyst_load, dst_port=dst_port)
            reward = agent.compute_reward(true_label, action, analyst_load, ts)
            agent.update(ts, analyst_load, action, reward, dst_port=dst_port)

            cumulative_reward += reward
            step += 1

            # Confusion matrix (rolling)
            # TP = agent flagged a real threat (Escalate OR Monitor)
            # FP = agent escalated benign traffic
            # FN = agent dismissed a real threat
            # TN = agent dismissed benign traffic or monitored benign
            if true_label == 1 and action >= 1:  # Escalate or Monitor a threat
                rolling_tp += 1
            elif true_label == 0 and action == 2:  # Escalated benign = false alarm
                rolling_fp += 1
            elif true_label == 1 and action == 0:  # Dismissed a real threat
                rolling_fn += 1
            else:  # Dismissed/Monitored benign
                rolling_tn += 1

            precision = rolling_tp / max(1, rolling_tp + rolling_fp)
            recall = rolling_tp / max(1, rolling_tp + rolling_fn)
            f1 = (2 * precision * recall) / max(1e-9, precision + recall)

            # Store
            cum_rewards.append(cumulative_reward)
            rolling_precisions.append(precision)
            rolling_recalls.append(recall)
            rolling_f1s.append(f1)
            phase_actions[phase_idx][action] += 1

            # Update live state counts
            live_state["events_captured"] += 1
            if true_label == 1:
                live_state["active_threats"] += 1
            if action == 0 and true_label == 1:
                live_state["failed_requests"] += 1
            if action >= 1:  # Monitor or Escalate = flagged for review
                live_state["flagged_ips"] += 1

            log_steps.append(
                {
                    "step": step,
                    "threat_score": round(ts, 4),
                    "action": ACTION_NAMES[action],
                    "true_label": true_label,
                    "reward": reward,
                    "analyst_load": analyst_load,
                    "dst_port": int(chunk["Dst Port"].iloc[i])
                    if "Dst Port" in chunk.columns
                    else 80,
                    "flow_dur": int(chunk["Flow Duration"].iloc[i])
                    if "Flow Duration" in chunk.columns
                    else 100,
                }
            )

            # Persist state every 5000 steps
            if step % 5000 == 0:
                live_state["logs"] = _build_representative_sample(log_steps)
                _persist_state(live_state)
                msg = (
                    f"  [Sim] step {step:>8,}  ε={agent.epsilon:.4f}  "
                    f"cum_R={cumulative_reward:>12,.0f}  "
                    f"P={precision:.3f}  R={recall:.3f}  F1={f1:.3f}"
                )
                print(msg)

                progress["sim_step"] = step
                progress["precision"] = round(precision, 4)
                progress["recall"] = round(recall, 4)
                progress["f1"] = round(f1, 4)
                progress["cumulative_reward"] = round(cumulative_reward, 0)
                progress["epsilon"] = round(agent.epsilon, 4)
                progress["status"] = f"Simulation step {step:,}/{est_total:,}"
                progress["console_log"].append(msg)
                progress["console_log"] = progress["console_log"][-50:]
                _persist_progress(progress)

    # Final state persist — representative sample
    live_state["logs"] = _build_representative_sample(log_steps)
    # flagged_ips already accumulated during simulation loop
    _persist_state(live_state)

    msg_done = f"[Pipeline] Simulation done. {step:,} total steps."
    msg_final = (
        f"  Final — P={rolling_precisions[-1]:.4f}  "
        f"R={rolling_recalls[-1]:.4f}  "
        f"F1={rolling_f1s[-1]:.4f}  "
        f"Cum_R={cumulative_reward:,.0f}"
    )
    print(f"\n{msg_done}")
    print(msg_final)

    # Save Q-table for continuous learning
    agent.save(OUTPUT_DIR)

    # ── Plots ───────────────────────────────────────────────
    progress["phase"] = "plotting"
    progress["status"] = "Generating plots..."
    progress["console_log"].append(msg_done)
    progress["console_log"].append(msg_final)
    _persist_progress(progress)

    _plot_metrics(
        cum_rewards, rolling_precisions, rolling_recalls, rolling_f1s, phase_actions
    )

    # Final progress
    progress["phase"] = "complete"
    progress["status"] = "Pipeline complete ✓"
    progress["completed"] = True
    progress["sim_step"] = step
    progress["console_log"].append("[Pipeline] All plots saved. Pipeline complete.")
    _persist_progress(progress)


# ── Plotting ────────────────────────────────────────────────


def _plot_metrics(cum_rewards, precisions, recalls, f1_scores, phase_actions):

    # 1. Recall, Precision & F1
    fig, ax = plt.subplots(figsize=(10, 4))
    xs = range(len(precisions))
    ax.plot(xs, recalls, label="Recall", linewidth=0.7, alpha=0.8)
    ax.plot(xs, precisions, label="Precision", linewidth=0.7, alpha=0.8)
    ax.plot(xs, f1_scores, label="F1-Score", linewidth=0.7, alpha=0.8, linestyle="--")
    ax.set_xlabel("Simulation Step")
    ax.set_ylabel("Score")
    ax.set_title("Rolling Recall, Precision & F1")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "recall_precision.png"), dpi=150)
    plt.close(fig)
    print(f"[Plot] Saved recall_precision.png")

    # 1b. Zoomed Recall, Precision & F1 (first 50K steps — learning phase)
    zoom = min(50_000, len(precisions))
    fig, ax = plt.subplots(figsize=(10, 4))
    xs_z = range(zoom)
    ax.plot(xs_z, recalls[:zoom], label="Recall", linewidth=1.2, alpha=0.9)
    ax.plot(xs_z, precisions[:zoom], label="Precision", linewidth=1.2, alpha=0.9)
    ax.plot(
        xs_z,
        f1_scores[:zoom],
        label="F1-Score",
        linewidth=1.2,
        alpha=0.9,
        linestyle="--",
    )
    ax.set_xlabel("Simulation Step")
    ax.set_ylabel("Score")
    ax.set_title("Learning Phase — First 50K Steps (Zoomed)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "recall_precision_zoomed.png"), dpi=150)
    plt.close(fig)
    print(f"[Plot] Saved recall_precision_zoomed.png")

    # 2. Cumulative Reward
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(cum_rewards, linewidth=0.7, color="green")
    ax.set_xlabel("Simulation Step")
    ax.set_ylabel("Cumulative Reward")
    ax.set_title("Cumulative Reward Over Time")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "cumulative_reward.png"), dpi=150)
    plt.close(fig)
    print(f"[Plot] Saved cumulative_reward.png")

    # 3. Action Distribution per Load Phase
    fig, ax = plt.subplots(figsize=(10, 4))
    phases = sorted(phase_actions.keys())
    bar_width = 0.25
    x_pos = np.arange(len(phases))
    for a_idx in range(3):
        counts = [phase_actions[p].get(a_idx, 0) for p in phases]
        ax.bar(x_pos + a_idx * bar_width, counts, bar_width, label=ACTION_NAMES[a_idx])
    ax.set_xticks(x_pos + bar_width)
    ax.set_xticklabels(
        [f"Load={LOAD_PHASES[min(p, len(LOAD_PHASES) - 1)]}" for p in phases]
    )
    ax.set_ylabel("Count")
    ax.set_title("Action Distribution per Analyst-Load Phase")
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "action_distribution.png"), dpi=150)
    plt.close(fig)
    print(f"[Plot] Saved action_distribution.png")


if __name__ == "__main__":
    run()
