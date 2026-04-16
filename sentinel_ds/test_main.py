"""
main.py — Orchestrator for the Adaptive Triage Engine.

1. Loads CIC-IDS2018 data in memory-safe chunks.
2. Trains XGBoost ThreatDetector on ~80% of chunks.
3. Runs online Contextual-Bandit simulation on remaining ~20%.
4. Produces matplotlib plots and exports live state as JSON
   for the React dashboard.
"""

import os
import sys
import json
import time
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict

# Ensure src/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from data_loader import load_data_in_chunks
from features import preprocess_features
from detector import ThreatDetector
from bandit import BanditAgent, ACTION_NAMES

# ── Config ──────────────────────────────────────────────────
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
STATE_FILE = os.path.join(OUTPUT_DIR, "state.json")
PROGRESS_FILE = os.path.join(OUTPUT_DIR, "progress.json")

TRAIN_RATIO = 0.80          # chronological split
LOAD_PHASES = [0.1, 0.3, 0.5, 0.7, 0.9]  # analyst load schedule
MAX_CHUNKS = None           # set to small int for quick testing

SAMPLE_SIZE = 100           # rows saved to state.json for the dashboard


def _build_representative_sample(log_steps, n=SAMPLE_SIZE):
    """
    Build a balanced sample of log entries for the dashboard.
    Priority: (1) all threat events, (2) escalate/monitor actions,
    (3) recent benign dismissals to fill remaining slots.
    """
    import random as _rng

    threats   = [e for e in log_steps if e.get("true_label") == 1]
    escalated = [e for e in log_steps if e.get("action") == "Escalate" and e.get("true_label") == 0]
    monitored = [e for e in log_steps if e.get("action") == "Monitor"  and e.get("true_label") == 0]
    benign    = [e for e in log_steps if e.get("action") == "Dismiss"  and e.get("true_label") == 0]

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
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Dataset", "Data"))
    all_files = sorted(
        glob.glob(os.path.join(data_dir, "*.parquet")) +
        glob.glob(os.path.join(data_dir, "*.csv"))
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
    chunk_idx = 0

    for chunk in train_gen:
        if len(train_buffer) < 2:
            train_buffer.append(chunk)
            continue
            
        # Pop the oldest chunk from buffer for training
        c_train = train_buffer.pop(0)
        train_buffer.append(chunk)  # Buffer the newest incoming chunk
        
        X, y = preprocess_features(c_train, fit_scaler=True)
        if len(np.unique(y)) < 2:
            msg = f"  [Train] Chunk {chunk_idx}: skipped (single class)"
            print(msg)
            progress["console_log"].append(msg)
        else:
            detector.partial_train(X, y)
            acc = (detector.predict(X) == y).mean()
            msg = f"  [Train] Chunk {chunk_idx}: acc={acc:.4f}  threat_rate={y.mean():.2%}"
            print(msg)
            progress["training_acc"] = round(float(acc), 4)

        progress["current_chunk"] = chunk_idx + 1
        progress["status"] = f"Training chunk {chunk_idx+1}"
        progress["console_log"].append(msg)
        progress["console_log"] = progress["console_log"][-50:]  # keep last 50
        _persist_progress(progress)
        chunk_idx += 1

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
    try:
        from src.features import save_scaler
    except ImportError:
        from features import save_scaler
    save_scaler(os.path.join(OUTPUT_DIR, "scaler.joblib"))

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
        threat_scores = detector.predict_proba(X)

        # Determine analyst load phase
        phase_idx = min(tidx, len(LOAD_PHASES) - 1)
        analyst_load = LOAD_PHASES[phase_idx]

        for i in range(len(y)):
            ts = float(threat_scores[i])
            true_label = int(y[i])
            action = agent.decide(ts, analyst_load)
            reward = agent.compute_reward(true_label, action, analyst_load, ts)
            agent.update(ts, analyst_load, action, reward)

            cumulative_reward += reward
            step += 1

            # Confusion matrix (rolling)
            # TP = agent flagged a real threat (Escalate OR Monitor)
            # FP = agent escalated benign traffic
            # FN = agent dismissed a real threat
            # TN = agent dismissed benign traffic or monitored benign
            if true_label == 1 and action >= 1:      # Escalate or Monitor a threat
                rolling_tp += 1
            elif true_label == 0 and action == 2:     # Escalated benign = false alarm
                rolling_fp += 1
            elif true_label == 1 and action == 0:     # Dismissed a real threat
                rolling_fn += 1
            else:                                      # Dismissed/Monitored benign
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

            log_steps.append({
                "step": step,
                "threat_score": round(ts, 4),
                "action": ACTION_NAMES[action],
                "true_label": true_label,
                "reward": reward,
                "analyst_load": analyst_load,
                "dst_port": int(chunk["Dst Port"].iloc[i]) if "Dst Port" in chunk.columns else 80,
                "flow_dur": int(chunk["Flow Duration"].iloc[i]) if "Flow Duration" in chunk.columns else 100,
            })

            # Persist state every 5000 steps
            if step % 5000 == 0:
                live_state["logs"] = _build_representative_sample(log_steps)
                _persist_state(live_state)
                msg = (f"  [Sim] step {step:>8,}  ε={agent.epsilon:.4f}  "
                       f"cum_R={cumulative_reward:>12,.0f}  "
                       f"P={precision:.3f}  R={recall:.3f}  F1={f1:.3f}")
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
    msg_final = (f"  Final — P={rolling_precisions[-1]:.4f}  "
                 f"R={rolling_recalls[-1]:.4f}  "
                 f"F1={rolling_f1s[-1]:.4f}  "
                 f"Cum_R={cumulative_reward:,.0f}")
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

    _plot_metrics(cum_rewards, rolling_precisions, rolling_recalls, rolling_f1s, phase_actions)

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
    ax.plot(xs_z, f1_scores[:zoom], label="F1-Score", linewidth=1.2, alpha=0.9, linestyle="--")
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
        ax.bar(x_pos + a_idx * bar_width, counts, bar_width,
               label=ACTION_NAMES[a_idx])
    ax.set_xticks(x_pos + bar_width)
    ax.set_xticklabels([f"Load={LOAD_PHASES[min(p, len(LOAD_PHASES)-1)]}"
                        for p in phases])
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
