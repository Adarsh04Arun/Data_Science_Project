#!/usr/bin/env python3
"""
Generate comprehensive metric visualisations from the saved simulation state.
Regenerates action_distribution.png with proper per-load counts,
and produces additional charts for presentation / report purposes.
"""
import json, os, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
STATE_PATH = os.path.join(OUTPUT_DIR, "state.json")
Q_TABLE_PATH = os.path.join(OUTPUT_DIR, "q_table.npy")
VISIT_PATH = os.path.join(OUTPUT_DIR, "visit_count.npy")
PROGRESS_PATH = os.path.join(OUTPUT_DIR, "progress.json")

ACTION_NAMES = ["Dismiss", "Monitor", "Escalate"]
LOAD_PHASES = [0.1, 0.3, 0.5, 0.7, 0.9]

# ── Style ──────────────────────────────────────────────────────────────
plt.rcParams.update({
    "figure.facecolor": "#ffffff",
    "axes.facecolor": "#f8fafc",
    "axes.edgecolor": "#cbd5e1",
    "axes.labelcolor": "#1e293b",
    "text.color": "#1e293b",
    "xtick.color": "#475569",
    "ytick.color": "#475569",
    "grid.color": "#e2e8f0",
    "legend.facecolor": "#ffffff",
    "legend.edgecolor": "#cbd5e1",
    "font.family": "sans-serif",
    "font.size": 11,
})

ACTION_COLORS = ["#3b82f6", "#f97316", "#ef4444"]  # blue, orange, red


def load_data():
    with open(STATE_PATH) as f:
        state = json.load(f)
    with open(PROGRESS_PATH) as f:
        progress = json.load(f)
    q_table = np.load(Q_TABLE_PATH)
    visits = np.load(VISIT_PATH)
    return state, progress, q_table, visits


# ── 1. ACTION DISTRIBUTION PER ANALYST LOAD ────────────────────────────
def _get_phase_counts():
    """Extract per-load-phase action counts from the visit_count Q-table."""
    visits = np.load(VISIT_PATH)
    phase_counts = {}
    for pi, load_val in enumerate(LOAD_PHASES):
        load_bin = min(int(load_val * 20), 19)
        if visits.ndim == 5:
            action_counts = visits[:, load_bin, :, :, :].sum(axis=(0, 1, 2))
        elif visits.ndim == 4:
            action_counts = visits[:, load_bin, :, :].sum(axis=(0, 1))
        else:
            action_counts = np.zeros(3)
        phase_counts[pi] = {a: int(action_counts[a]) for a in range(3)}
    return phase_counts


def plot_action_distribution(state):
    """
    Two-panel action distribution:
      Left  — 100% stacked bars (proportion per load, so all loads are comparable)
      Right — Raw counts with log scale (shows true volume differences)
    """
    phase_counts = _get_phase_counts()
    phases = sorted(phase_counts.keys())
    x_labels = [f"Load={l}" for l in LOAD_PHASES]

    # Build arrays: (n_phases, 3)
    raw = np.array([[phase_counts[p].get(a, 0) for a in range(3)] for p in phases], dtype=float)
    totals = raw.sum(axis=1, keepdims=True)
    totals[totals == 0] = 1  # avoid /0
    pct = raw / totals * 100

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # ── Left panel: 100 % stacked bars ──
    x = np.arange(len(phases))
    bottom = np.zeros(len(phases))
    for a_idx in range(3):
        vals = pct[:, a_idx]
        bars = ax1.bar(x, vals, bottom=bottom, color=ACTION_COLORS[a_idx],
                       label=ACTION_NAMES[a_idx], edgecolor="white", linewidth=0.6, width=0.55)
        # Label inside each segment if big enough
        for xi, (v, b) in enumerate(zip(vals, bottom)):
            if v > 5:
                ax1.text(xi, b + v / 2, f"{v:.1f}%", ha="center", va="center",
                         fontsize=9, fontweight="bold", color="white")
        bottom += vals

    ax1.set_xticks(x)
    ax1.set_xticklabels(x_labels, fontsize=10)
    ax1.set_ylabel("Action Share (%)", fontsize=12)
    ax1.set_title("Action Proportion per Load Phase", fontsize=13, fontweight="bold", pad=12)
    ax1.set_ylim(0, 105)
    ax1.legend(loc="upper right", fontsize=9, framealpha=0.9)
    ax1.grid(True, alpha=0.15, axis="y")
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    # ── Right panel: raw counts, log scale ──
    bar_w = 0.22
    for a_idx in range(3):
        counts = raw[:, a_idx]
        bars = ax2.bar(x + a_idx * bar_w, counts, bar_w,
                       label=ACTION_NAMES[a_idx], color=ACTION_COLORS[a_idx],
                       edgecolor="white", linewidth=0.5)
        for bar, cnt in zip(bars, counts):
            if cnt > 0:
                ax2.text(bar.get_x() + bar.get_width() / 2, cnt * 1.15,
                         f"{int(cnt):,}", ha="center", va="bottom", fontsize=7, color="#475569")

    ax2.set_xticks(x + bar_w)
    ax2.set_xticklabels(x_labels, fontsize=10)
    ax2.set_ylabel("Count (log scale)", fontsize=12)
    ax2.set_yscale("log")
    ax2.set_title("Raw Action Counts (Log Scale)", fontsize=13, fontweight="bold", pad=12)
    ax2.legend(loc="upper right", fontsize=9, framealpha=0.9)
    ax2.grid(True, alpha=0.15, axis="y")
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    fig.tight_layout()
    path = os.path.join(OUTPUT_DIR, "action_distribution.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[✓] Saved {path}")


# ── 2. Q-TABLE HEATMAP ─────────────────────────────────────────────────
def plot_q_heatmap():
    """
    Visualise the learned Q-values as a heatmap:
    Y-axis = threat score bin, X-axis = analyst load bin.
    Cell colour = best action (Dismiss/Monitor/Escalate).
    """
    q_table = np.load(Q_TABLE_PATH)
    visits = np.load(VISIT_PATH)
    
    if q_table.ndim == 5:
        # Marginalise over density and port → (threat, load, action)
        q_agg = q_table.mean(axis=(2, 3))  # shape (20, 20, 3)
        v_agg = visits.sum(axis=(2, 3))     # shape (20, 20, 3)
    elif q_table.ndim == 4:
        q_agg = q_table.mean(axis=2)
        v_agg = visits.sum(axis=2)
    else:
        print("[!] Unexpected Q-table shape, skipping heatmap")
        return
    
    best_action = q_agg.argmax(axis=-1)  # (20, 20)
    
    # Custom colormap: 0=Dismiss(blue), 1=Monitor(orange), 2=Escalate(red)
    from matplotlib.colors import ListedColormap
    cmap = ListedColormap(ACTION_COLORS)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(best_action, cmap=cmap, aspect="auto", origin="lower",
                   vmin=0, vmax=2)
    
    ax.set_xlabel("Analyst Load Bin (0=idle → 19=overloaded)", fontsize=12)
    ax.set_ylabel("Threat Score Bin (0=benign → 19=critical)", fontsize=12)
    ax.set_title("Learned Policy Heatmap\n(Best Action by Threat Score × Analyst Load)",
                 fontsize=14, fontweight="bold", pad=15)
    
    # Custom legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=ACTION_COLORS[0], label="Dismiss"),
        Patch(facecolor=ACTION_COLORS[1], label="Monitor"),
        Patch(facecolor=ACTION_COLORS[2], label="Escalate"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", fontsize=10, framealpha=0.9)
    
    fig.tight_layout()
    path = os.path.join(OUTPUT_DIR, "q_policy_heatmap.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[✓] Saved {path}")


# ── 3. THREAT SCORE DISTRIBUTION ───────────────────────────────────────
def plot_score_histogram(state):
    """
    Grouped bar chart of threat scores by discrete score bucket,
    split by true label (benign vs attack). Avoids empty gaps.
    """
    logs = state.get("logs", [])
    if len(logs) < 10:
        print("[!] Not enough logs for score histogram")
        return

    # Collect scores per label
    from collections import Counter
    benign_scores = [round(e["threat_score"], 4) for e in logs if e["true_label"] == 0]
    attack_scores = [round(e["threat_score"], 4) for e in logs if e["true_label"] == 1]

    # Find all unique score buckets
    all_scores = sorted(set(benign_scores + attack_scores))
    score_labels = [f"{s:.4f}" if s < 0.01 else f"{s:.2f}" for s in all_scores]

    benign_counts = Counter(benign_scores)
    attack_counts = Counter(attack_scores)

    x = np.arange(len(all_scores))
    bar_w = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))

    b_vals = [benign_counts.get(s, 0) for s in all_scores]
    a_vals = [attack_counts.get(s, 0) for s in all_scores]

    bars_b = ax.bar(x - bar_w / 2, b_vals, bar_w, label=f"Benign (n={len(benign_scores)})",
                    color="#22c55e", edgecolor="white", linewidth=0.6)
    bars_a = ax.bar(x + bar_w / 2, a_vals, bar_w, label=f"Attack (n={len(attack_scores)})",
                    color="#ef4444", edgecolor="white", linewidth=0.6)

    # Count labels on top
    for bar, cnt in zip(bars_b, b_vals):
        if cnt > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, cnt + 0.4,
                    str(cnt), ha="center", va="bottom", fontsize=10, fontweight="bold", color="#16a34a")
    for bar, cnt in zip(bars_a, a_vals):
        if cnt > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, cnt + 0.4,
                    str(cnt), ha="center", va="bottom", fontsize=10, fontweight="bold", color="#dc2626")

    ax.set_xticks(x)
    ax.set_xticklabels(score_labels, fontsize=11)
    ax.set_xlabel("Calibrated Threat Score", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("Threat Score Distribution (Benign vs Attack)", fontsize=14, fontweight="bold", pad=15)
    ax.legend(fontsize=11, framealpha=0.9)
    ax.grid(True, alpha=0.15, axis="y")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    path = os.path.join(OUTPUT_DIR, "score_distribution.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[✓] Saved {path}")


# ── 4. REWARD PER ACTION TYPE ──────────────────────────────────────────
def plot_reward_per_action(state):
    """
    Box-plot style comparison of rewards received for each action type.
    Shows whether the bandit learned the correct reward structure.
    """
    logs = state.get("logs", [])
    if len(logs) < 10:
        print("[!] Not enough logs for reward plot")
        return
    
    rewards_by_action = defaultdict(list)
    for e in logs:
        action_name = e.get("action", "Dismiss")
        rewards_by_action[action_name].append(e["reward"])
    
    fig, ax = plt.subplots(figsize=(9, 5))
    
    data = []
    labels = []
    colors = []
    for i, name in enumerate(ACTION_NAMES):
        if name in rewards_by_action and rewards_by_action[name]:
            data.append(rewards_by_action[name])
            labels.append(f"{name}\n(n={len(rewards_by_action[name])})")
            colors.append(ACTION_COLORS[i])
    
    bp = ax.boxplot(data, patch_artist=True, labels=labels,
                    medianprops=dict(color="#1e293b", linewidth=2))
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)
    
    ax.set_ylabel("Reward", fontsize=12)
    ax.set_title("Reward Distribution per Action Type", fontsize=14, fontweight="bold", pad=15)
    ax.grid(True, alpha=0.2, axis="y")
    ax.axhline(y=0, color="#64748b", linestyle="--", alpha=0.5, linewidth=1)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    path = os.path.join(OUTPUT_DIR, "reward_per_action.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[✓] Saved {path}")


# ── 5. CONFUSION MATRIX ────────────────────────────────────────────────
def plot_confusion_matrix(state, progress):
    """
    Build and display a confusion matrix from the final sim metrics.
    Rows = true label, Cols = predicted action.
    """
    logs = state.get("logs", [])
    if len(logs) < 10:
        print("[!] Not enough logs for confusion matrix")
        return
    
    # 2x3 matrix: true_label (0=benign, 1=attack) × action (0=dismiss, 1=monitor, 2=escalate)
    cm = np.zeros((2, 3), dtype=int)
    for e in logs:
        tl = e["true_label"]
        ai = ACTION_NAMES.index(e["action"]) if e["action"] in ACTION_NAMES else 0
        cm[tl, ai] += 1
    
    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(cm, cmap="YlOrRd", aspect="auto")
    
    ax.set_xticks(range(3))
    ax.set_xticklabels(ACTION_NAMES, fontsize=12)
    ax.set_yticks(range(2))
    ax.set_yticklabels(["Benign", "Attack"], fontsize=12)
    ax.set_xlabel("Bandit Action", fontsize=13)
    ax.set_ylabel("True Label", fontsize=13)
    ax.set_title("Action Confusion Matrix\n(True Label vs Bandit Decision)", fontsize=14, fontweight="bold", pad=15)
    
    # Annotate cells
    for i in range(2):
        for j in range(3):
            val = cm[i, j]
            text_color = "#ffffff" if val > cm.max() * 0.5 else "#1e293b"
            ax.text(j, i, f"{val:,}", ha="center", va="center",
                    fontsize=16, fontweight="bold", color=text_color)
    
    fig.colorbar(im, ax=ax, shrink=0.7, label="Count")
    fig.tight_layout()
    path = os.path.join(OUTPUT_DIR, "confusion_matrix.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[✓] Saved {path}")


# ── 6. SUMMARY METRICS CARD ────────────────────────────────────────────
def plot_metrics_card(progress):
    """
    A clean summary card showing the headline numbers.
    """
    p = progress
    metrics = {
        "Precision": p.get("precision", 0),
        "Recall": p.get("recall", 0),
        "F1-Score": 2 * p.get("precision", 0) * p.get("recall", 0) /
                    max(1e-9, p.get("precision", 0) + p.get("recall", 0)),
        "Cumulative Reward": p.get("cumulative_reward", 0),
        "Total Sim Steps": p.get("sim_step", 0),
        "ε (final)": p.get("epsilon", 0),
    }
    
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.axis("off")
    
    # Title
    ax.text(0.5, 0.95, "Adaptive Triage Engine — Final Metrics Summary",
            transform=ax.transAxes, ha="center", va="top",
            fontsize=16, fontweight="bold", color="#1e293b")
    
    cols = 3
    rows = 2
    for idx, (name, val) in enumerate(metrics.items()):
        row = idx // cols
        col = idx % cols
        x = 0.15 + col * 0.35
        y = 0.65 - row * 0.35
        
        if isinstance(val, float) and val < 10:
            val_str = f"{val:.4f}"
        elif isinstance(val, float):
            val_str = f"{val:,.0f}"
        else:
            val_str = f"{val:,}"
        
        ax.text(x, y, val_str, transform=ax.transAxes,
                ha="center", va="center", fontsize=22, fontweight="bold",
                color="#2563eb")
        ax.text(x, y - 0.1, name, transform=ax.transAxes,
                ha="center", va="center", fontsize=11, color="#64748b")
    
    fig.tight_layout()
    path = os.path.join(OUTPUT_DIR, "metrics_summary.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[✓] Saved {path}")


# ── MAIN ────────────────────────────────────────────────────────────────
def main():
    state, progress, q_table, visits = load_data()
    print(f"Q-table shape: {q_table.shape}")
    print(f"Visit count shape: {visits.shape}")
    print(f"Total sim steps: {progress.get('sim_step', '?')}")
    print(f"Logged events: {len(state.get('logs', []))}")
    print()
    
    plot_action_distribution(state)
    plot_q_heatmap()
    plot_score_histogram(state)
    plot_reward_per_action(state)
    plot_confusion_matrix(state, progress)
    plot_metrics_card(progress)
    
    print(f"\n[✓] All charts saved to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
