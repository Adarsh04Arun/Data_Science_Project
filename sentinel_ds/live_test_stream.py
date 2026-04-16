#!/usr/bin/env python3
"""
live_test_stream.py — Real-time streaming flow tester for the Adaptive Triage Engine.

Randomly samples real network flows from the dataset files and sends them
one-by-one to /api/test-flow, displaying a live terminal dashboard.

Usage examples
--------------
    python3 live_test_stream.py                          # 50 flows, 40% attacks, all types
    python3 live_test_stream.py --n-flows 200            # stream 200 flows
    python3 live_test_stream.py --attack-ratio 0.8       # 80% of flows are attacks
    python3 live_test_stream.py --attack-type ddos       # only DDoS attacks in the mix
    python3 live_test_stream.py --attack-type bruteforce # only Brute Force
    python3 live_test_stream.py --delay-ms 0             # as fast as possible (benchmark)
    python3 live_test_stream.py --no-update              # freeze Q-table (pure eval mode)
    python3 live_test_stream.py --save results.json      # also save raw results to JSON
    python3 live_test_stream.py --seed 123               # reproducible random sample
"""

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import requests

# ── Paths ───────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
DATA_DIR = (_HERE.parent / "Dataset" / "Data").resolve()
API_URL = "http://localhost:8000/api/test-flow"

# ── Feature list (kept in sync with src/features.py) ────────────────────────
sys.path.insert(0, str(_HERE / "src"))
try:
    from features import SELECTED_FEATURES  # type: ignore
except ImportError:
    SELECTED_FEATURES: List[str] = [
        "Dst Port",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "TotLen Fwd Pkts",
        "TotLen Bwd Pkts",
        "Fwd Pkt Len Max",
        "Fwd Pkt Len Min",
        "Fwd Pkt Len Mean",
        "Fwd Pkt Len Std",
        "Bwd Pkt Len Max",
        "Bwd Pkt Len Min",
        "Bwd Pkt Len Mean",
        "Bwd Pkt Len Std",
        "Flow Byts/s",
        "Flow Pkts/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Tot",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Tot",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Fwd Header Len",
        "Bwd Header Len",
        "Fwd Pkts/s",
        "Bwd Pkts/s",
        "Pkt Len Min",
        "Pkt Len Max",
        "Pkt Len Mean",
        "Pkt Len Std",
        "Pkt Len Var",
        "FIN Flag Cnt",
        "SYN Flag Cnt",
        "RST Flag Cnt",
        "PSH Flag Cnt",
        "ACK Flag Cnt",
        "Down/Up Ratio",
        "Pkt Size Avg",
        "Fwd Seg Size Avg",
        "Bwd Seg Size Avg",
        "Init Fwd Win Byts",
        "Init Bwd Win Byts",
        "Fwd Act Data Pkts",
        "Fwd Seg Size Min",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ]

# ── Attack-type keyword map ──────────────────────────────────────────────────
# Keys are CLI values; values are substrings matched against the Label column.
ATTACK_TYPE_MAP: Dict[str, List[str]] = {
    "all": [],  # empty = accept any non-benign label
    "ddos": ["ddos", "ddo s"],
    "bruteforce": [
        "brute force",
        "bruteforce",
        "ftp-patator",
        "ssh-patator",
        "web brute force",
        "ftp patator",
        "ssh patator",
    ],
    "portscan": ["portscan", "port scan", "port-scan"],
    "dos": ["dos", "hulk", "goldeneye", "slowloris", "slowhttptest"],
    "botnet": ["bot", "botnet"],
    "infiltration": ["infiltration"],
    "web": ["web attack", "xss", "sql injection", "sql-injection"],
}

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


# ════════════════════════════════════════════════════════════════════════════
# Data Loading
# ════════════════════════════════════════════════════════════════════════════


def _load_file(path: Path, max_rows: int = 15_000) -> pd.DataFrame:
    """Load up to *max_rows* from a Parquet or CSV file. Returns empty DF on error."""
    try:
        if path.suffix == ".parquet":
            try:
                import pyarrow.parquet as pq

                pf = pq.ParquetFile(path)
                batch = next(pf.iter_batches(batch_size=max_rows))
                return batch.to_pandas()
            except Exception:
                return pd.read_parquet(path).head(max_rows)
        elif path.suffix == ".csv":
            return pd.read_csv(path, nrows=max_rows)
    except Exception as exc:
        print(f"  {YELLOW}[skip] {path.name}: {exc}{RESET}")
    return pd.DataFrame()


def load_flows(
    n_flows: int,
    attack_ratio: float,
    attack_type: str = "all",
    seed: int = 42,
) -> List[pd.Series]:
    """
    Return a shuffled list of *n_flows* real pandas Series rows sampled from
    the dataset directory, respecting the requested attack/benign ratio.

    Parameters
    ----------
    n_flows       : total number of flows to return
    attack_ratio  : fraction [0–1] that should be real attacks
    attack_type   : one of the keys in ATTACK_TYPE_MAP ("all", "ddos", …)
    seed          : random seed for reproducibility
    """
    rng = random.Random(seed)
    np.random.seed(seed)

    n_attacks = max(0, int(round(n_flows * attack_ratio)))
    n_benign = n_flows - n_attacks
    attack_kws = ATTACK_TYPE_MAP.get(attack_type.lower(), [])

    # Discover dataset files
    all_files: List[Path] = sorted(DATA_DIR.glob("*.parquet")) + sorted(
        DATA_DIR.glob("*.csv")
    )
    if not all_files:
        print(f"{RED}No dataset files found in {DATA_DIR}{RESET}")
        sys.exit(1)

    print(f"\n{CYAN}Loading dataset files…{RESET}")

    benign_pool: List[pd.Series] = []
    attack_pool: List[pd.Series] = []

    # Shuffle file order so we don't always pull from the same files
    file_order = all_files[:]
    rng.shuffle(file_order)

    for fp in file_order:
        if len(benign_pool) >= n_benign * 4 and len(attack_pool) >= n_attacks * 4:
            break  # have enough headroom to sample from

        df = _load_file(fp)
        if df.empty or "Label" not in df.columns:
            continue

        # Normalise
        df.columns = df.columns.str.strip()
        df["Label"] = df["Label"].astype(str).str.strip()

        # Drop rows with Inf / NaN in any selected feature column
        feat_cols = [c for c in SELECTED_FEATURES if c in df.columns]
        df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=feat_cols)
        if df.empty:
            continue

        for _, row in df.iterrows():
            lbl_lower = row["Label"].lower()
            if lbl_lower == "benign":
                benign_pool.append(row)
            else:
                # Accept if no filter, or if label matches any keyword
                if not attack_kws or any(kw in lbl_lower for kw in attack_kws):
                    attack_pool.append(row)

    # Clamp requests to what is available
    if len(benign_pool) < n_benign:
        print(
            f"  {YELLOW}Only {len(benign_pool)} benign flows available "
            f"(requested {n_benign}) — adjusting{RESET}"
        )
        n_benign = len(benign_pool)

    if len(attack_pool) < n_attacks:
        print(
            f"  {YELLOW}Only {len(attack_pool)} attack flows available "
            f"(requested {n_attacks}) — adjusting{RESET}"
        )
        n_attacks = len(attack_pool)

    sampled = rng.sample(benign_pool, n_benign) + rng.sample(attack_pool, n_attacks)
    rng.shuffle(sampled)

    print(
        f"  {GREEN}Sampled {len(sampled)} flows "
        f"({n_attacks} attacks · {n_benign} benign){RESET}\n"
    )
    return sampled


# ════════════════════════════════════════════════════════════════════════════
# Payload construction
# ════════════════════════════════════════════════════════════════════════════


def build_payload(
    row: pd.Series,
    analyst_load: float = 0.3,
    send_label: bool = True,
) -> Dict[str, Any]:
    """
    Convert a DataFrame row into the JSON body expected by /api/test-flow.

    The 61 SELECTED_FEATURES are forwarded as numeric values.
    Src IP and Dst Port are also included when available so the behaviour
    aggregator on the API side can track real per-source-IP windows.
    """
    features: Dict[str, float] = {}
    for feat in SELECTED_FEATURES:
        val = row.get(feat, 0.0)
        try:
            fval = float(val)
        except (TypeError, ValueError):
            fval = 0.0
        if pd.isna(fval) or np.isinf(fval):
            fval = 0.0
        features[feat] = fval

    # Pass Src IP as a string feature so the behaviour aggregator can use it
    # as the per-source rolling-window key instead of falling back to dst_port.
    src_ip = row.get("Src IP", None) or row.get("src_ip", None)
    if src_ip is not None:
        features["Src IP"] = str(src_ip).strip()

    payload: Dict[str, Any] = {
        "features": features,
        "analyst_load": analyst_load,
    }
    if send_label:
        payload["label"] = str(row.get("Label", "Unknown")).strip()
    return payload


# ════════════════════════════════════════════════════════════════════════════
# Terminal display helpers
# ════════════════════════════════════════════════════════════════════════════


def _outcome_fmt(outcome: Optional[str]) -> str:
    if not outcome:
        return f"{DIM}  ?  {RESET}"
    pal = {"TP": GREEN, "TN": BLUE, "FP": YELLOW, "FN": RED}
    sym = {"TP": "✓", "TN": "✓", "FP": "✗", "FN": "✗"}
    c = pal.get(outcome, RESET)
    return f"{c}{outcome} {sym.get(outcome, '')}{RESET}"


def _action_fmt(action: str) -> str:
    if action == "Escalate":
        return f"{RED}Escalate{RESET}"
    if action == "Monitor":
        return f"{YELLOW}Monitor {RESET}"
    return f"{GREEN}Dismiss {RESET}"


def _level_fmt(level: str) -> str:
    if level == "HIGH":
        return f"{RED}HIGH  {RESET}"
    if level == "MEDIUM":
        return f"{YELLOW}MED   {RESET}"
    return f"{GREEN}LOW   {RESET}"


def print_header(
    n_flows: int, attack_ratio: float, delay_ms: int, attack_type: str, no_update: bool
) -> None:
    bar = "═" * 78
    print(f"\n{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}{CYAN}  ADAPTIVE TRIAGE ENGINE — Live Stream Test{RESET}")
    print(f"{CYAN}{bar}{RESET}")
    print(
        f"  Flows : {BOLD}{n_flows}{RESET}   "
        f"Attack ratio : {BOLD}{attack_ratio * 100:.0f}%{RESET}   "
        f"Type : {BOLD}{attack_type}{RESET}   "
        f"Delay : {BOLD}{delay_ms}ms{RESET}   "
        f"Q-table update : {BOLD}{'OFF (eval mode)' if no_update else 'ON'}{RESET}"
    )
    print(f"{CYAN}{'─' * 78}{RESET}")
    print(
        f"  {'#':<7} {'Label':<18} {'Score':>7}  "
        f"{'Level':<7} {'Action':<10} {'Outcome':<8} {'Reward':>9}"
    )
    print(f"{CYAN}{'─' * 78}{RESET}")


def print_flow_line(idx: int, total: int, label: str, result: Dict) -> None:
    score = result.get("threat_score", 0.0)
    level = result.get("threat_level", "?")
    action = result.get("action", "?")
    outcome = result.get("outcome")
    reward = result.get("reward")

    score_str = f"{score * 100:>6.1f}%"
    reward_str = f"{reward:>+9.1f}" if reward is not None else f"{'—':>9}"

    print(
        f"  {idx:>4}/{total:<4}  "
        f"{label:<18} "
        f"{score_str}  "
        f"{_level_fmt(level):<7} "
        f"{_action_fmt(action):<10} "
        f"{_outcome_fmt(outcome):<8} "
        f"{reward_str}"
    )


def print_metrics(results: List[Dict], final: bool = False) -> None:
    labeled = [r for r in results if r.get("outcome")]
    if not labeled:
        return

    tp = sum(1 for r in labeled if r["outcome"] == "TP")
    fp = sum(1 for r in labeled if r["outcome"] == "FP")
    tn = sum(1 for r in labeled if r["outcome"] == "TN")
    fn = sum(1 for r in labeled if r["outcome"] == "FN")

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    fpr = fp / max(1, fp + tn)

    title = (
        "FINAL RESULTS"
        if final
        else f"Running Metrics  ({len(labeled)} labelled flows)"
    )
    bar = "═" * 78 if final else "─" * 78

    print(f"\n{CYAN}{bar}{RESET}")
    print(f"  {BOLD}{title}{RESET}")

    # Row 1 — rates
    dr_col = GREEN if recall >= 0.95 else (YELLOW if recall >= 0.8 else RED)
    prec_col = GREEN if precision >= 0.8 else (YELLOW if precision >= 0.6 else RED)
    f1_col = GREEN if f1 >= 0.85 else (YELLOW if f1 >= 0.7 else RED)
    fpr_col = GREEN if fpr <= 0.2 else (YELLOW if fpr <= 0.5 else RED)

    print(
        f"  Detection Rate : {dr_col}{recall * 100:.1f}%{RESET}   "
        f"Precision : {prec_col}{precision * 100:.1f}%{RESET}   "
        f"F1 : {f1_col}{f1 * 100:.1f}%{RESET}   "
        f"False Alarm Rate : {fpr_col}{fpr * 100:.1f}%{RESET}"
    )

    # Row 2 — raw counts
    fn_str = (
        f"{RED}{fn} ← MISSED THREATS{RESET}"
        if fn > 0
        else f"{GREEN}{fn} ✓ none missed{RESET}"
    )
    print(
        f"  TP : {GREEN}{tp}{RESET}   "
        f"FP : {YELLOW}{fp}{RESET}   "
        f"TN : {BLUE}{tn}{RESET}   "
        f"FN : {fn_str}"
    )
    print(f"{CYAN}{bar}{RESET}\n")


# ════════════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live streaming flow tester — Adaptive Triage Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--n-flows", type=int, default=50, help="Total number of flows to stream"
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.4,
        help="Fraction of flows that are real attacks [0–1]",
    )
    parser.add_argument(
        "--attack-type",
        type=str,
        default="all",
        choices=list(ATTACK_TYPE_MAP.keys()),
        help="Attack family filter",
    )
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=200,
        help="Milliseconds to wait between each flow",
    )
    parser.add_argument(
        "--analyst-load",
        type=float,
        default=0.3,
        help="Simulated analyst busyness [0–1]",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for reproducible sampling"
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="Freeze Q-table — don't update from labels (eval mode)",
    )
    parser.add_argument(
        "--save",
        type=str,
        default=None,
        help="Path to save full result JSON (e.g. results.json)",
    )
    args = parser.parse_args()

    # ── Sanity checks ────────────────────────────────────────────────────
    if not (0.0 <= args.attack_ratio <= 1.0):
        print(f"{RED}--attack-ratio must be between 0 and 1{RESET}")
        sys.exit(1)

    # ── Verify API is reachable ──────────────────────────────────────────
    try:
        resp = requests.get("http://localhost:8000/api/health", timeout=3)
        if resp.status_code != 200:
            raise ConnectionError
    except Exception:
        print(f"\n{RED}Cannot reach backend at http://localhost:8000{RESET}")
        print(
            f"{YELLOW}Start it with:  cd sentinel_ds && uvicorn api:app --port 8000{RESET}\n"
        )
        sys.exit(1)

    # ── Load real flows from dataset ──────────────────────────────────────
    flows = load_flows(
        n_flows=args.n_flows,
        attack_ratio=args.attack_ratio,
        attack_type=args.attack_type,
        seed=args.seed,
    )
    if not flows:
        print(f"{RED}No flows could be loaded. Check {DATA_DIR}{RESET}")
        sys.exit(1)

    print_header(
        n_flows=len(flows),
        attack_ratio=args.attack_ratio,
        delay_ms=args.delay_ms,
        attack_type=args.attack_type,
        no_update=args.no_update,
    )

    # Warn if Src IP is absent — behaviour aggregator will use dst_port fallback
    sample_row = flows[0] if flows else pd.Series()
    has_src_ip = "Src IP" in sample_row.index or "src_ip" in sample_row.index
    if not has_src_ip:
        print(
            f"  {YELLOW}Note: 'Src IP' column not found in dataset — "
            f"behaviour aggregator will use dst_port as source key{RESET}\n"
        )

    results: List[Dict] = []
    errors = 0

    for idx, row in enumerate(flows, 1):
        label = str(row.get("Label", "Unknown")).strip()
        payload = build_payload(
            row,
            analyst_load=args.analyst_load,
            send_label=(not args.no_update),  # omit label → no Q-table update
        )
        # Always include the original label in metadata for display
        # (even in no-update mode where it is not sent to the API)
        payload.setdefault("_display_label", label)

        try:
            resp = requests.post(API_URL, json=payload, timeout=10)
            result = resp.json()
            if "error" in result:
                print(f"  {RED}API error on flow {idx}: {result['error']}{RESET}")
                errors += 1
                continue
        except requests.exceptions.ConnectionError:
            print(f"\n{RED}Lost connection to API at {API_URL}{RESET}")
            print(f"{YELLOW}Is the backend still running?{RESET}\n")
            break
        except requests.exceptions.Timeout:
            print(f"  {YELLOW}Timeout on flow {idx} — skipping{RESET}")
            errors += 1
            continue
        except Exception as exc:
            print(f"  {RED}Unexpected error on flow {idx}: {exc}{RESET}")
            errors += 1
            continue

        # Store original label for display (even in no-update mode)
        result["_label"] = label
        results.append(result)

        print_flow_line(idx, len(flows), label, result)

        # Print running metrics every 10 flows
        if idx % 10 == 0:
            print_metrics(results, final=False)

        if args.delay_ms > 0:
            time.sleep(args.delay_ms / 1000.0)

    # ── Final summary ─────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}{'═' * 78}{RESET}")
    print(
        f"{BOLD}  STREAM COMPLETE — "
        f"{len(results)} flows processed · {errors} errors{RESET}"
    )
    print_metrics(results, final=True)

    if args.save:
        out_path = Path(args.save)
        with open(out_path, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"{GREEN}Results saved → {out_path.resolve()}{RESET}\n")


if __name__ == "__main__":
    main()
