#!/usr/bin/env python3
"""
extract_scenarios.py — Extract real attack & benign feature vectors
from CIC-IDS2018 parquet files for the Test Model tab.

Saves scenario_vectors.json into output/ with pre-computed 24-feature
vectors that the XGBoost model can score directly.

Usage:
    python3 extract_scenarios.py
"""

import os, sys, json, glob
import numpy as np

# Ensure src/ importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

DATA_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "Dataset", "Data")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

# The 24 features available in the parquet files (same order as model)
MODEL_FEATURES = [
    "Flow Duration",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Down/Up Ratio", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def main():
    import pyarrow.parquet as pq
    import pandas as pd

    parquet_files = sorted(glob.glob(os.path.join(os.path.abspath(DATA_DIR), "*.parquet")))
    if not parquet_files:
        print("No parquet files found!")
        return

    # Read 10K rows from EACH file to get diverse attack types
    all_rows = []
    for f in parquet_files:
        pf = pq.ParquetFile(f)
        file_rows = []
        for batch in pf.iter_batches(batch_size=10000):
            df = batch.to_pandas()
            if "Label" not in df.columns:
                continue
            avail = [c for c in MODEL_FEATURES if c in df.columns]
            sub = df[avail + ["Label"]].replace([np.inf, -np.inf], np.nan).dropna()
            if len(sub) > 0:
                file_rows.append(sub)
            if sum(len(r) for r in file_rows) >= 10000:
                break
        if file_rows:
            combined = pd.concat(file_rows, ignore_index=True)
            all_rows.append(combined)
            print(f"  {os.path.basename(f)}: {len(combined):,} rows, labels={combined['Label'].str.strip().unique()}")

    df_all = pd.concat(all_rows, ignore_index=True)
    print(f"Loaded {len(df_all):,} rows")

    # Label distribution
    labels = df_all["Label"].str.strip().str.lower()
    print(f"\nLabel distribution:")
    for lab, cnt in labels.value_counts().items():
        print(f"  {lab}: {cnt:,}")

    # Separate
    benign_mask = labels == "benign"
    attack_mask = ~benign_mask

    benign_df = df_all[benign_mask]
    attack_df = df_all[attack_mask]

    scenarios = {}

    # 1. Benign — take the median row
    if len(benign_df) > 0:
        benign_vec = benign_df[MODEL_FEATURES].median().values
        scenarios["normal_benign"] = {
            "name": "🟢 Normal Benign Traffic",
            "desc": "Median values from all benign flows in CIC-IDS2018",
            "features": [float(v) for v in benign_vec],
        }
        print(f"\n✅ Benign scenario: median of {len(benign_df):,} rows")

    # 2. Per-attack-type scenarios — take the median of each attack label
    attack_types = df_all.loc[attack_mask, "Label"].str.strip().value_counts()
    labels_to_use = {
        "Brute Force": ("🔴 SSH Brute Force", "Real brute force attack pattern from CIC-IDS2018"),
        "Bot": ("🔴 Botnet Activity", "Real bot communication pattern from CIC-IDS2018"),
        "DoS attacks-Hulk": ("🔴 DoS Hulk Attack", "Real DoS Hulk attack pattern from CIC-IDS2018"),
        "DDoS attacks-LOIC-HTTP": ("🔴 DDoS LOIC-HTTP", "Real DDoS LOIC attack pattern from CIC-IDS2018"),
        "Infilteration": ("🟡 Infiltration", "Real infiltration/exfiltration pattern from CIC-IDS2018"),
        "DoS attacks-SlowHTTPTest": ("🟡 DoS Slowloris", "Real slow HTTP DoS pattern from CIC-IDS2018"),
        "FTP-BruteForce": ("🔴 FTP Brute Force", "Real FTP brute force pattern from CIC-IDS2018"),
        "SSH-Bruteforce": ("🔴 SSH Bruteforce", "Real SSH bruteforce pattern from CIC-IDS2018"),
        "DDOS attack-HOIC": ("🔴 DDoS HOIC", "Real DDoS HOIC attack pattern from CIC-IDS2018"),
        "DoS attacks-GoldenEye": ("🔴 DoS GoldenEye", "Real DoS GoldenEye attack from CIC-IDS2018"),
    }

    for raw_label, cnt in attack_types.head(10).items():
        label = raw_label.strip()
        mask = df_all["Label"].str.strip() == label
        sub = df_all.loc[mask, MODEL_FEATURES]
        if len(sub) < 5:
            continue
        vec = sub.median().values
        
        if label in labels_to_use:
            name, desc = labels_to_use[label]
        else:
            name = f"🔴 {label}"
            desc = f"Real {label} pattern from CIC-IDS2018 ({cnt:,} samples)"
        
        key = label.lower().replace(" ", "_").replace("-", "_")
        scenarios[key] = {
            "name": name,
            "desc": desc,
            "features": [float(v) for v in vec],
            "sample_count": int(cnt),
        }
        print(f"✅ {label}: median of {cnt:,} attack rows")

    # Save
    out_path = os.path.join(OUTPUT_DIR, "scenario_vectors.json")
    with open(out_path, "w") as f:
        json.dump({
            "feature_names": MODEL_FEATURES,
            "scenarios": scenarios,
        }, f, indent=2)

    print(f"\n📦 Saved {len(scenarios)} scenarios → {out_path}")


if __name__ == "__main__":
    main()
