"""
features.py — Feature engineering for the Adaptive Triage Engine.

Converts raw CIC-IDS2018 flow features into a standardised, binary-labelled
dataset optimised for GPU XGBoost training.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


# ── Feature columns we actually use ────────────────────────
# CICFlowMeter already exports 80+ statistical features.
# We keep the most predictive ones to reduce memory & latency.
SELECTED_FEATURES = [
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

# Shared scaler instance (supports incremental .partial_fit)
_scaler = StandardScaler()
_scaler_fitted = False


def _binarise_label(df: pd.DataFrame) -> pd.Series:
    """Map the Label column to binary: Benign=0, everything else=1."""
    return (df["Label"].str.strip().str.lower() != "benign").astype(np.int8)


def preprocess_features(df_chunk: pd.DataFrame, fit_scaler: bool = True):
    """
    Convert a raw CIC-IDS2018 chunk into (X, y) ready for XGBoost.

    Parameters
    ----------
    df_chunk : pd.DataFrame
        A single chunk from data_loader.
    fit_scaler : bool
        If True, calls partial_fit + transform. If False, transform only.

    Returns
    -------
    X : np.ndarray   (float32)
    y : np.ndarray   (int8)
    """
    global _scaler, _scaler_fitted

    # ── 1. Binary label (optional — missing for single-flow inference) ──
    if "Label" in df_chunk.columns:
        y = _binarise_label(df_chunk)
    else:
        y = None

    # ── 2. Feature selection — guarantee exactly SELECTED_FEATURES ──
    for c in SELECTED_FEATURES:
        if c not in df_chunk.columns:
            df_chunk[c] = 0
            
    X = df_chunk[SELECTED_FEATURES].copy()

    # ── 3. Downcast to float32 ──
    X = X.astype(np.float32)

    # ── 4. Scale ──
    if fit_scaler:
        _scaler.partial_fit(X)
        _scaler_fitted = True

    if _scaler_fitted:
        X_scaled = _scaler.transform(X).astype(np.float32)
    else:
        X_scaled = X.values

    return X_scaled, y.values if y is not None else None


def get_feature_names():
    """Return the ordered list of feature column names currently selected."""
    return list(SELECTED_FEATURES)


def save_scaler(path: str):
    """Persist the fitted StandardScaler to disk."""
    import joblib
    joblib.dump(_scaler, path)
    print(f"[Features] Scaler saved → {path}")


def load_scaler(path: str):
    """Load a previously saved StandardScaler."""
    import joblib
    return joblib.load(path)


# ── CLI quick-test ──────────────────────────────────────────
if __name__ == "__main__":
    from data_loader import load_data_in_chunks

    print("=" * 60)
    print("  Feature Engineering — Quick Test (1 chunk)")
    print("=" * 60)

    for chunk in load_data_in_chunks(max_chunks=1):
        X, y = preprocess_features(chunk)
        print(f"  X shape : {X.shape}  dtype: {X.dtype}")
        print(f"  y shape : {y.shape}  unique: {np.unique(y)}")
        print(f"  Threat rate: {y.mean():.2%}")
        break

    print("=" * 60)
