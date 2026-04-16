"""
data_loader.py — Memory-safe chunked data loader for CIC-IDS2018 parquet files.

Yields pandas DataFrames in manageable chunks using PyArrow's
iter_batches() to strictly keep memory below the WSL system limit.
"""

import os
import glob
import numpy as np
import pandas as pd
import pyarrow.parquet as pq


# ── CIC-IDS2017 (Parquet) → CIC-IDS2018 (SELECTED_FEATURES) alias map ──
# Parquet files use long column names; SELECTED_FEATURES uses abbreviated names.
# Keys are lowercase long names, values are the canonical short names.
_COL_ALIASES = {
    "total fwd packets":       "Tot Fwd Pkts",
    "total backward packets":  "Tot Bwd Pkts",
    "fwd packets length total":"TotLen Fwd Pkts",
    "bwd packets length total":"TotLen Bwd Pkts",
    "fwd packet length max":   "Fwd Pkt Len Max",
    "fwd packet length min":   "Fwd Pkt Len Min",
    "fwd packet length mean":  "Fwd Pkt Len Mean",
    "fwd packet length std":   "Fwd Pkt Len Std",
    "bwd packet length max":   "Bwd Pkt Len Max",
    "bwd packet length min":   "Bwd Pkt Len Min",
    "bwd packet length mean":  "Bwd Pkt Len Mean",
    "bwd packet length std":   "Bwd Pkt Len Std",
    "flow bytes/s":            "Flow Byts/s",
    "flow packets/s":          "Flow Pkts/s",
    "fwd iat total":           "Fwd IAT Tot",
    "bwd iat total":           "Bwd IAT Tot",
    "fwd header length":       "Fwd Header Len",
    "bwd header length":       "Bwd Header Len",
    "fwd packets/s":           "Fwd Pkts/s",
    "bwd packets/s":           "Bwd Pkts/s",
    "packet length min":       "Pkt Len Min",
    "packet length max":       "Pkt Len Max",
    "packet length mean":      "Pkt Len Mean",
    "packet length std":       "Pkt Len Std",
    "packet length variance":  "Pkt Len Var",
    "fin flag count":          "FIN Flag Cnt",
    "syn flag count":          "SYN Flag Cnt",
    "rst flag count":          "RST Flag Cnt",
    "psh flag count":          "PSH Flag Cnt",
    "ack flag count":          "ACK Flag Cnt",
    "avg packet size":         "Pkt Size Avg",
    "avg fwd segment size":    "Fwd Seg Size Avg",
    "avg bwd segment size":    "Bwd Seg Size Avg",
    "init fwd win bytes":      "Init Fwd Win Byts",
    "init bwd win bytes":      "Init Bwd Win Byts",
    "fwd act data packets":    "Fwd Act Data Pkts",
    "destination port":        "Dst Port",
    "subflow fwd packets":     "Subflow Fwd Pkts",
    "subflow fwd bytes":       "Subflow Fwd Byts",
    "subflow bwd packets":     "Subflow Bwd Pkts",
    "subflow bwd bytes":       "Subflow Bwd Byts",
    # Snake-case flow schema used by the smaller CSV attack sets
    "dst_port":                "Dst Port",
    "duration":                "Flow Duration",
    "fwd_packets_count":       "Tot Fwd Pkts",
    "bwd_packets_count":       "Tot Bwd Pkts",
    "fwd_total_payload_bytes": "TotLen Fwd Pkts",
    "bwd_total_payload_bytes": "TotLen Bwd Pkts",
    "fwd_payload_bytes_max":   "Fwd Pkt Len Max",
    "fwd_payload_bytes_min":   "Fwd Pkt Len Min",
    "fwd_payload_bytes_mean":  "Fwd Pkt Len Mean",
    "fwd_payload_bytes_std":   "Fwd Pkt Len Std",
    "bwd_payload_bytes_max":   "Bwd Pkt Len Max",
    "bwd_payload_bytes_min":   "Bwd Pkt Len Min",
    "bwd_payload_bytes_mean":  "Bwd Pkt Len Mean",
    "bwd_payload_bytes_std":   "Bwd Pkt Len Std",
    "bytes_rate":              "Flow Byts/s",
    "packets_rate":            "Flow Pkts/s",
    "packets_iat_mean":        "Flow IAT Mean",
    "packet_iat_std":          "Flow IAT Std",
    "packet_iat_max":          "Flow IAT Max",
    "packet_iat_min":          "Flow IAT Min",
    "fwd_packets_iat_total":   "Fwd IAT Tot",
    "fwd_packets_iat_mean":    "Fwd IAT Mean",
    "fwd_packets_iat_std":     "Fwd IAT Std",
    "fwd_packets_iat_max":     "Fwd IAT Max",
    "fwd_packets_iat_min":     "Fwd IAT Min",
    "bwd_packets_iat_total":   "Bwd IAT Tot",
    "bwd_packets_iat_mean":    "Bwd IAT Mean",
    "bwd_packets_iat_std":     "Bwd IAT Std",
    "bwd_packets_iat_max":     "Bwd IAT Max",
    "bwd_packets_iat_min":     "Bwd IAT Min",
    "fwd_psh_flag_counts":     "Fwd PSH Flags",
    "fwd_total_header_bytes":  "Fwd Header Len",
    "bwd_total_header_bytes":  "Bwd Header Len",
    "fwd_packets_rate":        "Fwd Pkts/s",
    "bwd_packets_rate":        "Bwd Pkts/s",
    "payload_bytes_min":       "Pkt Len Min",
    "payload_bytes_max":       "Pkt Len Max",
    "payload_bytes_mean":      "Pkt Len Mean",
    "payload_bytes_std":       "Pkt Len Std",
    "payload_bytes_variance":  "Pkt Len Var",
    "fin_flag_counts":         "FIN Flag Cnt",
    "syn_flag_counts":         "SYN Flag Cnt",
    "rst_flag_counts":         "RST Flag Cnt",
    "psh_flag_counts":         "PSH Flag Cnt",
    "ack_flag_counts":         "ACK Flag Cnt",
    "down_up_rate":            "Down/Up Ratio",
    "avg_segment_size":        "Pkt Size Avg",
    "fwd_avg_segment_size":    "Fwd Seg Size Avg",
    "bwd_avg_segment_size":    "Bwd Seg Size Avg",
    "fwd_init_win_bytes":      "Init Fwd Win Byts",
    "bwd_init_win_bytes":      "Init Bwd Win Byts",
    "active_mean":             "Active Mean",
    "active_std":              "Active Std",
    "active_max":              "Active Max",
    "active_min":              "Active Min",
    "idle_mean":               "Idle Mean",
    "idle_std":                "Idle Std",
    "idle_max":                "Idle Max",
    "idle_min":                "Idle Min",
}
# Build reverse lookup: lowercase short name → canonical short name
_COL_ALIASES_REV = {v.lower(): v for v in _COL_ALIASES.values()}

# Some source columns are reasonable fallbacks for more than one model feature.
_FEATURE_FALLBACKS = {
    "Fwd Act Data Pkts": ("fwd_packets_count",),
    "Fwd Seg Size Min": ("fwd_payload_bytes_min",),
}


def clean_chunk(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize column names, handle missing values, and yield cleaned DF."""
    # To handle the severe mismatch between Parquet (78 cols) & CSV (80+ cols),
    # we normalize all columns to lowercase and strip whitespace for robust matching.
    df.columns = df.columns.astype(str).str.strip().str.lower()
    if df.columns.duplicated().any():
        df = df.loc[:, ~df.columns.duplicated(keep="first")].copy()

    # Apply CIC-2017 → CIC-2018 alias mapping before feature matching
    df = df.rename(columns=_COL_ALIASES)
    # Lowercase again after rename (some aliases produce mixed case)
    df.columns = df.columns.str.lower()
    if df.columns.duplicated().any():
        df = df.loc[:, ~df.columns.duplicated(keep="first")].copy()
    
    # We enforce a strict mapping to the canonical `SELECTED_FEATURES`
    try:
        from src.features import SELECTED_FEATURES
    except ImportError:
        from features import SELECTED_FEATURES
    target_features = SELECTED_FEATURES
    target_features_lower = [col.lower() for col in target_features]
    
    # Pre-allocate output df
    out_df = pd.DataFrame(index=df.index)
    
    # Map input columns to strictly match `target_features` (maintaining exact casing expected downstream)
    for orig_name, lower_name in zip(target_features, target_features_lower):
        if lower_name in df.columns:
            out_df[orig_name] = df[lower_name]
        elif lower_name.replace(" ", "_") in df.columns:
            out_df[orig_name] = df[lower_name.replace(" ", "_")]
        elif orig_name in _FEATURE_FALLBACKS:
            fallback_col = next(
                (candidate for candidate in _FEATURE_FALLBACKS[orig_name] if candidate in df.columns),
                None,
            )
            if fallback_col is not None:
                out_df[orig_name] = df[fallback_col]
            else:
                out_df[orig_name] = 0.0
        else:
            out_df[orig_name] = 0.0  # Pad missing features safely
            
    # Always carry over the 'Label' and 'Timestamp' columns if they exist
    if "label" in df.columns:
        out_df["Label"] = df["label"]
    else:
        out_df["Label"] = "Unknown"
        
    # Replace inf/-inf with NaN, drop broken rows
    out_df = out_df.replace([np.inf, -np.inf], np.nan)
    out_df = out_df.dropna()
    
    return out_df


def load_data_in_chunks(
    data_dir: str = None,
    file_list: list = None,
    chunk_size: int = 500_000,
    max_chunks: int = None,
):
    """
    Yield cleaned pandas DataFrames. If file_list is provided, parses only those files.
    """
    if file_list is None:
        if data_dir is None:
            data_dir = os.path.join(
                os.path.dirname(__file__), os.pardir, os.pardir,
                "Dataset", "Data",
            )
        data_dir = os.path.abspath(data_dir)

        # Find both .parquet and .csv files
        data_files = sorted(
            glob.glob(os.path.join(data_dir, "*.parquet")) +
            glob.glob(os.path.join(data_dir, "*.csv"))
        )
    else:
        data_files = file_list

    if not data_files:
        raise FileNotFoundError(
            f"No .parquet or .csv files found for processing"
        )

    print(f"[DataLoader] Found {len(data_files)} data file(s)")

    chunks_yielded = 0
    for fpath in data_files:
        fname = os.path.basename(fpath)
        print(f"[DataLoader] Reading: {fname}")

        if fname.endswith(".parquet"):
            pf = pq.ParquetFile(fpath)
            for batch in pf.iter_batches(batch_size=chunk_size):
                df_chunk = batch.to_pandas()
                df_chunk = clean_chunk(df_chunk)

                if len(df_chunk) == 0:
                    continue

                chunks_yielded += 1
                print(f"[DataLoader]   chunk {chunks_yielded} (.parquet): {len(df_chunk):,} rows")
                yield df_chunk

                if max_chunks is not None and chunks_yielded >= max_chunks:
                    print(f"[DataLoader] Reached max_chunks={max_chunks}, stopping.")
                    return
        elif fname.endswith(".csv"):
            # Use pandas read_csv generator to keep memory low
            for df_chunk in pd.read_csv(fpath, chunksize=chunk_size, low_memory=False):
                df_chunk = clean_chunk(df_chunk)
                
                if len(df_chunk) == 0:
                    continue

                chunks_yielded += 1
                print(f"[DataLoader]   chunk {chunks_yielded} (.csv): {len(df_chunk):,} rows")
                yield df_chunk
                
                if max_chunks is not None and chunks_yielded >= max_chunks:
                    print(f"[DataLoader] Reached max_chunks={max_chunks}, stopping.")
                    return

    print(f"[DataLoader] Done — yielded {chunks_yielded} total chunk(s).")


# ── CLI quick-test ──────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  Data Loader — Quick Test (2 chunks)")
    print("=" * 60)
    for i, chunk in enumerate(load_data_in_chunks(max_chunks=2)):
        print(f"\n  Chunk {i}: shape={chunk.shape}, dtypes sample:")
        print(chunk.dtypes.head(5).to_string())
        print(f"  NaN count: {chunk.isna().sum().sum()}")
    print("=" * 60)
