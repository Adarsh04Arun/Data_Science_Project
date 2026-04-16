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


def clean_chunk(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf/-inf with NaN and drop all NaN rows."""
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    return df


def load_data_in_chunks(
    data_dir: str = None,
    chunk_size: int = 500_000,
    max_chunks: int = None,
):
    """
    Yield cleaned pandas DataFrames from all .parquet files in *data_dir*.

    Parameters
    ----------
    data_dir : str
        Path to the directory containing .parquet files.
    chunk_size : int
        Number of rows per yielded chunk.
    max_chunks : int or None
        Cap total chunks for rapid prototyping. None = no limit.

    Yields
    ------
    pd.DataFrame
        A cleaned chunk of the dataset.
    """
    if data_dir is None:
        data_dir = os.path.join(
            os.path.dirname(__file__), os.pardir, os.pardir,
            "Dataset", "Data",
        )
    data_dir = os.path.abspath(data_dir)

    parquet_files = sorted(glob.glob(os.path.join(data_dir, "*.parquet")))
    if not parquet_files:
        raise FileNotFoundError(
            f"No .parquet files found in {data_dir}"
        )

    print(f"[DataLoader] Found {len(parquet_files)} parquet file(s) in {data_dir}")

    chunks_yielded = 0
    for fpath in parquet_files:
        pf = pq.ParquetFile(fpath)
        fname = os.path.basename(fpath)
        print(f"[DataLoader] Reading: {fname}")

        for batch in pf.iter_batches(batch_size=chunk_size):
            df_chunk = batch.to_pandas()
            df_chunk = clean_chunk(df_chunk)

            if len(df_chunk) == 0:
                continue

            chunks_yielded += 1
            print(f"[DataLoader]   chunk {chunks_yielded}: {len(df_chunk):,} rows")
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
