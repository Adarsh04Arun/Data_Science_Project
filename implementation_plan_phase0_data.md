# Phase 0: Data Layer — Implementation Plan

## Objective
Build a robust, memory-efficient data loading pipeline that can process the massive CSE-CIC-IDS2018 `.parquet` dataset using GPU acceleration when possible, and CPU Pandas as a stable fallback.

## Requirements

- **Input:** Directory `Dataset/Data` containing multiple `.parquet` files (e.g., `Botnet...parquet`, `DDoS...parquet`).
- **Output:** A combined `pandas.DataFrame` or `cudf.DataFrame` ready for feature engineering operations.

## Proposed Changes

### [NEW] `src/data_loader.py`

#### 1. Core Functions

- `load_data_in_chunks(data_dir: str, chunk_size: int = 500_000, max_chunks: int = None) -> Iterator[pd.DataFrame]`
  - Given WSL memory constraints and the 8GB VRAM limit, loading gigabytes at once causes OOM (Out Of Memory) crashes.
  - This function uses `pyarrow.parquet.ParquetFile.iter_batches()` to yield manageable chunks of the dataset.
  - Allows `max_chunks` for rapid prototyping.
  
- `clean_chunk(df_chunk: pd.DataFrame) -> pd.DataFrame`
  - Replaces Infinity (`inf` / `-inf`) with `NaN` and drops all rows containing `NaN` to ensure stable XGBoost training.
  - We do this *per chunk* before any concatenation to keep memory low.

#### 2. Robustness & Fallbacks
- **No Heavy Parallelism in WSL:** We will avoid ThreadPoolExecutor or Dask local clusters to prevent the WSL worker crash issue previously encountered. Chunked linear reading with `pyarrow` is highly stable and performant enough for SSDs.
- `cudf` will be used defensively; data will be mapped onto the GPU *after* chunking and cleaning.

## Verification Plan

### Automated Testing
- Write a short test script that calls `load_data_in_chunks()` and pulls exactly 2 chunks.
- Verify `clean_chunk(df)` leaves exactly 0 `NaN` or `inf` values.
- Monitor WSL `htop` during execution to guarantee RAM stays below the system limit.
