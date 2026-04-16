# Phase 1: Feature Engineering — Implementation Plan

## Objective
Convert raw numerical and categorical flow features into a standardized, binary-labeled dataset optimized for XGBoost GPU training.

## Proposed Changes

### [NEW] `src/features.py`

- The `preprocess_features(df_chunk)` function handles standardizing a *single chunk* of data:
  1. **Label Binarization**:
     - Raw column: `Label`
     - Logic: Map "Benign" to `0`. Map all attack classes (e.g., "Bot", "DDoS", "Brute Force") to `1` (indicating a threat).
     - Target variable: `is_threat` (int8)

  2. **Feature Extraction & Scaling**:
     - Because we are processing in chunks to avoid WSL crashes, we must use `sklearn.preprocessing.StandardScaler().partial_fit()` or map values manually if doing it purely on GPU.
     - To simplify and keep the WSL engine fast, we can sample 10% of the dataset initially to `.fit()` the scaler, and then `.transform()` each individual chunk dynamically during the data loading loop.
     - *Significant optimization*: We will explicitly NOT compute Z-Scores or Rolling Windows, as the CIC-IDS2018 dataset already natively includes 80+ pre-calculated statistical network flow features (`Flow Packets/s`, `Idle Mean`, etc.). Eliminating this step saves immense CPU load.

  3. **Data Type Casting** (Memory Optimization):
     - CICFlowMeter parquets often represent all numeric features as `float64` or `int64`.
     - Cast the majority of flow features to `float32` natively via Pandas/cuDF.
     - Crucial strategy since storing 80+ features across 16+ million rows at `float64` would exceed 8GB GPU memory limits (the RTX 5060 Ti only has 8GB VRAM).

  4. **Addressing Correlated Features**:
     - Some network attributes might perfectly correlate dynamically. While XGBoost is robust to this, removing redundant features improves latency.

## Verification Plan

- Run `preprocess_features` on a single chunk.
- Check visually if `X.shape[1]` matches expected dimensionality.
- Assert that `X.dtypes` primarily are `float32` instead of `float64`.
- Assert that `y.unique()` contains only `0` and `1`.
