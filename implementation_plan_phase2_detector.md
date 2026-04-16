# Phase 2: GPU-Native Detector — Implementation Plan

## Objective
Train a high-performance XGBoost classifier on the prepared features using the NVIDIA RTX 5060 Ti.

## Proposed Changes

### [NEW] `src/detector.py`

- Create a `ThreatDetector` class (previously called `StaticDetector`):
  - `__init__(self, **kwargs)`: Initializes an XGBClassifier.
    - Important hyperparameters: `tree_method="hist"`, `device="cuda"` (Leverages GPU).
    - `scale_pos_weight`: Set to `~5.0` (or dynamically calculated) to naturally combat the extreme class imbalance in the dataset (i.e. heavy benign traffic vs sparse attack traffic).
  - `partial_train(self, X_train_chunk, y_train_chunk, **kwargs)`: Fits the XGBoost model iteratively. Because we must load data in chunks to avoid OOM crashes, we will utilise the `xgb_model` parameter in `.fit()` to update the underlying decision trees progressively.
  - `predict(self, X_test) -> np.ndarray`: Returns boolean/binary predictions.
  - `predict_proba(self, X_test) -> np.ndarray`: Returns the continuous probability `[0.0, 1.0]` that the flow is malicious (i.e., `pred[:, 1]`). This probability acts as the `threat_score` consumed by the Contextual Bandit.
  - `save(self, path: str)`: Saves the trained model checkpoint.
  - `load(self, path: str)`: Restores a checkpoint natively.

## GPU Consideration
- Using GPU (`device="cuda"`) drastically accelerates histogram building in XGBoost for large-scale data like CIC-IDS2018.
- Given your 8GB VRAM constraint, using `.astype('float32')` (as done in Phase 1) is mandatory.

## Verification
- Initialize `ThreatDetector`. Train on a 1-million row subset.
- Expect training to complete in <30 seconds via GPU acceleration.
- Ensure `predict_proba()` outputs valid float arrays strictly bounded between `0.0` and `1.0`.
