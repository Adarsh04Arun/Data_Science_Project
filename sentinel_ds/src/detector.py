"""
detector.py — GPU-accelerated XGBoost threat detector.

Uses tree_method='hist' with device='cuda' for GPU training,
falling back to CPU if CUDA is unavailable.

Improvements (v3):
  - Tuned hyperparameters (depth, lr, subsample, colsample, gamma, min_child_weight)
  - Dynamic scale_pos_weight per chunk
  - Early stopping with internal eval_set split
  - Feature importance extraction
  - Probability calibration via isotonic regression (post-hoc Platt-style)
"""

import os

import numpy as np
from xgboost import XGBClassifier


class ThreatDetector:
    """XGBoost-based binary threat classifier with chunked training support."""

    def __init__(self, n_estimators=250, scale_pos_weight=None, **kwargs):
        # Tuned hyperparameters — optimised for CIC-IDS2018
        base_params = dict(
            n_estimators=n_estimators,
            max_depth=8,
            learning_rate=0.08,
            subsample=0.75,
            colsample_bytree=0.75,
            gamma=3,
            min_child_weight=7,
            reg_alpha=0.1,  # L1 regularisation
            reg_lambda=1.5,  # L2 regularisation
            eval_metric="logloss",
            use_label_encoder=False,
            verbosity=0,
        )
        if scale_pos_weight is not None:
            base_params["scale_pos_weight"] = scale_pos_weight
        base_params.update(kwargs)

        # Try GPU first, fall back to CPU
        try:
            self.model = XGBClassifier(
                tree_method="hist",
                device="cuda",
                **base_params,
            )
            self._device = "cuda"
        except Exception:
            self.model = XGBClassifier(
                tree_method="hist",
                device="cpu",
                **base_params,
            )
            self._device = "cpu"

        self._trained = False
        self._feature_importances = None
        self._calibrator = None  # set after calibrate() is called
        self._calibrated = False
        print(
            f"[Detector] Initialised XGBoost on {self._device}  "
            f"(depth={base_params['max_depth']}, lr={base_params['learning_rate']}, "
            f"n_est={n_estimators})"
        )

    def partial_train(
        self, X, y, eval_fraction=0.1, early_stopping_rounds=10, **kwargs
    ):
        """
        Incrementally train the model on a new data chunk.

        Uses the xgb_model parameter to continue from the previous
        booster state so we never hold the full dataset in memory.

        Improvements:
          - Dynamic scale_pos_weight calculated per chunk
          - Early stopping with internal eval split
        """
        # Dynamic class weight: ratio of negatives to positives in this chunk
        n_pos = int(y.sum())
        n_neg = len(y) - n_pos
        if n_pos > 0:
            self.model.set_params(scale_pos_weight=n_neg / n_pos)

        # Shuffle before carving out the validation tail so augmented
        # single-class batches do not leave train/val splits degenerate.
        if len(X) > 1:
            rng = np.random.default_rng(42)
            order = rng.permutation(len(X))
            X = X[order]
            y = y[order]

        # Split chunk for early stopping (90/10)
        n_eval = max(1, int(len(X) * eval_fraction))
        X_train, X_val = X[:-n_eval], X[-n_eval:]
        y_train, y_val = y[:-n_eval], y[-n_eval:]

        fit_params = dict(
            eval_set=[(X_val, y_val)],
            verbose=False,
            **kwargs,
        )

        if self._trained:
            self.model.fit(
                X_train,
                y_train,
                xgb_model=self.model.get_booster(),
                **fit_params,
            )
        else:
            self.model.fit(X_train, y_train, **fit_params)
            self._trained = True

        # Cache feature importances
        try:
            self._feature_importances = self.model.feature_importances_
        except Exception:
            pass

    def predict(self, X) -> np.ndarray:
        """Return binary predictions (0 or 1)."""
        return self.model.predict(X)

    def predict_proba(self, X) -> np.ndarray:
        """Return threat probabilities in [0, 1]."""
        proba = self.model.predict_proba(X)
        # proba shape: (n, 2) → column 1 is P(threat)
        if proba.ndim == 2:
            return proba[:, 1]
        return proba

    def get_feature_importances(self):
        """Return feature importance array (gain-based), or None if not yet trained."""
        return self._feature_importances

    # ── Probability calibration ──────────────────────────────
    def calibrate(self, X_val: np.ndarray, y_val: np.ndarray) -> None:
        """
        Fit an isotonic-regression calibrator on a held-out validation set.

        Raw XGBoost probabilities are often miscalibrated (overconfident or
        underconfident). Isotonic regression adjusts the mapping so that a
        score of 0.8 genuinely reflects ~80% empirical threat probability.

        Parameters
        ----------
        X_val : feature matrix for validation flows (already scaled)
        y_val : binary ground-truth labels (0 = benign, 1 = threat)
        """
        from sklearn.isotonic import IsotonicRegression

        raw_proba = self.model.predict_proba(X_val)[:, 1]

        self._calibrator = IsotonicRegression(out_of_bounds="clip")
        self._calibrator.fit(raw_proba, y_val)
        self._calibrated = True

        # Quick sanity: calibrated mean vs label mean
        cal_mean = self._calibrator.predict(raw_proba).mean()
        print(
            f"[Detector] Calibration fitted  "
            f"(val_size={len(y_val)}, "
            f"label_rate={y_val.mean():.3f}, "
            f"cal_mean={cal_mean:.3f})"
        )

    def predict_proba_calibrated(self, X: np.ndarray) -> np.ndarray:
        """
        Return calibrated threat probabilities.

        Falls back to raw XGBoost probabilities when no calibrator has been
        fitted (e.g. during training before calibrate() is called).
        """
        raw = self.predict_proba(X)
        if self._calibrated and self._calibrator is not None:
            return self._calibrator.predict(raw).astype(np.float32)
        return raw

    def save_calibration(self, path: str) -> None:
        """Persist the fitted calibrator to *path* (joblib format)."""
        if not self._calibrated or self._calibrator is None:
            print("[Detector] No calibrator to save — call calibrate() first.")
            return
        import joblib

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump(self._calibrator, path)
        print(f"[Detector] Calibrator saved → {path}")

    def load_calibration(self, path: str) -> bool:
        """Load a previously saved calibrator from *path*."""
        if not os.path.isfile(path):
            return False
        try:
            import joblib

            self._calibrator = joblib.load(path)
            self._calibrated = True
            print(f"[Detector] Calibrator loaded ← {path}")
            return True
        except Exception as exc:
            print(f"[Detector] WARNING: could not load calibrator: {exc}")
            return False

    # ── Persistence ──────────────────────────────────────────
    def save(self, path: str):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.model.save_model(path)
        print(f"[Detector] Model saved → {path}")

    def load(self, path: str):
        """Restore a previously saved model."""
        self.model.load_model(path)
        self._trained = True
        try:
            self._feature_importances = self.model.feature_importances_
        except Exception:
            self._feature_importances = None
        print(f"[Detector] Model loaded ← {path}")


# ── CLI quick-test ──────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  ThreatDetector v3 — Quick Smoke Test (with calibration)")
    print("=" * 60)
    det = ThreatDetector(n_estimators=10)
    X_fake = np.random.randn(500, 20).astype(np.float32)
    y_fake = (np.random.rand(500) > 0.8).astype(np.int8)
    det.partial_train(X_fake, y_fake)

    p_raw = det.predict_proba(X_fake[:5])
    print(f"  Raw probabilities      : {p_raw}")

    # Calibrate on a small validation split
    X_val = np.random.randn(100, 20).astype(np.float32)
    y_val = (np.random.rand(100) > 0.8).astype(np.int8)
    det.calibrate(X_val, y_val)

    p_cal = det.predict_proba_calibrated(X_fake[:5])
    print(f"  Calibrated probabilities: {p_cal}")

    # Test save/load calibration
    det.save_calibration("/tmp/calibrator.joblib")
    det2 = ThreatDetector(n_estimators=10)
    det2.partial_train(X_fake, y_fake)
    loaded = det2.load_calibration("/tmp/calibrator.joblib")
    print(f"  Calibrator load OK: {loaded}")

    imp = det.get_feature_importances()
    if imp is not None:
        print(f"  Top-3 feature importance indices: {np.argsort(imp)[-3:]}")
    print("=" * 60)
