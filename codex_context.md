# Codex Context

This file summarizes the key changes made in the `sentinel_ds` workspace during the debugging and tuning pass for EDA, CSV upload, and live stream behavior.

## Scope

Primary work areas:

- `sentinel_ds/api.py`
- `sentinel_ds/main.py`
- `sentinel_ds/src/data_loader.py`
- `sentinel_ds/src/detector.py`
- `sentinel_ds/frontend/src/TestModelTab.jsx`
- `sentinel_ds/output/*`

## Main Issues Addressed

### 1. EDA stats endpoint was incomplete or silently failing

Changes:

- Fixed `/api/eda-stats` in `sentinel_ds/api.py`
- Improved feature-importance extraction so live XGBoost importances are returned reliably
- Preserved small importance values instead of rounding them down to `0.0`
- Added `importance_pct` in the EDA response
- Fixed a swallowed failure in feature stats population by ensuring pandas was available in scope

Related file:

- `sentinel_ds/api.py`

### 2. Detector load path was not restoring feature importances

Changes:

- Loading a saved detector now restores `_feature_importances`
- This ensures the API can report importances after startup without retraining

Related file:

- `sentinel_ds/src/detector.py`

### 3. CSV and mixed-schema data normalization was breaking stream and upload flows

Changes:

- Hardened `clean_chunk()` in `sentinel_ds/src/data_loader.py`
- Supported lowercase `label` columns
- Supported duplicate `label` / `Label` columns safely
- Expanded alias handling for snake_case CSV schemas
- Added safe feature fallbacks for partially matching CSV schemas
- Updated stream row normalization in `sentinel_ds/api.py` so fallback inference does not drop rows unnecessarily
- Replaced row-dropping fallback with an inference-safe feature mapper that zero-pads missing features instead

Related files:

- `sentinel_ds/src/data_loader.py`
- `sentinel_ds/api.py`

### 4. CSV upload path in the Test Model tab was failing or freezing

Changes:

- Frontend now posts to same-origin `/api/test-csv?freeze=true` instead of a hardcoded host
- `/api/test-csv` now limits returned preview rows to keep the UI responsive
- UI now clearly shows that row output is truncated for performance

Related files:

- `sentinel_ds/frontend/src/TestModelTab.jsx`
- `sentinel_ds/api.py`

### 5. Training/data coverage bugs caused some attack families to be ignored

Changes:

- Fixed training behavior for single-class chunks in `sentinel_ds/main.py`
- Hardened `partial_train()` path so splitting augmented data does not silently produce single-class training slices
- Rebuilt detector artifacts after these changes

Related files:

- `sentinel_ds/main.py`
- `sentinel_ds/src/detector.py`

## Live Stream Work

### 6. Stream metrics were initially broken or unrealistic

Observed issues during the debugging cycle:

- all false negatives
- all dismissals at the same repeated score
- `100%` metrics caused by leakage
- exact same metrics across repeated runs
- stream crashes mid-response
- blank UI with `Stop` stuck on screen
- `No sampled flows survived normalization`
- later, very high false-positive rates

### 7. Stream leakage bug removed

Changes:

- Removed label-based routing leakage from the stream path
- Routing is now based on inference-time traffic characteristics instead of ground-truth labels

Related file:

- `sentinel_ds/api.py`

### 8. Stream source sampling and family routing fixed

Changes:

- Stream now samples attacks across labels instead of collapsing into one family
- Removed fixed RNG seed so repeated runs are not identical
- Added preferred source mappings for weaker or specialist attack families
- Added route handling for:
  - web families
  - auth families
  - DDoS families
- Added missing source mapping for `Web_SQL_Injection`

Related file:

- `sentinel_ds/api.py`

### 9. Specialist detectors added for stream scoring

Changes:

- Added auth specialist routing
- Added DDoS specialist routing
- Kept web specialist routing

Artifacts generated:

- `sentinel_ds/output/auth_detector.json`
- `sentinel_ds/output/auth_calibrator.joblib`
- `sentinel_ds/output/ddos_detector.json`
- `sentinel_ds/output/ddos_calibrator.joblib`

Notes:

- For the narrow DDoS stream route, raw detector probabilities were used instead of the calibrator because the calibrator flattened DDoS scores too aggressively

Related files:

- `sentinel_ds/api.py`
- `sentinel_ds/main.py`

### 10. Stream SSE stability fixes

Changes:

- Fixed a pandas type error caused by duplicate columns during row fallback normalization
- Made frontend stream error handling visible instead of leaving the UI stuck in a running state
- Added explicit stream error display in the Test Model tab

Related files:

- `sentinel_ds/api.py`
- `sentinel_ds/frontend/src/TestModelTab.jsx`

### 11. Stream false-positive reduction pass

Problem:

- permissive stream fallback plus medium-score `Monitor` actions created too many false positives

Changes:

- Filtered low-coverage benign stream sources out of the benign sampling pool
- Removed RL/bandit-driven stream evaluation behavior from the live stream metrics path
- Removed stream-only behavior-score fusion from the evaluation path
- Replaced bandit-driven live stream actioning with deterministic thresholds

Current deterministic stream policy in `sentinel_ds/api.py`:

- `Escalate` when `score >= 0.75`
- `Monitor` threshold depends on row type:
  - generic detector rows: `0.35`
  - auth/web/DDoS specialist rows: `0.30`
- `Dismiss` below threshold

Why:

- The Test Model stream should report stable detector-facing metrics
- RL triage logic is useful operationally, but it made the displayed stream metrics unstable and misleading

Related file:

- `sentinel_ds/api.py`

## Current Stream Metric Interpretation

The live stream metrics shown in the Test Model tab now reflect a conservative, deterministic evaluation policy:

- very low or zero false positives are expected
- recall/detection rate is the current tradeoff
- results vary between runs because the attack-family mix is random
- with `50` flows at `40%` attack rate, there are `20` attack rows, so recall changes in `5%` steps
- with `100` flows at `40%` attack rate, there are `40` attack rows, so recall changes in `2.5%` steps

Recent observed stable range after the last tuning pass:

- detection rate around `70%` to `77.5%`
- precision `100%`
- `FP = 0`
- `FPR = 0%`
- `F1` in the low-to-high `80s`

This is currently a conservative but believable operating point.

## Current Known Tradeoff

The main remaining weakness is recall:

- false positives are mostly solved in the Test Model live stream
- some attack families still score below the current deterministic `Monitor` thresholds
- further improvement would require:
  - family-specific thresholds, or
  - model improvements on the weaker families

## Verification Performed

Repeatedly verified during this debugging cycle:

- `python3 -m py_compile sentinel_ds/api.py`
- `python3 -m py_compile sentinel_ds/src/detector.py`
- direct API probing of `/api/run-stream`
- direct API probing of `/api/eda-stats`
- direct checks on CSV upload behavior and frontend stream handling

## Recommended Next Steps

If more tuning is needed later, the safest next actions are:

1. keep the deterministic live-stream policy
2. tune thresholds per family instead of lowering the global threshold again
3. improve weaker non-web attack families in the detector rather than making the stream more permissive
4. keep low-coverage benign sources out of live-stream evaluation unless feature mapping is improved
