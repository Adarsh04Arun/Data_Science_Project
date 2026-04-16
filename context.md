# Adaptive Triage Engine — Change Log & Context

This file documents every significant change made to the project.
Each entry records the problem or motivation, the solution implemented, and the files affected.
This is intended as a running reference for presentations, vivas, and future development.

---

## Change 1 — UCB1 Cold-Start Bug Fix

### Problem
When the UCB1 bandit encountered a state (threat_score_bucket, load_bucket, density_bucket) that had never been visited during training, all three actions had `visit_count = 0`. UCB1 assigns `float('inf')` to unvisited actions. When all three values are infinity, `numpy.argmax([inf, inf, inf])` always returns index `0` by numpy's tie-breaking rule. Action index `0` is `Dismiss`.

This meant that any network flow landing in an unseen state — including genuine high-confidence threats scored at 100% by XGBoost — was silently dismissed. In the test CSV, all HIGH-threat flows (DDoS, PortScan, Infiltration) were being dismissed because the Q-table had only been trained on `threat_bucket = 0` states.

### Root Cause
The Q-table had only 5 of 2000 possible state buckets visited during the simulation phase. All 5 were at `threat_bucket = 0` (near-zero threat scores). Every other bucket, including all high-threat buckets, was completely unvisited.

### Solution
Added a **threat-aware cold-start fallback** in `BanditAgent.decide()`:

- If `visit_count[tb, lb, db].sum() == 0` (state completely unvisited):
  - `threat_score >= 0.7` → return `Escalate (2)`
  - `threat_score >= 0.3` → return `Monitor (1)`
  - otherwise → return `Dismiss (0)`

This replaces the dangerous numpy argmax tie-break with a principled rule-based prior for unseen states.

### Files Changed
- `sentinel_ds/src/bandit.py` — `decide()` method

---

## Change 2 — High-Confidence Dismiss Safety Constraint

### Problem
Even after the cold-start fix, the UCB1 algorithm could still choose `Dismiss` through the exploration path in a partially-visited state. If `Escalate` and `Monitor` had each been visited once but `Dismiss` had not, all three UCB values were: `Escalate = finite`, `Monitor = finite`, `Dismiss = inf`. The agent would then explore `Dismiss` even for flows with 100% threat score, simply because it had not been tried yet.

### Solution
Added a **hard safety constraint** that permanently blocks `Dismiss` from the UCB competition for high-confidence threats:

- If `threat_score >= 0.7`: set `ucb_values[0] = -inf` (Dismiss excluded entirely)
- If `threat_score >= 0.3` and any non-Dismiss action is still unvisited: also set `ucb_values[0] = -inf`

This means `Dismiss` can only win through genuine positive Q-value exploitation, never through exploration on high-score flows.

Also added improved tie-breaking logic: when multiple actions have infinite UCB values, priority ordering is applied based on threat score rather than always defaulting to the lowest index.

### Files Changed
- `sentinel_ds/src/bandit.py` — `decide()` method

---

## Change 3 — Scaler Validation and Reliability Fix

### Problem
The `scaler.joblib` artifact saved after training was discovered to be an **unfitted** `StandardScaler` object — it had no `mean_` attribute. When the API loaded it and tried to transform incoming CSV features, it raised:

```
"This StandardScaler instance is not fitted yet."
```

The root cause was that the API's `_load_models()` function was calling `preprocess_features(chunk, fit_scaler=True)` on a fresh data chunk to "warm up" the scaler. This overwrote the global `_scaler` object in `features.py` with a new fit on a different data distribution than training. This caused mismatched feature scaling between training and inference.

### Solution
Updated `_load_models()` in `api.py` to:

1. Load `scaler.joblib` from disk.
2. **Validate** that the loaded scaler is fitted by checking `hasattr(candidate, 'mean_')`.
3. If fitted: inject it directly into the `features.py` module globals (`_scaler` and `_scaler_fitted = True`).
4. If not fitted or file missing: fall back to a fresh fit on the first data chunk (with a warning printed to logs).

This ensures that the same scaler used during training is reused during CSV inference.

### Files Changed
- `sentinel_ds/api.py` — `_load_models()` function

---

## Change 4 — Online Learning During CSV Testing

### Problem
The `POST /api/test-csv` endpoint was purely inferential. It scored each row and returned results but never updated the bandit's Q-table. This meant the agent stayed frozen at its training-phase state and could not improve from the labelled test data being uploaded.

### Solution
After each row is scored and the agent makes a decision, if ground-truth labels are available (`has_labels = True`), the endpoint now calls:

1. `BanditAgent.compute_reward(true_label, action, analyst_load, score)` to compute the reward.
2. `bandit.update(score, analyst_load, action, reward)` to update the Q-table.

This makes CSV uploads act as a lightweight online learning path, reinforcing correct triage decisions and penalising wrong ones in real time.

### Files Changed
- `sentinel_ds/api.py` — `test_csv()` endpoint, per-row loop

---

## Change 5 — Metrics-First Test Model Frontend

### Problem
The Test Model tab displayed an `ACCURACY` card as the primary metric. Accuracy is misleading for intrusion detection because:
- The data is highly imbalanced.
- A model that dismisses everything can achieve high accuracy while missing all threats.
- Accuracy does not distinguish between missed threats (catastrophic) and false alarms (costly but recoverable).

The tab also showed no confusion matrices, no per-row outcome labels, and no way to evaluate triage quality separately from detection quality.

### Solution
Completely rewrote `TestModelTab.jsx` to replace accuracy with a full metrics-first evaluation view:

**Summary bar changes:**
- Removed: `ACCURACY` card
- Added: `DETECTION RATE`, `MISSED THREATS`, `F1 SCORE`

**New Metrics Panel (2-column):**
- Left column: **XGBoost Detector metrics** — Precision, Recall (TPR), F1, threshold info
- Right column: **UCB1 Bandit Agent metrics** — Precision, Detection Rate, F1, False Alarm Rate, Missed Threats (FN), False Alarms (FP)
- Both columns include a full **Confusion Matrix** with colour-coded TP/FP/TN/FN cells

**Per-row table:**
- Added `Outcome` column showing `TP`, `TN`, `FP`, or `FN` for each row
- Missed-threat rows (FN) get a red highlight via `csv-row--miss` class

**Bandit Patch Note:**
- Added a purple info banner explaining the UCB1 cold-start fix, the dismiss safety constraint, and that online Q-table updates are active

### Files Changed
- `sentinel_ds/frontend/src/TestModelTab.jsx` — full overwrite
- `sentinel_ds/frontend/src/index.css` — added styles for metrics panel, confusion matrix, outcome badges, bandit patch note, dataset source cards

---

## Change 6 — Backend Metrics Computation in /api/test-csv

### Problem
The `/api/test-csv` endpoint returned only:
- `accuracy` (misleading for imbalanced security data)
- `action_counts` (how many Dismiss/Monitor/Escalate)
- threat level counts

There was no confusion matrix, no precision/recall/F1, and no per-row outcome classification.

### Solution
Rewrote the scoring loop to track four confusion matrix counters for **both** the detector and the agent separately:

**Detector (threshold 0.5):**
- `det_tp`, `det_fp`, `det_tn`, `det_fn`
- Computes: `det_precision`, `det_recall`, `det_f1`

**Agent (Monitor or Escalate = positive):**
- `agent_tp`, `agent_fp`, `agent_tn`, `agent_fn`
- Computes: `agent_precision`, `agent_recall`, `agent_f1`, `agent_fpr`

**Per-row outcome field:**
- Each row now includes `"outcome": "TP" | "FP" | "TN" | "FN" | "?"`

**New API response structure:**
```
summary.metrics.detector  → precision, recall, f1, threshold, tp, fp, tn, fn
summary.metrics.agent     → precision, recall, f1, fpr, tp, fp, tn, fn,
                             missed_threats, false_alarms
```

Removed the misleading `summary.accuracy` field.

### Files Changed
- `sentinel_ds/api.py` — `test_csv()` endpoint, scoring loop and return statement

---

## Change 7 — Dataset Expansion: 29 Files Across 3 Groups

### Problem
The `DataPipelineTab.jsx` and `/api/pipeline-stats` endpoint only referenced the original **10 CIC-IDS2018 Parquet files**. The project actually uses **29 files** from three separate dataset sources:
- 10 Parquet files from CIC-IDS2018
- 18 CSV files from CIC-IDS2017
- 1 Parquet file from Cloud-DDoS-2024

The frontend and API were misrepresenting the actual data used.

### Solution

**Backend (`api.py` — `pipeline_stats()`):**
- Added `"total_files": 29`
- Added `"dataset_groups"` list with three entries, each containing:
  - `name`, `short` (short name), `files` (count), `type` (Parquet/CSV), `file_list`
- Updated `"parquet_files"` legacy list to include all 11 Parquet files
- Updated `"features_used"` from `60` to `61` to reflect actual schema

**Frontend (`DataPipelineTab.jsx`):**
- Replaced single flat file list with three **collapsible dataset source cards**, each showing dataset name, short identifier, file count, file format, and expandable file list
- Updated flow diagram first step from "10 Parquet files" to "29 files across 3 datasets"
- Updated processing statistics section to show:
  - Total Dataset Files = 29
  - 11 Parquet files
  - 18 CSV files
  - Features = 61
  - Scaler = StandardScaler

### Files Changed
- `sentinel_ds/api.py` — `pipeline_stats()` return statement
- `sentinel_ds/frontend/src/DataPipelineTab.jsx` — full overwrite

---

## Change 8 — CSS Additions for New UI Components

### Problem
The new frontend components (metrics panel, confusion matrix, outcome badges, dataset source cards, bandit patch note) had no corresponding CSS styles.

### Solution
Added a complete new CSS section at the end of `index.css` covering:

- `.metrics-panel` — 2-column grid container
- `.metrics-group` — individual panel (detector or agent)
- `.metrics-group__title` / `__icon` / `__sub` — header styling
- `.metric-row` — 3-column row of metric cards
- `.metric-card` / `.metric-card--small` — individual stat card
- `.metric-card__value--cyan/green/blue/orange/red` — color variants
- `.metric-card__tip` — tooltip shown on hover
- `.confusion-matrix` / `.cm-grid` — confusion matrix layout
- `.cm-cell--tp/fp/tn/fn` — color-coded confusion cells
- `.cm-cell__count` / `.cm-cell__tag` — cell content
- `.bandit-patch-note` / `__badge` / `__text` — patch info banner
- `.outcome-badge` — inline TP/FP/TN/FN badge
- `.csv-row--miss` — red row highlight for missed threats (FN)
- `.dataset-source-grid` / `.dataset-source-card` — dataset group cards
- `.dataset-source-card__toggle` / `.dataset-files-list` / `.dataset-file-entry` — expandable file list
- `.stat-box__value--purple` — extra color for stat boxes

### Files Changed
- `sentinel_ds/frontend/src/index.css` — appended new section

---

## Change 9 — README Rewrite

### Problem
The `README.md` described the original baseline architecture with:
- 60 features (outdated, now 61)
- 10x10 Q-table (outdated, now 20x20x5)
- epsilon-greedy (outdated, now UCB1)
- only one dataset mentioned
- no mention of recent safety fixes
- no mention of the metrics-first frontend

### Solution
Complete rewrite of `README.md` covering:
- current 2-stage architecture (XGBoost + UCB1 bandit)
- 61-feature pipeline
- 29 files / 3 datasets
- all recent safety fixes with explanations
- current known strengths and limitations
- updated artifact list
- updated repository structure
- metrics-first frontend documentation

### Files Changed
- `README.md` — full overwrite

---

## Change 10 — IMPROVEMENTS.md Restructure

### Problem
`IMPROVEMENTS.md` was written as a forward-looking recommendations document, but many of those recommendations had already been implemented. It still listed things like UCB1 exploration, Q-table persistence, and reward refinement as future suggestions when they were already complete.

### Solution
Restructured `IMPROVEMENTS.md` into two clear sections:

**Section 1 — Completed Upgrades:**
Documented all already-implemented improvements with explanation of what changed and why it matters:
- hyperparameter tuning
- dynamic class weighting
- chunk-aware validation
- feature importance extraction
- 61-feature schema
- scaler persistence and validation
- UCB1 bandit
- 20×20×5 Q-table
- threat density context
- reward refinement
- decaying learning rate
- Q-table persistence
- cold-start safety fix
- high-confidence dismiss blocking
- online CSV learning
- metrics-first frontend
- TP/TN/FP/FN outcome display
- 29-file / 3-dataset frontend

**Section 2 — Next-Step Roadmap:**
Honest list of remaining improvements with effort and benefit explanation:
- multi-class detection
- probability calibration
- feature pruning
- cross-file evaluation
- benign suppression for the agent
- test-time state isolation
- richer bandit context
- scaler rebuild enforcement
- formal benchmarking

### Files Changed
- `IMPROVEMENTS.md` — full overwrite

---

## Change 11 — Presentation Guide Expansion

### Problem
`presentation_guide.md` was missing:
- a ready-to-speak explanation of the current Test Model metrics
- an answer to "what will you improve next" for viva
- a 2-minute pitch speech
- a 5-minute full walkthrough speech
- a jury Q&A cheat sheet covering architecture, metrics, safety, data, and improvements

### Solution
Appended three major new sections to `presentation_guide.md`:

**Section 22 — Two-Minute Speech:**
A complete ready-to-say speech covering the problem, architecture, results, and next steps in under 2 minutes.

**Section 23 — Five-Minute Speech:**
A segmented walkthrough with separate blocks for:
- Problem (30 seconds)
- Architecture (60 seconds)
- Reward Design (45 seconds)
- UCB1 and Learning (45 seconds)
- Safety Fixes (45 seconds)
- Current Results (45 seconds)
- Closing (30 seconds)

**Section 24 — Jury Q&A Cheat Sheet:**
25 questions grouped into six categories with short and long answers:
- Architecture
- Metrics
- Safety Fixes
- Data and Pipeline
- Improvements
- Evaluation

Also added to the existing Q&A section:
- Q9: How to explain 100% detection rate with 60% precision
- Q10: Why detector has 100% precision but 73.3% recall
- Q11: What exactly will you improve next
- Q12: Honest technical conclusion right now

Also added a subsection in Section 14 (Example Demo Narrative) with:
- ready-to-say confusion matrix interpretation
- how to explain the divergence between detector recall and agent detection rate

### Files Changed
- `presentation_guide.md` — two edit passes appending new content

---

## Summary Table

| # | Change | Problem Solved | Files |
|---|--------|----------------|-------|
| 1 | UCB1 cold-start fix | All unseen states defaulted to Dismiss | `bandit.py` |
| 2 | High-confidence safety constraint | Agent could still dismiss 100% threats via exploration | `bandit.py` |
| 3 | Scaler validation fix | Saved scaler was unfitted, causing inference mismatch | `api.py` |
| 4 | Online CSV learning | Test endpoint did not update Q-table from labelled data | `api.py` |
| 5 | Metrics-first frontend | Accuracy card hid security-relevant evaluation gaps | `TestModelTab.jsx` |
| 6 | Backend metrics computation | API returned no precision/recall/confusion matrix | `api.py` |
| 7 | Dataset expansion (29 files) | Frontend/API only showed 10 files, 1 dataset | `api.py`, `DataPipelineTab.jsx` |
| 8 | CSS additions | New UI components had no styles | `index.css` |
| 9 | README rewrite | README described outdated architecture | `README.md` |
| 10 | IMPROVEMENTS.md restructure | Completed upgrades were still listed as future recommendations | `IMPROVEMENTS.md` |
| 11 | Presentation guide expansion | No ready-to-say speeches or jury cheat sheet | `presentation_guide.md` |

---

## Current System State (After All Changes)

### Detector
- XGBoost binary classifier
- 61-feature schema
- incremental chunk training
- dynamic class weighting
- feature importance extraction
- persisted as `detector.json`
- scaler persisted as `scaler.joblib` and validated on load

### Bandit Agent
- UCB1 contextual bandit
- 20 × 20 × 5 state space = 2000 states
- 3 actions: Dismiss, Monitor, Escalate
- asymmetric reward function
- decaying learning rate
- persisted as `q_table.npy` + `visit_count.npy`
- cold-start safety: threat-aware fallback for unseen states
- exploration safety: Dismiss blocked for high-score flows

### Pipeline
- 29 files across 3 dataset groups
- chunked streaming
- memory-safe training
- F1 tracked during simulation

### Frontend
- metrics-first Test Model tab
- detector + agent confusion matrices
- per-row TP/FP/TN/FN outcomes
- dataset source cards in pipeline tab
- patch note banner
- live training view

### Documentation
- README reflects current architecture
- IMPROVEMENTS distinguishes completed vs planned
- presentation guide includes speeches and cheat sheet
- context.md (this file) tracks all changes