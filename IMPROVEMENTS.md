# Adaptive Triage Engine — Improvements Status & Roadmap

This document separates what has **already been implemented** in the current system from the **next recommended improvements**.

The project has evolved significantly from the original baseline. Several of the previously proposed upgrades are now complete, including major detector tuning, contextual bandit upgrades, persistence, frontend observability improvements, and safety fixes for high-confidence threat triage.

---

# 1. Completed Upgrades

## 1.1 XGBoost Threat Detector — Implemented

The detector is no longer using the original minimal/default-style setup. It now includes the following implemented upgrades:

### Implemented detector improvements
- **Tuned hyperparameters**
  - `n_estimators=250`
  - `max_depth=8`
  - `learning_rate=0.08`
  - `subsample=0.75`
  - `colsample_bytree=0.75`
  - `gamma=3`
  - `min_child_weight=7`
  - `reg_alpha=0.1`
  - `reg_lambda=1.5`

### Why this matters
These changes improve:
- generalisation across attack families,
- resistance to overfitting per chunk,
- stability during incremental training,
- better performance on imbalanced security data.

---

## 1.2 Dynamic Class Weighting — Implemented

### What was upgraded
Instead of relying on a fixed `scale_pos_weight`, the detector now computes the ratio dynamically per chunk:

- `scale_pos_weight = negatives / positives`

### Why this matters
Security datasets are highly imbalanced. Dynamic weighting makes the detector:
- less biased toward benign traffic,
- more adaptive to chunk-level class distribution changes,
- better suited to mixed attack/benign file streams.

---

## 1.3 Early-Stopping-Aware Chunk Training — Implemented

### What was upgraded
Each chunk is internally split into:
- **training subset**
- **validation subset**

This is used during fitting to support chunk-level evaluation and controlled boosting progression.

### Why this matters
This reduces:
- wasteful over-training on easy chunks,
- sensitivity to benign-heavy partitions,
- instability from blindly fitting the same number of rounds everywhere.

---

## 1.4 Feature Importance Extraction — Implemented

### What was upgraded
The detector now stores feature importances and surfaces the top features during pipeline execution.

### Why this matters
This improves:
- explainability,
- debugging,
- future feature pruning decisions,
- presentation quality.

---

## 1.5 61-Feature Standardised Pipeline — Implemented

### What was upgraded
The pipeline now works with an explicit **61-feature schema** and guarantees a fixed feature order during training and inference.

### Implemented preprocessing behavior
- missing required columns are padded safely,
- features are downcast to `float32`,
- scaling is applied consistently through the shared feature pipeline,
- binary label conversion is standardised.

### Why this matters
A fixed schema is critical for:
- stable inference,
- compatibility between training and CSV uploads,
- avoiding feature mismatch errors.

---

## 1.6 Scaler Persistence — Implemented

### What was upgraded
The feature scaler is now saved and reused through:
- `scaler.joblib`

### Additional reliability fix
The API now validates whether the saved scaler is actually fitted before using it. If the scaler is invalid or empty, the system falls back safely instead of silently producing broken feature transforms.

### Why this matters
This prevents:
- train/inference preprocessing mismatch,
- invalid probability outputs caused by bad scaling,
- hidden deployment errors.

---

# 2. Contextual Bandit / RL Agent — Implemented Upgrades

## 2.1 UCB1 Exploration — Implemented

### Previous state
The original design discussed ε-greedy exploration.

### Current state
The bandit now uses **UCB1 (Upper Confidence Bound)** exploration.

### Why this matters
Compared with ε-greedy, UCB1 is more sample-efficient because it:
- prefers underexplored state-action pairs,
- reduces wasteful random exploration,
- converges faster to useful policies.

---

## 2.2 Finer Q-Table Resolution — Implemented

### Current state representation
The Q-table now uses:
- **20 threat-score buckets**
- **20 analyst-load buckets**
- **5 threat-density buckets**
- **3 actions**

### Total table size
- `20 × 20 × 5 × 3 = 6000` state-action values

### Why this matters
This lets the bandit distinguish:
- low-confidence vs high-confidence threats,
- quiet traffic vs bursty threat periods,
- low-load vs overloaded analyst conditions.

This is a major upgrade from the older low-resolution state design.

---

## 2.3 Threat Density Context — Implemented

### What was upgraded
The agent now includes a third context dimension:
- **rolling threat density**

This is computed from recent threat scores and discretised into density buckets.

### Why this matters
It improves behavior during:
- burst attacks,
- traffic spikes,
- sustained malicious periods.

The bandit is no longer reacting only to the current flow in isolation.

---

## 2.4 Reward Function Refinement — Implemented

### What was upgraded
The reward function is now asymmetric and threat-aware.

### Current reward behavior includes
- stronger penalty for **missing a true threat**
- higher reward for **correctly escalating real threats**
- explicit middle-ground treatment for **Monitor**
- stronger penalty for **false alarms under analyst load**
- small positive reward for **correct benign dismissal**

### Why this matters
This gives the agent more realistic SOC incentives:
- missing attacks is catastrophic,
- escalation has operational cost,
- monitoring is useful as a middle path,
- benign review still carries a cost.

---

## 2.5 Decaying Learning Rate — Implemented

### What was upgraded
The Q-table update now uses a decaying learning rate based on visit count.

### Why this matters
This allows:
- faster learning early on,
- more stable updates later,
- less oscillation after the policy matures.

---

## 2.6 Q-Table Persistence — Implemented

### What was upgraded
The bandit now persists:
- `q_table.npy`
- `visit_count.npy`

### Why this matters
This enables:
- continuous learning across runs,
- reproducibility,
- more realistic long-lived agent behavior,
- dashboard explanations based on learned state.

---

# 3. Safety & Reliability Fixes — Implemented

## 3.1 UCB1 Cold-Start Bug Fix — Implemented

### Problem that existed
When the agent entered a completely unseen state:
- all actions received infinite UCB values,
- tie-breaking defaulted to action index `0`,
- that incorrectly mapped unseen states to **Dismiss**.

This caused real high-confidence threats to be dismissed in CSV testing.

### Fix implemented
A threat-aware cold-start fallback was added:

- `score >= 0.7` → `Escalate`
- `score >= 0.3` → `Monitor`
- otherwise → `Dismiss`

### Why this matters
This removed a dangerous failure mode where genuine threats could be silently ignored simply because the state had not been visited before.

---

## 3.2 High-Confidence Dismiss Safety Constraint — Implemented

### Fix implemented
For high-confidence threats:
- `Dismiss` is excluded from exploration

Specifically, for high threat-score states, the agent is not allowed to "experiment" by dismissing them just because that action is underexplored.

### Why this matters
This is an operational safety guardrail:
- high-score threats should not be dropped for exploration purposes,
- RL exploration must stay within safe boundaries in security systems.

---

## 3.3 Online Learning During CSV Testing — Implemented

### What was upgraded
When labelled CSV files are uploaded in the test view:
- the agent now updates from those labelled outcomes online.

### Why this matters
This makes the uploaded test path:
- not just an inference demo,
- but also a lightweight reinforcement path for the bandit.

---

# 4. Frontend & Observability Upgrades — Implemented

## 4.1 Metrics-First Test View — Implemented

### Previous issue
The frontend focused too much on **accuracy**, which is not the right headline metric for intrusion detection and triage.

### Current upgrade
The Test Model tab now shows:

### Detector metrics
- Precision
- Recall
- F1 Score
- Confusion Matrix

### Agent metrics
- Precision
- Detection Rate
- F1 Score
- False Alarm Rate
- Missed Threats
- False Alarms
- Confusion Matrix

### Why this matters
This makes the frontend technically correct for security evaluation:
- recall matters more than raw accuracy,
- false negatives must be explicitly tracked,
- triage quality must be evaluated separately from detector quality.

---

## 4.2 Per-Row Outcome Labels — Implemented

### What was upgraded
Each tested flow now includes:
- `TP`
- `TN`
- `FP`
- `FN`

### Why this matters
This makes debugging and presentation much clearer:
- users can see exactly which rows were correctly handled,
- missed threats become immediately visible,
- false alarms are explicitly distinguishable.

---

## 4.3 Frontend Patch Explanation — Implemented

### What was upgraded
The frontend now explicitly communicates that:
- UCB1 cold-start behavior was fixed,
- unsafe high-confidence dismiss exploration is blocked,
- online Q-table updates are active during CSV scoring.

### Why this matters
This improves:
- transparency,
- demo quality,
- technical presentation readiness.

---

## 4.4 Data Pipeline Tab Accuracy — Implemented

### What was upgraded
The pipeline tab now reflects the real dataset footprint:
- **29 total files**
- **3 dataset groups**
- **11 Parquet files**
- **18 CSV files**
- **61 features**

### Why this matters
The frontend is now aligned with the actual project data, not an outdated earlier assumption.

---

# 5. Dataset Integration Upgrades — Implemented

## Current integrated data coverage
The system now documents and surfaces three dataset groups:

### 1. BCCC-CSE-CIC-IDS2018
- 10 files
- Parquet

### 2. BCCC-CIC-IDS2017
- 18 files
- CSV

### 3. BCCC-cPacket-Cloud-DDoS-2024
- 1 file
- Parquet

### Total
- **29 files**

### Why this matters
This improves:
- realism,
- breadth of attack coverage,
- frontend credibility,
- presentation strength.

---

# 6. Pipeline-Level Upgrades — Implemented

## 6.1 Held-Out Validation in Training Flow — Implemented

### What was upgraded
The training loop now uses a rolling buffer and evaluates on held-out chunks after detector training.

### Why this matters
This is more honest than reporting only in-sample training accuracy.

---

## 6.2 F1 Tracking in Simulation — Implemented

### What was upgraded
The main simulation loop now tracks:
- precision
- recall
- **F1 score**
- cumulative reward

### Why this matters
F1 is now a first-class metric in the live pipeline, not just a later recommendation.

---

# 7. Next-Step Recommendations

The following upgrades are still valuable and are **not yet fully implemented**.

---

## 7.1 Multi-Class Threat Detection

### Current state
The detector is still binary:
- benign
- threat

### Recommendation
Move to:
- `multi:softprob`
- attack-family-specific predictions such as:
  - DDoS
  - Botnet
  - Brute Force
  - Infiltration
  - Web Attack
  - DoS
  - Benign

### Benefit
This would allow:
- richer frontend explanations,
- attack-type-aware triage,
- more context for the bandit,
- better SOC usefulness.

---

## 7.2 Probability Calibration

### Current state
The detector outputs XGBoost probabilities directly.

### Recommendation
Apply calibration such as:
- Platt scaling
- isotonic regression

### Benefit
The bandit currently assumes the threat score is meaningful as a confidence value. Calibration would make those probabilities more trustworthy and improve action quality.

---

## 7.3 Feature Importance Pruning

### Current state
Feature importance is extracted, but the feature set is still fixed at 61.

### Recommendation
Use feature importance from a completed training run to remove weak features.

### Benefit
This could:
- reduce noise,
- improve speed,
- simplify the model,
- improve interpretability.

---

## 7.4 Cross-File Evaluation Dashboard

### Current state
Metrics are tracked globally.

### Recommendation
Add per-file evaluation:
- precision/recall/F1 by file
- attack-family-specific performance by source file
- detector vs bandit comparison by dataset group

### Benefit
This would reveal:
- where the detector underperforms,
- whether one attack family is being missed,
- how generalisable the system really is.

---

## 7.5 Better Benign Suppression for the Agent

### Current state
The latest fixes correctly prioritize not missing genuine threats, but the agent can still over-monitor benign traffic.

### Recommendation
Improve low-score benign handling by:
- stronger penalties for benign monitor actions,
- score-aware low-threat priors,
- stricter benign-side thresholds,
- optional inference-mode separation from training-mode exploration.

### Benefit
This would reduce:
- false alarm rate,
- analyst noise,
- excessive monitoring of low-confidence benign traffic.

---

## 7.6 Test-Time State Isolation

### Current state
CSV uploads can update the shared bandit state online.

### Recommendation
Add an option for:
- stateless evaluation mode
- isolated session-level test scoring
- explicit “learn from upload” toggle

### Benefit
This would improve:
- reproducibility,
- controlled evaluation,
- demo consistency.

---

## 7.7 Richer Context for the Bandit

### Current state
Current context:
- threat score
- analyst load
- threat density

### Recommendation
Potential future additions:
- time-of-day bucket
- source reputation / IP history
- dataset/source type
- attack-family class (if multi-class detector is implemented)

### Benefit
This could make triage decisions more realistic without replacing the current contextual-bandit design.

---

## 7.8 Proper Scaler Rebuild During Full Retraining

### Current state
Scaler persistence now works more safely, but if an old scaler artifact is invalid, the API falls back to a small rebuild path.

### Recommendation
Enforce full scaler regeneration and validation as part of pipeline completion checks.

### Benefit
This would make deployments cleaner and reduce the chance of stale artifacts.

---

## 7.9 Formal Offline Benchmarking

### Recommendation
Add a repeatable benchmark report that logs:
- detector precision / recall / F1
- agent precision / recall / F1
- false alarm rate
- missed threat count
- per-dataset performance
- before/after comparison for safety fixes

### Benefit
This would improve:
- scientific reporting,
- presentation strength,
- regression detection after future changes.

---

# 8. Priority Roadmap

## High Priority
1. **Probability calibration**
2. **Better benign suppression for the bandit**
3. **Test-time state isolation**
4. **Cross-file evaluation reporting**

## Medium Priority
5. **Multi-class detector**
6. **Feature pruning**
7. **Richer contextual inputs**
8. **Formal offline benchmarking**

## Lower Priority
9. **Additional artifact validation / deployment automation**
10. **More advanced frontend drill-down analytics**

---

# 9. Summary

The system has already completed many of the originally recommended upgrades:

## Already implemented
- tuned XGBoost
- dynamic class weighting
- chunk-aware validation
- feature importance extraction
- 61-feature schema
- scaler persistence and validation
- UCB1 contextual bandit
- finer Q-table
- threat-density context
- refined reward design
- decaying learning rate
- Q-table persistence
- cold-start safety fix
- high-confidence dismiss blocking
- online CSV learning
- metrics-first frontend
- TP/TN/FP/FN outcome display
- 29-file / 3-dataset frontend documentation
- F1 tracking in simulation

## Most important next steps
- calibrated detector probabilities
- lower false alarms on benign traffic
- isolated test/eval mode
- multi-class threat detection
- per-file benchmarking and reporting

Overall, the Adaptive Triage Engine has moved from a promising prototype into a much more robust, explainable, and presentation-ready hybrid ML + RL cybersecurity system.