# Adaptive Triage Engine — Changelog

## v1.0 — Core Pipeline (Completed)
**Files:** `data_loader.py`, `features.py`, `detector.py`, `bandit.py`, `main.py`

- Built memory-safe chunked data loading from 10 CIC-IDS2018 parquet files via PyArrow `iter_batches()`
- Implemented feature engineering: 60 selected CICFlowMeter features, float32 downcasting, incremental StandardScaler, binary label binarisation
- Created GPU-accelerated XGBoost ThreatDetector with CUDA/CPU fallback and partial_train() for incremental learning
- Built ε-greedy Contextual Bandit with discretised Q-table (10×10×3), asymmetric reward function (−1000 for missed threats)
- Orchestrator: 80/20 chronological train/test split, 5-phase analyst load schedule, matplotlib plots, JSON state export

## v2.0 — React Dashboard (Completed)
**Files:** `api.py`, `frontend/src/App.jsx`, `frontend/src/index.css`

- FastAPI backend with CORS, `/api/state` endpoint transforming raw pipeline data into display-friendly traffic logs and threat reports
- React + Vite frontend with premium dark SOC theme (Inter + JetBrains Mono, neon accents, glassmorphism, custom scrollbar)
- Dashboard: 4 KPI cards, live traffic feed with color-coded tags, endpoint hit bars, AI SOC analyst report cards with confidence bars, rule pills, and mitigation boxes
- Critical threat banner with pulse animation

## v3.0 — Explanation Tabs (Completed)
**Files:** `DataPipelineTab.jsx`, `ModelArchitectureTab.jsx`, `RLBanditTab.jsx`, `LiveMetricsTab.jsx`

- Added 5-tab navigation (Dashboard, Data Pipeline, Model, RL Bandit, Metrics)
- Data Pipeline tab: flow diagram, parquet file grid, processing stats, memory optimisation strategy
- Model tab: XGBoost config code block, incremental training steps, class imbalance bar
- RL Bandit tab: reward function table, ε decay visualisation, Q-table structure, action cards
- Metrics tab: pipeline status indicator, summary stats, embedded matplotlib plots with explanations

## v4.0 — Raw Data Examples & Live Training (Completed)
**Files:** `api.py`, `main.py`, `DataPipelineTab.jsx`, `LiveTrainingTab.jsx`, `index.css`

- `/api/data-sample` endpoint reads real parquet data and returns before/after processing views
- Data Pipeline tab now shows actual raw data rows (Dst Port, Flow Duration, Label, etc.) and the processed version (float32, is_threat binary label)
- Updated `main.py` to write `progress.json` throughout training and simulation phases
- `/api/progress` endpoint serves live progress data
- New **Live Training** tab with:
  - Phase progress tracker (Loading → Training → Simulation → Plotting → Complete)
  - Progress bar with percentage
  - Live metrics cards (Recall, Precision, Cumulative Reward, Epsilon)
  - Auto-scrolling console with color-coded log entries (green = training, blue = simulation, cyan = pipeline)

## v5.0 — AI Model Improvements (Completed)
**Files:** `detector.py`, `bandit.py`, `main.py`

### XGBoost Detector
- Tuned hyperparameters: `max_depth=8`, `lr=0.08`, `subsample=0.75`, `colsample_bytree=0.75`, `gamma=3`, `min_child_weight=7`, `n_estimators=250`
- Dynamic `scale_pos_weight` calculated per chunk based on actual class distribution
- Early stopping with 90/10 internal eval split per chunk
- Feature importance extraction and top-5 logging
- L1/L2 regularisation (`reg_alpha=0.1`, `reg_lambda=1.5`)

### Contextual Bandit RL
- **UCB1 exploration** replacing ε-greedy — uses existing `visit_count` for intelligent exploration
- Finer Q-table: 20×20×5 (2,000 states, up from 100)
- Richer context: added rolling **threat density** dimension (burst detection)
- Refined reward function: Monitor-aware rewards, threat_score scaling on missed-threat penalty, load-scaling on false alarms
- Decaying learning rate per state-action pair: `lr / (1 + decay × visits)`
- **Q-table persistence**: saves/loads between `main.py` runs for continuous learning

### Pipeline
- Proper validation set: last 2 training chunks held out, validation accuracy reported instead of training accuracy
- F1-score tracking alongside precision and recall (plotted + logged)
- Q-table auto-save/load in output directory

