# Adaptive Triage Engine

An AI-driven autonomous cyber threat hunting agent built to reduce alert fatigue in Security Operations Centers (SOCs). The system combines a high-speed supervised detector with a reinforcement-learning triage agent to decide whether suspicious network traffic should be **Dismissed**, **Monitored**, or **Escalated**.

The project includes:
- a **Python backend** for model training, simulation, and inference,
- a **FastAPI service** for dashboard APIs and CSV testing,
- a **React frontend** for live monitoring, architecture explanation, and test-time analysis.

---

## Overview

Traditional IDS systems answer only one question:

> "Is this flow malicious?"

That is not enough for a real SOC.

The Adaptive Triage Engine answers the more useful operational question:

> "Given this threat score, behavioural profile, and current analyst conditions, what should we do next?"

So the system is split into two stages:

1. **Threat Detection & Behaviour** — XGBoost models score network flows, fused with cross-flow behavioural aggregations, yielding a calibrated score from `0.0` to `1.0`.
2. **Autonomous Triage** — a contextual bandit chooses:
   - `Dismiss`
   - `Monitor`
   - `Escalate`

This makes the system both:
- **ML-driven** for pattern recognition, and
- **RL-driven** for operational decision-making.

---

## Current System Architecture

## 1. Stage One — Threat Detection & Calibration

The first layer consists of supervised binary classifiers that label flows as:

- `Benign = 0`
- `Threat = 1`

### Dual-Detector Architecture

- **Main Detector**: XGBoost model for general traffic (SYN floods, port scans, etc.).
- **Web Detector**: Specialized XGBoost model trained exclusively on web-port traffic (ports 80, 443, 8080, etc.) to catch subtle Application-layer attacks like XSS or SQLi.
- **Routing**: Flows are dynamically routed to the appropriate detector based on `dst_port`.

### Probability Calibration
Raw XGBoost outputs are not true probabilities. Both detectors are passed through an **Isotonic Regression Calibrator** trained on a reservoir-sampled validation set (representing a true mix of benign and threat data from across the entire training pipeline). This ensures that a threat score of `0.8` genuinely means an 80% statistical confidence.

### Feature Pipeline
The models are trained on **61 selected flow features** derived from CICFlowMeter-style network statistics, including:
- ports, packet counts, lengths, flow duration
- bytes/second, packets/second, inter-arrival times
- TCP flag counters, segment/window statistics, active/idle timings

### Behaviour Aggregation
Individual flow records cannot catch distributed brute force or scanning. A `BehaviourAggregator` maintains a per-source-IP sliding window to track:
- Connection rates (burst detection)
- Short-flow ratios (failed auth)
- Port diversity (scanning)
The behavioral score is fused with the detector score (`max(detector_score, behaviour_score)`).

### Adaptive Thresholding
- **Web-port flows**: Detection threshold is relaxed to `0.25` because web attacks statistically resemble benign HTTP at the flow layer.
- **Other flows**: Standard detection threshold of `0.5`.

---

## 2. Stage Two — Autonomous Analyst (Contextual Bandit RL)

The second layer is a **Contextual Bandit**, acting as the decision engine.

### Current context used by the bandit

The bandit operates on a discretised 4D context space:

1. **Threat Score** — from the calibrated XGBoost + Behaviour fusion
2. **Analyst Load** — simulated SOC busyness [0.0 - 1.0]
3. **Threat Density** — rolling average of recent threat scores
4. **Port Class** — categorical awareness of the traffic target (0=web, 1=auth/service, 2=other)

### Action space

The bandit can choose one of three actions:

- **Dismiss (0)** — ignore the flow
- **Monitor (1)** — flag for low-priority review / observation
- **Escalate (2)** — treat as a serious event requiring immediate attention

### Current bandit implementation

The RL agent features:
- **UCB1 exploration**
- **20 × 20 × 5 × 3 state discretisation** (18,000 buckets)
- **Q-table persistence**
- **decaying learning rate**
- **refined asymmetric reward function**

---

## Reward Design

The reward function is intentionally asymmetric because in cybersecurity:

> missing a real attack is far worse than reviewing a benign event.

### Current reward logic

- **Missed Threat** (`true=1`, `Dismiss`)
  - **Massive catastrophic penalty** (-3000)
- **Correct Escalation** (`true=1`, `Escalate`)
  - strong positive reward
- **Monitor a True Threat**
  - positive middle-ground reward
- **Dismiss a Benign Flow**
  - small positive reward
- **Escalate a Benign Flow**
  - negative reward (worsens under higher analyst load)
- **Monitor a Benign Flow**
  - small penalty (-30) to discourage lazy over-monitoring

---

## Important Reliability & Safety Fixes

### 1. UCB1 cold-start fix & High-threat safety constraint
- Unseen states now use a threat-aware fallback (`score >= 0.7` → `Escalate`, etc.) instead of defaulting to `Dismiss`.
- High-confidence threats (`>= 0.7`) strictly block `Dismiss` from UCB exploration.

### 2. Online learning & Freeze Mode
- Testing endpoints update the Q-table in real-time, learning from labelled feedback.
- Added `?freeze=true` to endpoints to disable Q-table updates when reproducible, side-effect-free benchmarking is required.

### 3. Scaler and Calibration Robustness
- Automatically validates the saved `StandardScaler` to ensure inference matches training.
- Calibration uses 5% reservoir sampling from across all training chunks to avoid single-class failure modes (where the last chunk was purely malicious).

---

## Datasets Used

The project currently works across **29 files** grouped into **3 datasets**.

1. **BCCC-CSE-CIC-IDS2018 (10 Parquet files)**
2. **BCCC-CIC-IDS2017 (18 CSV files)**
3. **BCCC-cPacket-Cloud-DDoS-2024 (1 Parquet file)**

---

## Data Pipeline

Designed for memory-constrained environments via chunked processing:
1. Stream file chunks
2. Clean and standardize features
3. Train XGBoost models incrementally
4. Calibrate via Reservoir Sampling
5. Simulate Contextual Bandit (online RL phase)
6. Generate Plots and Dashboard State

---

## Frontend Dashboard

The React frontend presents:
- **Dashboard** — live SOC-style operational view
- **Data Pipeline** — source datasets, preprocessing, feature engineering
- **Model** — detector explanation
- **RL Bandit** — contextual bandit explanation
- **Live Training** — real-time progress while `main.py` is running
- **Metrics** — generated plots and simulation performance
- **Test Model** — interactive CSV upload / endpoint tester

### Metrics-First Evaluation
Instead of misleading raw accuracy, the dashboard surfaces:
- **Detector metrics:** Precision, Recall, F1
- **Agent metrics:** Precision, Detection Rate, F1, False Alarms, Missed Threats
- **Confusion Matrices** for both layers.

---

## Quick Setup

### Requirements
- Ubuntu / WSL recommended
- Python 3.10+
- Node.js + npm

### Install dependencies

```bash
cd sentinel_ds
pip install -r requirements.txt
cd frontend
npm install
```

---

## Running the System

### 1. Start dashboard + backend
From the project root:
```bash
./start.sh
```
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`

### 2. Run the full training pipeline
```bash
cd sentinel_ds
python3 main.py
```

### 3. Testing Interfaces
- **Test Model Tab**: Upload `sentinel_ds/test_traffic.csv` directly in the UI.
- **Live Test Stream**: Simulates a live traffic feed from the command line:
  ```bash
  python3 live_test_stream.py --attack-ratio 0.4 --delay-ms 100
  ```