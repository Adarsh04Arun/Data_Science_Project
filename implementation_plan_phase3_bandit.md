# Phase 3 & 4: Contextual Bandit and Orchestration — Implementation Plan

## Objective
Build the simulated environment where the Bandit decides whether to Escalate, Monitor, or Dismiss based on Analyst Load and the Threat Score, and orchestrate the full pipeline.

## Proposed Changes

### [NEW] `src/bandit.py`

- Create a Contextual Q-Learning or Epsilon-Greedy `BanditAgent` class:
  - **State/Context (`x_t`)**: `[threat_score_bucket, analyst_load_bucket]`. Discretizing these continuous values (e.g., into 10 buckets each) simplifies the Q-table significantly and ensures fast convergence.
  - **Actions (`a_t`)**: 
    - `0`: Dismiss
    - `1`: Monitor
    - `2`: Escalate
  - **Rewards (`r_t`)**:
    - High penalty for False Negatives (Dismissing an actual threat).
    - Moderate penalty for False Positives (Escalating benign flows) scaled proportionally by `analyst_load`.
    - Positive reward for True Positives (Escalating a threat) and True Negatives (Dismissing a benign flow).
  - `decide(context_vector)`: Returns an action based on max Q-value + ε-greedy exploration.
  - `update(context_vector, action, reward)`: Bellman equation update for the Q-table.

### [NEW] `main.py`

- The orchestrator script:
  1. Initializes `data_loader.py` to yield sequential chunks of the datasets (preventing WSL OOM crashes).
  2. Applies `features.py` processing per chunk.
  3. **Chronological Split**: Since attacks are temporal, the orchestrator trains the `ThreatDetector` continuously on the first $N$ chunks (representing ~80% of the timeline) using `.partial_train()`.
  4. The remaining chunks (the last ~20% of the timeline) trigger the online simulation phase.
  5. Enters the highly-optimized simulation loop over the test chunks:
     - Derives `threat_score` vectors for the test chunk.
     - Modifies `analyst_load` periodically (e.g., follows a sine wave pattern or steps `0.2 -> 0.8 -> 0.2` to simulate shifts).
     - Passes `[threat_score, analyst_load]` to the `BanditAgent`.
     - Calculates the actual reward based on the Ground Truth `y` test label.
     - Updates the agent's Q-table immediately.
  6. **Logging/Visualization**: Plots cumulative reward, action divergence under high load, and rolling accuracy. Saves to `output/`.

## Verification
- Run `python3 main.py`.
- Pipeline should hit zero errors.
- Visual inspection of `output/*.png`:
  - When Analyst Load is artificially spiked to 0.9, the Bandit should shift its actions from "Escalate" toward "Monitor" or "Dismiss" for lower `threat_scores` to adapt to the penalization.
