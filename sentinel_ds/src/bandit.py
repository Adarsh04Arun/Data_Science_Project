"""
bandit.py — UCB1 Contextual Bandit for adaptive SOC triage.

Maps (threat_score, analyst_load, threat_density, port_class) contexts to actions:
  0 = Dismiss   |   1 = Monitor   |   2 = Escalate

Improvements (v3):
  - Port-class 4th context dimension (web / auth / other)
  - UCB1 exploration (replaces ε-greedy)
  - Finer Q-table (20×20×5×3 = 6,000 states)
  - Richer context: threat_density + port_class
  - Refined reward function with Monitor-aware rewards
  - Decaying learning rate per state-action visit
  - Q-table persistence with backward-compat shape migration
"""

import os

import numpy as np

# ── Reward Constants ────────────────────────────────────────
# v4 tuning: raised FP penalties to reduce false alarm rate
# while keeping missed-threat penalty dominant (security-first).
R_MISSED_THREAT = (
    -3000
)  # true=1, action=Dismiss — missing any threat is catastrophic
R_CORRECT_ESCALATE = 100  # true=1, action=Escalate (base, scaled by threat_score)
R_MONITOR_THREAT = 50  # true=1, action=Monitor (base, scaled by 1-load)
R_MONITOR_BENIGN = (
    -75
)  # true=0, action=Monitor — raised from -30 to discourage over-monitoring
R_CORRECT_DISMISS = 15  # true=0, action=Dismiss — raised from 10 to reward correct dismissals
R_FALSE_ALARM_BASE = -120  # true=0, action=Escalate (scaled by 1+load) — raised from -50
R_DEFAULT = 1  # fallback

ACTION_NAMES = {0: "Dismiss", 1: "Monitor", 2: "Escalate"}

# ── Port-class constants ────────────────────────────────────
PORT_CLASSES = 3  # 0 = web  |  1 = auth/service  |  2 = other
WEB_PORTS = frozenset({80, 443, 8080, 8443, 3000, 5000, 8000, 8888})
AUTH_PORTS = frozenset({22, 21, 23, 3389, 5900, 1433, 3306, 5432, 6379, 27017})


class BanditAgent:
    """UCB1 Contextual Bandit with a discretised Q-table and decaying LR.

    Context dimensions
    ------------------
    threat_score  : XGBoost probability in [0, 1]     → 20 buckets
    analyst_load  : fraction of analysts busy [0, 1]  → 20 buckets
    threat_density: rolling mean of recent scores     →  5 buckets
    port_class    : 0=web, 1=auth/service, 2=other    →  3 buckets

    Total states: 20 × 20 × 5 × 3 = 6,000
    Q-table shape: (20, 20, 5, 3, 3)  — last dim = 3 actions
    """

    def __init__(
        self,
        n_threat_buckets: int = 20,
        n_load_buckets: int = 20,
        n_density_buckets: int = 5,
        n_port_classes: int = PORT_CLASSES,
        n_actions: int = 3,
        ucb_c: float = 1.0,
        lr_init: float = 0.15,
        lr_decay: float = 0.001,
    ):
        self.n_tb = n_threat_buckets
        self.n_lb = n_load_buckets
        self.n_db = n_density_buckets
        self.n_pc = n_port_classes
        self.n_actions = n_actions

        self.ucb_c = ucb_c
        self.lr_init = lr_init
        self.lr_decay = lr_decay

        # Q-table shape: (threat, load, density, port_class, action)
        shape = (
            n_threat_buckets,
            n_load_buckets,
            n_density_buckets,
            n_port_classes,
            n_actions,
        )
        self.Q = np.zeros(shape)
        self.visit_count = np.zeros(shape, dtype=np.int64)
        self.total_steps = 0

        # Rolling threat density tracker
        self._recent_scores: list = []
        self._density_window = 100

        self.epsilon = 1.0  # kept for dashboard compat

    # ── Port classification ──────────────────────────────────
    @staticmethod
    def _classify_port(dst_port: int) -> int:
        """Map destination port to port class: 0=web, 1=auth/service, 2=other."""
        p = int(dst_port)
        if p in WEB_PORTS:
            return 0
        if p in AUTH_PORTS:
            return 1
        return 2

    # ── Discretisation ───────────────────────────────────────
    def _discretise(
        self,
        threat_score: float,
        analyst_load: float,
        threat_density: float = None,
        dst_port: int = 0,
    ):
        tb = int(np.clip(threat_score * self.n_tb, 0, self.n_tb - 1))
        lb = int(np.clip(analyst_load * self.n_lb, 0, self.n_lb - 1))

        if threat_density is None:
            threat_density = self._get_threat_density()
        db = int(np.clip(threat_density * self.n_db, 0, self.n_db - 1))

        pb = self._classify_port(dst_port)
        return tb, lb, db, pb

    def _get_threat_density(self) -> float:
        if not self._recent_scores:
            return 0.0
        return float(np.mean(self._recent_scores))

    def _get_lr(self, tb, lb, db, pb, action) -> float:
        visits = self.visit_count[tb, lb, db, pb, action]
        return self.lr_init / (1.0 + self.lr_decay * visits)

    # ── Action selection (UCB1) ──────────────────────────────
    def decide(
        self, threat_score: float, analyst_load: float, dst_port: int = 0
    ) -> int:
        """Select action using UCB1 with port-class-aware context."""
        tb, lb, db, pb = self._discretise(threat_score, analyst_load, dst_port=dst_port)
        self.total_steps += 1

        self._recent_scores.append(threat_score)
        if len(self._recent_scores) > self._density_window:
            self._recent_scores.pop(0)

        total_visits = self.visit_count[tb, lb, db, pb].sum()

        # ── Cold-start fallback ──────────────────────────────
        # When NO action in this state has ever been visited, UCB would assign
        # inf to all three actions and np.argmax breaks ties by returning 0
        # (Dismiss) — silently dismissing every high-confidence threat.
        if total_visits == 0:
            if threat_score >= 0.7:
                action = 2  # Escalate
            elif threat_score >= 0.3:
                action = 1  # Monitor
            else:
                action = 0  # Dismiss
            self.epsilon = 1.0
            return action

        ucb_values = np.zeros(self.n_actions)
        for a in range(self.n_actions):
            n_sa = self.visit_count[tb, lb, db, pb, a]
            if n_sa == 0:
                ucb_values[a] = float("inf")
            else:
                exploit = self.Q[tb, lb, db, pb, a]
                explore = self.ucb_c * np.sqrt(np.log(self.total_steps) / n_sa)
                ucb_values[a] = exploit + explore

        # ── Safety constraint ────────────────────────────────
        # Dismiss is permanently excluded from UCB for high-confidence threats
        # so exploration can never route a genuine threat to Dismiss.
        if threat_score >= 0.7:
            ucb_values[0] = -np.inf
        elif threat_score >= 0.3:
            if np.isinf(ucb_values[1]) or np.isinf(ucb_values[2]):
                ucb_values[0] = -np.inf

        # ── Tie-breaking for multiple inf actions ────────────
        inf_mask = np.isinf(ucb_values) & (ucb_values > 0)
        if inf_mask.sum() > 1:
            if threat_score >= 0.7:
                priority = [2, 1, 0]
            elif threat_score >= 0.3:
                priority = [1, 2, 0]
            else:
                priority = [0, 1, 2]
            action = next(a for a in priority if inf_mask[a])
        else:
            action = int(np.argmax(ucb_values))

        self.epsilon = max(0.01, 1.0 / (1.0 + 0.001 * total_visits))
        return action

    # ── Reward computation ───────────────────────────────────
    @staticmethod
    def compute_reward(
        true_label: int, action: int, analyst_load: float, threat_score: float = 0.5
    ) -> float:
        """Asymmetric reward with threat_score scaling and Monitor-aware logic."""
        if true_label == 1 and action == 0:
            return R_MISSED_THREAT * (1.0 + threat_score)

        if true_label == 1 and action == 2:
            return R_CORRECT_ESCALATE * (1.0 + threat_score)

        if true_label == 1 and action == 1:
            return R_MONITOR_THREAT * (1.0 - analyst_load)

        if true_label == 0 and action == 0:
            return R_CORRECT_DISMISS

        if true_label == 0 and action == 2:
            return R_FALSE_ALARM_BASE * (1.0 + analyst_load)

        if true_label == 0 and action == 1:
            return R_MONITOR_BENIGN

        return R_DEFAULT

    # ── Q-table update ───────────────────────────────────────
    def update(
        self,
        threat_score: float,
        analyst_load: float,
        action: int,
        reward: float,
        dst_port: int = 0,
    ):
        tb, lb, db, pb = self._discretise(threat_score, analyst_load, dst_port=dst_port)
        self.visit_count[tb, lb, db, pb, action] += 1

        lr = self._get_lr(tb, lb, db, pb, action)
        self.Q[tb, lb, db, pb, action] += lr * (reward - self.Q[tb, lb, db, pb, action])

    # ── Persistence ──────────────────────────────────────────
    def save(self, directory: str):
        os.makedirs(directory, exist_ok=True)
        np.save(os.path.join(directory, "q_table.npy"), self.Q)
        np.save(os.path.join(directory, "visit_count.npy"), self.visit_count)
        print(f"[Bandit] Q-table saved → {directory}  shape={self.Q.shape}")

    def load(self, directory: str) -> bool:
        """Load Q-table and visit counts, migrating old 4-D format if needed."""
        q_path = os.path.join(directory, "q_table.npy")
        v_path = os.path.join(directory, "visit_count.npy")
        if not (os.path.isfile(q_path) and os.path.isfile(v_path)):
            return False

        loaded_Q = np.load(q_path)
        loaded_V = np.load(v_path)
        expected = (self.n_tb, self.n_lb, self.n_db, self.n_pc, self.n_actions)
        old_4d = (self.n_tb, self.n_lb, self.n_db, self.n_actions)

        if loaded_Q.shape == expected:
            # Exact match — load directly
            self.Q = loaded_Q
            self.visit_count = loaded_V

        elif loaded_Q.shape == old_4d:
            # v2 format (no port-class) — broadcast across port classes
            print("[Bandit] Migrating v2 Q-table (4-D → 5-D with port-class dimension)")
            self.Q = np.broadcast_to(loaded_Q[:, :, :, np.newaxis, :], expected).copy()
            self.visit_count = np.broadcast_to(
                loaded_V[:, :, :, np.newaxis, :], expected
            ).copy()

        else:
            print(
                f"[Bandit] Q-table shape mismatch: got {loaded_Q.shape}, "
                f"expected {expected} — starting fresh"
            )
            return False

        self.total_steps = int(self.visit_count.sum())
        print(
            f"[Bandit] Q-table loaded ← {directory}  "
            f"shape={self.Q.shape}  visits={self.total_steps:,}"
        )
        return True


# ── CLI quick-test ───────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  BanditAgent v3 — Quick Smoke Test (port-class context)")
    print("=" * 60)
    agent = BanditAgent()
    ports = [80, 443, 22, 3389, 53, 8080, 21, 0]
    for i in range(400):
        ts = np.random.rand()
        al = np.random.rand()
        port = ports[i % len(ports)]
        a = agent.decide(ts, al, dst_port=port)
        true = 1 if ts > 0.5 else 0
        r = agent.compute_reward(true, a, al, ts)
        agent.update(ts, al, a, r, dst_port=port)

    print(f"  Q-table shape  : {agent.Q.shape}")
    print(f"  Total visits   : {agent.total_steps:,}")

    # Verify port class mapping
    for port, expected_cls in [
        (80, 0),
        (443, 0),
        (22, 1),
        (3389, 1),
        (53, 2),
        (9999, 2),
    ]:
        cls = BanditAgent._classify_port(port)
        status = "✓" if cls == expected_cls else "✗"
        print(f"  port={port:<5} → class {cls}  {status}")

    agent.save("/tmp/bandit_v3_test")
    agent2 = BanditAgent()
    agent2.load("/tmp/bandit_v3_test")
    print(f"  Loaded Q matches: {np.allclose(agent.Q, agent2.Q)}")

    # Test migration from old 4-D format
    old_q = np.zeros((20, 20, 5, 3))
    old_v = np.zeros((20, 20, 5, 3), dtype=np.int64)
    np.save("/tmp/q_table.npy", old_q)
    np.save("/tmp/visit_count.npy", old_v)
    agent3 = BanditAgent()
    migrated = agent3.load("/tmp")
    print(f"  Migration test  : shape={agent3.Q.shape}  migrated={migrated}")
    print("=" * 60)
