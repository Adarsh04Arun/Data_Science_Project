"""
behaviour.py — Sliding-window behavioural feature aggregator.

Computes cross-flow statistics per source IP over a rolling time window.
These features capture attack patterns (brute force, port scanning, web attacks)
that are statistically invisible in single per-flow measurements.

The aggregator is stateful: it must be updated with each incoming flow before
the features are extracted. During batch CSV processing, a synthetic source key
is derived from the destination port and flow index when no real source IP is
available.

Behavioural features computed
-----------------------------
beh_conn_rate_per_min   : connections per minute from this source
beh_short_flow_ratio    : fraction of flows with very short duration (failed/rejected)
beh_unique_dst_ports    : number of distinct destination ports (port diversity)
beh_pkt_size_std        : standard deviation of average packet sizes (payload uniformity)
beh_flow_count_window   : total flows from this source in the window
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional

import numpy as np

# ── Public feature name list (keep in sync with any callers) ─
BEHAVIOURAL_FEATURES: List[str] = [
    "beh_conn_rate_per_min",
    "beh_short_flow_ratio",
    "beh_unique_dst_ports",
    "beh_pkt_size_std",
    "beh_flow_count_window",
    "beh_large_payload_ratio",
    "beh_avg_duration",
]

# Thresholds used for normalising raw values to a [0, 1] behaviour score
_CONN_RATE_MAX   = 300.0   # 300 connections/min = saturated attack
_PORT_DIV_MAX    =  20.0   # 20 unique ports = clear port scan
_SHORT_DUR_THRESH = 1_000.0   # flow durations below 1 000 µs count as "short"
_LARGE_PAYLOAD_THRESH = 10_000.0  # fwd payload > 10 KB = large outbound
_LONG_DURATION_MAX = 120_000.0    # 120 sec = very long flow (exfiltration indicator)


class BehaviourAggregator:
    """
    Per-source-IP sliding window that accumulates flow records and computes
    cross-flow behavioural features on demand.

    Parameters
    ----------
    window_seconds    : only flows younger than this (wall-clock seconds) are
                        included in feature calculations.
    max_flows_per_src : maximum buffer depth per source (oldest entries are
                        discarded when the deque is full).
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_flows_per_src: int = 200,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_flows_per_src = max_flows_per_src
        # src_key → deque of flow records
        self._buffers: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=max_flows_per_src)
        )

    # ── Public API ───────────────────────────────────────────────

    def update(
        self,
        src_key: str,
        dst_port: int,
        flow_duration: float,
        pkt_size_avg: float,
        fwd_payload_bytes: float = 0.0,
    ) -> None:
        """
        Record a new flow for *src_key*.

        Parameters
        ----------
        src_key       : source identifier — ideally source IP; falls back to
                        any stable per-source string.
        dst_port      : destination port of this flow.
        flow_duration : flow duration in microseconds (CICFlowMeter unit).
        pkt_size_avg  : average packet size in bytes.
        fwd_payload_bytes : total forward (outbound) payload in bytes.
        """
        self._buffers[src_key].append(
            {
                "ts":       time.monotonic(),
                "dst_port": int(dst_port),
                "duration": float(flow_duration),
                "pkt_size": float(pkt_size_avg),
                "fwd_bytes": float(fwd_payload_bytes),
            }
        )

    def get_features(self, src_key: str) -> Dict[str, float]:
        """
        Return a dict of the five behavioural features for *src_key*.

        All values default to 0.0 when no history exists.
        """
        buf = self._buffers.get(src_key)
        if not buf:
            return {f: 0.0 for f in BEHAVIOURAL_FEATURES}

        now    = time.monotonic()
        cutoff = now - self.window_seconds
        window = [r for r in buf if r["ts"] >= cutoff]

        n = len(window)
        if n == 0:
            return {f: 0.0 for f in BEHAVIOURAL_FEATURES}

        # Connection rate (per minute)
        elapsed       = max(1.0, now - window[0]["ts"])
        conn_rate     = (n / elapsed) * 60.0

        # Short-flow ratio (failed / rejected connections)
        short_count   = sum(1 for r in window if r["duration"] < _SHORT_DUR_THRESH)
        short_ratio   = short_count / n

        # Port diversity
        unique_ports  = float(len(set(r["dst_port"] for r in window)))

        # Packet-size variance (attack tools tend to send uniform-size payloads)
        sizes         = [r["pkt_size"] for r in window]
        pkt_size_std  = float(np.std(sizes)) if len(sizes) > 1 else 0.0

        # Large-payload ratio (exfiltration signal)
        large_count   = sum(1 for r in window if r.get("fwd_bytes", 0) > _LARGE_PAYLOAD_THRESH)
        large_ratio   = large_count / n

        # Average flow duration (long flows = sustained exfiltration)
        avg_duration  = float(np.mean([r["duration"] for r in window]))

        return {
            "beh_conn_rate_per_min": conn_rate,
            "beh_short_flow_ratio":  short_ratio,
            "beh_unique_dst_ports":  unique_ports,
            "beh_pkt_size_std":      pkt_size_std,
            "beh_flow_count_window": float(n),
            "beh_large_payload_ratio": large_ratio,
            "beh_avg_duration":      avg_duration,
        }

    def get_score(self, src_key: str) -> float:
        """
        Aggregate the five behavioural features into a single normalised
        threat score in [0, 1].

        Weights
        -------
        - Connection rate     : 35 % — most reliable brute-force signal
        - Short-flow ratio    : 20 % — failed auth / rejected connections
        - Port diversity      : 15 % — port scanning indicator
        - Large-payload ratio : 20 % — data exfiltration signal
        - Avg duration        : 10 % — sustained connection indicator
        """
        feat = self.get_features(src_key)

        conn_rate_score  = min(1.0, feat["beh_conn_rate_per_min"] / _CONN_RATE_MAX)
        short_flow_score = float(feat["beh_short_flow_ratio"])
        port_div_score   = min(1.0, feat["beh_unique_dst_ports"] / _PORT_DIV_MAX)
        large_pay_score  = float(feat["beh_large_payload_ratio"])
        avg_dur_score    = min(1.0, feat["beh_avg_duration"] / _LONG_DURATION_MAX)

        score = (
            0.35 * conn_rate_score
            + 0.20 * short_flow_score
            + 0.15 * port_div_score
            + 0.20 * large_pay_score
            + 0.10 * avg_dur_score
        )
        return float(np.clip(score, 0.0, 1.0))

    def get_feature_vector(self, src_key: str) -> np.ndarray:
        """Return features as a float32 array in BEHAVIOURAL_FEATURES order."""
        feat = self.get_features(src_key)
        return np.array([feat[f] for f in BEHAVIOURAL_FEATURES], dtype=np.float32)

    def clear(self, src_key: Optional[str] = None) -> None:
        """Clear buffer for one source key, or all sources if *src_key* is None."""
        if src_key is None:
            self._buffers.clear()
        elif src_key in self._buffers:
            self._buffers[src_key].clear()

    def source_count(self) -> int:
        """Return number of distinct sources currently tracked."""
        return len(self._buffers)

    # ── Persistence ──────────────────────────────────────────────

    def save(self, path: str) -> None:
        """Persist aggregator state to disk via joblib."""
        import joblib
        # Convert defaultdict of deques → plain dict of lists for serialisation
        state = {
            "window_seconds": self.window_seconds,
            "max_flows_per_src": self.max_flows_per_src,
            "buffers": {k: list(v) for k, v in self._buffers.items()},
        }
        joblib.dump(state, path)

    @classmethod
    def load(cls, path: str) -> "BehaviourAggregator":
        """Restore aggregator state from a file saved by `save()`."""
        import os
        import joblib
        if not os.path.exists(path):
            return cls()
        state = joblib.load(path)
        agg = cls(
            window_seconds=state.get("window_seconds", 60.0),
            max_flows_per_src=state.get("max_flows_per_src", 200),
        )
        for k, records in state.get("buffers", {}).items():
            dq = agg._buffers[k]
            for r in records:
                dq.append(r)
        return agg


# ── CLI smoke test ───────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  BehaviourAggregator — Smoke Test")
    print("=" * 60)

    agg = BehaviourAggregator(window_seconds=10.0)

    # Simulate a brute-force attacker: many short flows to the same port
    for _ in range(120):
        agg.update("192.168.1.101", dst_port=22, flow_duration=200.0, pkt_size_avg=52.0)

    # Simulate normal user: a few longer flows to various ports
    for port in [80, 443, 8080]:
        agg.update("10.0.0.5", dst_port=port, flow_duration=50_000.0, pkt_size_avg=512.0)

    for src in ["192.168.1.101", "10.0.0.5"]:
        feats = agg.get_features(src)
        score = agg.get_score(src)
        print(f"\n  {src}")
        for k, v in feats.items():
            print(f"    {k:<30}: {v:.3f}")
        print(f"    {'behaviour_score':<30}: {score:.3f}")

    print()
    print(f"  Sources tracked: {agg.source_count()}")
    print("=" * 60)
