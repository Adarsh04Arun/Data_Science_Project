"""
data_generator.py — Mock & Real Data Loader for Adaptive Triage Engine

Generates synthetic telecom SOC events matching the schema of
telecom_soc_events_sample_5k.csv, or loads the real CSV.
"""

import os
import random
import string
import numpy as np
import pandas as pd
from datetime import datetime, timedelta


# ──────────────────────────────────────────────────────────
# Constants — mirrors the real dataset's categorical values
# ──────────────────────────────────────────────────────────
HOSTS = [
    "IMS-CSCF-01", "CRM-APP-01", "SBC-EDGE-01", "BSS-APP-01",
    "TELCO-CORE-01", "TELCO-CORE-02", "PGW-01", "SGW-01",
    "FW-EDGE-01", "NAT-01",
]

USERS = ["alice", "bob", "charlie", "netops", "secops",
         "dbadmin", "system", "svc_ims", "svc_bss", "svc_crm"]

PROCESSES = [
    "", "systemd", "postgres", "node.exe", "nginx.exe",
    "java.exe", "kamailio", "freeswitch", "dnsmasq",
    "powershell.exe", "sshd",
]

EVENT_TYPES = [
    "net_connection", "dns_query", "logon_success", "logon_failure",
    "proc_start", "sip_invite", "sip_register", "autorun_entry",
    "service_install", "scheduled_task_created",
]

ACTIONS = ["auth", "query", "connect", "spawn", "register",
           "permit", "deny", "invite"]

SEVERITIES = [
    ("informational", 0),
    ("low", 1),
    ("medium", 2),
    ("high", 3),
    ("critical", 4),
]

PROTOCOLS = ["HTTP", "HTTPS", "DNS", "SIP", "SSH", "SMTP"]

SERVICES = [
    "VoIP", "Core-Network", "BSS", "Customer-CRM",
    "Mail-Server", "Web-Portal", "OSS",
]

DNS_QUERIES = [
    "pool.ntp.org", "update.microsoft.com", "cdn.media-service.com",
    "api.telco.local", "sip.telco.example", "auth.telco.example",
    "metrics.telco.example", "login.partner-ssp.com",
    "repo.oss-mirror.net", "packages.cloud.example",
]

COUNTRIES = ["US", "US", "US", "US", "IN", "CN", "CN"]  # weighted toward US

SUSPICIOUS_EVENT_TYPES = [
    "autorun_entry", "service_install", "scheduled_task_created",
]

SUSPICIOUS_PROCESSES = ["powershell.exe"]


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────

def _random_internal_ip():
    """Generate a random RFC-1918 internal IP."""
    prefix = random.choice(["10.", "172.16.", "172.17.", "172.18.",
                            "192.168."])
    if prefix == "10.":
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"{prefix}{random.randint(0,255)}.{random.randint(1,254)}"


def _random_external_ip():
    """Generate a random public-ish IP."""
    return (f"{random.choice([1,8,13,23,31,34,40,52,54,64,72,91,104,128,142,185,199])}."
            f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(1,254)}")


def _random_hex(length=16):
    return "".join(random.choices(string.hexdigits[:16], k=length))


def _build_msg(event_type, protocol, service, country, is_internal_dst):
    """Build a realistic msg field matching the real data format."""
    bytes_out = random.randint(40, 40000)
    bytes_in = random.randint(40, 25000)
    latency_ms = random.randint(1, 120)

    if is_internal_dst:
        direction = "internal"
    elif random.random() < 0.15:
        direction = "ingress"
    else:
        direction = "egress"

    parts = [f"direction={direction}"]

    # DNS queries have extra fields
    if event_type == "dns_query":
        query = random.choice(DNS_QUERIES)
        parts.insert(0, f"query={query}")
        if random.random() < 0.6:
            parts.insert(1, f"answer={_random_external_ip()}")

    # SIP events have call_id / from / to
    if event_type in ("sip_invite", "sip_register"):
        parts.insert(0, f"call_id={_random_hex()}")
        parts.insert(1, f"from=+91{random.randint(6000000000, 9999999999)}")
        if event_type == "sip_invite":
            parts.insert(2, f"to=+91{random.randint(6000000000, 9999999999)}")

    parts.extend([
        f"bytes_out={bytes_out}",
        f"bytes_in={bytes_in}",
        f"latency_ms={latency_ms}",
        f"protocol={protocol}",
        f"service={service}",
        f"asn=AS{random.choice([3356, 4837, 8075, 9498, 13335, 15169, 16509])}",
        f"country={country}",
    ])

    return "; ".join(parts)


# ──────────────────────────────────────────────────────────
# Suspicious-label logic  (mirrors real data distribution)
# ──────────────────────────────────────────────────────────

def _compute_suspicious_probability(event_type, severity_num, country,
                                    is_internal_src, process):
    """
    Heuristic probability of label_suspicious=1.
    Real data has ~15-18 % positive rate. We replicate that.
    """
    p = 0.04  # baseline

    # High / critical severity → more suspicious
    if severity_num >= 3:
        p += 0.15
    if severity_num == 4:
        p += 0.10

    # Persistence / lateral-movement event types
    if event_type in SUSPICIOUS_EVENT_TYPES:
        p += 0.35

    # External source hitting internal target
    if not is_internal_src:
        p += 0.05

    # Suspicious origin countries
    if country == "CN":
        p += 0.10

    # Suspicious process
    if process in SUSPICIOUS_PROCESSES:
        p += 0.12

    return min(p, 0.95)


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

def generate_mock_data(n: int = 5000, seed: int = 42) -> pd.DataFrame:
    """
    Generate *n* synthetic telecom SOC events.

    Returns a DataFrame with the same columns as the real
    telecom_soc_events_sample_5k.csv.
    """
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)
    random.seed(seed)

    base_time = datetime(2025, 8, 28, 13, 0, 0)
    rows = []

    for _ in range(n):
        # Timestamp within an 8-hour window
        offset_sec = rng.randint(0, 8 * 3600)
        ts = base_time + timedelta(seconds=offset_sec)
        timestamp = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        date_str = ts.strftime("%Y-%m-%d")
        hour = ts.hour

        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        process = rng.choice(PROCESSES)
        event_type = rng.choice(EVENT_TYPES)
        action = rng.choice(ACTIONS)
        status = "observed"
        sev_name, sev_num = rng.choice(SEVERITIES)
        protocol = rng.choice(PROTOCOLS)
        service = rng.choice(SERVICES)

        # Source / Destination IPs
        is_internal_src = 1 if rng.random() < 0.82 else 0
        is_internal_dst = 1 if rng.random() < 0.30 else 0

        src_ip = _random_internal_ip() if is_internal_src else _random_external_ip()
        dst_ip = (_random_internal_ip() if is_internal_dst
                  else _random_external_ip())

        country = rng.choice(COUNTRIES)
        tags = "telecom|realtime"

        msg = _build_msg(event_type, protocol, service, country,
                         is_internal_dst)

        # Label
        p_sus = _compute_suspicious_probability(
            event_type, sev_num, country, is_internal_src, process
        )
        label_suspicious = 1 if rng.random() < p_sus else 0

        rows.append({
            "timestamp": timestamp,
            "date": date_str,
            "hour": hour,
            "host": host,
            "user": user,
            "process": process,
            "event_type": event_type,
            "action": action,
            "status": status,
            "severity": sev_name,
            "severity_num": sev_num,
            "protocol": protocol,
            "service": service,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "is_internal_src": is_internal_src,
            "is_internal_dst": is_internal_dst,
            "tags": tags,
            "msg": msg,
            "label_suspicious": label_suspicious,
        })

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def load_real_data(csv_path: str | None = None) -> pd.DataFrame:
    """
    Load the real telecom_soc_events_sample_5k.csv.

    Parameters
    ----------
    csv_path : str, optional
        Explicit path to the CSV file. If None, tries the default
        relative path from the sentinel_ds project root.

    Returns
    -------
    pd.DataFrame
    """
    if csv_path is None:
        # Default: relative to this file → sentinel_ds/src/ → up 2 → Telecom-SOC/
        csv_path = os.path.join(
            os.path.dirname(__file__), os.pardir, os.pardir,
            "Telecom-SOC", "telecom_soc_events_sample_5k.csv",
        )

    csv_path = os.path.abspath(csv_path)

    if not os.path.isfile(csv_path):
        raise FileNotFoundError(
            f"Real data not found at {csv_path}. "
            "Use generate_mock_data() instead."
        )

    df = pd.read_csv(csv_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def load_data(prefer_real: bool = True, n_mock: int = 5000) -> pd.DataFrame:
    """
    Convenience loader: tries real data first, falls back to mock.

    Parameters
    ----------
    prefer_real : bool
        If True, attempt to load the CSV; fall back to mock on failure.
    n_mock : int
        Number of rows if generating mock data.

    Returns
    -------
    tuple[pd.DataFrame, str]
        (dataframe, source_label)
    """
    if prefer_real:
        try:
            df = load_real_data()
            print(f"[DataLoader] ✓ Loaded REAL data — {len(df):,} rows")
            return df, "real"
        except FileNotFoundError as e:
            print(f"[DataLoader] Real data unavailable: {e}")
            print("[DataLoader] Falling back to mock data …")

    df = generate_mock_data(n=n_mock)
    print(f"[DataLoader] ✓ Generated MOCK data — {len(df):,} rows")
    return df, "mock"


# ──────────────────────────────────────────────────────────
# CLI quick-test
# ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Adaptive Triage Engine — Data Generator")
    print("=" * 60)

    # Try real data first
    df, source = load_data(prefer_real=True)

    print(f"\n  Source : {source}")
    print(f"  Shape : {df.shape}")
    print(f"  Columns: {list(df.columns)}")
    print(f"\n  Label distribution:")
    print(df["label_suspicious"].value_counts().to_string())
    print(f"\n  Suspicious rate: "
          f"{df['label_suspicious'].mean():.1%}")
    print(f"\n  Sample rows:\n{df.head(3).to_string()}")
    print("=" * 60)
