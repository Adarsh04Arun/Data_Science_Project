#!/usr/bin/env python3
"""
generate_test_csv.py — Generate a CIC-IDS2018-formatted CSV for testing.

Creates ~50 rows of mixed attack scenarios + benign traffic with
all 62 features that the XGBoost detector expects.

Usage:
    python3 generate_test_csv.py              # → test_traffic.csv
    python3 generate_test_csv.py output.csv   # → custom filename
"""

import sys
import csv
import random
import math

# The exact 62 features the model uses + Label column
FEATURES = [
    "Src IP",
    "Dst Port", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd Header Len", "Bwd Header Len",
    "Fwd Pkts/s", "Bwd Pkts/s",
    "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt",
    "Down/Up Ratio", "Pkt Size Avg",
    "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Init Fwd Win Byts", "Init Bwd Win Byts",
    "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    "Label",
]


def _jitter(base, pct=0.15):
    """Add ±pct% random noise to a value."""
    return base * (1 + random.uniform(-pct, pct))


def make_benign_http():
    """Normal HTTP browsing flow — based on real CIC-IDS benign distributions."""
    # Real benign: very short flows, few packets, small payloads
    dur = random.choice([
        random.uniform(0, 500),       # very short (majority of real benign)
        random.uniform(500, 5000),    # moderate
        random.uniform(5000, 30000),  # occasional longer flows
    ])
    fwd_pkts = random.choice([1, 1, 2, 2, 2, 3, 3, 4])  # median ~2
    bwd_pkts = random.choice([0, 1, 1, 2, 2, 2, 3, 3])  # median ~2
    fwd_payload = random.uniform(40, 200)  # median ~88 bytes
    bwd_payload = random.uniform(40, 200)
    total_pkts = fwd_pkts + bwd_pkts
    return {
        "Src IP": f"192.168.1.{random.randint(10, 50)}",
        "Dst Port": random.choice([80, 443, 443, 53, 53, 53]),  # real: 53/443/80 dominate
        "Flow Duration": dur,
        "Tot Fwd Pkts": fwd_pkts, "Tot Bwd Pkts": bwd_pkts,
        "TotLen Fwd Pkts": fwd_payload * fwd_pkts,
        "TotLen Bwd Pkts": bwd_payload * bwd_pkts,
        "Fwd Pkt Len Max": fwd_payload, "Fwd Pkt Len Min": 0,
        "Fwd Pkt Len Mean": fwd_payload * 0.8, "Fwd Pkt Len Std": 10,
        "Bwd Pkt Len Max": bwd_payload, "Bwd Pkt Len Min": 0,
        "Bwd Pkt Len Mean": bwd_payload * 0.8, "Bwd Pkt Len Std": 10,
        "Flow Byts/s": _jitter(800), "Flow Pkts/s": _jitter(20),
        "Flow IAT Mean": _jitter(500), "Flow IAT Std": _jitter(200),
        "Flow IAT Max": _jitter(2000), "Flow IAT Min": _jitter(10),
        "Fwd IAT Tot": _jitter(dur * 0.6), "Fwd IAT Mean": _jitter(300),
        "Fwd IAT Std": _jitter(100), "Fwd IAT Max": _jitter(1500), "Fwd IAT Min": _jitter(10),
        "Bwd IAT Tot": _jitter(dur * 0.4), "Bwd IAT Mean": _jitter(400),
        "Bwd IAT Std": _jitter(150), "Bwd IAT Max": _jitter(1200), "Bwd IAT Min": _jitter(20),
        "Fwd PSH Flags": 0, "Fwd Header Len": 32 * fwd_pkts, "Bwd Header Len": 32 * bwd_pkts,
        "Fwd Pkts/s": _jitter(10), "Bwd Pkts/s": _jitter(10),
        "Pkt Len Min": 0, "Pkt Len Max": max(fwd_payload, bwd_payload),
        "Pkt Len Mean": (fwd_payload + bwd_payload) / 2 * 0.5,
        "Pkt Len Std": 15, "Pkt Len Var": 225,
        "FIN Flag Cnt": 1, "SYN Flag Cnt": 1, "RST Flag Cnt": 0,
        "PSH Flag Cnt": random.choice([0, 1]), "ACK Flag Cnt": 1,
        "Down/Up Ratio": round(bwd_pkts / max(1, fwd_pkts), 1),
        "Pkt Size Avg": (fwd_payload + bwd_payload) / 2 * 0.5,
        "Fwd Seg Size Avg": fwd_payload * 0.8, "Bwd Seg Size Avg": bwd_payload * 0.8,
        "Init Fwd Win Byts": random.choice([0, 0, 8192, 29200, 65535]),  # real: median=0
        "Init Bwd Win Byts": random.choice([0, 0, 8192, 29200, 65535]),
        "Fwd Act Data Pkts": max(1, fwd_pkts - 1), "Fwd Seg Size Min": 8,  # TCP min=8
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
        "Label": "Benign",
    }


def make_ssh_bruteforce():
    """SSH brute force attack flow."""
    dur = _jitter(2000)
    fwd_pkts = random.randint(50, 200)
    return {
        "Src IP": "10.0.0.101",
        "Dst Port": 22, "Flow Duration": dur,
        "Tot Fwd Pkts": fwd_pkts, "Tot Bwd Pkts": fwd_pkts * 2,
        "TotLen Fwd Pkts": 64 * fwd_pkts, "TotLen Bwd Pkts": 40 * fwd_pkts,
        "Fwd Pkt Len Max": 64, "Fwd Pkt Len Min": 40,
        "Fwd Pkt Len Mean": 52, "Fwd Pkt Len Std": 8,
        "Bwd Pkt Len Max": 40, "Bwd Pkt Len Min": 40,
        "Bwd Pkt Len Mean": 40, "Bwd Pkt Len Std": 0,
        "Flow Byts/s": _jitter(500000), "Flow Pkts/s": _jitter(5000),
        "Flow IAT Mean": _jitter(50), "Flow IAT Std": _jitter(20),
        "Flow IAT Max": _jitter(200), "Flow IAT Min": _jitter(5),
        "Fwd IAT Tot": dur, "Fwd IAT Mean": _jitter(40),
        "Fwd IAT Std": _jitter(15), "Fwd IAT Max": _jitter(100), "Fwd IAT Min": _jitter(5),
        "Bwd IAT Tot": dur * 0.8, "Bwd IAT Mean": _jitter(30),
        "Bwd IAT Std": _jitter(10), "Bwd IAT Max": _jitter(80), "Bwd IAT Min": _jitter(3),
        "Fwd PSH Flags": 1, "Fwd Header Len": 160 * fwd_pkts, "Bwd Header Len": 120 * fwd_pkts,
        "Fwd Pkts/s": _jitter(3000), "Bwd Pkts/s": _jitter(6000),
        "Pkt Len Min": 40, "Pkt Len Max": 64, "Pkt Len Mean": 48,
        "Pkt Len Std": 10, "Pkt Len Var": 100,
        "FIN Flag Cnt": 0, "SYN Flag Cnt": random.randint(60, 100), "RST Flag Cnt": 1,
        "PSH Flag Cnt": 1, "ACK Flag Cnt": 1,
        "Down/Up Ratio": 2.0, "Pkt Size Avg": 48,
        "Fwd Seg Size Avg": 52, "Bwd Seg Size Avg": 40,
        "Init Fwd Win Byts": 1024, "Init Bwd Win Byts": 0,
        "Fwd Act Data Pkts": fwd_pkts, "Fwd Seg Size Min": 20,
        "Active Mean": 100, "Active Std": 50, "Active Max": 300, "Active Min": 10,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
        "Label": "Brute Force",
    }


def make_ddos():
    """DDoS SYN flood attack flow."""
    dur = _jitter(1000)
    fwd_pkts = random.randint(500, 2000)
    return {
        "Src IP": "10.0.0.102",
        "Dst Port": 80, "Flow Duration": dur,
        "Tot Fwd Pkts": fwd_pkts, "Tot Bwd Pkts": 0,
        "TotLen Fwd Pkts": 40 * fwd_pkts, "TotLen Bwd Pkts": 0,
        "Fwd Pkt Len Max": 40, "Fwd Pkt Len Min": 40,
        "Fwd Pkt Len Mean": 40, "Fwd Pkt Len Std": 0,
        "Bwd Pkt Len Max": 0, "Bwd Pkt Len Min": 0,
        "Bwd Pkt Len Mean": 0, "Bwd Pkt Len Std": 0,
        "Flow Byts/s": _jitter(2000000), "Flow Pkts/s": _jitter(10000),
        "Flow IAT Mean": _jitter(1), "Flow IAT Std": _jitter(0.5),
        "Flow IAT Max": _jitter(5), "Flow IAT Min": 0,
        "Fwd IAT Tot": dur, "Fwd IAT Mean": _jitter(1),
        "Fwd IAT Std": _jitter(0.3), "Fwd IAT Max": _jitter(3), "Fwd IAT Min": 0,
        "Bwd IAT Tot": 0, "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0, "Bwd IAT Max": 0, "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0, "Fwd Header Len": 40 * fwd_pkts, "Bwd Header Len": 0,
        "Fwd Pkts/s": _jitter(10000), "Bwd Pkts/s": 0,
        "Pkt Len Min": 40, "Pkt Len Max": 40, "Pkt Len Mean": 40,
        "Pkt Len Std": 0, "Pkt Len Var": 0,
        "FIN Flag Cnt": 0, "SYN Flag Cnt": fwd_pkts, "RST Flag Cnt": 0,
        "PSH Flag Cnt": 0, "ACK Flag Cnt": 0,
        "Down/Up Ratio": 0, "Pkt Size Avg": 40,
        "Fwd Seg Size Avg": 40, "Bwd Seg Size Avg": 0,
        "Init Fwd Win Byts": 1024, "Init Bwd Win Byts": 0,
        "Fwd Act Data Pkts": 0, "Fwd Seg Size Min": 40,
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
        "Label": "DDoS",
    }


def make_data_exfil():
    """Slow data exfiltration over HTTPS."""
    dur = _jitter(120000000)
    fwd_pkts = random.randint(50, 150)
    payload = _jitter(50000)
    return {
        "Src IP": "10.0.0.103",
        "Dst Port": 443, "Flow Duration": dur,
        "Tot Fwd Pkts": fwd_pkts, "Tot Bwd Pkts": 5,
        "TotLen Fwd Pkts": payload * fwd_pkts, "TotLen Bwd Pkts": 200,
        "Fwd Pkt Len Max": payload, "Fwd Pkt Len Min": 1000,
        "Fwd Pkt Len Mean": payload * 0.7, "Fwd Pkt Len Std": payload * 0.2,
        "Bwd Pkt Len Max": 40, "Bwd Pkt Len Min": 40,
        "Bwd Pkt Len Mean": 40, "Bwd Pkt Len Std": 0,
        "Flow Byts/s": _jitter(500), "Flow Pkts/s": _jitter(2),
        "Flow IAT Mean": _jitter(2000000), "Flow IAT Std": _jitter(500000),
        "Flow IAT Max": _jitter(5000000), "Flow IAT Min": _jitter(100000),
        "Fwd IAT Tot": dur * 0.9, "Fwd IAT Mean": _jitter(1500000),
        "Fwd IAT Std": _jitter(400000), "Fwd IAT Max": _jitter(4000000), "Fwd IAT Min": _jitter(50000),
        "Bwd IAT Tot": dur * 0.1, "Bwd IAT Mean": _jitter(20000000),
        "Bwd IAT Std": _jitter(5000000), "Bwd IAT Max": _jitter(30000000), "Bwd IAT Min": _jitter(10000000),
        "Fwd PSH Flags": 1, "Fwd Header Len": 160 * fwd_pkts, "Bwd Header Len": 120,
        "Fwd Pkts/s": _jitter(1), "Bwd Pkts/s": _jitter(0.05),
        "Pkt Len Min": 40, "Pkt Len Max": payload, "Pkt Len Mean": payload * 0.5,
        "Pkt Len Std": payload * 0.3, "Pkt Len Var": (payload * 0.3) ** 2,
        "FIN Flag Cnt": 1, "SYN Flag Cnt": 1, "RST Flag Cnt": 0,
        "PSH Flag Cnt": 1, "ACK Flag Cnt": 1,
        "Down/Up Ratio": 0.03, "Pkt Size Avg": payload * 0.5,
        "Fwd Seg Size Avg": payload * 0.7, "Bwd Seg Size Avg": 40,
        "Init Fwd Win Byts": 65535, "Init Bwd Win Byts": 65535,
        "Fwd Act Data Pkts": fwd_pkts, "Fwd Seg Size Min": 1000,
        "Active Mean": _jitter(50000), "Active Std": _jitter(20000),
        "Active Max": _jitter(100000), "Active Min": _jitter(10000),
        "Idle Mean": _jitter(2000000), "Idle Std": _jitter(500000),
        "Idle Max": _jitter(5000000), "Idle Min": _jitter(500000),
        "Label": "Infiltration",
    }


def make_port_scan():
    """Port scanning / reconnaissance."""
    dur = _jitter(500)
    fwd_pkts = random.randint(100, 500)
    port = random.choice([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 3306, 3389, 5432, 8080])
    return {
        "Src IP": "10.0.0.104",
        "Dst Port": port, "Flow Duration": dur,
        "Tot Fwd Pkts": fwd_pkts, "Tot Bwd Pkts": int(fwd_pkts * 0.3),
        "TotLen Fwd Pkts": 40 * fwd_pkts, "TotLen Bwd Pkts": 40 * int(fwd_pkts * 0.3),
        "Fwd Pkt Len Max": 40, "Fwd Pkt Len Min": 40,
        "Fwd Pkt Len Mean": 40, "Fwd Pkt Len Std": 0,
        "Bwd Pkt Len Max": 40, "Bwd Pkt Len Min": 0,
        "Bwd Pkt Len Mean": 20, "Bwd Pkt Len Std": 20,
        "Flow Byts/s": _jitter(800000), "Flow Pkts/s": _jitter(3000),
        "Flow IAT Mean": _jitter(2), "Flow IAT Std": _jitter(1),
        "Flow IAT Max": _jitter(10), "Flow IAT Min": 0,
        "Fwd IAT Tot": dur, "Fwd IAT Mean": _jitter(2),
        "Fwd IAT Std": _jitter(1), "Fwd IAT Max": _jitter(5), "Fwd IAT Min": 0,
        "Bwd IAT Tot": dur * 0.5, "Bwd IAT Mean": _jitter(5),
        "Bwd IAT Std": _jitter(3), "Bwd IAT Max": _jitter(15), "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0, "Fwd Header Len": 40 * fwd_pkts, "Bwd Header Len": 40 * int(fwd_pkts * 0.3),
        "Fwd Pkts/s": _jitter(3000), "Bwd Pkts/s": _jitter(900),
        "Pkt Len Min": 0, "Pkt Len Max": 40, "Pkt Len Mean": 30,
        "Pkt Len Std": 15, "Pkt Len Var": 225,
        "FIN Flag Cnt": 0, "SYN Flag Cnt": random.randint(80, 100), "RST Flag Cnt": int(fwd_pkts * 0.7),
        "PSH Flag Cnt": 0, "ACK Flag Cnt": 0,
        "Down/Up Ratio": 0.3, "Pkt Size Avg": 30,
        "Fwd Seg Size Avg": 40, "Bwd Seg Size Avg": 20,
        "Init Fwd Win Byts": 1024, "Init Bwd Win Byts": 0,
        "Fwd Act Data Pkts": 0, "Fwd Seg Size Min": 40,
        "Active Mean": 50, "Active Std": 20, "Active Max": 100, "Active Min": 5,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
        "Label": "PortScan",
    }


def main():
    out_file = sys.argv[1] if len(sys.argv) > 1 else "test_traffic.csv"

    generators = [
        (make_benign_http,    20, "Benign HTTP"),
        (make_ssh_bruteforce, 8,  "SSH Brute Force"),
        (make_ddos,           8,  "DDoS Flood"),
        (make_data_exfil,     7,  "Data Exfiltration"),
        (make_port_scan,      7,  "Port Scan"),
    ]

    rows = []
    for gen_func, count, name in generators:
        for _ in range(count):
            rows.append(gen_func())
        print(f"  Generated {count:>2} × {name}")

    # Shuffle for realism
    random.shuffle(rows)

    with open(out_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURES)
        writer.writeheader()
        for row in rows:
            # Ensure all fields exist
            clean = {k: round(row.get(k, 0), 4) if isinstance(row.get(k, 0), float) else row.get(k, 0) for k in FEATURES}
            writer.writerow(clean)

    print(f"\n✅ Generated {len(rows)} rows → {out_file}")
    print(f"   Columns: {len(FEATURES)} (62 features + Label)")
    print(f"\n   To test: load this CSV into the pipeline or use the dashboard's Test Model tab.")


if __name__ == "__main__":
    main()
