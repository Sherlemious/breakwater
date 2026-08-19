# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy>=2.0.0"]
# ///
"""
Generate synthetic test data for the DDoS Mitigation Tool.

Two outputs (both written by default):
  1. data/test_windows.csv  — pre-computed traffic windows, loadable directly
                              into the DB without running the PCAP pipeline.
  2. pcaps/test_traffic.pcap — a real PCAP that exercises the full ingestion
                               pipeline (parser → extractor → writer).

Traffic scenario (20 minutes total):
  00:00 – 06:00   Normal baseline traffic
  06:00 – 08:00   UDP Flood
  08:00 – 10:00   SYN Flood
  10:00 – 12:00   ICMP Flood
  12:00 – 14:00   HTTP Flood  (port-concentrated TCP)
  14:00 – 20:00   Normal recovery

Usage
-----
    # Generate both (requires scapy for PCAP)
    python scripts/gen_test_data.py

    # CSV only (no scapy needed)
    python scripts/gen_test_data.py --csv-only

    # Load the CSV straight into SQLite after generating
    python scripts/gen_test_data.py --csv-only --load
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import random
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

import numpy as np

# ── Paths ─────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
CSV_OUT  = ROOT / "data" / "test_windows.csv"
PCAP_OUT = ROOT / "pcaps" / "test_traffic.pcap"
DB_PATH  = os.environ.get("SQLITE_DB_PATH", str(ROOT / "data" / "ddos_tool.db"))

SCHEMA_SQL = ROOT / "ingestion" / "schema.sql"

EPOCH = 1_700_000_000.0   # fixed start time for reproducibility
WINDOW = 1.0              # seconds per window

RNG = np.random.default_rng(42)


# ── Attack scenario ────────────────────────────────────────────────────────

@dataclass
class Phase:
    name: str
    label: int          # 0=BENIGN 1=ATTACK
    duration_s: int
    pkt_s_mu:   float
    pkt_s_sig:  float
    bytes_s_mu: float
    bytes_s_sig: float
    avg_pkt_mu: float
    avg_pkt_sig: float
    unique_src_mu: float
    unique_src_sig: float
    src_entropy_mu: float
    src_entropy_sig: float
    dst_entropy_mu: float
    dst_entropy_sig: float
    tcp_frac_mu: float
    udp_frac_mu: float
    icmp_frac_mu: float
    syn_ratio_mu: float
    syn_ratio_sig: float


PHASES: List[Phase] = [
    Phase("BENIGN",     0,  360,  300, 60,  200_000, 40_000,  620, 80,  120, 25, 6.1, 0.4, 3.4, 0.4, 0.60, 0.30, 0.05, 0.14, 0.04),
    Phase("UDP Flood",  1,  120, 8000, 900, 480_000, 60_000,   60, 10,    7,  2, 1.4, 0.3, 0.4, 0.1, 0.02, 0.97, 0.01, 0.05, 0.02),
    Phase("SYN Flood",  1,  120, 5500, 700, 286_000, 40_000,   52,  6,    5,  2, 1.2, 0.3, 0.3, 0.1, 0.98, 0.01, 0.01, 0.93, 0.04),
    Phase("ICMP Flood", 1,  120, 6000, 800, 504_000, 70_000,   84, 10,    6,  2, 1.3, 0.3, 0.2, 0.1, 0.02, 0.01, 0.97, 0.02, 0.01),
    Phase("HTTP Flood", 1,  120, 4000, 600, 800_000, 80_000, 1400, 60,    8,  2, 1.5, 0.3, 0.2, 0.1, 0.99, 0.01, 0.00, 0.40, 0.05),
    Phase("BENIGN",     0,  360,  280, 55,  190_000, 38_000,  615, 80,  115, 25, 6.0, 0.4, 3.3, 0.4, 0.61, 0.29, 0.05, 0.13, 0.04),
]

ATTACKER_IPS = [f"10.0.{i}.{j}" for i in range(1, 4) for j in range(1, 6)]
NORMAL_POOL  = [f"192.168.{i}.{j}" for i in range(0, 10) for j in range(1, 30)]
COMMON_PORTS = [80, 443, 22, 8080, 53, 25, 110, 3306]


# ── CSV / window generation ────────────────────────────────────────────────

def _clamp(val: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, val))


def _norm(mu, sig, lo, hi) -> float:
    return _clamp(float(RNG.normal(mu, sig)), lo, hi)


def _pick_top_src(phase: Phase):
    if phase.label == 1:
        return random.choice(ATTACKER_IPS), _norm(0.55, 0.1, 0.3, 0.95)
    return random.choice(NORMAL_POOL), _norm(0.05, 0.02, 0.01, 0.15)


def _proto_fracs(phase: Phase):
    tcp  = _clamp(_norm(phase.tcp_frac_mu,  0.03, 0.0, 1.0), 0, 1)
    udp  = _clamp(_norm(phase.udp_frac_mu,  0.03, 0.0, 1.0), 0, 1)
    icmp = _clamp(_norm(phase.icmp_frac_mu, 0.02, 0.0, 1.0), 0, 1)
    total = tcp + udp + icmp or 1.0
    other = max(0.0, 1.0 - tcp - udp - icmp)
    s = tcp + udp + icmp + other
    return tcp/s, udp/s, icmp/s, other/s


def generate_windows() -> list[dict]:
    rows = []
    ts = EPOCH
    for phase in PHASES:
        n_windows = int(phase.duration_s / WINDOW)
        for _ in range(n_windows):
            pkt_s  = _norm(phase.pkt_s_mu,  phase.pkt_s_sig,  1, 50_000)
            bytes_s = _norm(phase.bytes_s_mu, phase.bytes_s_sig, 64, 5_000_000)
            avg_pkt = _norm(phase.avg_pkt_mu, phase.avg_pkt_sig, 40, 1500)
            u_src   = max(1, int(_norm(phase.unique_src_mu, phase.unique_src_sig, 1, 500)))
            s_ent   = _norm(phase.src_entropy_mu, phase.src_entropy_sig, 0, 10)
            d_ent   = _norm(phase.dst_entropy_mu, phase.dst_entropy_sig, 0, 10)
            syn_r   = _norm(phase.syn_ratio_mu, phase.syn_ratio_sig, 0, 1)
            top_src, top_src_frac = _pick_top_src(phase)
            top_port = 80 if phase.label else random.choice(COMMON_PORTS)
            top_port_frac = _norm(0.7, 0.1, 0.3, 0.99) if phase.label else _norm(0.25, 0.05, 0.1, 0.6)
            tcp, udp, icmp, other = _proto_fracs(phase)

            rows.append({
                "ts":               ts,
                "ts_end":           ts + WINDOW,
                "pkt_s":            round(pkt_s, 3),
                "bytes_s":          round(bytes_s, 3),
                "avg_pkt_size":     round(avg_pkt, 3),
                "unique_src_ips":   u_src,
                "src_ip_entropy":   round(s_ent, 4),
                "top_src_ip":       top_src,
                "top_src_ip_frac":  round(top_src_frac, 4),
                "dst_port_entropy": round(d_ent, 4),
                "top_dst_port":     top_port,
                "top_dst_port_frac": round(top_port_frac, 4),
                "proto_tcp_frac":   round(tcp, 4),
                "proto_udp_frac":   round(udp, 4),
                "proto_icmp_frac":  round(icmp, 4),
                "proto_other_frac": round(other, 4),
                "syn_ratio":        round(syn_r, 4),
                "label":            phase.label,
                "label_detail":     phase.name,
            })
            ts += WINDOW
    return rows


def write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[gen] CSV written  -> {path}  ({len(rows)} rows)")


# ── DB loader ──────────────────────────────────────────────────────────────

def load_into_db(rows: list[dict], db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")

    schema = SCHEMA_SQL.read_text()
    conn.executescript(schema)

    # Create a synthetic ingestion run for this test data
    cur = conn.execute(
        "INSERT INTO ingestion_runs (pcap_file, mode, status, started_at, completed_at) "
        "VALUES (?, 'detect', 'completed', ?, ?)",
        ("test_synthetic", EPOCH, EPOCH + sum(p.duration_s for p in PHASES)),
    )
    run_id = cur.lastrowid

    conn.executemany(
        """
        INSERT INTO traffic_windows (
            run_id, ts, ts_end,
            pkt_s, bytes_s, avg_pkt_size,
            unique_src_ips, src_ip_entropy,
            top_src_ip, top_src_ip_frac,
            dst_port_entropy, top_dst_port, top_dst_port_frac,
            proto_tcp_frac, proto_udp_frac, proto_icmp_frac, proto_other_frac,
            syn_ratio, label, label_detail
        ) VALUES (
            :run_id, :ts, :ts_end,
            :pkt_s, :bytes_s, :avg_pkt_size,
            :unique_src_ips, :src_ip_entropy,
            :top_src_ip, :top_src_ip_frac,
            :dst_port_entropy, :top_dst_port, :top_dst_port_frac,
            :proto_tcp_frac, :proto_udp_frac, :proto_icmp_frac, :proto_other_frac,
            :syn_ratio, :label, :label_detail
        )
        """,
        [{**r, "run_id": run_id} for r in rows],
    )
    conn.execute(
        "UPDATE ingestion_runs SET windows_extracted = ? WHERE run_id = ?",
        (len(rows), run_id),
    )
    conn.commit()
    conn.close()
    print(f"[gen] Loaded {len(rows)} windows into {db_path}  (run_id={run_id})")


# ── PCAP generation ────────────────────────────────────────────────────────

def generate_pcap(path: Path, seconds_per_phase: int = 10) -> None:
    """
    Generate a small test PCAP (scaled-down version of the scenario).
    Uses scapy — only called when --csv-only is NOT set.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.utils import wrpcap
        from scapy.packet import Raw
    except ImportError:
        print("[gen] scapy not installed — skipping PCAP generation", file=sys.stderr)
        return

    pkts = []
    ts = EPOCH

    def _ip():
        return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

    for phase in PHASES:
        duration = min(phase.duration_s, seconds_per_phase)
        pkt_rate = int(phase.pkt_s_mu)
        end_ts = ts + duration

        while ts < end_ts:
            n = max(1, int(RNG.normal(pkt_rate / 10, pkt_rate / 50)))
            for _ in range(n):
                src = random.choice(ATTACKER_IPS) if phase.label else _ip()
                dst = f"10.10.10.{random.randint(1, 5)}"
                proto_roll = RNG.random()

                if proto_roll < phase.tcp_frac_mu:
                    flags = "S" if RNG.random() < phase.syn_ratio_mu else "A"
                    p = (IP(src=src, dst=dst) /
                         TCP(sport=random.randint(1024, 65535), dport=80, flags=flags))
                elif proto_roll < phase.tcp_frac_mu + phase.udp_frac_mu:
                    p = (IP(src=src, dst=dst) /
                         UDP(sport=random.randint(1024, 65535), dport=80) /
                         Raw(b"\x00" * 40))
                else:
                    p = IP(src=src, dst=dst) / ICMP()

                p.time = ts + RNG.random() * 0.1
                pkts.append(p)

            ts += 0.1

    pkts.sort(key=lambda p: p.time)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), pkts)
    print(f"[gen] PCAP written -> {path}  ({len(pkts)} packets)")


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Generate synthetic DDoS test data.")
    ap.add_argument("--csv-only", action="store_true",
                    help="Skip PCAP generation (no scapy needed).")
    ap.add_argument("--load", action="store_true",
                    help="Load the CSV into SQLite after generating.")
    ap.add_argument("--db", default=DB_PATH, metavar="PATH",
                    help=f"SQLite DB path (default: {DB_PATH}).")
    ap.add_argument("--csv", default=str(CSV_OUT), metavar="PATH",
                    help=f"CSV output path (default: {CSV_OUT}).")
    args = ap.parse_args()

    print("[gen] Generating synthetic traffic windows …")
    rows = generate_windows()

    write_csv(rows, Path(args.csv))

    if not args.csv_only:
        generate_pcap(PCAP_OUT)

    if args.load:
        load_into_db(rows, args.db)
        print("[gen] Done. Run the detection module next.")
    else:
        print("[gen] Done. Use --load to insert into SQLite, or run the ingestion")
        print(f"      pipeline against {PCAP_OUT} for the real PCAP path.")

    # Print a quick summary
    from collections import Counter
    counts = Counter(r["label_detail"] for r in rows)
    total  = len(rows)
    print(f"\n  {'Phase':<15} {'Windows':>8}  {'%':>6}")
    print(f"  {'-'*32}")
    for name, n in counts.items():
        print(f"  {name:<15} {n:>8}  {100*n/total:>5.1f}%")
    print(f"  {'TOTAL':<15} {total:>8}")


if __name__ == "__main__":
    main()
