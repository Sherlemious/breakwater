"""Tests for ingestion.extractor — no scapy, no DB needed."""
import math

import pytest

from ingestion.extractor import _entropy, extract_windows
from ingestion.models import RawPacket


# ── helpers ───────────────────────────────────────────────────────────────────

def pkt(ts, src="1.1.1.1", dst="2.2.2.2", proto="TCP",
        length=100, sport=12345, dport=80, is_syn=False):
    return RawPacket(
        ts=ts, src_ip=src, dst_ip=dst, protocol=proto,
        length=length, src_port=sport, dst_port=dport, is_syn=is_syn,
    )


def windows_from(packets, window_size=1.0):
    return list(extract_windows(iter(packets), run_id=1, window_size=window_size))


# ── windowing ─────────────────────────────────────────────────────────────────

def test_single_window():
    pkts = [pkt(0.0), pkt(0.3), pkt(0.9)]
    ws = windows_from(pkts)
    assert len(ws) == 1
    assert ws[0].ts == 0.0
    assert ws[0].ts_end == 1.0


def test_two_windows():
    pkts = [pkt(0.1), pkt(1.1)]
    ws = windows_from(pkts)
    assert len(ws) == 2
    assert ws[0].ts == 0.0
    assert ws[1].ts == 1.0


def test_gap_skips_empty_windows():
    # Packets at t=0 and t=5 — seconds 1-4 are empty and should be skipped
    pkts = [pkt(0.5), pkt(5.5)]
    ws = windows_from(pkts)
    assert len(ws) == 2
    assert ws[1].ts == 5.0


def test_empty_stream_yields_nothing():
    assert windows_from([]) == []


# ── volume features ───────────────────────────────────────────────────────────

def test_pkt_s():
    # 4 packets in a 1-second window → pkt_s = 4.0
    pkts = [pkt(0.0), pkt(0.2), pkt(0.5), pkt(0.9)]
    w = windows_from(pkts)[0]
    assert w.pkt_s == pytest.approx(4.0)


def test_bytes_s():
    pkts = [pkt(0.0, length=200), pkt(0.5, length=300)]
    w = windows_from(pkts)[0]
    assert w.bytes_s == pytest.approx(500.0)
    assert w.avg_pkt_size == pytest.approx(250.0)


# ── protocol fractions ────────────────────────────────────────────────────────

def test_proto_fractions_sum_to_one():
    pkts = [
        pkt(0.1, proto="TCP"),
        pkt(0.2, proto="UDP"),
        pkt(0.3, proto="ICMP"),
        pkt(0.4, proto="OTHER"),
    ]
    w = windows_from(pkts)[0]
    total = w.proto_tcp_frac + w.proto_udp_frac + w.proto_icmp_frac + w.proto_other_frac
    assert total == pytest.approx(1.0)
    assert w.proto_tcp_frac  == pytest.approx(0.25)
    assert w.proto_udp_frac  == pytest.approx(0.25)
    assert w.proto_icmp_frac == pytest.approx(0.25)


def test_all_udp():
    pkts = [pkt(0.1, proto="UDP"), pkt(0.2, proto="UDP")]
    w = windows_from(pkts)[0]
    assert w.proto_udp_frac == pytest.approx(1.0)
    assert w.proto_tcp_frac == pytest.approx(0.0)


# ── SYN ratio ────────────────────────────────────────────────────────────────

def test_syn_ratio_pure_syn_flood():
    pkts = [pkt(0.1, proto="TCP", is_syn=True)] * 9 + [pkt(0.2, proto="TCP", is_syn=False)]
    w = windows_from(pkts)[0]
    assert w.syn_ratio == pytest.approx(0.9)


def test_syn_ratio_zero_when_no_tcp():
    pkts = [pkt(0.1, proto="UDP")] * 5
    w = windows_from(pkts)[0]
    assert w.syn_ratio == pytest.approx(0.0)


# ── source diversity ──────────────────────────────────────────────────────────

def test_unique_src_ips():
    pkts = [
        pkt(0.1, src="10.0.0.1"),
        pkt(0.2, src="10.0.0.2"),
        pkt(0.3, src="10.0.0.1"),  # duplicate
    ]
    w = windows_from(pkts)[0]
    assert w.unique_src_ips == 2


def test_top_src_ip():
    pkts = [
        pkt(0.1, src="1.1.1.1"),
        pkt(0.2, src="1.1.1.1"),
        pkt(0.3, src="2.2.2.2"),
    ]
    w = windows_from(pkts)[0]
    assert w.top_src_ip == "1.1.1.1"
    assert w.top_src_ip_frac == pytest.approx(2 / 3)


def test_single_source_entropy_is_zero():
    pkts = [pkt(0.1, src="1.1.1.1"), pkt(0.2, src="1.1.1.1")]
    w = windows_from(pkts)[0]
    assert w.src_ip_entropy == pytest.approx(0.0)


def test_uniform_sources_have_max_entropy():
    # 4 unique sources, each appearing once → entropy = log2(4) = 2.0
    pkts = [pkt(0.1 * i, src=f"10.0.0.{i}") for i in range(1, 5)]
    w = windows_from(pkts)[0]
    assert w.src_ip_entropy == pytest.approx(math.log2(4), rel=1e-4)


# ── destination port entropy ──────────────────────────────────────────────────

def test_single_dst_port_entropy_is_zero():
    pkts = [pkt(0.1, dport=80), pkt(0.2, dport=80)]
    w = windows_from(pkts)[0]
    assert w.dst_port_entropy == pytest.approx(0.0)


def test_destination_ip_features():
    pkts = [
        pkt(0.1, dst="10.0.0.1"),
        pkt(0.2, dst="10.0.0.1"),
        pkt(0.3, dst="10.0.0.2"),
    ]
    w = windows_from(pkts)[0]
    assert w.unique_dst_ips == 2
    assert w.top_dst_ip == "10.0.0.1"
    assert w.top_dst_ip_frac == pytest.approx(2 / 3)
    assert w.dst_ip_entropy > 0.0


def test_web_port_fraction():
    pkts = [
        pkt(0.1, dport=80),
        pkt(0.2, dport=443),
        pkt(0.3, dport=22),
        pkt(0.4, dport=53),
    ]
    w = windows_from(pkts)[0]
    assert w.web_port_frac == pytest.approx(0.5)


def test_protocol_counts_and_syn_count():
    pkts = [
        pkt(0.1, proto="TCP", is_syn=True),
        pkt(0.2, proto="TCP", is_syn=False),
        pkt(0.3, proto="UDP"),
        pkt(0.4, proto="ICMP"),
    ]
    w = windows_from(pkts)[0]
    assert w.tcp_count == 2
    assert w.udp_count == 1
    assert w.icmp_count == 1
    assert w.syn_count == 1


# ── entropy helper ────────────────────────────────────────────────────────────

def test_entropy_empty_counter_is_zero():
    from collections import Counter
    assert _entropy(Counter()) == 0.0


def test_entropy_uniform():
    from collections import Counter
    c = Counter({"a": 1, "b": 1, "c": 1, "d": 1})
    assert _entropy(c) == pytest.approx(math.log2(4))
