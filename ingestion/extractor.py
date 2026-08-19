"""
RawPacket stream → TrafficWindow stream.

Packets are bucketed into fixed-size time windows (default 1 second).
Each window is emitted as a TrafficWindow with all features computed.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Generator, Iterable

from .models import RawPacket, TrafficWindow

WEB_PORTS = {80, 443, 8080, 8000, 8443}


def extract_windows(
    packets: Iterable[RawPacket],
    run_id: int,
    window_size: float = 1.0,
) -> Generator[TrafficWindow, None, None]:
    """
    Consume a packet stream and yield one TrafficWindow per time bucket.

    Windows with zero packets (gaps in traffic) are skipped — the detection
    module treats missing windows as normal silence, not anomalies.
    """
    bucket: list[RawPacket] = []
    window_start: float | None = None

    for pkt in packets:
        if window_start is None:
            window_start = _bucket_start(pkt.ts, window_size)

        if pkt.ts >= window_start + window_size:
            if bucket:
                yield _compute(bucket, window_start, window_start + window_size, run_id)
            # Advance to the bucket that contains pkt.ts (handles gaps)
            window_start = _bucket_start(pkt.ts, window_size)
            bucket = []

        bucket.append(pkt)

    if bucket and window_start is not None:
        yield _compute(bucket, window_start, window_start + window_size, run_id)


# ─────────────────────────────────────────────────────────────────────────────

def _bucket_start(ts: float, window_size: float) -> float:
    return math.floor(ts / window_size) * window_size


def _entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counter.values()
        if c > 0
    )


def _compute(
    pkts: list[RawPacket],
    ts: float,
    ts_end: float,
    run_id: int,
) -> TrafficWindow:
    n = len(pkts)
    duration = ts_end - ts  # equals window_size

    total_bytes = sum(p.length for p in pkts)

    src_ctr = Counter(p.src_ip for p in pkts)
    dst_ip_ctr = Counter(p.dst_ip for p in pkts)
    dst_port_ctr = Counter(p.dst_port for p in pkts if p.dst_port is not None)
    proto_ctr = Counter(p.protocol for p in pkts)
    web_port_n = sum(1 for p in pkts if p.dst_port in WEB_PORTS)

    tcp_n = proto_ctr["TCP"]
    udp_n = proto_ctr["UDP"]
    icmp_n = proto_ctr["ICMP"]
    syn_n = sum(1 for p in pkts if p.is_syn)

    top_src = src_ctr.most_common(1)
    top_dst_ip = dst_ip_ctr.most_common(1)
    top_dst = dst_port_ctr.most_common(1)

    return TrafficWindow(
        run_id=run_id,
        ts=ts,
        ts_end=ts_end,
        # Volume
        pkt_s=n / duration,
        bytes_s=total_bytes / duration,
        avg_pkt_size=total_bytes / n,
        # Source diversity
        unique_src_ips=len(src_ctr),
        src_ip_entropy=_entropy(src_ctr),
        top_src_ip=top_src[0][0] if top_src else None,
        top_src_ip_frac=top_src[0][1] / n if top_src else None,
        # Destination IP diversity
        unique_dst_ips=len(dst_ip_ctr),
        dst_ip_entropy=_entropy(dst_ip_ctr),
        top_dst_ip=top_dst_ip[0][0] if top_dst_ip else None,
        top_dst_ip_frac=top_dst_ip[0][1] / n if top_dst_ip else None,
        # Destination ports
        dst_port_entropy=_entropy(dst_port_ctr),
        top_dst_port=top_dst[0][0] if top_dst else None,
        top_dst_port_frac=top_dst[0][1] / n if top_dst else None,
        web_port_frac=web_port_n / n,
        # Protocol fractions
        proto_tcp_frac=tcp_n / n,
        proto_udp_frac=udp_n / n,
        proto_icmp_frac=icmp_n / n,
        proto_other_frac=proto_ctr["OTHER"] / n,
        # SYN ratio (0 if no TCP)
        syn_ratio=syn_n / tcp_n if tcp_n else 0.0,
        tcp_count=tcp_n,
        udp_count=udp_n,
        icmp_count=icmp_n,
        syn_count=syn_n,
    )
