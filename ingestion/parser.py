"""
PCAP → RawPacket stream.

Uses scapy's PcapReader for memory-efficient streaming (one packet at a time,
no full-file load). Packets that can't be parsed are silently skipped.
"""
from __future__ import annotations

from typing import Generator

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import PcapReader

from .models import RawPacket


def iter_packets(pcap_path: str) -> Generator[RawPacket, None, None]:
    """Yield one RawPacket per parseable IP packet in the PCAP."""
    with PcapReader(pcap_path) as reader:
        for frame in reader:
            pkt = _parse(frame)
            if pkt is not None:
                yield pkt


def _parse(frame) -> RawPacket | None:
    if not frame.haslayer(IP):
        return None

    ip = frame[IP]
    ts = float(frame.time)
    length = len(frame)

    if frame.haslayer(TCP):
        tcp = frame[TCP]
        flags = tcp.flags
        return RawPacket(
            ts=ts,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol="TCP",
            length=length,
            src_port=tcp.sport,
            dst_port=tcp.dport,
            is_syn=bool(flags & 0x02) and not bool(flags & 0x10),  # SYN and not ACK
        )

    if frame.haslayer(UDP):
        udp = frame[UDP]
        return RawPacket(
            ts=ts,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol="UDP",
            length=length,
            src_port=udp.sport,
            dst_port=udp.dport,
        )

    if frame.haslayer(ICMP):
        return RawPacket(
            ts=ts,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol="ICMP",
            length=length,
        )

    return RawPacket(
        ts=ts,
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol="OTHER",
        length=length,
    )
