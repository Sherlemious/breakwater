"""
Pipeline data models for the ingestion module.

RawPacket     — one parsed packet from a PCAP file
TrafficWindow — feature-aggregated 1-second window (maps to traffic_windows table)
BaselineFeatureStats — percentile stats for one feature (maps to baseline_stats)
IngestionRun  — PCAP processing job state (maps to ingestion_runs)

The detection, mitigation, and dashboard modules import from here too
so everyone shares the same type definitions.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import ClassVar, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Ingestion-phase types (written by A)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RawPacket:
    """Single packet parsed from a PCAP file."""
    ts: float               # Unix timestamp (seconds, float)
    src_ip: str
    dst_ip: str
    protocol: str           # 'TCP' | 'UDP' | 'ICMP' | 'OTHER'
    length: int             # total on-wire bytes
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    is_syn: bool = False    # TCP SYN flag set and ACK flag NOT set


@dataclass
class TrafficWindow:
    """
    Feature vector for one aggregated time window.

    Mirrors the traffic_windows table exactly so rows can be inserted
    directly with dataclasses.asdict().
    """
    run_id:            int
    ts:                float   # window start (Unix seconds)
    ts_end:            float   # window end

    # Volume
    pkt_s:             float
    bytes_s:           float
    avg_pkt_size:      float

    # Source diversity
    unique_src_ips:    int
    src_ip_entropy:    float

    # Top talker
    top_src_ip:        Optional[str]
    top_src_ip_frac:   Optional[float]

    # Destination IP diversity
    unique_dst_ips:    int
    dst_ip_entropy:    float
    top_dst_ip:        Optional[str]
    top_dst_ip_frac:   Optional[float]

    # Destination ports
    dst_port_entropy:  float
    top_dst_port:      Optional[int]
    top_dst_port_frac: Optional[float]

    # Application targeting
    web_port_frac:     float = 0.0

    # Protocol distribution (fractions sum to 1.0)
    proto_tcp_frac:    float = 0.0
    proto_udp_frac:    float = 0.0
    proto_icmp_frac:   float = 0.0
    proto_other_frac:  float = 0.0

    # Protocol-specific signals
    syn_ratio:         float = 0.0  # SYN / total-TCP
    tcp_count:         int = 0
    udp_count:         int = 0
    icmp_count:        int = 0
    syn_count:         int = 0

    # Ground truth from labeled dataset (None if unknown)
    label:             Optional[int] = None   # 0=BENIGN  1=ATTACK
    label_detail:      Optional[str] = None   # e.g. "UDP Flood"

    # Populated after DB insert
    window_id:         Optional[int] = None

    BASELINE_FEATURES: ClassVar[Tuple[str, ...]] = (
        "pkt_s",
        "bytes_s",
        "avg_pkt_size",
        "unique_src_ips",
        "src_ip_entropy",
        "top_src_ip_frac",
        "unique_dst_ips",
        "dst_ip_entropy",
        "top_dst_ip_frac",
        "dst_port_entropy",
        "top_dst_port_frac",
        "proto_tcp_frac",
        "proto_udp_frac",
        "proto_icmp_frac",
        "proto_other_frac",
        "syn_ratio",
        "web_port_frac",
        "tcp_count",
        "udp_count",
        "icmp_count",
        "syn_count",
    )

    def as_feature_dict(self) -> dict:
        """Return only the numeric features used for baseline / anomaly scoring."""
        return {f: getattr(self, f) for f in self.BASELINE_FEATURES}


@dataclass
class BaselineFeatureStats:
    """
    Percentile statistics for one traffic feature over the learn window.
    Maps to one row in baseline_stats.
    """
    feature:      str
    mean:         float
    std:          float
    min:          float
    p10:          float
    p25:          float
    p50:          float
    p75:          float
    p90:          float
    p95:          float
    p99:          float
    max:          float
    window_count: int
    run_id:       int
    computed_at:  float = field(default_factory=time.time)


@dataclass
class IngestionRun:
    """
    Current state of a PCAP processing job.
    Maps to one row in ingestion_runs; updated in place as the job progresses.
    """
    pcap_file:         str
    mode:              str              # 'learn' | 'detect'
    dataset_split:     str = "unknown" # 'train' | 'test' | 'unknown'
    status:            str = 'running'  # 'running' | 'completed' | 'failed'
    packets_processed: int = 0
    windows_extracted: int = 0
    started_at:        float = field(default_factory=time.time)
    completed_at:      Optional[float] = None
    error:             Optional[str] = None
    run_id:            Optional[int] = None   # populated after DB insert


# ─────────────────────────────────────────────────────────────────────────────
# Detection-phase types (written by B)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WindowAnomalyScore:
    """
    Detection result for one traffic window.
    Maps to one row in window_anomaly_scores.
    """
    window_id:           int
    anomaly_score:       float   # composite  0.0 – 1.0

    z_pkt_s:             Optional[float] = None
    z_bytes_s:           Optional[float] = None
    z_unique_src_ips:    Optional[float] = None
    z_src_ip_entropy:    Optional[float] = None
    z_dst_port_entropy:  Optional[float] = None
    z_syn_ratio:         Optional[float] = None
    z_proto_tcp_frac:    Optional[float] = None

    triggered_features:  List[str] = field(default_factory=list)
    computed_at:         float = field(default_factory=time.time)

    def triggered_features_str(self) -> str:
        return ",".join(self.triggered_features)


# ─────────────────────────────────────────────────────────────────────────────
# Mitigation / alert types (written by C; read/acknowledged by D)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ActiveAlert:
    """
    Current state of one detected attack alert.
    Maps to one row in active_alerts.
    Row is updated in place (never duplicated) as severity/status changes.
    """
    alert_type:           str   # 'volumetric'|'network_protocols'|'application_layer'|'composite'
    severity:             str   # 'low'|'medium'|'high'|'critical'
    anomaly_score:        float
    description:          str
    created_at:           float = field(default_factory=time.time)
    window_id_start:      Optional[int] = None
    window_id_end:        Optional[int] = None
    source_ips:           List[str] = field(default_factory=list)
    triggered_features:   List[str] = field(default_factory=list)
    acknowledged_at:      Optional[float] = None
    resolved_at:          Optional[float] = None
    notification_sent_at: Optional[float] = None
    alert_id:             Optional[int] = None

    def source_ips_json(self) -> str:
        return json.dumps(self.source_ips)

    def triggered_features_str(self) -> str:
        return ",".join(self.triggered_features)

    @property
    def is_open(self) -> bool:
        return self.resolved_at is None

    @property
    def needs_notification(self) -> bool:
        return self.notification_sent_at is None


@dataclass
class ActiveMitigation:
    """
    Current state of one active firewall / rate-limit rule.
    Maps to one row in active_mitigations.
    """
    rule_type:     str   # 'rate_limit' | 'block_port' | 'block_ip'
    target:        str   # IP address or port as string
    iptables_cmd:  str   # exact iptables command that was run
    applied_at:    float = field(default_factory=time.time)
    alert_id:      Optional[int] = None
    expires_at:    Optional[float] = None   # None = no automatic expiry
    revoked_at:    Optional[float] = None   # None = still active
    notes:         Optional[str] = None
    mitigation_id: Optional[int] = None

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None:
            return time.time() < self.expires_at
        return True
