from __future__ import annotations

import json
from typing import Any

EPSILON = 1e-6
TRIGGER_THRESHOLD = 0.50

STAT_WEIGHTS: dict[str, float] = {
    "pkt_s": 0.16,
    "bytes_s": 0.13,
    "top_src_ip_frac": 0.08,
    "src_ip_entropy": 0.08,
    "unique_src_ips": 0.06,
    "top_dst_ip_frac": 0.07,
    "dst_ip_entropy": 0.05,
    "top_dst_port_frac": 0.07,
    "dst_port_entropy": 0.05,
    "syn_ratio": 0.10,
    "syn_count": 0.06,
    "proto_udp_frac": 0.03,
    "proto_icmp_frac": 0.03,
    "web_port_frac": 0.03,
}

HIGH_ONLY_FEATURES = {
    "pkt_s",
    "bytes_s",
    "unique_src_ips",
    "top_src_ip_frac",
    "top_dst_ip_frac",
    "top_dst_port_frac",
    "syn_ratio",
    "syn_count",
    "proto_udp_frac",
    "proto_icmp_frac",
    "web_port_frac",
}

LOW_ONLY_FEATURES = {
    "src_ip_entropy",
    "dst_ip_entropy",
    "dst_port_entropy",
}

BLEND_STAT_WEIGHT = 0.60
BLEND_RF_WEIGHT = 0.40
SUSPICIOUS_THRESHOLD = 0.45


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def robust_feature_score(feature: str, value: float, baseline_row: dict[str, float]) -> float:
    p25 = float(baseline_row["p25"])
    p50 = float(baseline_row["p50"])
    p75 = float(baseline_row["p75"])
    iqr = max(p75 - p25, EPSILON)

    if feature in HIGH_ONLY_FEATURES and value <= p50:
        return 0.0
    if feature in LOW_ONLY_FEATURES and value >= p50:
        return 0.0

    raw = abs(float(value) - p50) / iqr
    return clamp01(raw / 6.0)


def compute_statistical_score(
    window: dict[str, Any],
    baseline: dict[str, dict[str, float]],
) -> tuple[float, dict[str, float], list[str]]:
    feature_scores: dict[str, float] = {}
    weighted_sum = 0.0
    total_weight = 0.0

    for feature, weight in STAT_WEIGHTS.items():
        if feature not in baseline or feature not in window:
            continue
        value = 0.0 if window[feature] is None else float(window[feature])
        score = robust_feature_score(feature, value, baseline[feature])
        feature_scores[feature] = score
        weighted_sum += score * weight
        total_weight += weight

    if total_weight == 0.0:
        raise ValueError("Cannot compute statistical score: no baseline features available")

    stat_score = clamp01(weighted_sum / total_weight)
    triggered = [f for f, s in sorted(feature_scores.items(), key=lambda kv: kv[1], reverse=True) if s >= TRIGGER_THRESHOLD]
    return stat_score, feature_scores, triggered


def classify_attack_type(window: dict[str, Any], feature_scores: dict[str, float]) -> tuple[str | None, float | None, list[str]]:
    syn_raw = _raw01(window, "syn_ratio")
    tcp_raw = _raw01(window, "proto_tcp_frac")
    udp_raw = _raw01(window, "proto_udp_frac")
    icmp_raw = _raw01(window, "proto_icmp_frac")
    web_raw = _raw01(window, "web_port_frac")
    port_focus = max(feature_scores.get("top_dst_port_frac", 0.0), _raw01(window, "top_dst_port_frac"))
    protocol_count = max(
        _count_score(window, "tcp_count"),
        _count_score(window, "udp_count"),
        _count_score(window, "icmp_count"),
    )

    volumetric_parts = {
        "pkt_s": feature_scores.get("pkt_s", 0.0),
        "bytes_s": feature_scores.get("bytes_s", 0.0),
        "unique_src_ips": feature_scores.get("unique_src_ips", 0.0),
        "top_dst_ip_frac": feature_scores.get("top_dst_ip_frac", 0.0),
    }
    network_parts = {
        "syn_ratio": max(feature_scores.get("syn_ratio", 0.0), syn_raw),
        "syn_count": feature_scores.get("syn_count", 0.0),
        "proto_udp_frac": max(feature_scores.get("proto_udp_frac", 0.0), udp_raw),
        "proto_icmp_frac": max(feature_scores.get("proto_icmp_frac", 0.0), icmp_raw),
        "protocol_packet_count": protocol_count,
    }
    application_parts = {
        "web_port_frac": max(feature_scores.get("web_port_frac", 0.0), web_raw),
        "top_dst_port_frac": port_focus,
        "proto_tcp_frac": tcp_raw,
        "dst_port_focus": feature_scores.get("dst_port_entropy", 0.0),
    }

    volumetric = (
        0.35 * volumetric_parts["pkt_s"]
        + 0.30 * volumetric_parts["bytes_s"]
        + 0.20 * volumetric_parts["unique_src_ips"]
        + 0.15 * volumetric_parts["top_dst_ip_frac"]
    )
    network_protocols = (
        0.30 * network_parts["syn_ratio"]
        + 0.20 * network_parts["syn_count"]
        + 0.20 * network_parts["proto_udp_frac"]
        + 0.15 * network_parts["proto_icmp_frac"]
        + 0.15 * network_parts["protocol_packet_count"]
    )
    if syn_raw >= 0.50 or udp_raw >= 0.70 or icmp_raw >= 0.50:
        network_protocols += 0.25
    application_layer = (
        0.35 * application_parts["web_port_frac"]
        + 0.25 * application_parts["top_dst_port_frac"]
        + 0.20 * application_parts["proto_tcp_frac"]
        + 0.20 * application_parts["dst_port_focus"]
    )

    type_scores = {
        "volumetric": clamp01(volumetric),
        "network_protocols": clamp01(network_protocols),
        "application_layer": clamp01(application_layer),
    }
    best_type = max(type_scores, key=type_scores.get)
    total = sum(type_scores.values())
    confidence = clamp01(type_scores[best_type] / total) if total > 0 else 0.0

    evidence_pool = {
        **feature_scores,
        **volumetric_parts,
        **network_parts,
        **application_parts,
    }
    top_evidence = [name for name, _ in sorted(evidence_pool.items(), key=lambda kv: kv[1], reverse=True)[:3]]
    return best_type, confidence, top_evidence


def _raw01(window: dict[str, Any], feature: str) -> float:
    value = window.get(feature, 0.0)
    return clamp01(0.0 if value is None else float(value))


def _count_score(window: dict[str, Any], feature: str) -> float:
    value = window.get(feature, 0.0)
    count = 0.0 if value is None else float(value)
    return clamp01(count / 1000.0)


def compute_hybrid_score(statistical_score: float, rf_attack_probability: float | None) -> float:
    if rf_attack_probability is None:
        return clamp01(statistical_score)
    return clamp01(BLEND_STAT_WEIGHT * statistical_score + BLEND_RF_WEIGHT * rf_attack_probability)


def build_explanation(
    final_score: float,
    statistical_score: float,
    rf_attack_probability: float | None,
    predicted_attack_type: str | None,
    attack_type_confidence: float | None,
    triggered_features: list[str],
    top_evidence: list[str],
) -> str:
    payload = {
        "final_score": round(final_score, 6),
        "statistical_score": round(statistical_score, 6),
        "rf_attack_probability": None if rf_attack_probability is None else round(rf_attack_probability, 6),
        "predicted_attack_type": predicted_attack_type,
        "attack_type_confidence": None if attack_type_confidence is None else round(attack_type_confidence, 6),
        "triggered_features": triggered_features,
        "top_evidence": top_evidence,
    }
    return json.dumps(payload, separators=(",", ":"))
