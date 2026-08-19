from model.scoring import (
    SUSPICIOUS_THRESHOLD,
    classify_attack_type,
    compute_hybrid_score,
    compute_statistical_score,
)


def _baseline_row(p50: float, spread: float = 10.0) -> dict[str, float]:
    return {"p25": p50 - spread / 2, "p50": p50, "p75": p50 + spread / 2}


def test_statistical_score_computes_and_triggers_features():
    baseline = {
        "pkt_s": _baseline_row(100.0, 20.0),
        "bytes_s": _baseline_row(1000.0, 200.0),
        "top_src_ip_frac": _baseline_row(0.2, 0.2),
        "src_ip_entropy": _baseline_row(3.0, 1.0),
        "unique_src_ips": _baseline_row(20.0, 10.0),
        "top_dst_ip_frac": _baseline_row(0.3, 0.2),
        "dst_ip_entropy": _baseline_row(2.5, 1.0),
        "top_dst_port_frac": _baseline_row(0.4, 0.2),
        "dst_port_entropy": _baseline_row(2.0, 1.0),
        "syn_ratio": _baseline_row(0.1, 0.1),
        "syn_count": _baseline_row(10.0, 8.0),
        "proto_udp_frac": _baseline_row(0.2, 0.2),
        "proto_icmp_frac": _baseline_row(0.05, 0.1),
        "web_port_frac": _baseline_row(0.3, 0.2),
    }
    window = {
        "pkt_s": 180.0,
        "bytes_s": 1900.0,
        "top_src_ip_frac": 0.7,
        "src_ip_entropy": 0.5,
        "unique_src_ips": 70.0,
        "top_dst_ip_frac": 0.8,
        "dst_ip_entropy": 0.3,
        "top_dst_port_frac": 0.9,
        "dst_port_entropy": 0.4,
        "syn_ratio": 0.8,
        "syn_count": 120.0,
        "proto_udp_frac": 0.7,
        "proto_icmp_frac": 0.4,
        "web_port_frac": 0.8,
    }
    score, feature_scores, triggered = compute_statistical_score(window, baseline)
    assert 0.0 <= score <= 1.0
    assert feature_scores["pkt_s"] > 0.0
    assert "pkt_s" in triggered


def test_hybrid_score_blends_or_falls_back():
    assert compute_hybrid_score(0.8, None) == 0.8
    blended = compute_hybrid_score(0.8, 0.2)
    assert abs(blended - 0.56) < 1e-6


def test_attack_type_returns_official_types_for_suspicious_case():
    feature_scores = {
        "pkt_s": 1.0,
        "bytes_s": 1.0,
        "unique_src_ips": 0.7,
        "top_dst_ip_frac": 0.9,
    }
    attack_type, confidence, evidence = classify_attack_type({}, feature_scores)
    assert attack_type in {"volumetric", "network_protocols", "application_layer"}
    assert confidence is not None and 0.0 <= confidence <= 1.0
    assert isinstance(evidence, list)
    assert SUSPICIOUS_THRESHOLD == 0.45


def test_attack_type_prefers_volumetric_for_volume_evidence():
    feature_scores = {
        "pkt_s": 1.0,
        "bytes_s": 1.0,
        "unique_src_ips": 0.9,
        "top_dst_ip_frac": 0.8,
    }

    attack_type, confidence, evidence = classify_attack_type({}, feature_scores)

    assert attack_type == "volumetric"
    assert confidence is not None and confidence > 0.0
    assert "pkt_s" in evidence


def test_attack_type_prefers_network_protocols_for_protocol_evidence():
    window = {
        "syn_ratio": 0.95,
        "proto_tcp_frac": 0.98,
        "tcp_count": 2000,
    }
    feature_scores = {
        "syn_ratio": 1.0,
        "syn_count": 0.9,
        "pkt_s": 0.5,
        "bytes_s": 0.4,
    }

    attack_type, confidence, evidence = classify_attack_type(window, feature_scores)

    assert attack_type == "network_protocols"
    assert confidence is not None and confidence > 0.0
    assert "syn_ratio" in evidence


def test_attack_type_prefers_application_layer_for_service_evidence():
    window = {
        "proto_tcp_frac": 0.95,
        "web_port_frac": 0.95,
        "top_dst_port_frac": 0.9,
    }
    feature_scores = {
        "web_port_frac": 0.9,
        "top_dst_port_frac": 0.9,
        "dst_port_entropy": 0.8,
        "pkt_s": 0.4,
        "bytes_s": 0.3,
    }

    attack_type, confidence, evidence = classify_attack_type(window, feature_scores)

    assert attack_type == "application_layer"
    assert confidence is not None and confidence > 0.0
    assert "web_port_frac" in evidence
