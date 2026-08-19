from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ingestion.db import get_conn, init_db
from mitigation.core import (
    build_block_ip_command,
    build_block_port_command,
    build_rate_limit_command,
    choose_decision,
    load_events_file,
    parse_event,
    process_event,
    process_events,
)


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test.db")
    init_db(path).close()
    conn = get_conn(path)
    conn.execute(
        """
        INSERT INTO ingestion_runs (
            pcap_file, mode, status, packets_processed, windows_extracted, started_at, completed_at
        ) VALUES ('attack.pcap', 'detect', 'completed', 10, 1, ?, ?)
        """,
        (time.time(), time.time()),
    )
    run_id = conn.execute("SELECT run_id FROM ingestion_runs").fetchone()["run_id"]
    conn.execute(
        """
        INSERT INTO traffic_windows (
            run_id, ts, ts_end, pkt_s, bytes_s, avg_pkt_size,
            unique_src_ips, src_ip_entropy, top_src_ip, top_src_ip_frac,
            dst_port_entropy, top_dst_port, top_dst_port_frac,
            proto_tcp_frac, proto_udp_frac, proto_icmp_frac, proto_other_frac,
            syn_ratio, label, label_detail
        ) VALUES (?, 1.0, 2.0, 5000.0, 500000.0, 100.0,
            5, 0.5, '192.168.1.20', 0.7,
            0.1, 80, 0.9,
            0.9, 0.05, 0.03, 0.02,
            0.8, 1, 'SYN Flood')
        """,
        (run_id,),
    )
    conn.execute(
        """
        INSERT INTO traffic_windows (
            run_id, ts, ts_end, pkt_s, bytes_s, avg_pkt_size,
            unique_src_ips, src_ip_entropy, top_src_ip, top_src_ip_frac,
            dst_port_entropy, top_dst_port, top_dst_port_frac,
            proto_tcp_frac, proto_udp_frac, proto_icmp_frac, proto_other_frac,
            syn_ratio, label, label_detail
        ) VALUES (?, 2.0, 3.0, 4000.0, 400000.0, 100.0,
            4, 0.4, '192.168.1.20', 0.8,
            0.1, 80, 0.9,
            0.9, 0.05, 0.03, 0.02,
            0.8, 1, 'SYN Flood')
        """,
        (run_id,),
    )
    conn.execute(
        """
        INSERT INTO traffic_windows (
            run_id, ts, ts_end, pkt_s, bytes_s, avg_pkt_size,
            unique_src_ips, src_ip_entropy, top_src_ip, top_src_ip_frac,
            dst_port_entropy, top_dst_port, top_dst_port_frac,
            proto_tcp_frac, proto_udp_frac, proto_icmp_frac, proto_other_frac,
            syn_ratio, label, label_detail
        ) VALUES (?, 3.0, 4.0, 300.0, 30000.0, 100.0,
            20, 3.0, '10.0.0.5', 0.1,
            2.0, 443, 0.2,
            0.9, 0.05, 0.03, 0.02,
            0.1, 0, 'BENIGN')
        """,
        (run_id,),
    )
    conn.commit()
    yield conn
    conn.close()


def event(level=72, attack_type="Volumetric_attacks", flag=True, window_id=1):
    return parse_event({"id": window_id, "flag": flag, "level": level, "type": attack_type})


def window(conn):
    return conn.execute("SELECT * FROM traffic_windows WHERE window_id = 1").fetchone()


def test_load_events_file_accepts_single_object_and_array(tmp_path):
    one = tmp_path / "one.json"
    one.write_text(json.dumps({"id": 1, "flag": True, "level": 55, "type": "Volumetric_attacks"}))
    many = tmp_path / "many.json"
    many.write_text(json.dumps([
        {"id": 1, "flag": True, "level": 55, "type": "Volumetric_attacks"},
        {"id": 2, "flag": False, "level": 10, "type": "Application-layer"},
    ]))

    assert len(load_events_file(one)) == 1
    assert len(load_events_file(many)) == 2


def test_parse_event_accepts_official_model_types():
    assert parse_event({"id": 1, "flag": True, "level": 55, "type": "volumetric"}).attack_type == "volumetric"
    assert parse_event({"id": 1, "flag": True, "level": 55, "type": "network_protocols"}).attack_type == "network_protocols"
    assert parse_event({"id": 1, "flag": True, "level": 55, "type": "application_layer"}).attack_type == "application_layer"


def test_process_events_accepts_empty_event_list(db):
    assert process_events(db, []) == []


@pytest.mark.parametrize(
    "payload",
    [
        {"flag": True, "level": 55, "type": "Volumetric_attacks"},
        {"id": "1", "flag": True, "level": 55, "type": "Volumetric_attacks"},
        {"id": 1, "flag": "true", "level": 55, "type": "Volumetric_attacks"},
        {"id": 1, "flag": True, "level": 101, "type": "Volumetric_attacks"},
        {"id": 1, "flag": True, "level": 55, "type": "bad"},
    ],
)
def test_parse_event_rejects_invalid_payloads(payload):
    with pytest.raises(ValueError):
        parse_event(payload)


def test_policy_severity_bands(db):
    assert choose_decision(event(level=20), window(db)).rule_type is None
    assert choose_decision(event(level=45), window(db)).rule_type == "rate_limit"
    assert choose_decision(event(level=70), window(db)).rule_type == "rate_limit"
    assert choose_decision(event(level=90), window(db)).rule_type == "block_ip"


def test_network_protocol_high_severity_prefers_block_port(db):
    decision = choose_decision(event(level=70, attack_type="Network_protocols"), window(db))

    assert decision.rule_type == "block_port"
    assert decision.target == "192.168.1.20:tcp/80"
    assert decision.command == "iptables -A INPUT -s 192.168.1.20 -p tcp --dport 80 -j DROP"


def test_whitelist_causes_alert_only(db):
    decision = choose_decision(event(level=90), window(db), whitelisted=True)

    assert decision.rule_type is None
    assert "whitelisted" in decision.reason


def test_blacklist_causes_immediate_block(db):
    decision = choose_decision(event(level=20), window(db), blacklisted=True)

    assert decision.rule_type == "block_ip"
    assert decision.command == "iptables -A INPUT -s 192.168.1.20 -j DROP"


def test_iptables_command_builders():
    assert build_block_ip_command("1.2.3.4") == "iptables -A INPUT -s 1.2.3.4 -j DROP"
    assert (
        build_block_port_command("1.2.3.4", "tcp", 443)
        == "iptables -A INPUT -s 1.2.3.4 -p tcp --dport 443 -j DROP"
    )
    command = build_rate_limit_command("1.2.3.4", 25, 50)
    assert command.startswith("iptables -A INPUT -s 1.2.3.4")
    assert "--hashlimit-above 25/second" in command
    assert "--hashlimit-burst 50" in command
    assert command.endswith("-j DROP")


def test_process_event_writes_alert_and_mitigation(db):
    result = process_event(db, event(level=90))
    db.commit()

    alert = db.execute("SELECT * FROM active_alerts").fetchone()
    mitigation = db.execute("SELECT * FROM active_mitigations").fetchone()
    assert result["status"] == "mitigated"
    assert alert["alert_type"] == "volumetric"
    assert alert["severity"] == "critical"
    assert alert["anomaly_score"] == pytest.approx(0.9)
    assert json.loads(alert["source_ips"]) == ["192.168.1.20"]
    assert mitigation["rule_type"] == "block_ip"
    assert mitigation["target"] == "192.168.1.20"
    assert mitigation["iptables_cmd"] == "iptables -A INPUT -s 192.168.1.20 -j DROP"
    assert "simulated; command stored but not executed" in mitigation["notes"]


def test_block_ip_suppresses_future_windows_for_same_top_source(db):
    result = process_event(db, event(level=90))

    rows = db.execute(
        "SELECT window_id, top_src_ip, suppressed_at FROM traffic_windows ORDER BY ts"
    ).fetchall()
    assert result["removed_windows"] == 1
    assert rows[0]["suppressed_at"] is None
    assert rows[1]["suppressed_at"] is not None
    assert rows[2]["suppressed_at"] is None


def test_block_ip_preserves_future_scores_while_suppressing_windows(db):
    db.execute(
        """
        INSERT INTO window_anomaly_scores (window_id, anomaly_score, computed_at)
        VALUES (2, 0.95, ?)
        """,
        (time.time(),),
    )

    process_event(db, event(level=90))

    assert db.execute("SELECT COUNT(*) FROM window_anomaly_scores WHERE window_id = 2").fetchone()[0] == 1
    assert db.execute("SELECT suppressed_at FROM traffic_windows WHERE window_id = 2").fetchone()[0] is not None


def test_block_ip_preserves_future_alert_references_while_suppressing_windows(db):
    db.execute(
        """
        INSERT INTO active_alerts (
            alert_type, severity, anomaly_score, window_id_start, window_id_end,
            source_ips, triggered_features, description, created_at
        ) VALUES ('volumetric', 'high', 0.8, 2, 2, '["192.168.1.20"]', 'pkt_s', 'future alert', ?)
        """,
        (time.time(),),
    )

    process_event(db, event(level=90))

    alert = db.execute("SELECT * FROM active_alerts WHERE description LIKE 'future alert%'").fetchone()
    assert alert["resolved_at"] is None
    assert alert["window_id_start"] == 2
    assert alert["window_id_end"] == 2


@pytest.mark.parametrize(
        ("level", "attack_type", "expected_rule", "expected_alert_type"),
        [
        (45, "Application-layer", "rate_limit", "application_layer"),
        (70, "Network_protocols", "block_port", "network_protocols"),
        (90, "Volumetric_attacks", "block_ip", "volumetric"),
        (70, "network_protocols", "block_port", "network_protocols"),
        (45, "application_layer", "rate_limit", "application_layer"),
    ],
)
def test_process_event_persists_medium_high_critical_actions(
    db, level, attack_type, expected_rule, expected_alert_type
):
    process_event(db, event(level=level, attack_type=attack_type))

    alert = db.execute("SELECT * FROM active_alerts ORDER BY alert_id DESC LIMIT 1").fetchone()
    mitigation = db.execute(
        "SELECT * FROM active_mitigations ORDER BY mitigation_id DESC LIMIT 1"
    ).fetchone()
    assert alert["alert_type"] == expected_alert_type
    assert mitigation["rule_type"] == expected_rule


def test_flag_false_writes_nothing(db):
    result = process_event(db, event(flag=False))

    assert result["status"] == "ignored"
    assert db.execute("SELECT COUNT(*) FROM active_alerts").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM active_mitigations").fetchone()[0] == 0


def test_whitelisted_source_writes_alert_without_mitigation(db):
    db.execute(
        "INSERT INTO ip_list (ip, list_type, reason, added_at) VALUES (?, 'whitelist', ?, ?)",
        ("192.168.1.20", "critical IP", time.time()),
    )
    result = process_event(db, event(level=90))

    assert result["status"] == "alert_only"
    assert db.execute("SELECT COUNT(*) FROM active_alerts").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM active_mitigations").fetchone()[0] == 0


def test_blacklisted_source_writes_block_ip_even_at_low_level(db):
    db.execute(
        "INSERT INTO ip_list (ip, list_type, reason, added_at) VALUES (?, 'blacklist', ?, ?)",
        ("192.168.1.20", "known attacker", time.time()),
    )
    result = process_event(db, event(level=20))

    mitigation = db.execute("SELECT * FROM active_mitigations").fetchone()
    assert result["status"] == "mitigated"
    assert mitigation["rule_type"] == "block_ip"


def test_duplicate_event_does_not_insert_duplicate_mitigation(db):
    first = process_event(db, event(level=90))
    second = process_event(db, event(level=95))

    assert first["mitigation_id"] == second["mitigation_id"]
    assert db.execute("SELECT COUNT(*) FROM active_mitigations").fetchone()[0] == 1


def test_missing_window_raises_and_writes_nothing(db):
    with pytest.raises(ValueError, match="traffic window not found"):
        process_event(db, event(window_id=999))

    assert db.execute("SELECT COUNT(*) FROM active_alerts").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM active_mitigations").fetchone()[0] == 0


def test_cli_processes_json_file(tmp_path):
    db_path = str(tmp_path / "cli.db")
    init_db(db_path).close()
    conn = get_conn(db_path)
    conn.execute(
        """
        INSERT INTO ingestion_runs (
            pcap_file, mode, status, packets_processed, windows_extracted, started_at, completed_at
        ) VALUES ('attack.pcap', 'detect', 'completed', 10, 1, ?, ?)
        """,
        (time.time(), time.time()),
    )
    run_id = conn.execute("SELECT run_id FROM ingestion_runs").fetchone()["run_id"]
    conn.execute(
        """
        INSERT INTO traffic_windows (
            run_id, ts, ts_end, pkt_s, bytes_s, avg_pkt_size,
            unique_src_ips, src_ip_entropy, top_src_ip, top_src_ip_frac,
            dst_port_entropy, top_dst_port, top_dst_port_frac,
            proto_tcp_frac, proto_udp_frac, proto_icmp_frac, proto_other_frac,
            syn_ratio, label, label_detail
        ) VALUES (?, 1.0, 2.0, 5000.0, 500000.0, 100.0,
            5, 0.5, '10.0.0.9', 0.7,
            0.1, 80, 0.9,
            0.9, 0.05, 0.03, 0.02,
            0.8, 1, 'SYN Flood')
        """,
        (run_id,),
    )
    conn.commit()
    conn.close()

    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps({"id": 1, "flag": True, "level": 90, "type": "Volumetric_attacks"}))

    completed = subprocess.run(
        [sys.executable, "-m", "mitigation", "--events-file", str(events_file), "--db", db_path],
        cwd=str(Path(__file__).resolve().parents[2]),
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr
    conn = get_conn(db_path)
    assert conn.execute("SELECT COUNT(*) FROM active_alerts").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM active_mitigations").fetchone()[0] == 1
    conn.close()
