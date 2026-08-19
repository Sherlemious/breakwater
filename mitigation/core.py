from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALLOWED_TYPES = {
    "Volumetric_attacks": "volumetric",
    "Network_protocols": "network_protocols",
    "Application-layer": "application_layer",
    "volumetric": "volumetric",
    "network_protocols": "network_protocols",
    "application_layer": "application_layer",
}

DEFAULT_DB_PATH = os.environ.get("SQLITE_DB_PATH", "/app/db/ddos_tool.db")
DEFAULT_EVENTS_FILE = "/app/data/mitigation_events.json"
LOW_LEVEL_MAX = int(os.environ.get("MITIGATION_LOW_LEVEL_MAX", "30"))
MEDIUM_LEVEL_MAX = int(os.environ.get("MITIGATION_MEDIUM_LEVEL_MAX", "60"))
CRITICAL_LEVEL_MIN = int(os.environ.get("MITIGATION_CRITICAL_LEVEL_MIN", "81"))


@dataclass(frozen=True)
class MitigationEvent:
    window_id: int
    flag: bool
    level: int
    attack_type: str


@dataclass(frozen=True)
class Decision:
    rule_type: str | None
    target: str | None
    command: str | None
    reason: str
    expires_in_seconds: int | None = None


def get_conn(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def load_events_file(path: str | Path) -> list[MitigationEvent]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else [raw]
    if not isinstance(items, list):
        raise ValueError("events file must contain a JSON object or an array")
    return [parse_event(item) for item in items]


def parse_event(item: Any) -> MitigationEvent:
    if not isinstance(item, dict):
        raise ValueError("event must be a JSON object")

    missing = {"id", "flag", "level", "type"} - set(item)
    if missing:
        raise ValueError(f"event missing required fields: {', '.join(sorted(missing))}")

    if not isinstance(item["id"], int) or isinstance(item["id"], bool):
        raise ValueError("event id must be an integer traffic window id")
    if not isinstance(item["flag"], bool):
        raise ValueError("event flag must be boolean")
    if not isinstance(item["level"], int) or isinstance(item["level"], bool):
        raise ValueError("event level must be an integer from 0 to 100")
    if not 0 <= item["level"] <= 100:
        raise ValueError("event level must be between 0 and 100")
    if item["type"] not in ALLOWED_TYPES:
        allowed = ", ".join(sorted(ALLOWED_TYPES))
        raise ValueError(f"event type must be one of: {allowed}")

    return MitigationEvent(
        window_id=item["id"],
        flag=item["flag"],
        level=item["level"],
        attack_type=item["type"],
    )


def process_events(conn: sqlite3.Connection, events: list[MitigationEvent]) -> list[dict[str, Any]]:
    results = []
    for event in events:
        results.append(process_event(conn, event))
    conn.commit()
    return results


def process_event(conn: sqlite3.Connection, event: MitigationEvent) -> dict[str, Any]:
    if not event.flag:
        return {"window_id": event.window_id, "status": "ignored", "reason": "flag=false"}

    window = conn.execute(
        "SELECT * FROM traffic_windows WHERE window_id = ?", (event.window_id,)
    ).fetchone()
    if window is None:
        raise ValueError(f"traffic window not found: {event.window_id}")

    source_ip = window["top_src_ip"]
    if not source_ip:
        alert_id = insert_alert(conn, event, window, [], "No source IP available; alert logged only")
        return {
            "window_id": event.window_id,
            "status": "alert_only",
            "alert_id": alert_id,
            "reason": "missing top_src_ip",
        }

    whitelisted = is_listed(conn, source_ip, "whitelist")
    blacklisted = is_listed(conn, source_ip, "blacklist")
    decision = choose_decision(event, window, whitelisted, blacklisted)
    alert_id = insert_alert(conn, event, window, [source_ip], decision.reason)

    mitigation_id = None
    removed_windows = 0
    if decision.rule_type and decision.target and decision.command:
        mitigation_id = upsert_mitigation(conn, alert_id, event, decision)
        removed_windows = apply_simulated_traffic_effect(conn, window, decision)

    return {
        "window_id": event.window_id,
        "status": "mitigated" if mitigation_id else "alert_only",
        "alert_id": alert_id,
        "mitigation_id": mitigation_id,
        "rule_type": decision.rule_type,
        "target": decision.target,
        "command": decision.command,
        "reason": decision.reason,
        "removed_windows": removed_windows,
    }


def choose_decision(
    event: MitigationEvent,
    window: sqlite3.Row,
    whitelisted: bool = False,
    blacklisted: bool = False,
) -> Decision:
    source_ip = window["top_src_ip"]
    port = window["top_dst_port"]
    protocol = infer_protocol(window)
    attack_type = normalized_attack_type(event)

    if whitelisted:
        return Decision(None, None, None, f"whitelisted source {source_ip}; mitigation skipped")
    if blacklisted:
        command = build_block_ip_command(source_ip)
        return Decision("block_ip", source_ip, command, f"blacklisted source {source_ip}; immediate block", 60 * 60)
    if event.level <= LOW_LEVEL_MAX:
        return Decision(None, None, None, f"low severity level={event.level}; alert logged only")
    if event.level <= MEDIUM_LEVEL_MAX:
        command = build_rate_limit_command(source_ip, 100, 200)
        return Decision("rate_limit", source_ip, command, rate_note(event, "lenient"), 15 * 60)
    if event.level < CRITICAL_LEVEL_MIN:
        if attack_type == "network_protocols" and port is not None and protocol in {"tcp", "udp"}:
            target = f"{source_ip}:{protocol}/{int(port)}"
            command = build_block_port_command(source_ip, protocol, int(port))
            return Decision("block_port", target, command, rate_note(event, "protocol port block"), 30 * 60)
        command = build_rate_limit_command(source_ip, 25, 50)
        return Decision("rate_limit", source_ip, command, rate_note(event, "strict"), 30 * 60)

    command = build_block_ip_command(source_ip)
    return Decision("block_ip", source_ip, command, rate_note(event, "critical block"), 60 * 60)


def infer_protocol(window: sqlite3.Row) -> str:
    fractions = {
        "tcp": float(window["proto_tcp_frac"] or 0.0),
        "udp": float(window["proto_udp_frac"] or 0.0),
        "icmp": float(window["proto_icmp_frac"] or 0.0),
        "other": float(window["proto_other_frac"] or 0.0),
    }
    if float(window["syn_ratio"] or 0.0) >= 0.5:
        return "tcp"
    return max(fractions, key=fractions.get)


def is_listed(conn: sqlite3.Connection, ip: str, list_type: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM ip_list WHERE ip = ? AND list_type = ?",
        (ip, list_type),
    ).fetchone()
    return row is not None


def insert_alert(
    conn: sqlite3.Connection,
    event: MitigationEvent,
    window: sqlite3.Row,
    source_ips: list[str],
    description: str,
) -> int:
    now = time.time()
    cur = conn.execute(
        """
        INSERT INTO active_alerts (
            alert_type, severity, anomaly_score, window_id_start, window_id_end,
            source_ips, triggered_features, description, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalized_attack_type(event),
            severity_name(event.level),
            event.level / 100.0,
            event.window_id,
            event.window_id,
            json.dumps(source_ips),
            triggered_features(window),
            description,
            now,
        ),
    )
    return int(cur.lastrowid)


def upsert_mitigation(
    conn: sqlite3.Connection,
    alert_id: int,
    event: MitigationEvent,
    decision: Decision,
) -> int:
    now = time.time()
    expires_at = now + decision.expires_in_seconds if decision.expires_in_seconds else None
    existing = conn.execute(
        """
        SELECT mitigation_id, expires_at, notes
        FROM active_mitigations
        WHERE rule_type = ? AND target = ? AND revoked_at IS NULL
        """,
        (decision.rule_type, decision.target),
    ).fetchone()

    notes = f"simulated; command stored but not executed; level={event.level}; type={event.attack_type}; {decision.reason}"
    if existing:
        old_expires = existing["expires_at"]
        should_extend = expires_at is not None and (old_expires is None or expires_at > old_expires)
        new_expires = expires_at if should_extend else old_expires
        conn.execute(
            """
            UPDATE active_mitigations
            SET expires_at = ?, notes = ?
            WHERE mitigation_id = ?
            """,
            (new_expires, f"{existing['notes'] or ''}; duplicate event refreshed", existing["mitigation_id"]),
        )
        return int(existing["mitigation_id"])

    cur = conn.execute(
        """
        INSERT INTO active_mitigations (
            rule_type, target, iptables_cmd, alert_id, applied_at, expires_at, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            decision.rule_type,
            decision.target,
            decision.command,
            alert_id,
            now,
            expires_at,
            notes,
        ),
    )
    return int(cur.lastrowid)


def apply_simulated_traffic_effect(
    conn: sqlite3.Connection,
    window: sqlite3.Row,
    decision: Decision,
) -> int:
    if decision.rule_type != "block_ip" or not decision.target:
        return 0

    cur = conn.execute(
        """
        UPDATE traffic_windows
        SET suppressed_at = ?,
            suppressed_by = ?,
            suppressed_reason = ?
        WHERE run_id = ?
          AND ts > ?
          AND top_src_ip = ?
          AND suppressed_at IS NULL
        """,
        (
            time.time(),
            f"mitigation:{decision.rule_type}:{decision.target}",
            "simulated block_ip traffic suppression",
            window["run_id"],
            window["ts"],
            decision.target,
        ),
    )
    return cur.rowcount


def severity_name(level: int) -> str:
    if level <= LOW_LEVEL_MAX:
        return "low"
    if level <= MEDIUM_LEVEL_MAX:
        return "medium"
    if level < CRITICAL_LEVEL_MIN:
        return "high"
    return "critical"


def triggered_features(window: sqlite3.Row) -> str:
    features = []
    if float(window["pkt_s"] or 0.0) > 0:
        features.append("pkt_s")
    if float(window["bytes_s"] or 0.0) > 0:
        features.append("bytes_s")
    if window["top_src_ip"]:
        features.append("top_src_ip")
    if window["top_dst_port"] is not None:
        features.append("top_dst_port")
    if float(window["syn_ratio"] or 0.0) >= 0.5:
        features.append("syn_ratio")
    return ",".join(features)


def build_rate_limit_command(source_ip: str, rate_per_second: int, burst: int) -> str:
    name = "limit_" + re.sub(r"[^A-Za-z0-9_]", "_", source_ip)
    return (
        f"iptables -A INPUT -s {source_ip} "
        f"-m hashlimit --hashlimit-above {rate_per_second}/second "
        f"--hashlimit-burst {burst} --hashlimit-mode srcip "
        f"--hashlimit-name {name} -j DROP"
    )


def build_block_ip_command(source_ip: str) -> str:
    return f"iptables -A INPUT -s {source_ip} -j DROP"


def build_block_port_command(source_ip: str, protocol: str, port: int) -> str:
    return f"iptables -A INPUT -s {source_ip} -p {protocol} --dport {port} -j DROP"


def normalized_attack_type(event: MitigationEvent) -> str:
    return ALLOWED_TYPES[event.attack_type]


def rate_note(event: MitigationEvent, action: str) -> str:
    return f"{action}; level={event.level}; type={event.attack_type}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply simulated DDoS mitigations to SQLite state.")
    parser.add_argument("--events-file", default=DEFAULT_EVENTS_FILE)
    parser.add_argument("--db", default=DEFAULT_DB_PATH)
    args = parser.parse_args(argv)

    events = load_events_file(args.events_file)
    conn = get_conn(args.db)
    try:
        results = process_events(conn, events)
    finally:
        conn.close()

    print(json.dumps(results, indent=2, sort_keys=True))
    return 0
