from __future__ import annotations

import os
import sqlite3
import json
import ipaddress
import smtplib
import logging
import subprocess
import sys
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, send_from_directory, request, Response


DB_PATH          = os.getenv("SQLITE_DB_PATH", "/app/db/ddos_tool.db")
DATA_DIR         = os.getenv("DATA_DIR", "/app/data")
APP_ROOT         = os.getenv("APP_ROOT", str(Path(__file__).resolve().parents[2]))
PCAP_INPUT_DIR   = os.getenv("PCAP_INPUT_DIR", "/app/input")
PCAP_INJECTION_DEFAULT = os.getenv("PCAP_INJECTION_DEFAULT", "attack-test.pcap")
COOLDOWN_SECONDS = int(os.getenv("NOTIFICATION_COOLDOWN_SECONDS", "1800"))
NOTIFICATION_THRESHOLD = float(os.getenv("NOTIFICATION_THRESHOLD", "0.70"))
BROWSER_NOTIFICATIONS_ENABLED = os.getenv("BROWSER_NOTIFICATIONS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
EMAIL_NOTIFICATIONS_ENABLED = os.getenv("EMAIL_NOTIFICATIONS_ENABLED", "auto").strip().lower()

SMTP_HOST     = os.getenv("SMTP_HOST",     "sandbox.smtp.mailtrap.io")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER",     "")   # paste Mailtrap username here
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")   # paste Mailtrap password here
ALERT_EMAIL   = os.getenv("ALERT_EMAIL",   "abd.moh.yousef@gmail.com")
SMTP_FROM     = os.getenv("SMTP_FROM",     "ddos-sentinel@demo.local")

FRONTEND_DIST = os.getenv("FRONTEND_DIST", "/app/dashboard/frontend/dist")
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

from ingestion.db import init_db


def _init_dashboard_db() -> None:
    conn = init_db(DB_PATH)
    conn.close()
    logging.info("dashboard database schema ready at %s", DB_PATH)


_init_dashboard_db()
app = Flask(__name__, static_folder=FRONTEND_DIST, static_url_path="")
notification_history: list[dict[str, Any]] = []
pcap_job_lock = threading.Lock()
pcap_job_status: dict[str, Any] = {
    "state": "idle",
    "filename": "",
    "effective_filename": PCAP_INJECTION_DEFAULT,
    "started_at": None,
    "completed_at": None,
    "message": "",
    "error": "",
    "windows_before": None,
    "windows_after": None,
    "scores_before": None,
    "scores_after": None,
}


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _query(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _scalar(sql: str, params: tuple[Any, ...] = ()) -> Any:
    rows = _query(sql, params)
    if not rows:
        return None
    return next(iter(rows[0].values()))


def _pcap_files() -> list[str]:
    root = Path(PCAP_INPUT_DIR)
    if not root.exists():
        return []
    return sorted(
        p.name for p in root.iterdir()
        if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}
    )


def _resolve_pcap_filename(raw_filename: str | None) -> tuple[str, Path]:
    filename = (raw_filename or "").strip() or PCAP_INJECTION_DEFAULT
    if Path(filename).is_absolute() or ".." in Path(filename).parts:
        raise ValueError("filename must be a PCAP name inside the mounted input directory")
    candidate = (Path(PCAP_INPUT_DIR) / filename).resolve()
    root = Path(PCAP_INPUT_DIR).resolve()
    if candidate.parent != root:
        raise ValueError("nested PCAP paths are not supported")
    if candidate.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("filename must end with .pcap or .pcapng")
    if not candidate.exists():
        raise FileNotFoundError(f"PCAP not found: {filename}")
    return filename, candidate


def _set_pcap_job(**updates: Any) -> None:
    with pcap_job_lock:
        pcap_job_status.update(updates)


def _run_checked(cmd: list[str]) -> str:
    pythonpath = os.environ.get("PYTHONPATH", "")
    env = {
        **os.environ,
        "SQLITE_DB_PATH": DB_PATH,
        "MODEL_ARTIFACT_DIR": DATA_DIR,
        "PYTHONPATH": f"{APP_ROOT}{os.pathsep}{pythonpath}" if pythonpath else APP_ROOT,
    }
    completed = subprocess.run(
        cmd,
        cwd=APP_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("PCAP_INJECTION_TIMEOUT_SECONDS", "600")),
    )
    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    if completed.returncode != 0:
        raise RuntimeError(output.strip() or f"{cmd} exited with status {completed.returncode}")
    return output.strip()


def _pcap_injection_worker(filename: str, pcap_path: Path) -> None:
    try:
        windows_before = int(_scalar("SELECT COUNT(*) FROM traffic_windows") or 0)
        scores_before = int(_scalar("SELECT COUNT(*) FROM window_anomaly_scores") or 0)
        _set_pcap_job(
            state="running",
            message=f"Ingesting {filename}",
            windows_before=windows_before,
            scores_before=scores_before,
            error="",
        )

        ingest_output = _run_checked([
            sys.executable,
            "-m",
            "ingestion",
            str(pcap_path),
            "--mode",
            "detect",
            "--dataset-split",
            "test",
        ])
        _set_pcap_job(message=f"Scoring {filename}")
        score_output = _run_checked([sys.executable, "-m", "model", "score"])

        windows_after = int(_scalar("SELECT COUNT(*) FROM traffic_windows") or 0)
        scores_after = int(_scalar("SELECT COUNT(*) FROM window_anomaly_scores") or 0)
        _set_pcap_job(
            state="completed",
            completed_at=time.time(),
            message=(
                f"Injected {filename}: +{windows_after - windows_before} windows, "
                f"+{scores_after - scores_before} scores"
            ),
            windows_after=windows_after,
            scores_after=scores_after,
            output="\n".join(part for part in (ingest_output, score_output) if part)[-4000:],
        )
    except Exception as exc:
        logging.exception("pcap injection failed")
        _set_pcap_job(
            state="failed",
            completed_at=time.time(),
            message="PCAP injection failed",
            error=str(exc),
        )


def _page_args(default_limit: int = 50, max_limit: int = 200) -> tuple[int, int]:
    try:
        limit = int(request.args.get("limit", str(default_limit)))
        offset = int(request.args.get("offset", "0"))
    except ValueError:
        limit, offset = default_limit, 0
    return max(1, min(limit, max_limit)), max(0, offset)


def _page_response(items: list[dict[str, Any]], total: int, limit: int, offset: int):
    next_offset = offset + len(items)
    return jsonify({
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
        "has_more": next_offset < total,
    })



def _get_ip_list(list_type: str) -> dict[str, Any]:
    rows = _query(
        "SELECT ip FROM ip_list WHERE list_type = ? ORDER BY added_at",
        (list_type,),
    )
    ts = _query(
        "SELECT datetime(MAX(added_at), 'unixepoch') AS ts FROM ip_list WHERE list_type = ?",
        (list_type,),
    )
    return {"ips": [r["ip"] for r in rows], "last_updated": ts[0]["ts"] if ts else None}


def _add_ip(ip: str, list_type: str) -> dict[str, Any]:
    import time as _time
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO ip_list (ip, list_type, added_at) VALUES (?, ?, ?)",
            (ip, list_type, _time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return _get_ip_list(list_type)


def _suppress_blacklisted_windows(conn: sqlite3.Connection, ip: str, window_id: int | None) -> dict[str, Any]:
    start_ts = None
    run_id = None
    from_window_id = None
    if window_id is not None:
        row = conn.execute(
            "SELECT window_id, run_id, ts FROM traffic_windows WHERE window_id = ?",
            (window_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"window not found: {window_id}")
        run_id = row["run_id"]
        start_ts = row["ts"]
        from_window_id = row["window_id"]
    else:
        row = conn.execute("SELECT MAX(ts) AS ts FROM traffic_windows").fetchone()
        start_ts = row["ts"] if row else None

    if start_ts is None:
        return {"affected_windows": 0, "from_window_id": from_window_id, "from_timestamp": None}

    now = time.time()
    params: list[Any] = [now, f"blacklist:{ip}", "manual blacklist from dashboard", ip, start_ts]
    run_filter = ""
    if run_id is not None:
        run_filter = "AND run_id = ?"
        params.append(run_id)
    cur = conn.execute(
        f"""
        UPDATE traffic_windows
        SET suppressed_at = ?, suppressed_by = ?, suppressed_reason = ?
        WHERE top_src_ip = ?
          AND ts >= ?
          {run_filter}
          AND suppressed_at IS NULL
        """,
        params,
    )
    return {
        "affected_windows": cur.rowcount,
        "from_window_id": from_window_id,
        "from_timestamp": start_ts,
    }


def _restore_blacklisted_windows(conn: sqlite3.Connection, ip: str) -> int:
    cur = conn.execute(
        """
        UPDATE traffic_windows
        SET suppressed_at = NULL,
            suppressed_by = NULL,
            suppressed_reason = NULL
        WHERE suppressed_by = ?
        """,
        (f"blacklist:{ip}",),
    )
    return cur.rowcount


def _apply_manual_blacklist(ip: str, window_id: int | None = None) -> dict[str, Any]:
    now = time.time()
    expires_at = now + 60 * 60
    command = f"iptables -A INPUT -s {ip} -j DROP"
    conn = _conn()
    try:
        suppression = _suppress_blacklisted_windows(conn, ip, window_id)
        existing = conn.execute(
            """
            SELECT mitigation_id
            FROM active_mitigations
            WHERE rule_type = 'block_ip'
              AND target = ?
              AND revoked_at IS NULL
            """,
            (ip,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE active_mitigations
                SET expires_at = ?, notes = ?
                WHERE mitigation_id = ?
                """,
                (expires_at, "manual blacklist from dashboard; refreshed", existing["mitigation_id"]),
            )
        else:
            conn.execute(
                """
                INSERT INTO active_mitigations (
                    rule_type, target, iptables_cmd, alert_id, applied_at, expires_at, notes
                ) VALUES ('block_ip', ?, ?, NULL, ?, ?, ?)
                """,
                (ip, command, now, expires_at, "manual blacklist from dashboard"),
            )
        conn.commit()
        return suppression
    finally:
        conn.close()


def _revoke_manual_blacklist(ip: str) -> int:
    conn = _conn()
    try:
        restored_windows = _restore_blacklisted_windows(conn, ip)
        conn.execute(
            """
            UPDATE active_mitigations
            SET revoked_at = ?
            WHERE rule_type = 'block_ip'
              AND target = ?
              AND revoked_at IS NULL
              AND notes LIKE 'manual blacklist from dashboard%'
            """,
            (time.time(), ip),
        )
        conn.commit()
        return restored_windows
    finally:
        conn.close()


def _remove_ip(ip: str, list_type: str) -> dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("DELETE FROM ip_list WHERE ip = ? AND list_type = ?", (ip, list_type))
        conn.commit()
    finally:
        conn.close()
    return _get_ip_list(list_type)


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "db_path": DB_PATH})


@app.get("/api/summary")
def summary():
    sql = """
    SELECT
      (SELECT COUNT(*) FROM traffic_windows WHERE suppressed_at IS NULL) AS windows_count,
      (SELECT COUNT(*) FROM window_anomaly_scores was JOIN traffic_windows tw ON tw.window_id = was.window_id WHERE tw.suppressed_at IS NULL) AS scored_count,
      (SELECT COUNT(*) FROM active_alerts) AS alerts_count,
      (SELECT COUNT(*) FROM active_mitigations) AS mitigations_count
    """
    rows = _query(sql)
    return jsonify(rows[0] if rows else {})


@app.get("/api/anomaly-trend")
def anomaly_trend():
    sql = """
    SELECT
      datetime(tw.ts, 'unixepoch') AS timestamp,
      was.anomaly_score,
      was.rf_attack_probability,
      was.predicted_attack_type
    FROM traffic_windows tw
    JOIN window_anomaly_scores was ON was.window_id = tw.window_id
    WHERE tw.suppressed_at IS NULL
    ORDER BY tw.ts, tw.window_id
    LIMIT 2000
    """
    return jsonify(_query(sql))


@app.get("/api/network-series")
def network_series():
    start = int(request.args.get("start", "0"))
    end = int(request.args.get("end", "500"))
    length = max(end - start + 1, 1)
    sql = """
    SELECT
      window_id,
      datetime(ts, 'unixepoch') AS timestamp,
      pkt_s AS pkt_count,
      bytes_s AS byte_count,
      unique_src_ips AS src_ip_unique,
      COALESCE(unique_dst_ips, 0) AS dst_port_unique,
      COALESCE(proto_tcp_frac, 0.0) * 100.0 AS tcp_pct,
      COALESCE(proto_udp_frac, 0.0) * 100.0 AS udp_pct,
      COALESCE(proto_icmp_frac, 0.0) * 100.0 AS icmp_pct
    FROM traffic_windows
    WHERE suppressed_at IS NULL
    ORDER BY ts, window_id
    LIMIT ? OFFSET ?
    """
    return jsonify(_query(sql, (length, start)))


@app.get("/api/score-series")
def score_series():
    start = int(request.args.get("start", "0"))
    end = int(request.args.get("end", "500"))
    length = max(end - start + 1, 1)
    sql = """
    SELECT
      tw.window_id,
      datetime(tw.ts, 'unixepoch') AS timestamp,
      was.anomaly_score,
      was.rf_attack_probability,
      was.predicted_attack_type
    FROM traffic_windows tw
    JOIN window_anomaly_scores was ON was.window_id = tw.window_id
    WHERE tw.suppressed_at IS NULL
    ORDER BY tw.ts, tw.window_id
    LIMIT ? OFFSET ?
    """
    rows = _query(sql, (length, start))
    if rows:
        _record_notifications(rows)
    return jsonify(rows)


def _alert_email_body(row: dict[str, Any]) -> tuple[str, str]:
    attack_type   = row.get("predicted_attack_type") or "unknown"
    anomaly_score = float(row.get("anomaly_score") or 0.0)
    rf_prob       = float(row.get("rf_attack_probability") or 0.0)
    timestamp     = row.get("timestamp", "—")
    window_id     = row.get("window_id")

    # Pull alert + mitigation details linked to this window
    details = _query(
        """
        SELECT aa.severity, aa.source_ips, aa.description,
               tw.top_src_ip,
               am.rule_type, am.target, am.iptables_cmd, am.expires_at
        FROM active_alerts aa
        JOIN traffic_windows tw ON tw.window_id = aa.window_id_start
        LEFT JOIN active_mitigations am ON am.alert_id = aa.alert_id AND am.revoked_at IS NULL
        WHERE aa.window_id_start = ?
        ORDER BY aa.created_at DESC
        LIMIT 1
        """,
        (window_id,),
    )

    severity  = details[0]["severity"]  if details else "high"
    source_ip = details[0]["top_src_ip"] if details else "unknown"
    rule_type = details[0]["rule_type"]  if details else "—"
    target    = details[0]["target"]     if details else "—"
    cmd       = details[0]["iptables_cmd"] if details else "—"

    TYPE_LABEL = {
        "volumetric":        "Volumetric (bandwidth flood)",
        "network_protocols": "Network Protocol (SYN/UDP flood)",
        "application_layer": "Application-Layer (HTTP flood)",
    }
    subject = f"[DDoS Sentinel] {severity.upper()} — {TYPE_LABEL.get(attack_type, attack_type)} detected"

    body = f"""\
DDoS SENTINEL — AUTOMATED ALERT
=================================

A high-confidence DDoS attack has been detected and mitigation has
been applied automatically.

DETECTION SUMMARY
-----------------
  Attack Type    : {TYPE_LABEL.get(attack_type, attack_type)}
  Severity       : {severity.upper()}
  Anomaly Score  : {anomaly_score:.3f} / 1.000
  RF Probability : {rf_prob:.3f} / 1.000
  Detected At    : {timestamp}
  Source IP      : {source_ip}
  Window ID      : {window_id}

MITIGATION APPLIED
------------------
  Rule Type      : {rule_type}
  Target         : {target}
  iptables cmd   : {cmd}

ACTION REQUIRED
---------------
The above rule has been simulated and stored. If this is a live
environment, apply the iptables command on your border gateway.

Review the full dashboard for active alerts and mitigation history.

-- DDoS Sentinel (automated)
"""
    return subject, body


def _email_notifications_enabled() -> bool:
    if EMAIL_NOTIFICATIONS_ENABLED in {"0", "false", "no", "off"}:
        return False
    return bool(SMTP_USER and SMTP_PASSWORD)


def _notification_entry(
    row: dict[str, Any],
    *,
    channel: str,
    recipient: str,
    status: str,
    epoch: int,
    title: str,
    message: str,
) -> dict[str, Any]:
    attack_type = row.get("predicted_attack_type") or "unknown"
    score = float(row.get("anomaly_score") or 0.0)
    window_id = row.get("window_id")
    return {
        "id": f"{channel}:{attack_type}:{window_id}:{epoch}",
        "timestamp": row.get("timestamp"),
        "channel": channel,
        "recipient": recipient,
        "alert_type": attack_type,
        "status": status,
        "epoch": epoch,
        "window_id": window_id,
        "score": score,
        "title": title,
        "message": message,
    }


def _record_notifications(score_rows: list[dict[str, Any]]) -> None:
    now = int(_query("SELECT strftime('%s','now') AS now")[0]["now"])
    last_sent: dict[str, int] = {}
    for item in reversed(notification_history):
        alert_type = item.get("alert_type")
        if alert_type and alert_type not in last_sent:
            last_sent[alert_type] = int(item.get("epoch", 0))

    for row in score_rows:
        score       = float(row.get("anomaly_score") or 0.0)
        attack_type = row.get("predicted_attack_type") or "unknown"
        if score < NOTIFICATION_THRESHOLD or attack_type == "unknown":
            continue
        prev = last_sent.get(attack_type, 0)
        if now - prev < COOLDOWN_SECONDS:
            continue

        subject, body = _alert_email_body(row)
        message = f"{attack_type} attack detected with anomaly score {score:.3f}."
        sent_any_channel = False

        if BROWSER_NOTIFICATIONS_ENABLED:
            notification_history.append(_notification_entry(
                row,
                channel="browser",
                recipient="dashboard",
                status="queued",
                epoch=now,
                title=subject,
                message=message,
            ))
            sent_any_channel = True

        if _email_notifications_enabled():
            try:
                _send_email(subject, body)
                email_status = "success"
            except Exception:
                logging.exception("auto alert email failed")
                email_status = "email_failed"

            notification_history.append(_notification_entry(
                row,
                channel="email",
                recipient=ALERT_EMAIL,
                status=email_status,
                epoch=now,
                title=subject,
                message=message,
            ))
            sent_any_channel = True

        if not sent_any_channel:
            notification_history.append(_notification_entry(
                row,
                channel="local",
                recipient="server-log",
                status="no_channel_enabled",
                epoch=now,
                title=subject,
                message=message,
            ))

        last_sent[attack_type] = now

    if len(notification_history) > 300:
        del notification_history[:-300]


@app.get("/api/attack-types")
def attack_types():
    sql = """
    SELECT
      predicted_attack_type AS type,
      COUNT(*) AS count
    FROM window_anomaly_scores was
    JOIN traffic_windows tw ON tw.window_id = was.window_id
    WHERE was.predicted_attack_type IS NOT NULL
      AND tw.suppressed_at IS NULL
    GROUP BY was.predicted_attack_type
    ORDER BY count DESC
    """
    return jsonify(_query(sql))


@app.get("/api/alerts")
def alerts():
    limit, offset = _page_args()
    sql = """
    SELECT
      alert_id,
      datetime(created_at, 'unixepoch') AS timestamp,
      alert_type,
      severity,
      anomaly_score,
      window_id_start AS window_id,
      source_ips,
      description
    FROM active_alerts
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
    """
    total = int(_query("SELECT COUNT(*) AS total FROM active_alerts")[0]["total"])
    return _page_response(_query(sql, (limit, offset)), total, limit, offset)


@app.get("/api/mitigation-events")
def mitigation_events():
    """All mitigation actions with alert context, for the mitigation timeline."""
    limit, offset = _page_args()
    sql = """
    SELECT
      am.mitigation_id,
      datetime(am.applied_at, 'unixepoch') AS timestamp,
      am.rule_type,
      am.target,
      am.iptables_cmd,
      am.notes,
      aa.severity,
      aa.alert_type,
      aa.anomaly_score
    FROM active_mitigations am
    LEFT JOIN active_alerts aa ON aa.alert_id = am.alert_id
    ORDER BY am.applied_at DESC
    LIMIT ? OFFSET ?
    """
    total = int(_query("SELECT COUNT(*) AS total FROM active_mitigations")[0]["total"])
    return _page_response(_query(sql, (limit, offset)), total, limit, offset)


@app.get("/api/mitigations")
def mitigations():
    sql = """
    SELECT
      mitigation_id,
      datetime(applied_at, 'unixepoch') AS timestamp,
      rule_type,
      target,
      iptables_cmd,
      notes
    FROM active_mitigations
    ORDER BY applied_at DESC
    LIMIT 200
    """
    return jsonify(_query(sql))


@app.get("/api/window-meta")
def window_meta():
    sql = """
    SELECT
      COUNT(*) AS total,
      datetime(MIN(ts), 'unixepoch') AS min_ts,
      datetime(MAX(ts), 'unixepoch') AS max_ts
    FROM traffic_windows
    WHERE suppressed_at IS NULL
    """
    rows = _query(sql)
    return jsonify(rows[0] if rows else {"total": 0, "min_ts": None, "max_ts": None})


@app.get("/api/notification-history")
def notification_history_view():
    return jsonify(notification_history[-50:])


@app.post("/api/test-notification")
def test_notification():
    now_row = _query("SELECT strftime('%s','now') AS epoch, datetime('now') AS ts")[0]
    epoch = int(now_row["epoch"])
    row = {
        "window_id": "manual-test",
        "timestamp": now_row["ts"],
        "predicted_attack_type": "test",
        "anomaly_score": 1.0,
    }
    entry = _notification_entry(
        row,
        channel="browser",
        recipient="dashboard",
        status="queued",
        epoch=epoch,
        title="[DDoS Sentinel] Test browser notification",
        message="Browser notifications are wired to the dashboard.",
    )
    notification_history.append(entry)
    if len(notification_history) > 300:
        del notification_history[:-300]
    return jsonify({"ok": True, "notification": entry})


@app.get("/api/pcap-injection/status")
def pcap_injection_status():
    with pcap_job_lock:
        status = dict(pcap_job_status)
    status["default_filename"] = PCAP_INJECTION_DEFAULT
    status["input_dir"] = PCAP_INPUT_DIR
    status["available_pcaps"] = _pcap_files()
    return jsonify(status)


@app.get("/pcap-injection/status")
def pcap_injection_status_alias():
    return pcap_injection_status()


@app.post("/api/pcap-injection")
@app.post("/pcap-injection")
def pcap_injection_start():
    payload = request.get_json(silent=True) or {}
    try:
        filename, pcap_path = _resolve_pcap_filename(payload.get("filename"))
    except FileNotFoundError as exc:
        return jsonify({"ok": False, "error": str(exc), "available_pcaps": _pcap_files()}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    with pcap_job_lock:
        if pcap_job_status.get("state") in {"queued", "running"}:
            return jsonify({"ok": False, "error": "PCAP injection already running", "job": dict(pcap_job_status)}), 409
        pcap_job_status.update({
            "state": "queued",
            "filename": (payload.get("filename") or "").strip(),
            "effective_filename": filename,
            "started_at": time.time(),
            "completed_at": None,
            "message": f"Queued {filename}",
            "error": "",
            "output": "",
            "windows_before": None,
            "windows_after": None,
            "scores_before": None,
            "scores_after": None,
        })
        job_snapshot = dict(pcap_job_status)

    thread = threading.Thread(
        target=_pcap_injection_worker,
        args=(filename, pcap_path),
        daemon=True,
    )
    thread.start()
    return jsonify({"ok": True, "job": job_snapshot})


@app.get("/api/cooldown-status")
def cooldown_status():
    if not notification_history:
        return jsonify({"status": "idle", "seconds": 0})
    last = notification_history[-1]
    now = int(_query("SELECT strftime('%s','now') AS now")[0]["now"])
    rem = COOLDOWN_SECONDS - max(0, now - int(last.get("epoch", 0)))
    if rem > 0:
        return jsonify({"status": "in_cooldown", "seconds": rem, "alert_type": last.get("alert_type")})
    return jsonify({"status": "ready", "seconds": 0, "alert_type": last.get("alert_type")})


@app.get("/api/whitelist")
def whitelist_get():
    return jsonify(_get_ip_list("whitelist"))


@app.post("/api/whitelist")
def whitelist_add():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "invalid ip"}), 400
    _remove_ip(ip, "blacklist")
    restored_windows = _revoke_manual_blacklist(ip)
    result = _add_ip(ip, "whitelist")
    result["restored_windows"] = restored_windows
    return jsonify(result)


@app.delete("/api/whitelist/<path:ip>")
def whitelist_delete(ip: str):
    return jsonify(_remove_ip(ip, "whitelist"))


@app.get("/api/blacklist")
def blacklist_get():
    return jsonify(_get_ip_list("blacklist"))


@app.post("/api/blacklist")
def blacklist_add():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    raw_window_id = payload.get("window_id")
    window_id = None
    if raw_window_id not in (None, ""):
        try:
            window_id = int(raw_window_id)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid window_id"}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "invalid ip"}), 400
    _remove_ip(ip, "whitelist")
    result = _add_ip(ip, "blacklist")
    try:
        result.update(_apply_manual_blacklist(ip, window_id))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(result)


@app.delete("/api/blacklist/<path:ip>")
def blacklist_delete(ip: str):
    result = _remove_ip(ip, "blacklist")
    result["restored_windows"] = _revoke_manual_blacklist(ip)
    return jsonify(result)


@app.get("/api/export-alerts.csv")
def export_alerts_csv():
    rows = _query(
        """
        SELECT
          alert_id,
          datetime(created_at, 'unixepoch') AS timestamp,
          alert_type,
          severity,
          anomaly_score,
          description
        FROM active_alerts
        ORDER BY created_at DESC
        """
    )
    lines = ["alert_id,timestamp,alert_type,severity,anomaly_score,description"]
    for r in rows:
        desc = str(r.get("description", "")).replace('"', '""')
        lines.append(
            f"{r.get('alert_id','')},{r.get('timestamp','')},{r.get('alert_type','')},{r.get('severity','')},{r.get('anomaly_score','')},\"{desc}\""
        )
    csv_text = "\n".join(lines)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/<path:path>")
def assets(path: str):
    if path.startswith("api/"):
        return jsonify({"error": f"unknown endpoint: /{path}"}), 404
    file_path = os.path.join(app.static_folder, path)
    if os.path.exists(file_path):
        return send_from_directory(app.static_folder, path)
    try:
        return send_from_directory(app.static_folder, "index.html")
    except Exception:
        return jsonify({"error": "frontend not built"}), 404


def _send_email(subject: str, body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"DDoS Sentinel <{SMTP_FROM}>"
    msg["To"]      = ALERT_EMAIL
    msg.attach(MIMEText(body, "plain"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.ehlo()
        s.starttls()
        s.login(SMTP_USER, SMTP_PASSWORD)
        s.sendmail(SMTP_FROM, ALERT_EMAIL, msg.as_string())


@app.post("/api/test-email")
def test_email():
    try:
        _send_email(
            subject="[DDoS Sentinel] Test notification",
            body=(
                "This is a test alert from DDoS Sentinel.\n\n"
                "If you received this, the email notification system is working correctly.\n\n"
                f"Dashboard DB: {DB_PATH}"
            ),
        )
        return jsonify({"ok": True, "recipient": ALERT_EMAIL})
    except Exception as exc:
        logging.exception("test-email failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("BACKEND_PORT", "8051")))
