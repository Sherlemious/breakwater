"""
DB writer for the ingestion pipeline.

Responsibilities:
  - Open/update an ingestion_run row for the current job
  - Batch-insert TrafficWindow rows
  - Compute and store BaselineFeatureStats (learn mode only)
  - Mark the run as completed or failed
"""
from __future__ import annotations

import time
from typing import Iterable

import numpy as np

from .db import get_conn
from .models import BaselineFeatureStats, IngestionRun, TrafficWindow

_BATCH = 500   # rows per INSERT


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline(
    windows: Iterable[TrafficWindow],
    pcap_file: str,
    mode: str,
    dataset_split: str = "unknown",
    db_path: str | None = None,
) -> IngestionRun:
    """
    Consume a window stream, write everything to SQLite, return the run record.

    In 'learn' mode the baseline_stats table is also populated at the end.
    """
    conn = get_conn(db_path)

    run = _start_run(conn, pcap_file, mode, dataset_split)
    all_windows: list[TrafficWindow] = []

    try:
        batch: list[TrafficWindow] = []
        for w in windows:
            w.run_id = run.run_id  # type: ignore[assignment]
            batch.append(w)
            all_windows.append(w)
            if len(batch) >= _BATCH:
                _insert_windows(conn, batch)
                run.windows_extracted += len(batch)
                batch = []

        if batch:
            _insert_windows(conn, batch)
            run.windows_extracted += len(batch)

        if mode == "learn" and all_windows:
            _write_baseline(conn, all_windows, run.run_id)  # type: ignore[arg-type]

        _finish_run(conn, run, status="completed")

    except Exception as exc:
        _finish_run(conn, run, status="failed", error=str(exc))
        raise

    finally:
        conn.close()

    return run


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _start_run(conn, pcap_file: str, mode: str, dataset_split: str) -> IngestionRun:
    run = IngestionRun(
        pcap_file=pcap_file,
        mode=mode,
        dataset_split=dataset_split,
        started_at=time.time(),
    )
    cur = conn.execute(
        """
        INSERT INTO ingestion_runs (pcap_file, mode, dataset_split, status, started_at)
        VALUES (?, ?, ?, 'running', ?)
        """,
        (run.pcap_file, run.mode, run.dataset_split, run.started_at),
    )
    conn.commit()
    run.run_id = cur.lastrowid
    return run


def _finish_run(conn, run: IngestionRun, status: str, error: str | None = None) -> None:
    run.status = status
    run.completed_at = time.time()
    run.error = error
    conn.execute(
        """
        UPDATE ingestion_runs
        SET status = ?, packets_processed = ?, windows_extracted = ?,
            completed_at = ?, error = ?
        WHERE run_id = ?
        """,
        (
            run.status,
            run.packets_processed,
            run.windows_extracted,
            run.completed_at,
            run.error,
            run.run_id,
        ),
    )
    conn.commit()


def _insert_windows(conn, batch: list[TrafficWindow]) -> None:
    conn.executemany(
        """
        INSERT INTO traffic_windows (
            run_id, ts, ts_end,
            pkt_s, bytes_s, avg_pkt_size,
            unique_src_ips, src_ip_entropy,
            top_src_ip, top_src_ip_frac,
            unique_dst_ips, dst_ip_entropy, top_dst_ip, top_dst_ip_frac,
            dst_port_entropy, top_dst_port, top_dst_port_frac,
            web_port_frac,
            proto_tcp_frac, proto_udp_frac, proto_icmp_frac, proto_other_frac,
            syn_ratio, tcp_count, udp_count, icmp_count, syn_count,
            label, label_detail
        ) VALUES (
            :run_id, :ts, :ts_end,
            :pkt_s, :bytes_s, :avg_pkt_size,
            :unique_src_ips, :src_ip_entropy,
            :top_src_ip, :top_src_ip_frac,
            :unique_dst_ips, :dst_ip_entropy, :top_dst_ip, :top_dst_ip_frac,
            :dst_port_entropy, :top_dst_port, :top_dst_port_frac,
            :web_port_frac,
            :proto_tcp_frac, :proto_udp_frac, :proto_icmp_frac, :proto_other_frac,
            :syn_ratio, :tcp_count, :udp_count, :icmp_count, :syn_count,
            :label, :label_detail
        )
        """,
        [_window_row(w) for w in batch],
    )
    conn.commit()


def _window_row(w: TrafficWindow) -> dict:
    return {
        "run_id": w.run_id,
        "ts": w.ts,
        "ts_end": w.ts_end,
        "pkt_s": w.pkt_s,
        "bytes_s": w.bytes_s,
        "avg_pkt_size": w.avg_pkt_size,
        "unique_src_ips": w.unique_src_ips,
        "src_ip_entropy": w.src_ip_entropy,
        "top_src_ip": w.top_src_ip,
        "top_src_ip_frac": w.top_src_ip_frac,
        "unique_dst_ips": w.unique_dst_ips,
        "dst_ip_entropy": w.dst_ip_entropy,
        "top_dst_ip": w.top_dst_ip,
        "top_dst_ip_frac": w.top_dst_ip_frac,
        "dst_port_entropy": w.dst_port_entropy,
        "top_dst_port": w.top_dst_port,
        "top_dst_port_frac": w.top_dst_port_frac,
        "web_port_frac": w.web_port_frac,
        "proto_tcp_frac": w.proto_tcp_frac,
        "proto_udp_frac": w.proto_udp_frac,
        "proto_icmp_frac": w.proto_icmp_frac,
        "proto_other_frac": w.proto_other_frac,
        "syn_ratio": w.syn_ratio,
        "tcp_count": w.tcp_count,
        "udp_count": w.udp_count,
        "icmp_count": w.icmp_count,
        "syn_count": w.syn_count,
        "label": w.label,
        "label_detail": w.label_detail,
    }


def _write_baseline(conn, windows: list[TrafficWindow], run_id: int) -> None:
    """Compute percentile stats for every baseline feature and upsert into DB."""
    now = time.time()
    arrays: dict[str, list[float]] = {f: [] for f in TrafficWindow.BASELINE_FEATURES}
    for w in windows:
        for f in TrafficWindow.BASELINE_FEATURES:
            value = getattr(w, f)
            arrays[f].append(0.0 if value is None else value)

    stats: list[BaselineFeatureStats] = []
    for feature, values in arrays.items():
        arr = np.array(values, dtype=float)
        stats.append(BaselineFeatureStats(
            feature=feature,
            mean=float(arr.mean()),
            std=float(arr.std()),
            min=float(arr.min()),
            p10=float(np.percentile(arr, 10)),
            p25=float(np.percentile(arr, 25)),
            p50=float(np.percentile(arr, 50)),
            p75=float(np.percentile(arr, 75)),
            p90=float(np.percentile(arr, 90)),
            p95=float(np.percentile(arr, 95)),
            p99=float(np.percentile(arr, 99)),
            max=float(arr.max()),
            window_count=len(values),
            run_id=run_id,
            computed_at=now,
        ))

    conn.execute("DELETE FROM baseline_stats")
    conn.executemany(
        """
        INSERT INTO baseline_stats
            (feature, mean, std, min, p10, p25, p50, p75, p90, p95, p99,
             max, window_count, run_id, computed_at)
        VALUES
            (:feature, :mean, :std, :min, :p10, :p25, :p50, :p75, :p90, :p95, :p99,
             :max, :window_count, :run_id, :computed_at)
        """,
        [vars(s) for s in stats],
    )
    conn.commit()
