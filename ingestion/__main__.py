"""
Entry point: python -m ingestion

Usage
-----
    # Learn mode — build baseline from normal traffic PCAP
    python -m ingestion /app/input/normal.pcap --mode learn

    # Detect mode — extract windows from a PCAP for anomaly scoring
    python -m ingestion /app/input/attack.pcap --mode detect

    # Scan the entire input directory (processes every *.pcap in order)
    python -m ingestion /app/input --mode detect
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .db import init_db
from .extractor import extract_windows
from .models import TrafficWindow
from .parser import iter_packets
from .writer import run_pipeline


def _parse_args():
    p = argparse.ArgumentParser(
        prog="python -m ingestion",
        description="Ingest PCAP files into the DDoS tool state store.",
    )
    p.add_argument(
        "input",
        help="Path to a .pcap file or a directory of .pcap files.",
    )
    p.add_argument(
        "--mode",
        choices=["learn", "detect"],
        default="detect",
        help="'learn' builds the traffic baseline; 'detect' scores windows (default: detect).",
    )
    p.add_argument(
        "--window-size",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Aggregation window in seconds (default: 1.0).",
    )
    p.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="Override SQLITE_DB_PATH environment variable.",
    )
    p.add_argument(
        "--dataset-split",
        choices=["train", "test", "unknown"],
        default="unknown",
        help="Dataset split tag for this ingestion run (default: unknown).",
    )
    p.add_argument(
        "--label",
        type=int,
        choices=[0, 1],
        default=None,
        help="Optional file-level label to write on all extracted windows.",
    )
    p.add_argument(
        "--label-detail",
        default=None,
        help="Optional label description applied to all extracted windows.",
    )
    return p.parse_args()


def _resolve_pcaps(input_path: str) -> list[Path]:
    p = Path(input_path)
    if p.is_dir():
        pcaps = sorted(p.glob("*.pcap")) + sorted(p.glob("*.pcapng"))
        if not pcaps:
            print(f"[ingestion] No .pcap files found in {p}", file=sys.stderr)
            sys.exit(1)
        return pcaps
    if not p.exists():
        print(f"[ingestion] File not found: {p}", file=sys.stderr)
        sys.exit(1)
    return [p]


def main() -> None:
    args = _parse_args()
    pcap_files = _resolve_pcaps(args.input)

    print("[ingestion] Applying schema …")
    init_db(args.db)

    for pcap_file in pcap_files:
        print(f"[ingestion] Processing {pcap_file.name}  mode={args.mode}")
        packets = iter_packets(str(pcap_file))
        windows = extract_windows(packets, run_id=0, window_size=args.window_size)
        if args.label is not None:
            windows = (
                _with_label(w, label=args.label, label_detail=args.label_detail)
                for w in windows
            )
        run = run_pipeline(
            windows,
            str(pcap_file),
            mode=args.mode,
            dataset_split=args.dataset_split,
            db_path=args.db,
        )
        suffix = "  [baseline updated]" if args.mode == "learn" else ""
        print(f"[ingestion] Done — {run.windows_extracted} windows extracted{suffix}")


def _with_label(window: TrafficWindow, label: int, label_detail: str | None) -> TrafficWindow:
    window.label = label
    window.label_detail = label_detail
    return window


if __name__ == "__main__":
    main()
