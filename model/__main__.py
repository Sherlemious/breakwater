from __future__ import annotations

import argparse
import os
from pathlib import Path

import joblib

from .db import get_conn
from .reader import FEATURE_NAMES, load_baseline, load_feature_matrix, load_windows, save_scores
from .scoring import (
    SUSPICIOUS_THRESHOLD,
    build_explanation,
    classify_attack_type,
    compute_hybrid_score,
    compute_statistical_score,
)
from .train import MODEL_FILENAME, train_random_forest


def _artifact_dir() -> Path:
    configured = os.environ.get("MODEL_ARTIFACT_DIR")
    if configured:
        return Path(configured)
    docker_path = Path("/app/data")
    return docker_path if docker_path.exists() else Path("data")


def _load_rf_model():
    path = _artifact_dir() / MODEL_FILENAME
    if not path.exists():
        return None
    return joblib.load(path)


def cmd_train(args) -> None:
    conn = get_conn(args.db)
    try:
        result = train_random_forest(conn)
    finally:
        conn.close()
    metrics = result["metrics"]
    print(
        "[model] train completed "
        f"rows_train={metrics['n_train_rows']} rows_val={metrics['n_validation_rows']} "
        f"f1={metrics['validation']['f1']:.4f}"
    )


def cmd_score(args) -> None:
    conn = get_conn(args.db)
    try:
        baseline = load_baseline(conn)
        if not baseline:
            raise ValueError("No baseline found. Run ingestion in learn mode first.")

        windows = load_windows(conn, unscored_only=True)
        rf_model = _load_rf_model()
        rows = []
        for w in windows:
            stat_score, feature_scores, triggered = compute_statistical_score(w, baseline)
            rf_prob = None
            if rf_model is not None:
                X = [[_numeric_feature(w[f]) for f in rf_model.feature_names_in_]] if hasattr(rf_model, "feature_names_in_") else None
                if X is None:
                    X = [[_numeric_feature(w[f]) for f in FEATURE_NAMES]]
                rf_prob = float(rf_model.predict_proba(X)[0][1])

            final_score = compute_hybrid_score(stat_score, rf_prob)
            predicted_type = None
            attack_conf = None
            top_evidence: list[str] = []
            if final_score >= SUSPICIOUS_THRESHOLD:
                predicted_type, attack_conf, top_evidence = classify_attack_type(w, feature_scores)

            rows.append(
                {
                    "window_id": w["window_id"],
                    "anomaly_score": final_score,
                    "statistical_score": stat_score,
                    "rf_attack_probability": rf_prob,
                    "predicted_attack_type": predicted_type,
                    "attack_type_confidence": attack_conf,
                    "triggered_features": triggered,
                    "explanation": build_explanation(
                        final_score=final_score,
                        statistical_score=stat_score,
                        rf_attack_probability=rf_prob,
                        predicted_attack_type=predicted_type,
                        attack_type_confidence=attack_conf,
                        triggered_features=triggered,
                        top_evidence=top_evidence,
                    ),
                }
            )

        if rows:
            save_scores(conn, rows)
        print(f"[model] score completed windows_scored={len(rows)} rf_loaded={rf_model is not None}")
    finally:
        conn.close()


def cmd_auto(args) -> None:
    conn = get_conn(args.db)
    try:
        rf_exists = (_artifact_dir() / MODEL_FILENAME).exists()
        if not rf_exists:
            _, y, _ = load_feature_matrix(conn, labeled_only=True, dataset_split="train")
            if len(y) > 0 and len(set(y.tolist())) >= 2:
                conn.close()
                cmd_train(args)
                conn = get_conn(args.db)
        cmd_score(args)
    finally:
        conn.close()


def _numeric_feature(value) -> float:
    return 0.0 if value is None else float(value)


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m model", description="Model service CLI")
    parser.add_argument("--db", default=None, help="Override SQLITE_DB_PATH")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("train")
    sub.add_parser("score")
    sub.add_parser("auto")
    args = parser.parse_args()

    if args.command == "train":
        cmd_train(args)
    elif args.command == "score":
        cmd_score(args)
    else:
        cmd_auto(args)


if __name__ == "__main__":
    main()
